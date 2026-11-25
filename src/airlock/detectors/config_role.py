"""`config_role` detector: capability rules over build tooling.

Task 3.1 (`ARCHITECTURE.md` 9.1). The single-line capability rules (`cfg-dynamic-code`,
`cfg-network`, `cfg-chain-endpoint`) are pattern data and run in the engine pass. What lives
here is logic a pattern cannot express: the two-tier spawn rule (whose pattern stays in the data
file, but which the engine must not run or every dropper line would be reported twice), the
combination rule, and the appended tail.

Two hard rules shape this module. There is no comment or string masking (ADR-013), so a payload
cannot be hidden behind `//`. And network alone is a WARN, because some legitimate Next.js
configs fetch at build time; what makes it fatal is pairing it with a way to run something.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext, Severity
from ..roles import TOOLING_CONFIG_ROLE
from ..rules import apply_patterns, finding_for, line_matches

NETWORK_RULE_ID = "cfg-network"
SPAWN_RULE_ID = "cfg-process-spawn"
DYNAMIC_RULE_ID = "cfg-dynamic-code"
EXEC_RULE_ID = "cfg-network-exec"
TAIL_RULE_ID = "cfg-appended-tail"

#: `require()` of something computed at run time: the dependency is no longer visible to a
#: lockfile review, which is the third execution ingredient of the combination rule.
_NON_LITERAL_REQUIRE = re.compile(r"""\brequire\s*\(\s*(?!["'`])[A-Za-z_$][\w$.[\]+\-]*\s*\)""")

#: A spawn that fetches, decodes or hands a script to an interpreter, rather than running a
#: build tool that was named up front. The third branch is the array form a config passes to
#: `spawnSync`, where the flag and the script are separate arguments.
_DANGEROUS_COMMAND = re.compile(
    r"""(?ix)
    \b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|certutil|base64|fromCharCode|atob)\b
    | \b(?:sh|bash|cmd|powershell|python[23]?|node|perl|ruby)\b[\s\S]{0,2}\s+-[ce]\b
    | \s(?:-c|-e)\s+["'`]
    | [(\[]\s*["'`]-[ce]["'`]
    """
)


def _by_id(ctx: ScanContext) -> dict[str, Rule]:
    return {rule.id: rule for rule in ctx.rules}


def _text_lines(text: str) -> dict[int, str]:
    return {number: raw.removesuffix("\r") for number, raw in enumerate(text.split("\n"), start=1)}


def _spawn_tier(rule: Rule, lines: dict[int, str], line_cap: int) -> tuple[tuple[int, bool], ...]:
    """Spawn hits as (line number, is dangerous).

    `cfg-process-spawn` is a code rule with a pattern in the data file, so the engine never runs
    it and this is the only place its WARN tier is emitted. A hit that names a downloader, a
    decoder or an inline script is the dropper shape, so it becomes HIGH here rather than
    stacking a second finding on the same line.
    """
    if rule.pattern is None:
        return ()
    return tuple(
        (number, _DANGEROUS_COMMAND.search(line) is not None)
        for number, line in lines.items()
        if len(line) <= line_cap and line_matches(rule, line)
    )


def _spawn_findings(
    rule: Rule, entry: FileEntry, lines: dict[int, str], line_cap: int
) -> list[PendingFinding]:
    findings: list[PendingFinding] = []
    for number, dangerous in _spawn_tier(rule, lines, line_cap):
        line = lines[number]
        findings.append(
            finding_for(
                rule,
                entry,
                number,
                evidence=line,
                message=(
                    (
                        "Process execution from a build config: the command names a downloader, a "
                        "decoder or an inline script, so it is not a build step stated up front"
                    )
                    if dangerous
                    else rule.title
                ),
                severity=Severity.HIGH if dangerous else rule.severity,
            )
        )
    return findings


def _require_lines(lines: dict[int, str], line_cap: int) -> tuple[int, ...]:
    return tuple(
        number
        for number, line in lines.items()
        if len(line) <= line_cap and _NON_LITERAL_REQUIRE.search(line)
    )


def _combination(
    rule: Rule,
    entry: FileEntry,
    lines: dict[int, str],
    network: list[int],
    execution: list[int],
) -> PendingFinding | None:
    """Network plus any execution ingredient in one file is HIGH, whatever each half alone is."""
    if not network or not execution:
        return None
    first = min(network + execution)
    return finding_for(
        rule,
        entry,
        first,
        evidence=lines.get(first, ""),
        message=(
            f"{rule.title}: network capability at line {min(network)} and execution at line "
            f"{min(execution)} sit in the same file"
        ),
    )


def _shannon_entropy(text: str) -> float:
    """Bits per character over a window. Empty input is zero, not undefined."""
    if not text:
        return 0.0
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in Counter(text).values())


def _tail_window(lines: dict[int, str], tail_max_len: int) -> tuple[int, int, str]:
    """The trailing non-empty lines as one window: (first line, last line, text).

    A payload split over the final two lines is measured as neither half when only the last line is
    read: the blob before the terminator is never seen. Lines are gathered backwards until the
    window reaches `tail_max_len`, and joined oldest to newest so entropy is measured over what the
    file actually ends with.

    Only a line that is one whitespace-free token is joined to the one after it. Ordinary code
    lines carry spaces, and joining them would make the tail of a short config read as an opaque
    blob purely because prose and code sit at the same entropy as a base64 run at this window size.
    The final line is always the window's seed, so the rules this check already had are unchanged.
    """
    picked: list[tuple[int, str]] = []
    size = 0
    for number, line in reversed(list(lines.items())):
        if not line.strip():
            continue
        if picked and len(line.split()) > 1:
            break
        size += len(line) + (1 if picked else 0)
        picked.append((number, line))
        if size >= tail_max_len:
            break
    if not picked:
        return 0, 0, ""
    picked.reverse()
    return picked[0][0], picked[-1][0], "\n".join(line for _, line in picked)


def _tail_finding(
    rule: Rule, entry: FileEntry, tail_max_len: int, tail_entropy: float
) -> PendingFinding | None:
    """The appended payload shape: trailing bytes that are too long or too opaque.

    The length reason stays on the final line, because a minified bundle is one line by
    construction. Entropy is measured across the window, so a high-entropy blob and a short
    terminator after it are one payload rather than two innocent lines.
    """
    lines = _text_lines(entry.text or "")
    first_number, last_number, trailing = _tail_window(lines, tail_max_len)
    if not trailing:
        return None
    window = trailing[-tail_max_len:]
    entropy = _shannon_entropy(window)
    if len(lines[last_number]) > tail_max_len:
        reason = f"is longer than the {tail_max_len} character tail limit"
    elif entropy > tail_entropy:
        reason = (
            f"carries {entropy:.2f} bits of entropy per character, over the {tail_entropy} limit"
        )
    else:
        return None
    return finding_for(
        rule,
        entry,
        last_number,
        evidence=lines[last_number],
        message=(
            f"{rule.title}: the trailing bytes from line {first_number} to line {last_number} "
            f"{reason}"
        ),
    )


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Emit the config-role findings a pattern cannot express.

    The engine pass already ran the `pattern` rules over every file, including the capability
    rules below, so this yields only what the engine cannot: the spawn tiers, the combination
    and the appended tail. Emitting a pattern hit again here would double-report the line.
    """
    rules = _by_id(ctx)
    exec_rule = rules.get(EXEC_RULE_ID)
    tail_rule = rules.get(TAIL_RULE_ID)
    spawn_rule = rules.get(SPAWN_RULE_ID)

    for entry in ctx.entries:
        if TOOLING_CONFIG_ROLE not in entry.roles or entry.text is None:
            continue
        lines = _text_lines(entry.text)
        hits = apply_patterns(ctx.rules, entry, ctx.policy.line_cap)
        network = [finding.line for finding in hits if finding.rule_id == NETWORK_RULE_ID]
        execution = [finding.line for finding in hits if finding.rule_id == DYNAMIC_RULE_ID] + list(
            _require_lines(lines, ctx.policy.line_cap)
        )

        if spawn_rule is not None:
            spawn_findings = _spawn_findings(spawn_rule, entry, lines, ctx.policy.line_cap)
            yield from spawn_findings
            execution += [finding.line for finding in spawn_findings]

        if exec_rule is not None:
            combination = _combination(exec_rule, entry, lines, network, sorted(execution))
            if combination is not None:
                yield combination

        if tail_rule is not None:
            tail = _tail_finding(tail_rule, entry, ctx.policy.tail_max_len, ctx.policy.tail_entropy)
            if tail is not None:
                yield tail
