"""`ci_surface` detector: the CI-layer rules that need two conditions at once.

Task 3.6 (`ARCHITECTURE.md` 9.6). The family's single-condition rules (`pat-privileged-trigger`,
`pat-lifecycle-fetch` and `pat-editor-command-path`) are pattern data and run in the engine pass,
so this module yields only what a line-at-a-time pattern cannot: a secret interpolation paired
with a verb that displays it, a privileged trigger paired with a head checkout, and a fetch paired
with what the same line hands it to.

Two hard rules shape it. There is no comment or string masking (ADR-013), so a YAML comment that
spells out the shape is a match by design. And no line past `line_cap` is searched, which is why the
trigger and fetch halves read their pattern out of the rule data through `rules.line_matches` rather
than carrying their own copy: an over-cap line is `cfg-long-line`'s account to give, and a second
uncapped reader of the same text would be a ReDoS hole in the one layer meant to close it.

The pairings are separate linear searches instead of one regex for the same reason. The obvious
single pattern for the dropper, a downloader then `.*` then a shell, restarts its `.*` at every
column, so it is quadratic in the line length and therefore unbounded in a file. Every matcher below
is a literal or a bounded character class, and the two that pair conditions run only on lines the
first condition already hit.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext
from ..roles import INSTALL_HOOK_ROLE
from ..rules import finding_for, line_matches

LIFECYCLE_EXEC_WINDOW = 3
PRIVILEGED_RULE_ID = "pat-privileged-trigger"
FETCH_RULE_ID = "pat-lifecycle-fetch"
EXEC_RULE_ID = "pat-lifecycle-exec"
SECRET_DUMP_RULE_ID = "pat-secret-dump"
HEAD_CHECKOUT_RULE_ID = "pat-ptr-head-checkout"

#: `${{ secrets.NAME }}`, the only form in which a workflow can name a credential it was given.
_SECRETS_INTERP = re.compile(r"""\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}""")

#: A command that puts a value where a human or a later step can read it. Passing a secret through
#: `env:` or `with:` is not in this list, because that is how a workflow uses one, and it is the
#: negative fixture rather than a finding.
_DISPLAY_VERB = re.compile(
    r"""\b(?:echo|printf|print|cat|tee|xxd|base64)\b|\b(?:Write-Output|Add-Content|Out-File)\b"""
)

#: The one echo that is hygiene: masking a value so a later log line cannot leak it.
_MASK_MARKER = "::add-mask::"

#: The separators that make one YAML line several commands. `::add-mask::` redacts the value its
#: own command names, so a second command on the same line is judged on its own.
_SEGMENT_BREAK = re.compile(r"""[;&|]+""")

#: A `git fetch` of the contributor's tree. `_HEAD_REF` expects an explicit `refs/pull/...` or the
#: `pull_request` context, but a run block fetches the short `pull/N/head` form and then checks out
#: `FETCH_HEAD`, which gives the head ref and the checkout half on lines `actions/checkout` never
#: appears on. The intervening run is bounded so the pattern stays linear on a cap-length line.
_FETCH_PR_REF = re.compile(
    r"""\bgit\s+fetch\b[^\n]{0,200}?\bpull/(?:\d+|\$\{\{[^}]{1,64}\}\})/(?:head|merge)\b""",
    re.VERBOSE,
)

#: A ref that resolves to the contributor's tree rather than the base. `refs/pull/N/head` and
#: `refs/pull/N/merge` are the explicit forms; `github.event.pull_request.head` covers the ref, the
#: sha and the fork clone url, which all point at the untrusted tree.
_HEAD_REF = re.compile(
    r"""github\.event\.pull_request\.head\b|refs/pull/[^/'"\s]+/(?:head|merge)\b""",
    re.VERBOSE,
)

#: A checkout step, including one pinned by owner and fork. Without it the head ref could be an
#: argument in a step that never checks anything out.
_CHECKOUT_STEP = re.compile(r"""uses:\s*(?:[\w.\-]+/)?actions/checkout@""")

#: What a fetched payload gets handed to: a shell or interpreter after a separator, PowerShell's
#: `Invoke-Expression`, a process substitution, or an `eval`. Each of these is innocent until the
#: same line also fetches, which is why the check that runs this is a two-condition one.
_EXEC_TARGET = re.compile(
    r"""
      ^\s*(?:sudo\s+)?(?:[\w.\-/]*/)?
        (?:sh|bash|dash|zsh|pwsh|powershell|python[23]?|node|perl|ruby|cmd|iex)(?:\.exe)?\b
    | (?:\||&&|;)\s*(?:sudo\s+)?(?:[\w.\-/]*/)?
        (?:sh|bash|dash|zsh|pwsh|powershell|python[23]?|node|perl|ruby|cmd|iex)(?:\.exe)?\b
    | \bInvoke-Expression\b
    | <\(\s*(?:curl|wget|Invoke-WebRequest)\b
    | (?<![\w.$])eval\b
    """,
    re.VERBOSE,
)


def _by_id(ctx: ScanContext) -> dict[str, Rule]:
    return {rule.id: rule for rule in ctx.rules}


def _text_lines(text: str) -> dict[int, str]:
    return {number: raw.removesuffix("\r") for number, raw in enumerate(text.split("\n"), start=1)}


def _shares_a_role(rule: Rule, entry: FileEntry) -> bool:
    """Does this rule claim a role the entry resolved to?

    The role list comes from the rule data, so a rename in `rules/builtin/ci_surface.toml` moves
    this dispatch with it instead of leaving a detector that quietly finds nothing.
    """
    return bool(set(rule.roles) & set(entry.roles))


def _searchable(lines: dict[int, str], line_cap: int) -> Iterable[tuple[int, str]]:
    return ((number, line) for number, line in lines.items() if len(line) <= line_cap)


def _first_hit(
    lines: dict[int, str], line_cap: int, test: re.Pattern[str]
) -> tuple[int, str] | None:
    for number, line in _searchable(lines, line_cap):
        if test.search(line):
            return number, line
    return None


def _first_pattern_hit(
    rule: Rule | None, lines: dict[int, str], line_cap: int
) -> tuple[int, str] | None:
    """First line a rule's own pattern hits, so the trigger half is not copied into code."""
    if rule is None or rule.pattern is None:
        return None
    for number, line in _searchable(lines, line_cap):
        if line_matches(rule, line):
            return number, line
    return None


def _unmasked(line: str) -> str:
    """The line with the commands that mask a value taken out of it.

    `::add-mask::` is hygiene for the one value it names, so the exemption is per command rather
    than per line: `echo "::add-mask::${{ secrets.A }}"; echo ${{ secrets.B }}` still prints a
    credential, and a line-scoped skip let it through.
    """
    return " ".join(
        segment for segment in _SEGMENT_BREAK.split(line) if _MASK_MARKER not in segment
    )


def _secret_dumps(
    rule: Rule, entry: FileEntry, lines: dict[int, str], line_cap: int
) -> list[PendingFinding]:
    """Every line that names a credential and something that would print or store it."""
    findings: list[PendingFinding] = []
    for number, line in _searchable(lines, line_cap):
        judged = _unmasked(line) if _MASK_MARKER in line else line
        if not _SECRETS_INTERP.search(judged) or not _DISPLAY_VERB.search(judged):
            continue
        findings.append(
            finding_for(
                rule,
                entry,
                number,
                evidence=line,
                message=(
                    f"{rule.title}: the line interpolates a credential the job was given and names "
                    "a command that writes it to the log or to a later step's environment"
                ),
            )
        )
    return findings


def _fetched_head(lines: dict[int, str], line_cap: int) -> tuple[int, str] | None:
    """A fetch of a pull request ref that a later checkout acts on.

    The checkout requirement is what separates a fetch that only downloads objects from the
    pairing this rule reports: without a `git checkout` after it, the contributor's tree never
    becomes the working copy.
    """
    searchable = list(_searchable(lines, line_cap))
    for index, (number, line) in enumerate(searchable):
        if not _FETCH_PR_REF.search(line):
            continue
        if any("git checkout" in later for _, later in searchable[index:]):
            return number, line
    return None


def _head_checkout(
    rule: Rule,
    entry: FileEntry,
    lines: dict[int, str],
    trigger_rule: Rule | None,
    line_cap: int,
) -> PendingFinding | None:
    """Privileged trigger plus a head ref plus a checkout, in one file."""
    trigger = _first_pattern_hit(trigger_rule, lines, line_cap)
    if trigger is None:
        return None
    step = _first_hit(lines, line_cap, _CHECKOUT_STEP)
    head = _first_hit(lines, line_cap, _HEAD_REF)
    if step is not None and head is not None:
        number, line = head
        return finding_for(
            rule,
            entry,
            number,
            evidence=line,
            message=(
                f"{rule.title}: the trigger on line {trigger[0]} runs in the base context, and "
                f"the checkout on line {step[0]} is told to use the head ref on line {number}"
            ),
        )
    fetched = _fetched_head(lines, line_cap)
    if fetched is None:
        return None
    number, line = fetched
    return finding_for(
        rule,
        entry,
        number,
        evidence=line,
        message=(
            f"{rule.title}: the trigger on line {trigger[0]} runs in the base context, and the "
            f"fetch on line {number} pulls a pull request ref that a later checkout uses"
        ),
    )


def _lifecycle_execs(
    rule: Rule,
    entry: FileEntry,
    lines: dict[int, str],
    fetch_rule: Rule,
    line_cap: int,
) -> list[PendingFinding]:
    """Lines where the fetch and the handover are both present.

    The fetch half is read from `pat-lifecycle-fetch`'s pattern rather than restated, so the WARN
    and the HIGH cannot drift apart on what counts as a client verb.
    """
    findings: list[PendingFinding] = []
    searchable = dict(_searchable(lines, line_cap))
    for number, line in searchable.items():
        if not line_matches(fetch_rule, line):
            continue
        exec_line = number
        if INSTALL_HOOK_ROLE in entry.roles:
            exec_line = next(
                (
                    candidate
                    for candidate in range(number, number + LIFECYCLE_EXEC_WINDOW)
                    if candidate in searchable and _EXEC_TARGET.search(searchable[candidate])
                ),
                0,
            )
        elif not _EXEC_TARGET.search(line):
            continue
        if not exec_line:
            continue
        findings.append(
            finding_for(
                rule,
                entry,
                number,
                evidence=line,
                message=(f"{rule.title}: the fetched result reaches a shell on line {exec_line}"),
            )
        )
    return findings


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Emit the CI-surface findings a single line pattern cannot decide."""
    rules = _by_id(ctx)
    line_cap = ctx.policy.line_cap
    dump_rule = rules.get(SECRET_DUMP_RULE_ID)
    head_rule = rules.get(HEAD_CHECKOUT_RULE_ID)
    exec_rule = rules.get(EXEC_RULE_ID)
    fetch_rule = rules.get(FETCH_RULE_ID)
    trigger_rule = rules.get(PRIVILEGED_RULE_ID)

    for entry in ctx.entries:
        if entry.text is None or line_cap <= 0:
            continue
        lines = _text_lines(entry.text)
        if dump_rule is not None and _shares_a_role(dump_rule, entry):
            yield from _secret_dumps(dump_rule, entry, lines, line_cap)
        if head_rule is not None and _shares_a_role(head_rule, entry):
            combination = _head_checkout(head_rule, entry, lines, trigger_rule, line_cap)
            if combination is not None:
                yield combination
        if exec_rule is not None and fetch_rule is not None and _shares_a_role(exec_rule, entry):
            yield from _lifecycle_execs(exec_rule, entry, lines, fetch_rule, line_cap)
