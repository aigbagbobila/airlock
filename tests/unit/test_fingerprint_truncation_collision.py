"""Evidence over the display cap no longer collides in the fingerprint (#17)."""

from __future__ import annotations

from pathlib import Path

from airlock.detectors import DETECTOR_NAMES
from airlock.fingerprint import MAX_EVIDENCE_CHARS, PendingFinding, number_occurrences
from airlock.model import FileEntry, Policy, Suppression
from airlock.policy import suppress
from airlock.roles import known_roles
from airlock.rules import finding_for, load_role_globs, load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
RULE_ID = "cfg-process-spawn"

SHARED = "const payload = '" + "a" * 220
FIRST = SHARED + "FIRST';"
SECOND = SHARED + "SECOND';"


def shipped_rules():
    role_globs = load_role_globs(REPO_ROOT / "rules" / "roles.toml")
    return load_rules(
        REPO_ROOT / "rules" / "builtin",
        known_detectors=DETECTOR_NAMES,
        known_roles=sorted(known_roles(role_globs)),
    )


ENTRY = FileEntry(
    path="postcss.config.mjs",
    sha256="a" * 64,
    roles=("tooling-config", "source"),
    text=FIRST + "\n" + SECOND + "\n",
)


def pending(line: int, evidence: str) -> PendingFinding:
    rule = next(rule for rule in shipped_rules() if rule.id == RULE_ID)
    return finding_for(rule, ENTRY, line, evidence=evidence)


class TestCollision:
    def test_lines_sharing_the_display_cap_get_different_fingerprints(self) -> None:
        first, second = number_occurrences([pending(1, FIRST), pending(2, SECOND)])
        assert len(FIRST) > MAX_EVIDENCE_CHARS and len(SECOND) > MAX_EVIDENCE_CHARS
        assert first.fingerprint != second.fingerprint
        # The occurrence index stays at zero because the identity is the full line, not the
        # shared 200-character excerpt.
        assert first.occurrence == second.occurrence == 0

    def test_the_stored_excerpt_is_still_capped_for_display(self) -> None:
        finding = number_occurrences([pending(1, FIRST)])[0]
        assert finding.evidence is not None
        assert len(finding.evidence) == MAX_EVIDENCE_CHARS + 3
        assert finding.evidence.endswith("...")


class TestSuppression:
    def test_suppressing_the_first_line_leaves_the_second_active(self) -> None:
        findings = number_occurrences([pending(1, FIRST), pending(2, SECOND)])
        first = next(finding for finding in findings if finding.line == 1)
        policy = Policy(
            suppressions=(
                Suppression(
                    rule=RULE_ID,
                    path=first.path,
                    fingerprint=first.fingerprint,
                    reason="reviewed: the first line only",
                ),
            )
        )
        result = suppress(findings, policy, shipped_rules())
        assert [finding.line for finding in result.suppressed] == [1]
        assert [finding.line for finding in result.findings] == [2]
        assert result.findings[0].suppressed_by is None


class TestShortEvidence:
    def test_the_pinned_vector_for_short_evidence_is_unchanged(self) -> None:
        # A suppression written before this change keys on this exact digest, and the evidence
        # fits the cap, so the hash input must be byte-identical to the old formula.
        finding = number_occurrences([pending(1, "eval(payload)")])[0]
        assert (
            finding.fingerprint
            == "sha256:c91cd8d2d46e4614cf3232bced47acc67ec6f5784eac896f6b79a1338cd48d97"
        )
