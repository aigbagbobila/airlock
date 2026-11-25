"""`pat-secret-dump` judges the mask marker per command (#33).

`::add-mask::` excuses the command that carries it. The line-scoped skip it replaced also excused
every later command on the same YAML line, so masking one token and printing another produced no
finding at all. The tests here pin the split positive, the single masked echo the carve-out exists
for, and a credential handed to an input.
"""

from __future__ import annotations

from tests.fixtures import Case, context
from tests.fixtures.ci_surface_mask import masked_then_dumped, secret_as_input, single_masked

from airlock import runner
from airlock.model import Severity

RULE_ID = "pat-secret-dump"


def findings(case: Case) -> list[tuple[str, Severity, int]]:
    return [(item.rule_id, item.severity, item.line) for item in runner.collect(context(case))]


class TestMaskIsPerCommand:
    def test_masking_one_secret_does_not_excuse_a_second_on_the_same_line(self) -> None:
        hits = [item for item in findings(masked_then_dumped()) if item[0] == RULE_ID]
        assert hits == [(RULE_ID, Severity.HIGH, 4)]

    def test_the_single_masked_echo_is_still_the_innocent_case(self) -> None:
        assert RULE_ID not in {rule_id for rule_id, _, _ in findings(single_masked())}

    def test_a_credential_handed_to_an_input_is_not_a_dump(self) -> None:
        assert RULE_ID not in {rule_id for rule_id, _, _ in findings(secret_as_input())}
