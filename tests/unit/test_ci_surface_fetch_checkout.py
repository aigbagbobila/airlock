"""`pat-ptr-head-checkout` accepts a run-block checkout of a pull request ref (#34).

`_head_checkout` needed an `actions/checkout` step, so the shape that fetches
`pull/<number>/head` and then checks out `FETCH_HEAD` in a `pull_request_target` workflow was
invisible: the fetch line matched neither the head-ref pattern nor the checkout pattern, and only
the trigger WARN fired. The tests here pin the positive, the finding's line, and the three
negatives the issue names.
"""

from __future__ import annotations

from tests.fixtures import Case, context
from tests.fixtures.ci_surface_fetch_checkout import (
    base_branch_fetch,
    fetch_never_checked_out,
    fetch_then_checkout,
    unprivileged_trigger,
)

from airlock import runner
from airlock.model import Severity

RULE_ID = "pat-ptr-head-checkout"


def findings(case: Case) -> list[tuple[str, Severity, int]]:
    return [(item.rule_id, item.severity, item.line) for item in runner.collect(context(case))]


class TestRunBlockCheckout:
    def test_a_fetch_of_the_pull_request_head_that_is_checked_out_is_high(self) -> None:
        hits = [item for item in findings(fetch_then_checkout()) if item[0] == RULE_ID]
        assert hits == [(RULE_ID, Severity.HIGH, 7)], "the finding sits on the fetch line"

    def test_fetching_the_base_branch_is_not_the_head(self) -> None:
        assert RULE_ID not in {rule_id for rule_id, _, _ in findings(base_branch_fetch())}

    def test_an_unprivileged_trigger_keeps_the_same_commands_clean(self) -> None:
        assert RULE_ID not in {rule_id for rule_id, _, _ in findings(unprivileged_trigger())}

    def test_a_fetch_nothing_checks_out_is_not_the_pairing(self) -> None:
        assert RULE_ID not in {rule_id for rule_id, _, _ in findings(fetch_never_checked_out())}
