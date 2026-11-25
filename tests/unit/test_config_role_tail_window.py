"""`cfg-appended-tail` measures the trailing bytes across lines (#36).

The rule kept only the last non-empty line, so a high-entropy blob on the penultimate line and a
short terminator after it were measured as neither: the last line is short and low entropy, the
blob is never examined. The tests here pin the split positive, the comment tail that must stay
clean, and the minified single-line tail the length reason has always covered.
"""

from __future__ import annotations

from tests.fixtures import Case, context
from tests.fixtures.config_role_tail_window import (
    comment_tail,
    minified_tail,
    split_payload,
)

from airlock import runner

RULE_ID = "cfg-appended-tail"


def fires(case: Case) -> bool:
    return RULE_ID in {item.rule_id for item in runner.collect(context(case))}


class TestTheTrailingWindow:
    def test_a_payload_split_over_the_last_two_lines_is_reported(self) -> None:
        assert fires(split_payload())

    def test_a_three_line_comment_tail_is_clean(self) -> None:
        assert not fires(comment_tail())

    def test_a_minified_last_line_still_fires_on_its_length(self) -> None:
        assert fires(minified_tail())
