"""`pat-jwt` matches the three-segment token envelope (#37).

A JSON Web Token committed in source or a workflow file is a live bearer credential that no shipped
rule matched before this one. The rule is a regex with no decoder and no network: it anchors on the
base64url header prefix `eyJ` and requires three bounded segments, which is what keeps a truncated
pair and prose about the shape clean.
"""

from __future__ import annotations

from tests.fixtures import Case, context, fired
from tests.fixtures.jwt_shape import pat_jwt

from airlock import runner
from airlock.model import Severity

RULE_ID = "pat-jwt"


def findings(case: Case) -> list[tuple[str, Severity, int]]:
    return [(item.rule_id, item.severity, item.line) for item in runner.collect(context(case))]


class TestTokenEnvelope:
    def test_a_committed_token_is_high(self) -> None:
        fixture = pat_jwt()
        assert fixture.positive is not None
        hits = [item for item in findings(fixture.positive) if item[0] == RULE_ID]
        assert hits == [(RULE_ID, Severity.HIGH, 1)]

    def test_a_truncated_pair_and_a_bare_header_stay_clean(self) -> None:
        fixture = pat_jwt()
        assert fixture.negative is not None
        assert RULE_ID not in fired(fixture.negative)
