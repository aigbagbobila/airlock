"""Glob matching cost: golden answers, memoised states and the fail-closed budget (#23)."""

from __future__ import annotations

import re

import pytest

from airlock import roles
from airlock.roles import match_glob

#: Answers taken from the recursive matcher before the memo, plus the precedence cases in
#: `test_roles.py`. A memoised matcher must not move any of them.
GOLDEN: tuple[tuple[str, str, bool], ...] = (
    ("**", "a", True),
    ("**", "a/b/c", True),
    ("*", "a.js", True),
    ("*", "x/a.js", False),
    ("**/*.js", "a.js", True),
    ("**/*.js", "deep/nested/file.js", True),
    ("**/*.js", "deep/nested/file.ts", False),
    ("vendor/**", "vendor", True),
    ("vendor/**", "vendor/a/b/c.js", True),
    ("vendor/**", "vendored/a.js", False),
    ("a/**/b", "a/b", True),
    ("a/**/b", "a/x/y/b", True),
    ("a/**/b", "a/x/y/c", False),
    ("**/page.tsx", "app/[id]/page.tsx", True),
    ("**/[id].tsx", "app/[id]/page.tsx", False),
    ("a?c.js", "abc.js", True),
    ("a?c.js", "ac.js", False),
    ("a/b", "a", False),
    ("", "", True),
)

DEEP_PATH = "/".join(["vendor"] * 200 + ["target"])
PATHOLOGICAL = "**/**/**/target"


class _CountingPattern:
    """A compiled segment that records how often it was asked to match."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self._pattern = pattern
        self.calls = 0

    def match(self, value: str) -> re.Match[str] | None:
        self.calls += 1
        return self._pattern.match(value)


class TestGoldenTable:
    @pytest.mark.parametrize(("pattern", "path", "expected"), GOLDEN)
    def test_the_memoised_matcher_keeps_every_answer(
        self, pattern: str, path: str, expected: bool
    ) -> None:
        assert match_glob(pattern, path) is expected


class TestMemo:
    def test_a_deep_path_against_three_double_stars_visits_each_state_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counted: list[_CountingPattern] = []

        def factory(segment: str) -> _CountingPattern:
            compiled = _CountingPattern(re.compile(re.escape(segment)))
            counted.append(compiled)
            return compiled

        monkeypatch.setattr(roles, "_segment_pattern", factory)
        assert match_glob(PATHOLOGICAL, DEEP_PATH) is True
        # One compiled segment (`target`), asked at most once per path index. The recursive
        # matcher re-entered the same (pattern, path) pairs at every offset, as depth to the
        # number of `**` segments; a repeated pair would show up as more calls than indices.
        assert len(counted) == 1
        assert counted[0].calls <= len(DEEP_PATH.split("/")) + 1


class TestBudget:
    def test_a_low_budget_raises_instead_of_hanging(self) -> None:
        with pytest.raises(ValueError) as caught:
            match_glob(PATHOLOGICAL, DEEP_PATH, max_steps=5)
        text = str(caught.value)
        assert PATHOLOGICAL in text
        assert f"{len(DEEP_PATH.split('/'))} segments" in text

    def test_the_default_budget_covers_a_deep_path(self) -> None:
        assert match_glob(PATHOLOGICAL, DEEP_PATH) is True
