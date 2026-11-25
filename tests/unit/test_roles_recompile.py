"""The role matcher is compiled once per scan, not per file (#24)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

import pytest

from airlock import collector, roles
from airlock.collector import collect
from airlock.model import Policy
from airlock.roles import RoleMatcher, compile_role_globs, resolve_roles

ROLE_GLOBS: dict[str, tuple[str, ...]] = {
    "editor-autorun": ("**/.vscode/tasks.json",),
    "tooling-config": ("**/postcss.config.*", "**/tailwind.config.*"),
}


class TestSignature:
    def test_a_plain_mapping_still_resolves(self) -> None:
        assert resolve_roles("postcss.config.mjs", b"", ROLE_GLOBS) == (
            "tooling-config",
            "source",
        )

    def test_the_compiled_matcher_resolves_the_same_tuple(self) -> None:
        matcher = compile_role_globs(ROLE_GLOBS)
        assert isinstance(matcher, RoleMatcher)
        for path in ("postcss.config.mjs", ".vscode/tasks.json", "src/main.py", "vendor/a.md"):
            assert resolve_roles(path, b"", matcher) == resolve_roles(path, b"", ROLE_GLOBS)

    def test_magic_still_wins_over_the_matcher(self) -> None:
        matcher = compile_role_globs(ROLE_GLOBS)
        assert resolve_roles("payload.rs", b"\x00asm\x01\x00\x00\x00", matcher) == ("wasm",)


class TestCompileCount:
    def test_one_hundred_paths_compile_each_segment_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        builds: dict[str, int] = {}
        real = roles._segment_pattern

        def factory(segment: str) -> re.Pattern[str]:
            builds[segment] = builds.get(segment, 0) + 1
            return real(segment)

        monkeypatch.setattr(roles, "_segment_pattern", factory)
        matcher = compile_role_globs(ROLE_GLOBS)
        for index in range(100):
            resolve_roles(f"apps/app{index}/postcss.config.mjs", b"", matcher)
        # Every distinct segment is compiled on the build, never once per path.
        assert builds["postcss.config.*"] == 1
        assert builds["tailwind.config.*"] == 1
        assert max(builds.values()) == 1


class TestCollectBuildsOnce:
    def test_collect_builds_one_matcher(
        self, scratch_repo, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = scratch_repo({"postcss.config.mjs": "export default {}\n", "src/a.py": "x = 1\n"})
        calls: list[Mapping[str, tuple[str, ...]]] = []
        original = roles.compile_role_globs

        def counting(role_globs: Mapping[str, tuple[str, ...]]) -> RoleMatcher:
            calls.append(role_globs)
            return original(role_globs)

        monkeypatch.setattr(collector, "compile_role_globs", counting)
        collection = collect(Path(repo.root), Policy(), ROLE_GLOBS)
        assert len(calls) == 1
        entry = next(item for item in collection.entries if item.path == "postcss.config.mjs")
        assert entry.roles == ("tooling-config", "source")
