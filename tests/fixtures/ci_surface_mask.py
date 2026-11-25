"""`pat-secret-dump` fixtures for the per-command mask exemption (#33).

`::add-mask::` redacts the value its own command names, so it excuses that command and no other.
The cases here are the three an example-driven suite would otherwise miss: a masked secret
followed by a second unmasked one on the same line (the dump), the single masked echo (the
negative the carve-out exists for), and a credential handed to an input (the ordinary use).

The secret interpolations and the marker are assembled from fragments at call time, so no
committed file in this repository holds a working dump (`AGENTS.md` 4).
"""

from __future__ import annotations

from . import Case, File, Fixture, assemble

WORKFLOW_PATH = ".github/workflows/publish.yml"
MASK = assemble("::add-", "mask::")
SECRET_A = "${{ " + assemble("secrets", ".TOKEN_A }}")
SECRET_B = "${{ " + assemble("secrets", ".TOKEN_B }}")
CHECKOUT = assemble("uses: actions/checkout@", "v4")


def _workflow(*lines: str) -> Case:
    return Case(files=(File(WORKFLOW_PATH, text="\n".join(lines) + "\n"),))


def masked_then_dumped() -> Case:
    """One command masks a token, the next prints a different one."""
    return _workflow(
        "jobs:",
        "  publish:",
        "    steps:",
        f'      - run: echo "{MASK}{SECRET_A}"; echo "{SECRET_B}"',
    )


def single_masked() -> Case:
    """The hygiene echo the carve-out is for: masking is not displaying."""
    return _workflow(
        "jobs:",
        "  publish:",
        "    steps:",
        f'      - run: echo "{MASK}{SECRET_A}"',
    )


def secret_as_input() -> Case:
    """A credential passed to an action's input is how a workflow uses one."""
    return _workflow(
        "jobs:",
        "  publish:",
        "    steps:",
        f"      - {CHECKOUT}",
        "        with:",
        f"          token: {SECRET_B}",
    )


def fixture() -> Fixture:
    """The pair the issue names, for a reader who wants the shape in one object."""
    return Fixture(positive=masked_then_dumped(), negative=single_masked())
