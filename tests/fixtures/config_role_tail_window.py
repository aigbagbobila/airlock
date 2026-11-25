"""`cfg-appended-tail` fixtures for the trailing window (#36).

The rule used to judge only the final non-empty line, so a payload split over the last two lines
was measured as two innocent ones: a high-entropy blob and a short terminator. These cases carry
the split positive, a comment tail that must stay clean, and a single-line minified tail that has
to keep firing.

The opaque run is generated at call time, from the same shape as the shipped `cfg_appended_tail`
negative, so no committed file holds the blob (`AGENTS.md` 4).
"""

from __future__ import annotations

from . import LINE_CAP, TAIL_MAX_LEN, Case, File, Fixture

CASE_PATH = "postcss.config.js"


def _config(*lines: str) -> Case:
    return Case(files=(File(CASE_PATH, text="\n".join(lines) + "\n"),))


def _opaque(count: int) -> str:
    """A deterministic high-entropy run: the shape of a payload line with none of one in it."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    value = 2_023_111_407_481_932_319
    out: list[str] = []
    for _ in range(count):
        value = (value * 63_641_362_238_467_930_051 + 14_426_950_408_889_633_075) % 2**64
        out.append(alphabet[(value >> 33) % len(alphabet)])
    return "".join(out)


def split_payload() -> Case:
    """A blob on the penultimate line and a short terminator on the last one.

    Each line alone is under both bounds and low enough in entropy to pass; together they are one
    payload, which is what the window measures.
    """
    blob = _opaque(40)
    assert len(blob) < LINE_CAP
    return _config(
        "export default {",
        "  plugins: { tailwindcss: {} },",
        "};",
        blob,
        "};",
    )


def comment_tail() -> Case:
    """Three short comments after a valid config: a tail by shape, not a payload."""
    comments = ("// keep", "// built", "// tested")
    assert sum(len(line) + 1 for line in comments) <= TAIL_MAX_LEN
    return _config("export default {", "  plugins: [],", "};", *comments)


def minified_tail() -> Case:
    """The one-line minified bundle the length reason has always been for."""
    return _config("export default {", "  plugins: [],", "};", "n" * (TAIL_MAX_LEN + 1))


def fixture() -> Fixture:
    return Fixture(positive=split_payload(), negative=comment_tail())
