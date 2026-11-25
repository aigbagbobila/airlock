"""`pat-jwt` fixture builder (task 9.86, `ARCHITECTURE.md` 9.6).

A committed JSON Web Token is a bearer credential: whoever reads the bundle can present it until it
expires. The envelope is three base64url segments, and the positive here assembles one at call time
from fragments, so no committed file in this repository holds a usable token (`AGENTS.md` 4).

The negative is a near miss of the same rule: the header alone is prose about the shape, the
two-segment pair is the truncated form, and neither is a credential anyone can present.
"""

from __future__ import annotations

from . import Case, File, Fixture, assemble

#: A path the role globs resolve to `source`, which is the role the rule claims.
SOURCE_PATH = "src/supabaseClient.ts"

#: The base64url header of a token, split so the envelope never appears whole in this repository.
HEADER = assemble("ey", "JhbGciOiJIUzI1NiJ9")
#: The claims segment, in the same shape the header has.
CLAIMS = assemble("ey", "JleHAiOjIwOTk5OTk5OTl9")
#: The HMAC segment. It is generated text, not a signature over anything.
SIGNATURE = assemble("q", "8f3Vn2Kp0Lx7Yc4Wm")


def _token() -> str:
    return assemble(HEADER, ".", CLAIMS, ".", SIGNATURE)


def pat_jwt() -> Fixture:
    return Fixture(
        positive=Case(
            files=(
                File(
                    SOURCE_PATH,
                    text=("export const KEY = " + repr(_token()) + ";\n"),
                ),
            )
        ),
        # Two segments are not a token, and the header on its own is the part every article about
        # the shape quotes. Both stay clean, which is what keeps prose out of the report.
        negative=Case(
            files=(
                File(
                    SOURCE_PATH,
                    text=(
                        f'const header = "{HEADER}";\n'
                        f'const pair = "{HEADER}.{CLAIMS}";\n'
                        "// two segments are truncated, and the header is prose\n"
                    ),
                ),
            )
        ),
    )


BUILDERS = {"pat_jwt": pat_jwt}
