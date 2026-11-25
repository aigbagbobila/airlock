"""`pat-ptr-head-checkout` fixtures for a run-block checkout (#34).

The privileged pairing used to need an `actions/checkout` step, so a `pull_request_target` workflow
that fetched the contributor's tree with `git fetch` and then checked out `FETCH_HEAD` was reported
as nothing but the trigger WARN. These cases carry the positive and the three negatives the issue
names: a fetch of the base branch, an unprivileged trigger, and a fetch nothing checks out.

The trigger, the ref and the fetch client are assembled from fragments at call time, so no
committed file here is a working workflow (`AGENTS.md` 4).
"""

from __future__ import annotations

from . import Case, File, Fixture, assemble

WORKFLOW_PATH = ".github/workflows/pr-build.yml"
TRIGGER = assemble("pull_request_", "target")
UNPRIVILEGED = assemble("pull_re", "quest")
EVENT_NUMBER = "${{ " + assemble("github.event.", "number }}")
PR_REF = assemble("pull/", EVENT_NUMBER, "/head")


def _workflow(trigger: str, *lines: str) -> Case:
    body = "\n".join(
        [
            "on:",
            f"  {trigger}:",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            *lines,
        ]
    )
    return Case(files=(File(WORKFLOW_PATH, text=body + "\n"),))


def fetch_then_checkout() -> Case:
    """The positive: a run block fetches the pull request head and checks out what it fetched."""
    return _workflow(
        TRIGGER,
        f"      - run: git fetch origin {PR_REF}",
        "      - run: git checkout FETCH_HEAD",
    )


def base_branch_fetch() -> Case:
    """A fetch of the base branch downloads reviewed objects, whatever the trigger."""
    return _workflow(
        TRIGGER,
        "      - run: git fetch origin main",
        "      - run: git checkout FETCH_HEAD",
    )


def unprivileged_trigger() -> Case:
    """`pull_request` is a read-only context: the same two commands are ordinary CI."""
    return _workflow(
        UNPRIVILEGED,
        f"      - run: git fetch origin {PR_REF}",
        "      - run: git checkout FETCH_HEAD",
    )


def fetch_never_checked_out() -> Case:
    """Downloading the objects does not make the contributor's tree the working copy."""
    return _workflow(
        TRIGGER,
        f"      - run: git fetch origin {PR_REF}",
        "      - run: npm run build",
    )


def fixture() -> Fixture:
    """The positive and the nearest negative, in one object."""
    return Fixture(positive=fetch_then_checkout(), negative=fetch_never_checked_out())
