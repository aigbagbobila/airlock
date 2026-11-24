"""A detector-error message always names its exception type inside the budget (#16)."""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from airlock.fingerprint import PendingFinding
from airlock.model import MAX_MESSAGE_CHARS, ScanContext, Severity
from airlock.runner import _detector_error


class _Exploding:
    """A detector stub whose module name is as long as the report budget."""

    def __init__(self, module: str, error: BaseException) -> None:
        self.__module__ = module
        self._error = error

    def __call__(self, ctx: ScanContext) -> Iterable[PendingFinding]:
        raise self._error


class TestDetectorError:
    def test_a_long_module_name_keeps_the_exception_type(self) -> None:
        detector = _Exploding("scanner." + "namespace." * 20 + "detector", ValueError("boom"))
        finding = _detector_error(detector, ValueError("boom"))
        assert "ValueError" in finding.message
        assert len(finding.message) <= MAX_MESSAGE_CHARS
        # The last component survives, so an operator can still tell two detectors apart.
        assert "detector" in finding.message
        # The finding is constructible, which is the failure the old slice caused.
        built = finding.to_finding(0)
        assert built.severity == Severity.HIGH

    def test_an_empty_exception_message_still_names_the_type(self) -> None:
        detector = _Exploding("scanner.detector", RuntimeError())
        finding = _detector_error(detector, RuntimeError())
        assert "RuntimeError" in finding.message
        assert len(finding.message) <= MAX_MESSAGE_CHARS

    def test_a_short_module_name_is_unchanged(self) -> None:
        detector = _Exploding("airlock.detectors.config_role", KeyError("x"))
        finding = _detector_error(detector, KeyError("x"))
        assert "config_role: KeyError" in finding.message
        # The exception text stays out of the message and in the evidence.
        assert "'x'" not in finding.message
        assert finding.evidence is not None and "'x'" in finding.evidence

    @pytest.mark.parametrize("module_length", [0, 1, 30, 199, 200, 300])
    def test_every_module_length_stays_inside_the_budget(self, module_length: int) -> None:
        detector = _Exploding("m" * module_length, ValueError("v"))
        finding = _detector_error(detector, ValueError("v"))
        assert len(finding.message) <= MAX_MESSAGE_CHARS
        assert "ValueError" in finding.message
