"""Preflight rules: input validation and the status selection (D2 section 7.4).

Requirement: R-PF-1 (deterministic preflight), R-PF-2 (unreadable facts are never PASS).
"""

from __future__ import annotations

import pytest

from slopseal.preflight.model import REQUIRED, Check, Result, Status
from slopseal.preflight.rules import evaluate


def _all_pass() -> list[Check]:
    return [Check(i, c, t, Result.PASS) for i, c, t in REQUIRED]


def test_missing_required_check_is_not_run_and_gives_not_enforced() -> None:
    checks = [c for c in _all_pass() if c.id != "A9"]
    result = evaluate(checks)
    assert result.status is Status.NOT_ENFORCED
    assert "A9" in result.named


def test_duplicate_check_id_is_rejected() -> None:
    checks = _all_pass() + [Check("A1", "A", "dup", Result.PASS)]
    with pytest.raises(ValueError, match="duplicate"):
        evaluate(checks)


def test_unknown_check_id_is_rejected() -> None:
    checks = _all_pass() + [Check("Z9", "A", "unknown", Result.PASS)]
    with pytest.raises(ValueError, match="unknown"):
        evaluate(checks)


def test_partial_names_every_failed_class_b_check_in_order() -> None:
    checks = [
        Check(i, c, t, Result.FAIL if i in ("B1", "B2") else Result.PASS) for i, c, t in REQUIRED
    ]
    result = evaluate(checks)
    assert result.status is Status.PARTIALLY_ENFORCED
    assert result.named == ("B1", "B2")


def test_a_failure_outranks_a_class_b_failure() -> None:
    checks = [
        Check(i, c, t, Result.FAIL if i in ("A2", "B1") else Result.PASS) for i, c, t in REQUIRED
    ]
    result = evaluate(checks)
    assert result.status is Status.NOT_ENFORCED
    assert result.named == ("A2",)


def test_every_single_result_gives_exactly_one_known_status() -> None:
    """Whichever check takes each outcome, the rules return one status and never raise."""
    for outcome in (Result.PASS, Result.FAIL, Result.NOT_RUN):
        for target_id, _cls, _title in REQUIRED:
            checks = [
                Check(i, c, t, outcome if i == target_id else Result.PASS) for i, c, t in REQUIRED
            ]
            assert evaluate(checks).status in set(Status)
