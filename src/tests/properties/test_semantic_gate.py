"""Property tests for the Needle spike's decision rule and gate arithmetic.

Requirements: R-3.5, R-3.7. Hypothesis runs 500 examples per property (conftest.py profile).
These test the rule, not the model. The model result is in docs/needle_spike.csv.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.semantic.spike import (
    GATE_MATCH_ALLOW_MIN,
    GATE_MISMATCH_ALLOW_MAX,
    Case,
    CaseResult,
    decide,
    gate,
)

names = st.sampled_from(["parse", "parse_file", "uuid4", "colorize"])
confidences = st.floats(min_value=0.0, max_value=1.0)


@given(called=names, declared=names, confidence=confidences, threshold=st.floats(0.0, 1.0))
def test_decide_allows_only_the_declared_tool_at_or_above_threshold(
    called: str, declared: str, confidence: float, threshold: float
) -> None:
    expected = "ALLOW" if called == declared and confidence >= threshold else "QUARANTINE"
    assert decide(called, confidence, declared, threshold) == expected


@given(confidence=confidences, threshold=st.floats(0.0, 1.0))
def test_abstention_never_allows(confidence: float, threshold: float) -> None:
    assert decide(None, confidence, "parse", threshold) == "QUARANTINE"


@given(confidence=confidences, declared=names)
def test_missing_confidence_never_allows(confidence: float, declared: str) -> None:
    assert decide(declared, None, declared, 0.0) == "QUARANTINE"


def _result(label: str, allowed: bool, index: int) -> CaseResult:
    case = Case(f"{label[0]}{index}", label, "pypi", "pkg", "api", "purpose")
    verdict = "ALLOW" if allowed else "QUARANTINE"
    expected = "ALLOW" if label == "match" else "QUARANTINE"
    return CaseResult(
        case,
        "api" if allowed else None,
        0.9 if allowed else 0.1,
        "",
        verdict,
        verdict == expected,
        True,
    )


@given(
    match_allowed=st.integers(min_value=0, max_value=5),
    mismatch_allowed=st.integers(min_value=0, max_value=5),
)
def test_gate_passes_iff_both_rates_meet_their_bounds(
    match_allowed: int, mismatch_allowed: int
) -> None:
    results = [_result("match", i < match_allowed, i) for i in range(5)]
    results += [_result("mismatch", i < mismatch_allowed, i) for i in range(5)]
    summary = gate(results)
    expected = (match_allowed / 5 >= GATE_MATCH_ALLOW_MIN) and (
        mismatch_allowed / 5 <= GATE_MISMATCH_ALLOW_MAX
    )
    assert summary["passed"] is expected


def test_gate_boundary_values_are_inclusive() -> None:
    # 4 of 5 matches allowed (0.80) and 1 of 5 mismatches allowed (0.20) sit exactly on the bounds.
    results = [_result("match", i < 4, i) for i in range(5)]
    results += [_result("mismatch", i < 1, i) for i in range(5)]
    summary = gate(results)
    assert summary["match_allow_rate"] == pytest.approx(0.8)
    assert summary["mismatch_allow_rate"] == pytest.approx(0.2)
    assert summary["passed"] is True


def test_the_recorded_spike_result_fails_the_gate() -> None:
    """The committed spike result is a failure: 2 of 5 matches allowed, 0 of 5 mismatches."""
    results = [_result("match", i < 2, i) for i in range(5)]
    results += [_result("mismatch", False, i) for i in range(5)]
    summary = gate(results)
    assert summary["match_allow_rate"] == pytest.approx(0.4)
    assert summary["mismatch_allow_rate"] == pytest.approx(0.0)
    assert summary["passed"] is False
