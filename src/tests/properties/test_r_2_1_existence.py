"""Property tests for check 2.1 (registry existence).

Requirements: R-2.1, R-P-1. Properties: P-FC-2.
Hypothesis runs 500 examples per property (conftest.py profile, R-PBT-1).
"""

from __future__ import annotations

import string
from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.existence import check_existence
from slopseal.core.types import (
    Ecosystem,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)

ecosystems = st.sampled_from(list(Ecosystem))
names = st.text(alphabet=string.ascii_letters + string.digits + "-_.", min_size=1, max_size=40)
reasons = st.text(min_size=1, max_size=80)


@st.composite
def registry_results(draw: st.DrawFn) -> RegistryResult:
    ecosystem = draw(ecosystems)
    name = draw(names)
    kind = draw(st.sampled_from(["record", "missing", "unknown"]))
    if kind == "record":
        published = draw(st.one_of(st.none(), st.just(NOW - timedelta(days=400))))
        return RegistryRecord(ecosystem, name, published, draw(st.integers(0, 500)))
    if kind == "missing":
        return RegistryMissing(ecosystem, name)
    return RegistryUnknown(ecosystem, name, draw(reasons))


@given(ecosystem=ecosystems, name=names)
def test_r_2_1_missing_package_is_hard_block(ecosystem: Ecosystem, name: str) -> None:
    result = check_existence(RegistryMissing(ecosystem, name))
    assert result.level is Level.HARD_BLOCK
    assert result.check == "existence"


@given(ecosystem=ecosystems, name=names, reason=reasons)
def test_p_fc_2_unknown_registry_never_passes(ecosystem: Ecosystem, name: str, reason: str) -> None:
    result = check_existence(RegistryUnknown(ecosystem, name, reason))
    assert result.level >= Level.BLOCK
    assert result.level is not Level.PASS


@given(ecosystem=ecosystems, name=names)
def test_r_2_1_existing_package_passes(ecosystem: Ecosystem, name: str) -> None:
    result = check_existence(RegistryRecord(ecosystem, name, NOW - timedelta(days=400), 12))
    assert result.level is Level.PASS


@given(result=registry_results())
def test_r_2_1_result_is_total_and_never_warns(result: RegistryResult) -> None:
    """Every registry state maps to exactly PASS, HARD_BLOCK, or BLOCK. Never WARN, never raises."""
    level = check_existence(result).level
    assert level in {Level.PASS, Level.HARD_BLOCK, Level.BLOCK}
