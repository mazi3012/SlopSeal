"""Property tests for check 2.10 (maintainer reputation).

Requirements: R-2.10, R-P-1. Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.core.maintainer import Maintainers, MaintainersUnknown, check_maintainer
from slopseal.core.types import Level

MIN_AGE = 90
counts = st.integers(min_value=0, max_value=5)
ages = st.one_of(st.none(), st.floats(min_value=0.0, max_value=2000.0))
levels = st.sampled_from([Level.WARN, Level.BLOCK])


def oracle(count: int, age: float | None) -> bool:
    """True when a finding is expected under the v1 rule."""
    if count < 0:
        return True
    if count > 0 and age is None:
        return True
    if count == 0:
        return True
    return age is not None and age < MIN_AGE


@given(count=counts, age=ages, level=levels)
def test_r_2_10_finding_matches_oracle(count: int, age: float | None, level: Level) -> None:
    assume(not (count > 0 and age is None))  # Unknown state is covered by the fail-closed test.
    result = check_maintainer(Maintainers(count, age), min_account_age_days=MIN_AGE, level=level)
    if count < 0:
        assert result.level is Level.BLOCK
        return
    assert (result.level is level) == oracle(count, age)


@given(count=counts, age=st.floats(min_value=0.0, max_value=2000.0), level=levels)
def test_r_2_10_result_is_pass_or_configured_level(count: int, age: float, level: Level) -> None:
    result = check_maintainer(Maintainers(count, age), min_account_age_days=MIN_AGE, level=level)
    assert result.level in {Level.PASS, level}


@given(
    count=st.integers(min_value=1, max_value=5), age=st.floats(min_value=MIN_AGE, max_value=2000.0)
)
def test_r_2_10_established_maintainers_pass(count: int, age: float) -> None:
    result = check_maintainer(
        Maintainers(count, age), min_account_age_days=MIN_AGE, level=Level.BLOCK
    )
    assert result.level is Level.PASS


@given(reason=st.text(min_size=1, max_size=40), level=levels)
def test_p_fc_2_unknown_maintainer_data_blocks(reason: str, level: Level) -> None:
    result = check_maintainer(MaintainersUnknown(reason), min_account_age_days=MIN_AGE, level=level)
    assert result.level is Level.BLOCK


@given(level=levels)
def test_p_fc_2_listed_maintainers_without_age_block(level: Level) -> None:
    result = check_maintainer(Maintainers(2, None), min_account_age_days=MIN_AGE, level=level)
    assert result.level is Level.BLOCK


@given(count=st.integers(max_value=-1), level=levels)
def test_negative_count_blocks(count: int, level: Level) -> None:
    result = check_maintainer(Maintainers(count, 10.0), min_account_age_days=MIN_AGE, level=level)
    assert result.level is Level.BLOCK


@given(count=counts, age=st.floats(min_value=0.0, max_value=2000.0))
def test_r_2_10_adding_a_maintainer_never_adds_a_finding(count: int, age: float) -> None:
    before = check_maintainer(
        Maintainers(count, age), min_account_age_days=MIN_AGE, level=Level.WARN
    )
    after = check_maintainer(
        Maintainers(count + 1, age), min_account_age_days=MIN_AGE, level=Level.WARN
    )
    if before.level is Level.PASS:
        assert after.level is Level.PASS


def test_r_2_10_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        check_maintainer(Maintainers(1, 1.0), min_account_age_days=-1, level=Level.WARN)
    with pytest.raises(ValueError, match="WARN or BLOCK"):
        check_maintainer(Maintainers(1, 1.0), min_account_age_days=MIN_AGE, level=Level.PASS)
