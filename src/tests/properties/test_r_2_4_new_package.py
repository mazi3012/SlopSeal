"""Property tests for check 2.4 (new package).

Requirements: R-2.4, R-P-1. Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.new_package import check_new_package
from slopseal.core.types import (
    Ecosystem,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryUnknown,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
MAX_AGE = 7
MAX_RELEASES = 3

ages = st.one_of(
    st.floats(min_value=-30.0, max_value=400.0),
    st.sampled_from([6.999, 7.0, 7.001, 0.0, -0.5]),
)
releases = st.integers(min_value=0, max_value=10)


def record(age: float, release_count: int) -> RegistryRecord:
    return RegistryRecord(
        Ecosystem.NPM,
        "fixture-pkg",
        NOW - timedelta(days=age),
        release_count,
    )


@given(age=ages, release_count=releases)
def test_r_2_4_flagged_iff_young_and_few_releases(age: float, release_count: int) -> None:
    """Flagged exactly when age < 7 days AND releases < 3. Either condition alone does not flag."""
    result = check_new_package(
        record(age, release_count),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    expected = age < MAX_AGE and release_count < MAX_RELEASES
    assert (result.level is Level.HARD_BLOCK) == expected


@given(age=st.floats(min_value=MAX_AGE, max_value=400.0), release_count=releases)
def test_r_2_4_established_package_is_never_flagged(age: float, release_count: int) -> None:
    result = check_new_package(
        record(age, release_count),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    assert result.level is Level.PASS


@given(age=st.floats(min_value=-30.0, max_value=MAX_AGE - 0.001))
def test_r_2_4_many_releases_is_never_flagged(age: float) -> None:
    result = check_new_package(
        record(age, MAX_RELEASES),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    assert result.level is Level.PASS


@given(age=st.floats(min_value=0.0, max_value=MAX_AGE - 0.001), release_count=st.integers(0, 2))
def test_r_2_4_configured_level_is_applied(age: float, release_count: int) -> None:
    for level in (Level.WARN, Level.BLOCK, Level.HARD_BLOCK):
        result = check_new_package(
            record(age, release_count),
            NOW,
            max_age_days=MAX_AGE,
            max_releases=MAX_RELEASES,
            level=level,
        )
        assert result.level is level


@given(age=ages, release_count=releases)
def test_r_2_4_result_is_pass_or_configured_level(age: float, release_count: int) -> None:
    result = check_new_package(
        record(age, release_count),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
        level=Level.WARN,
    )
    assert result.level in {Level.PASS, Level.WARN}


def test_p_fc_2_unknown_registry_blocks() -> None:
    result = check_new_package(
        RegistryUnknown(Ecosystem.NPM, "x", "timeout"),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    assert result.level is Level.BLOCK


def test_unknown_publish_time_blocks() -> None:
    result = check_new_package(
        RegistryRecord(Ecosystem.NPM, "x", None, release_count=1),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    assert result.level is Level.BLOCK


@pytest.mark.parametrize("release_count", [-1, -100])
def test_negative_release_count_blocks(release_count: int) -> None:
    result = check_new_package(
        record(1.0, release_count),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    assert result.level is Level.BLOCK


def test_missing_package_is_left_to_existence_check() -> None:
    result = check_new_package(
        RegistryMissing(Ecosystem.NPM, "x"),
        NOW,
        max_age_days=MAX_AGE,
        max_releases=MAX_RELEASES,
    )
    assert result.level is Level.PASS


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        check_new_package(record(1.0, 0), NOW, max_age_days=-1, max_releases=3)
    with pytest.raises(ValueError, match="WARN, BLOCK, or HARD_BLOCK"):
        check_new_package(
            record(1.0, 0),
            NOW,
            max_age_days=7,
            max_releases=3,
            level=Level.PASS,
        )
