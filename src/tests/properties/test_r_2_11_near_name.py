"""Property tests for check 2.11 (near-name similarity) and its similarity helpers.

Requirements: R-2.11, R-P-1. Hypothesis runs 500 examples per property (conftest.py profile).
The Levenshtein oracle is an independent recursive implementation.
"""

from __future__ import annotations

import string
from datetime import UTC, datetime, timedelta
from functools import cache

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.core.distance import levenshtein
from slopseal.core.near_name import check_near_name
from slopseal.core.similarity import jaro_winkler, keyboard_substitution
from slopseal.core.types import (
    Ecosystem,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryUnknown,
)

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
MAX_DISTANCE = 3
MIN_JW = 0.92
TOP_N = ("requests", "numpy", "flask", "pandas", "django", "httpx")
ALPHABET = string.ascii_lowercase + "-"
names = st.text(alphabet=ALPHABET, min_size=1, max_size=12)


def reference_levenshtein(a: str, b: str) -> int:
    @cache
    def dist(i: int, j: int) -> int:
        if i == 0:
            return j
        if j == 0:
            return i
        cost = 0 if a[i - 1] == b[j - 1] else 1
        return min(dist(i - 1, j) + 1, dist(i, j - 1) + 1, dist(i - 1, j - 1) + cost)

    result = dist(len(a), len(b))
    dist.cache_clear()
    return result


def record(name: str, age: float = 400.0) -> RegistryRecord:
    return RegistryRecord(Ecosystem.NPM, name, NOW - timedelta(days=age), 10)


def oracle_near(name: str, top: tuple[str, ...]) -> bool:
    if name in top:
        return False
    for candidate in top:
        if (
            reference_levenshtein(name, candidate) <= MAX_DISTANCE
            or jaro_winkler(name, candidate) >= MIN_JW
            or keyboard_substitution(name, candidate)
        ):
            return True
    return False


# ---- Similarity helpers ----------------------------------------------------------------


def test_jaro_winkler_known_value() -> None:
    """Published reference value for the classic MARTHA/MARHTA pair (about 0.961)."""
    assert round(jaro_winkler("martha", "marhta"), 4) == 0.9611


@given(a=names, b=names)
def test_jaro_winkler_is_symmetric_and_bounded(a: str, b: str) -> None:
    value = jaro_winkler(a, b)
    assert 0.0 <= value <= 1.0
    assert value == pytest.approx(jaro_winkler(b, a))


@given(a=names)
def test_jaro_winkler_identity_is_one(a: str) -> None:
    assert jaro_winkler(a, a) == 1.0


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("q", "w", True),
        ("a", "z", True),
        ("1", "q", True),
        ("f", "g", True),
        ("a", "p", False),
        ("q", "m", False),
        ("v", "b", True),  # bottom row: v and b are neighbours
        ("b", "c", False),  # bottom row: c and b are two keys apart
        ("b", "k", False),
    ],
)
def test_keyboard_substitution_table(a: str, b: str, expected: bool) -> None:
    assert keyboard_substitution(a, b) is expected


@given(a=names, b=names)
def test_keyboard_substitution_is_symmetric(a: str, b: str) -> None:
    assert keyboard_substitution(a, b) == keyboard_substitution(b, a)


# ---- Check 2.11 ------------------------------------------------------------------------


@given(name=names)
def test_r_2_11_warn_iff_any_near_signal(name: str) -> None:
    result = check_near_name(
        record(name), TOP_N, max_distance=MAX_DISTANCE, min_jaro_winkler=MIN_JW
    )
    assert (result.level is Level.WARN) == oracle_near(name, TOP_N)


@given(name=names, age=st.floats(min_value=0.0, max_value=400.0))
def test_r_2_11_has_no_age_condition(name: str, age: float) -> None:
    """A young and an established package with the same name get the same verdict."""
    young = check_near_name(record(name, age=1.0), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW)
    old = check_near_name(record(name, age=age), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW)
    assert young.level is old.level


@given(name=names)
def test_r_2_11_never_blocks_a_known_package(name: str) -> None:
    level = check_near_name(record(name), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW).level
    assert level in {Level.PASS, Level.WARN}


@given(data=st.data())
def test_r_2_11_top_n_name_passes(data: st.DataObject) -> None:
    name = data.draw(st.sampled_from(TOP_N))
    result = check_near_name(record(name), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW)
    assert result.level is Level.PASS


@given(name=names, extra=names)
def test_r_2_11_adding_a_top_name_never_removes_a_warning(name: str, extra: str) -> None:
    # An input equal to the added top name is itself a top-N package, so it passes by design.
    assume(extra != name)
    before = check_near_name(record(name), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW).level
    after = check_near_name(
        record(name), (*TOP_N, extra), max_distance=3, min_jaro_winkler=MIN_JW
    ).level
    if before is Level.WARN:
        assert after is Level.WARN


@given(name=names)
def test_r_2_11_result_does_not_depend_on_top_order(name: str) -> None:
    forward = check_near_name(record(name), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW)
    backward = check_near_name(
        record(name), tuple(reversed(TOP_N)), max_distance=3, min_jaro_winkler=MIN_JW
    )
    assert forward == backward


@given(name=names)
def test_p_fc_2_unknown_registry_blocks(name: str) -> None:
    result = check_near_name(
        RegistryUnknown(Ecosystem.NPM, name, "timeout"),
        TOP_N,
        max_distance=3,
        min_jaro_winkler=MIN_JW,
    )
    assert result.level is Level.BLOCK


def test_empty_top_n_blocks() -> None:
    assert (
        check_near_name(record("requestz"), (), max_distance=3, min_jaro_winkler=MIN_JW).level
        is Level.BLOCK
    )


@given(name=names)
def test_missing_package_passes_here(name: str) -> None:
    result = check_near_name(
        RegistryMissing(Ecosystem.NPM, name),
        TOP_N,
        max_distance=3,
        min_jaro_winkler=MIN_JW,
    )
    assert result.level is Level.PASS


def test_warn_carries_remedy_naming_the_nearest_package() -> None:
    result = check_near_name(record("requestz"), TOP_N, max_distance=3, min_jaro_winkler=MIN_JW)
    assert result.level is Level.WARN
    assert result.remedy == "Did you mean requests?"


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        check_near_name(record("x"), TOP_N, max_distance=-1, min_jaro_winkler=0.9)
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        check_near_name(record("x"), TOP_N, max_distance=3, min_jaro_winkler=1.5)


@given(a=names, b=names)
def test_r_2_11_keyboard_clause_is_subsumed_by_levenshtein(a: str, b: str) -> None:
    """A keyboard-adjacent substitution is one edit, so Levenshtein <= 3 already covers it.

    This documents a redundancy in the R-2.11 rule as written. If the keyboard clause is meant
    to add coverage, the rule needs a different metric (for example a weighted distance).
    """
    if keyboard_substitution(a, b):
        assert levenshtein(a, b) == 1
