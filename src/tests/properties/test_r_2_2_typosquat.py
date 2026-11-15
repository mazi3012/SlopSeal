"""Property tests for check 2.2 (typosquat), its distance and normalization helpers.

Requirements: R-2.2, R-2.2a, R-P-1. Properties: P-TY-1, P-FC-2.
Hypothesis runs 500 examples per property (conftest.py profile, R-PBT-1).

The distance oracle below is an independent recursive implementation. The property
tests compare the production code to it, so they do not test the code against itself.
"""

from __future__ import annotations

import string
from datetime import UTC, datetime, timedelta
from functools import cache

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.core.distance import levenshtein
from slopseal.core.names import normalize_name
from slopseal.core.types import (
    CheckResult,
    Ecosystem,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)
from slopseal.core.typosquat import check_typosquat

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
MAX_DISTANCE = 2
MAX_AGE_DAYS = 30
TOP_N = ("requests", "numpy", "flask", "pandas", "django", "pydantic", "httpx")

# Lowercase, digits, hyphen only: normalization is the identity for npm and for these names,
# so the oracle compares like with like.
NAME_ALPHABET = string.ascii_lowercase + string.digits + "-"
TEXT_12 = st.text(alphabet=NAME_ALPHABET, max_size=12)
edge_ages = st.sampled_from([0.0, 0.5, 29.999, 30.0, 30.001, 400.0])
ages_days = st.one_of(st.floats(min_value=0.0, max_value=400.0), edge_ages)


def reference_levenshtein(a: str, b: str) -> int:
    """Independent oracle: plain recursion with memoization over prefix lengths."""

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


@st.composite
def edited_names(draw: st.DrawFn, base: str, min_edits: int = 0, max_edits: int = 4) -> str:
    """Apply min_edits..max_edits random insertions, deletions, or substitutions to `base`."""
    name = base
    for _ in range(draw(st.integers(min_edits, max_edits))):
        operation = draw(st.sampled_from(["insert", "delete", "substitute"]))
        char = draw(st.sampled_from(NAME_ALPHABET))
        if operation == "delete" and len(name) > 1:
            index = draw(st.integers(0, len(name) - 1))
            name = name[:index] + name[index + 1 :]
        elif operation == "substitute" and name:
            index = draw(st.integers(0, len(name) - 1))
            name = name[:index] + char + name[index + 1 :]
        else:
            index = draw(st.integers(0, len(name)))
            name = name[:index] + char + name[index:]
    return name


def record(name: str, age_days: float) -> RegistryRecord:
    return RegistryRecord(
        Ecosystem.NPM,
        name,
        NOW - timedelta(days=age_days),
        release_count=1,
    )


def oracle_distance(name: str) -> int:
    return min(reference_levenshtein(name, top) for top in TOP_N)


# ---- Levenshtein distance -------------------------------------------------------------


@given(a=TEXT_12, b=TEXT_12)
def test_levenshtein_matches_independent_oracle(a: str, b: str) -> None:
    assert levenshtein(a, b) == reference_levenshtein(a, b)


@given(a=TEXT_12, b=TEXT_12)
def test_levenshtein_is_symmetric_and_zero_only_for_equal(a: str, b: str) -> None:
    d = levenshtein(a, b)
    assert d == levenshtein(b, a)
    assert (d == 0) == (a == b)


@given(
    a=st.text(alphabet=NAME_ALPHABET, max_size=10),
    b=st.text(alphabet=NAME_ALPHABET, max_size=10),
    c=st.text(alphabet=NAME_ALPHABET, max_size=10),
)
def test_levenshtein_satisfies_triangle_inequality(a: str, b: str, c: str) -> None:
    assert levenshtein(a, c) <= levenshtein(a, b) + levenshtein(b, c)


@given(a=TEXT_12, b=TEXT_12)
def test_levenshtein_bounded_by_longer_length(a: str, b: str) -> None:
    assert levenshtein(a, b) <= max(len(a), len(b))


# ---- Name normalization ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right"),
    [("Foo_Bar.baz", "foo-bar-baz"), ("foo__bar", "foo-bar"), ("FLASK", "flask")],
)
def test_pypi_names_compare_under_pep503(left: str, right: str) -> None:
    assert normalize_name(Ecosystem.PYPI, left) == normalize_name(Ecosystem.PYPI, right)


def test_normalization_keeps_whitespace_visible() -> None:
    assert normalize_name(Ecosystem.NPM, " flask") == " flask"


# ---- Check 2.2 -------------------------------------------------------------------------


@given(data=st.data(), age=ages_days)
def test_p_ty_1_hard_block_iff_distance_and_age_intersect(data: st.DataObject, age: float) -> None:
    """P-TY-1: HARD_BLOCK exactly when a top-N name is 1..2 edits away AND age < 30 days."""
    base = data.draw(st.sampled_from(TOP_N))
    name = data.draw(edited_names(base))
    distance = oracle_distance(name)

    result = check_typosquat(
        record(name, age),
        TOP_N,
        NOW,
        max_distance=MAX_DISTANCE,
        max_age_days=MAX_AGE_DAYS,
    )

    expected_block = 1 <= distance <= MAX_DISTANCE and age < MAX_AGE_DAYS
    assert (result.level is Level.HARD_BLOCK) == expected_block


@given(data=st.data(), age=st.floats(min_value=MAX_AGE_DAYS, max_value=400.0))
def test_p_ty_1_old_package_is_never_a_typosquat(data: st.DataObject, age: float) -> None:
    """P-TY-1 (age half): a close name on an established package does not HARD_BLOCK."""
    base = data.draw(st.sampled_from(TOP_N))
    name = data.draw(edited_names(base))
    result = check_typosquat(record(name, age), TOP_N, NOW, max_distance=2, max_age_days=30)
    assert result.level is not Level.HARD_BLOCK


@given(
    name=st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=20),
    age=ages_days,
)
def test_p_ty_1_far_name_is_never_a_typosquat(name: str, age: float) -> None:
    """P-TY-1 (distance half): more than 2 edits from every top-N name never HARD_BLOCKs."""
    assume(oracle_distance(name) > MAX_DISTANCE)
    result = check_typosquat(record(name, age), TOP_N, NOW, max_distance=2, max_age_days=30)
    assert result.level is not Level.HARD_BLOCK


@given(
    data=st.data(),
    age=st.floats(min_value=0.0, max_value=29.999),
)
def test_hard_block_carries_remedy_and_evidence(data: st.DataObject, age: float) -> None:
    """Generated with one or two edits and a young age, so most draws are blocking candidates."""
    base = data.draw(st.sampled_from(TOP_N))
    name = data.draw(edited_names(base, min_edits=1, max_edits=2))
    assume(1 <= oracle_distance(name) <= MAX_DISTANCE)

    result = check_typosquat(record(name, age), TOP_N, NOW, max_distance=2, max_age_days=30)

    assert result.level is Level.HARD_BLOCK
    assert result.remedy is not None
    assert result.remedy.startswith("Did you mean ")
    assert any(key == "distance" for key, _ in result.evidence)


@given(data=st.data())
def test_top_n_name_itself_passes_even_when_young(data: st.DataObject) -> None:
    """A top-N package is not its own typosquat, regardless of age."""
    name = data.draw(st.sampled_from(TOP_N))
    result = check_typosquat(record(name, 1.0), TOP_N, NOW, max_distance=2, max_age_days=30)
    assert result.level is Level.PASS


# ---- Fail closed (P-FC-2) --------------------------------------------------------------


@given(name=st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=20), reason=st.text(min_size=1))
def test_p_fc_2_unknown_registry_blocks_typosquat(name: str, reason: str) -> None:
    result = check_typosquat(
        RegistryUnknown(Ecosystem.NPM, name, reason),
        TOP_N,
        NOW,
        max_distance=2,
        max_age_days=30,
    )
    assert result.level >= Level.BLOCK
    assert result.level is not Level.PASS


@given(name=st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=20))
def test_unknown_publish_time_blocks(name: str) -> None:
    result = check_typosquat(
        RegistryRecord(Ecosystem.NPM, name, None, release_count=1),
        TOP_N,
        NOW,
        max_distance=2,
        max_age_days=30,
    )
    assert result.level is Level.BLOCK


def test_empty_top_n_blocks_rather_than_passes() -> None:
    result = check_typosquat(
        record("requestz", 1.0),
        (),
        NOW,
        max_distance=2,
        max_age_days=30,
    )
    assert result.level is Level.BLOCK


@given(name=st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=20))
def test_missing_package_is_not_applicable_to_typosquat(name: str) -> None:
    """Existence (2.1) reports missing packages, so this check returns PASS, not a second block."""
    result: CheckResult = check_typosquat(
        RegistryMissing(Ecosystem.NPM, name),
        TOP_N,
        NOW,
        max_distance=2,
        max_age_days=30,
    )
    assert result.level is Level.PASS


def test_negative_thresholds_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        check_typosquat(
            record("requestz", 1.0),
            TOP_N,
            NOW,
            max_distance=-1,
            max_age_days=30,
        )


@given(data=st.data(), age=ages_days)
def test_result_type_is_closed(data: st.DataObject, age: float) -> None:
    """Typosquat only ever returns PASS or HARD_BLOCK for a known record. Never WARN."""
    base = data.draw(st.sampled_from(TOP_N))
    name = data.draw(edited_names(base))
    result: RegistryResult = record(name, age)
    level = check_typosquat(result, TOP_N, NOW, max_distance=2, max_age_days=30).level
    assert level in {Level.PASS, Level.HARD_BLOCK}
