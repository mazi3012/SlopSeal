"""Property tests for check 2.3 (slopsquat signature match).

Requirements: R-2.3. Hypothesis runs 500 examples per property (conftest.py profile, R-PBT-1).
The distance oracle is an independent recursive implementation.
"""

from __future__ import annotations

import string
from functools import cache

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.core.signatures import Signature, check_slopsquat
from slopseal.core.types import Ecosystem, Level

NAME_ALPHABET = string.ascii_lowercase + string.digits + "-"
TEXT_NAME = st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=20)
MAX_DISTANCE = 1

# Curated, illustrative patterns. The real list lives in the policy file.
SIGNATURES = (
    Signature("react-codeshift", "react-codemod"),
    Signature("jscodeshift-react", "jscodeshift"),
)
TOP_N = ("react-codemod", "jscodeshift", "requests", "numpy", "flask")


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


@st.composite
def edited(draw: st.DrawFn, base: str, min_edits: int, max_edits: int) -> str:
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


@given(data=st.data())
def test_r_2_3_exact_signature_is_hard_block(data: st.DataObject) -> None:
    signature = data.draw(st.sampled_from(SIGNATURES))
    result = check_slopsquat(
        Ecosystem.NPM, signature.pattern, SIGNATURES, TOP_N, max_distance=MAX_DISTANCE
    )
    assert result.level is Level.HARD_BLOCK
    assert result.check == "slopsquat"


@given(data=st.data())
def test_r_2_3_remedy_names_the_mimicked_package(data: st.DataObject) -> None:
    signature = data.draw(st.sampled_from(SIGNATURES))
    result = check_slopsquat(
        Ecosystem.NPM, signature.pattern, SIGNATURES, TOP_N, max_distance=MAX_DISTANCE
    )
    assert result.remedy == f"Did you mean {signature.mimics}?"


@given(data=st.data())
def test_r_2_3_near_variant_within_tolerance_is_hard_block(data: st.DataObject) -> None:
    signature = data.draw(st.sampled_from(SIGNATURES))
    name = data.draw(edited(signature.pattern, min_edits=0, max_edits=MAX_DISTANCE))
    assume(name not in TOP_N)

    result = check_slopsquat(Ecosystem.NPM, name, SIGNATURES, TOP_N, max_distance=MAX_DISTANCE)

    within = any(reference_levenshtein(name, sig.pattern) <= MAX_DISTANCE for sig in SIGNATURES)
    assert (result.level is Level.HARD_BLOCK) == within


@given(name=TEXT_NAME)
def test_r_2_3_matches_oracle_for_any_name(name: str) -> None:
    """Whatever the name, the verdict equals the oracle's reading of the signature list."""
    result = check_slopsquat(Ecosystem.NPM, name, SIGNATURES, TOP_N, max_distance=MAX_DISTANCE)
    within = any(reference_levenshtein(name, sig.pattern) <= MAX_DISTANCE for sig in SIGNATURES)
    expected_block = within and name not in TOP_N
    assert (result.level is Level.HARD_BLOCK) == expected_block


@given(data=st.data())
def test_r_2_3_top_n_name_is_never_a_signature(data: st.DataObject) -> None:
    """A real top-N package is not a slopsquat, even when a signature is close to it."""
    name = data.draw(st.sampled_from(TOP_N))
    signatures = (*SIGNATURES, Signature(name, "something-else"))
    result = check_slopsquat(Ecosystem.NPM, name, signatures, TOP_N, max_distance=MAX_DISTANCE)
    assert result.level is Level.PASS


@given(name=TEXT_NAME)
def test_r_2_3_result_does_not_depend_on_signature_order(name: str) -> None:
    forward = check_slopsquat(Ecosystem.NPM, name, SIGNATURES, TOP_N, max_distance=MAX_DISTANCE)
    backward = check_slopsquat(
        Ecosystem.NPM, name, tuple(reversed(SIGNATURES)), TOP_N, max_distance=MAX_DISTANCE
    )
    assert forward == backward


@given(name=TEXT_NAME)
def test_r_2_3_empty_signature_list_passes(name: str) -> None:
    result = check_slopsquat(Ecosystem.NPM, name, (), TOP_N, max_distance=MAX_DISTANCE)
    assert result.level is Level.PASS


@given(name=TEXT_NAME)
def test_r_2_3_result_is_pass_or_hard_block_only(name: str) -> None:
    level = check_slopsquat(Ecosystem.NPM, name, SIGNATURES, TOP_N, max_distance=MAX_DISTANCE).level
    assert level in {Level.PASS, Level.HARD_BLOCK}


def test_r_2_3_pypi_names_compare_under_pep503() -> None:
    result = check_slopsquat(
        Ecosystem.PYPI,
        "React_Codeshift",
        (Signature("react-codeshift", "react-codemod"),),
        TOP_N,
        max_distance=0,
    )
    assert result.level is Level.HARD_BLOCK


def test_r_2_3_negative_tolerance_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        check_slopsquat(Ecosystem.NPM, "x", SIGNATURES, TOP_N, max_distance=-1)


@pytest.mark.parametrize(("pattern", "mimics"), [("", "react-codemod"), ("react-codeshift", "")])
def test_r_2_3_signature_requires_pattern_and_mimics(pattern: str, mimics: str) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        Signature(pattern, mimics)
