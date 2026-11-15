"""Property tests for check 2.9 (license policy).

Requirements: R-2.9, R-P-1. Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.license import LicenseUnknown, check_license
from slopseal.core.types import Level

LICENSES = ["MIT", "Apache-2.0", "GPL-3.0-only", "BSD-3-Clause", "AGPL-3.0-only"]
licenses = st.sampled_from(LICENSES)
subsets = st.lists(licenses, max_size=3, unique=True)


def acceptable(term: str, allow: list[str], deny: list[str]) -> bool:
    if term.lower() in {d.lower() for d in deny}:
        return False
    return not allow or term.lower() in {a.lower() for a in allow}


@given(
    terms=st.lists(licenses, min_size=1, max_size=3),
    operator=st.sampled_from([" OR ", " AND "]),
    allow=subsets,
    deny=subsets,
)
def test_r_2_9_chain_matches_oracle(
    terms: list[str], operator: str, allow: list[str], deny: list[str]
) -> None:
    expression = operator.join(terms)
    flags = [acceptable(term, allow, deny) for term in terms]
    expected_pass = any(flags) if operator == " OR " else all(flags)
    if len(terms) == 1:
        expected_pass = flags[0]
    result = check_license(expression, allow=allow, deny=deny, level=Level.BLOCK)
    assert (result.level is Level.PASS) == expected_pass


@given(terms=st.lists(licenses, min_size=2, max_size=3, unique=True), allow=subsets, deny=subsets)
def test_r_2_9_or_is_order_independent(terms: list[str], allow: list[str], deny: list[str]) -> None:
    forward = check_license(" OR ".join(terms), allow=allow, deny=deny)
    backward = check_license(" OR ".join(reversed(terms)), allow=allow, deny=deny)
    assert forward.level is backward.level


@given(
    terms=st.lists(licenses, min_size=1, max_size=3, unique=True),
    extra=licenses,
    allow=subsets,
    deny=subsets,
)
def test_r_2_9_adding_an_or_term_never_reduces_pass(
    terms: list[str], extra: str, allow: list[str], deny: list[str]
) -> None:
    before = check_license(" OR ".join(terms), allow=allow, deny=deny).level
    after = check_license(" OR ".join([*terms, extra]), allow=allow, deny=deny).level
    if before is Level.PASS:
        assert after is Level.PASS


@given(
    terms=st.lists(licenses, min_size=1, max_size=3, unique=True),
    extra=licenses,
    allow=subsets,
    deny=subsets,
)
def test_r_2_9_adding_an_and_term_never_creates_pass(
    terms: list[str], extra: str, allow: list[str], deny: list[str]
) -> None:
    before = check_license(" AND ".join(terms), allow=allow, deny=deny).level
    after = check_license(" AND ".join([*terms, extra]), allow=allow, deny=deny).level
    if after is Level.PASS:
        assert before is Level.PASS


@given(level=st.sampled_from([Level.WARN, Level.BLOCK]))
def test_r_2_9_undeclared_uses_undeclared_level(level: Level) -> None:
    assert check_license(None, undeclared_level=level).level is level
    assert check_license("   ", undeclared_level=level).level is level


@given(reason=st.text(min_size=1, max_size=40))
def test_p_fc_2_unknown_license_blocks(reason: str) -> None:
    assert check_license(LicenseUnknown(reason)).level is Level.BLOCK


@given(
    left=licenses,
    right=licenses,
    shape=st.sampled_from(["parens", "mixed", "with"]),
)
def test_r_2_9_unsupported_expression_blocks(left: str, right: str, shape: str) -> None:
    expressions = {
        "parens": f"({left} OR {right})",
        "mixed": f"{left} OR {right} AND MIT",
        "with": f"{left} WITH Classpath-exception-2.0",
    }
    assert check_license(expressions[shape]).level is Level.BLOCK


@given(term=licenses)
def test_r_2_9_comparison_is_case_insensitive(term: str) -> None:
    assert check_license(term.upper(), allow=[term.lower()]).level is Level.PASS


@given(term=licenses)
def test_r_2_9_result_is_pass_or_configured_level(term: str) -> None:
    level = check_license(term, deny=[term], level=Level.WARN).level
    assert level in {Level.PASS, Level.WARN}


def test_r_2_9_invalid_levels_are_rejected() -> None:
    with pytest.raises(ValueError, match="WARN or BLOCK"):
        check_license("MIT", level=Level.HARD_BLOCK)
    with pytest.raises(ValueError, match="WARN or BLOCK"):
        check_license(None, undeclared_level=Level.PASS)
