"""Property tests for check 2.8 (allow-list and deny-list).

Requirements: R-2.8. Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import string

from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.core.allow_deny import check_allow_deny
from slopseal.core.names import normalize_name
from slopseal.core.types import Ecosystem, Level

NAME = st.text(alphabet=string.ascii_lowercase + "-_.", min_size=1, max_size=16)
name_lists = st.lists(NAME, max_size=5)


@given(name=NAME, deny=name_lists, allow=name_lists)
def test_r_2_8_denied_name_is_block(name: str, deny: list[str], allow: list[str]) -> None:
    result = check_allow_deny(Ecosystem.PYPI, name, allow=allow, deny=[*deny, name])
    assert result.level is Level.BLOCK


@given(name=NAME, deny=name_lists, allow=name_lists)
def test_r_2_8_name_not_on_deny_list_is_not_blocked(
    name: str, deny: list[str], allow: list[str]
) -> None:
    target = normalize_name(Ecosystem.PYPI, name)
    assume(all(normalize_name(Ecosystem.PYPI, d) != target for d in deny))
    result = check_allow_deny(Ecosystem.PYPI, name, allow=allow, deny=deny)
    assert result.level is Level.PASS


@given(name=NAME, allow=name_lists)
def test_r_2_8_deny_wins_over_allow(name: str, allow: list[str]) -> None:
    result = check_allow_deny(Ecosystem.PYPI, name, allow=[*allow, name], deny=[name])
    assert result.level is Level.BLOCK


@given(name=NAME, deny=name_lists)
def test_r_2_8_allow_only_passes_with_exempt_flag(name: str, deny: list[str]) -> None:
    target = normalize_name(Ecosystem.PYPI, name)
    assume(all(normalize_name(Ecosystem.PYPI, d) != target for d in deny))
    result = check_allow_deny(Ecosystem.PYPI, name, allow=[name], deny=deny)
    assert result.level is Level.PASS
    assert ("exempt", True) in result.evidence


@given(name=NAME, deny=name_lists, allow=name_lists)
def test_r_2_8_result_is_pass_or_block_only(name: str, deny: list[str], allow: list[str]) -> None:
    level = check_allow_deny(Ecosystem.PYPI, name, allow=allow, deny=deny).level
    assert level in {Level.PASS, Level.BLOCK}


@given(name=NAME, deny=name_lists, allow=name_lists)
def test_r_2_8_pypi_comparison_is_pep503(name: str, deny: list[str], allow: list[str]) -> None:
    variant = name.upper().replace("-", "_").replace(".", "__")
    left = check_allow_deny(Ecosystem.PYPI, name, allow=allow, deny=deny)
    right = check_allow_deny(Ecosystem.PYPI, variant, allow=allow, deny=deny)
    assert left.level is right.level
