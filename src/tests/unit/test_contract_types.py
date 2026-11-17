"""Unit tests for the Contract Check types (R-C-5, design 2.3).

Requirements: R-C-5. Properties: P-C-2 (UNKNOWN never gives PRESENT or ABSENT).
"""

from __future__ import annotations

import pytest

from slopseal.contract.limits import DETAIL_MAX_CHARS, MAX_NAME_LENGTH
from slopseal.contract.types import (
    Answer,
    ContractComplete,
    ContractDigestMismatch,
    ContractUnknown,
    UnknownReason,
    answer,
    valid_name,
)


def test_r_c_5_there_are_exactly_seven_typed_reasons() -> None:
    assert {r.value for r in UnknownReason} == {
        "sdist_only",
        "dynamic_exports",
        "limit",
        "parse_error",
        "network",
        "no_digest",
        "not_in_snapshot",
    }


def test_r_c_5_complete_contract_is_sorted_and_unique() -> None:
    contract = ContractComplete(("parse_file", "parse", "parse"))
    assert contract.exports == ("parse", "parse_file")


@pytest.mark.parametrize("bad", ["", "a b", "a\tb", "a\x00b", "x" * (MAX_NAME_LENGTH + 1)])
def test_r_c_2_a_name_failing_the_name_check_is_rejected(bad: str) -> None:
    assert valid_name(bad) is False
    with pytest.raises(ValueError, match="name check"):
        ContractComplete((bad,))


def test_r_c_5_a_long_detail_is_rejected() -> None:
    with pytest.raises(ValueError, match="DETAIL_MAX_CHARS"):
        ContractUnknown(UnknownReason.LIMIT, "x" * (DETAIL_MAX_CHARS + 1))


def test_r_c_5_a_control_character_in_detail_is_rejected() -> None:
    with pytest.raises(ValueError, match="control"):
        ContractDigestMismatch("sha256", "bad\x07bell")


def test_r_c_5_answer_is_decided_only_for_a_complete_contract() -> None:
    complete = ContractComplete(("parse",))
    assert answer(complete, "parse") is Answer.PRESENT
    assert answer(complete, "read") is Answer.ABSENT
    unknown = ContractUnknown(UnknownReason.DYNAMIC_EXPORTS, "setattr on the module")
    assert answer(unknown, "parse") is Answer.UNKNOWN
    assert answer(unknown, "read") is Answer.UNKNOWN
    mismatch = ContractDigestMismatch("sha256", "digest differs")
    assert answer(mismatch, "parse") is Answer.UNKNOWN
