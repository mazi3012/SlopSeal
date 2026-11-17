"""R-C-5 and R-C-3: a partial contract (two entry points, one complete) is PRESENT only for the
names a complete entry lists. It is never ABSENT, and every other name stays UNKNOWN.

Requirements: R-C-5, R-C-3. Property: P-C-2 (carved out for PRESENT, see properties.md).
"""

from __future__ import annotations

import pytest

from slopseal.contract.types import ContractComplete, ContractUnknown, UnknownReason
from slopseal.quarantine.api_surface import ApiSurface, check_contract


def _partial(names: tuple[str, ...]) -> ContractUnknown:
    return ContractUnknown(UnknownReason.DYNAMIC_EXPORTS, "one entry point is not complete", names)


def test_r_c_5_a_name_listed_by_a_complete_entry_is_present() -> None:
    surface = check_contract(_partial(("parse",)), "parse")
    assert surface.outcome is ApiSurface.PRESENT


def test_r_c_5_a_name_no_complete_entry_lists_is_unknown_not_absent() -> None:
    surface = check_contract(_partial(("parse",)), "stringify")
    assert surface.outcome is ApiSurface.UNKNOWN
    assert surface.reason is UnknownReason.DYNAMIC_EXPORTS


def test_r_c_5_an_unknown_without_partial_names_is_never_present_or_absent() -> None:
    for declared in ("parse", "stringify"):
        surface = check_contract(ContractUnknown(UnknownReason.LIMIT, "too large"), declared)
        assert surface.outcome is ApiSurface.UNKNOWN


def test_r_c_5_a_complete_contract_still_gives_absent_for_an_unlisted_name() -> None:
    surface = check_contract(ContractComplete(("parse",)), "stringify")
    assert surface.outcome is ApiSurface.ABSENT


def test_r_c_5_partial_names_are_checked_by_the_name_rule() -> None:
    with pytest.raises(ValueError, match="partial name fails the name check"):
        ContractUnknown(UnknownReason.DYNAMIC_EXPORTS, "x", ("has space",))
