"""Contract Check result types: the three-valued answer, the seven typed reasons, and results.

Layer 0 (pure data, no I/O). A contract is complete only when every export-affecting statement
of the artifact was read and modelled (completeness rule, R-C-2 and R-C-3). Unknown is an explicit
value with one typed reason, never None and never an exception (tech.md).

Requirements: R-C-1, R-C-5. Properties: P-C-2, P-C-3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from slopseal.contract.limits import DETAIL_MAX_CHARS, MAX_NAME_LENGTH

_NAME_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f]")


class Answer(Enum):
    """The answer to one probe: decided (PRESENT or ABSENT), or UNKNOWN."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class UnknownReason(Enum):
    """The seven typed reasons. Each has one meaning, and no cause uses another's label (R-C-5)."""

    SDIST_ONLY = "sdist_only"
    DYNAMIC_EXPORTS = "dynamic_exports"
    LIMIT = "limit"
    PARSE_ERROR = "parse_error"
    NETWORK = "network"
    NO_DIGEST = "no_digest"
    NOT_IN_SNAPSHOT = "not_in_snapshot"


def valid_name(name: str) -> bool:
    """A contract name: non-empty, at most MAX_NAME_LENGTH, no whitespace, no control character."""
    return 0 < len(name) <= MAX_NAME_LENGTH and _NAME_FORBIDDEN.search(name) is None


def _check_detail(detail: str) -> None:
    if len(detail) > DETAIL_MAX_CHARS:
        raise ValueError("detail is longer than DETAIL_MAX_CHARS")
    if _NAME_FORBIDDEN.search(detail.replace(" ", "")) is not None:
        raise ValueError("detail contains a control character")


@dataclass(frozen=True)
class ContractComplete:
    """A complete contract: every export of the artifact was read. Names are sorted and unique."""

    exports: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in self.exports:
            if not valid_name(name):
                raise ValueError("export name fails the name check")
        object.__setattr__(self, "exports", tuple(sorted(set(self.exports))))


@dataclass(frozen=True)
class ContractUnknown:
    """No decided answer. Gives BLOCK, never ALLOW and never QUARANTINE (R-C-5)."""

    reason: UnknownReason
    detail: str
    # Names listed by a complete entry point of a package whose entry points are not all complete
    # (R-C-3, two entry points). A declared API in `partial` is PRESENT; nothing is ABSENT.
    partial: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _check_detail(self.detail)
        for name in self.partial:
            if not valid_name(name):
                raise ValueError("partial name fails the name check")
        object.__setattr__(self, "partial", tuple(sorted(set(self.partial))))


@dataclass(frozen=True)
class ContractDigestMismatch:
    """The downloaded artifact does not match the digest the registry published (T23). BLOCK."""

    algorithm: str
    detail: str

    def __post_init__(self) -> None:
        _check_detail(self.detail)


ContractResult = ContractComplete | ContractUnknown | ContractDigestMismatch


def answer(result: ContractResult, name: str) -> Answer:
    """The answer for one probe. Only a complete contract can give PRESENT or ABSENT."""
    if isinstance(result, ContractComplete):
        return Answer.PRESENT if name in result.exports else Answer.ABSENT
    return Answer.UNKNOWN
