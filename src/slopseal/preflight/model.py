"""Preflight data model (D2 report section 7.4).

A check is one measured fact: PASS, FAIL, or NOT_RUN. NOT_RUN means the check could not be
evaluated, and it is never treated as PASS. The status is derived from the checks by
`rules.evaluate` and by no other code.

Requirements: D2 section 7.4, AC-35. Layer 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Result(Enum):
    PASS = "PASS"  # noqa: S105 - a result label, not a password
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


class Status(Enum):
    ENFORCED = "ENFORCED"
    PARTIALLY_ENFORCED = "PARTIALLY ENFORCED"
    NOT_ENFORCED = "NOT ENFORCED"


CLASS_A = "A"  # security-critical: any FAIL or NOT_RUN gives NOT ENFORCED
CLASS_B = "B"  # coverage and durability: a FAIL gives PARTIALLY ENFORCED at most

# Every check the preflight must evaluate. A missing check is treated as NOT_RUN.
REQUIRED: tuple[tuple[str, str, str], ...] = (
    ("A1", CLASS_A, "no sudo, su, or polkit route for the agent account"),
    ("A2", CLASS_A, "no Docker group or socket route for the agent account"),
    ("A3", CLASS_A, "service state, key, and sockets unreadable by the agent"),
    ("A4", CLASS_A, "ptrace_scope at least 1 and no CAP_SYS_PTRACE for the agent"),
    ("A5", CLASS_A, "anchor integrity: receipts verify and match the installation"),
    ("A6", CLASS_A, "no direct registry route from the agent"),
    ("A7", CLASS_A, "policy file matches the pinned hash"),
    ("A8", CLASS_A, "verdict socket binding (SO_PEERCRED) active"),
    ("A9", CLASS_A, "Kiro escape routes that run outside the sandbox are disabled"),
    ("B1", CLASS_B, "protected audit replica present and head-verified"),
    ("B2", CLASS_B, "approved artifact route answers for an ALLOW grant"),
)


@dataclass(frozen=True)
class Check:
    id: str
    cls: str
    title: str
    result: Result
    detail: str = ""


@dataclass(frozen=True)
class Evaluation:
    status: Status
    reason: str
    checks: tuple[Check, ...]
    named: tuple[str, ...] = ()  # the check ids the reason refers to
