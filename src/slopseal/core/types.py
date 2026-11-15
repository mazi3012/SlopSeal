"""Shared types for L1 deterministic checks.

Placed in core/ for Phase 1 so the phase stays inside its file scope. The design
(design.md section 3) places these in a lower `types` layer; move them when that
layer exists.

Requirements: R-2.1, R-V-4. Design: design.md sections 4 and 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum


class Ecosystem(Enum):
    PYPI = "pypi"
    NPM = "npm"
    CARGO = "cargo"
    RUBYGEMS = "rubygems"
    GO = "go"


class Level(IntEnum):
    """Severity of one check result. Higher is stricter."""

    PASS = 0
    WARN = 1
    BLOCK = 2
    HARD_BLOCK = 3


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check. Checks return this and never raise on untrusted input."""

    check: str
    level: Level
    reason: str
    remedy: str | None = None
    evidence: tuple[tuple[str, str | int | float | bool], ...] = ()


@dataclass(frozen=True)
class RegistryRecord:
    """A package found in the registry.

    first_published is None when the registry did not report a publish time. Checks
    that need the package age treat None as unknown state and block (fail closed).
    """

    ecosystem: Ecosystem
    name: str
    first_published: datetime | None
    release_count: int


@dataclass(frozen=True)
class RegistryMissing:
    """The registry answered, and the package does not exist."""

    ecosystem: Ecosystem
    name: str


@dataclass(frozen=True)
class RegistryUnknown:
    """The registry could not answer: timeout, error, partial data, or no snapshot entry state.

    This is a value, not an exception, so every caller must handle it (fail closed).
    """

    ecosystem: Ecosystem
    name: str
    reason: str


RegistryResult = RegistryRecord | RegistryMissing | RegistryUnknown
