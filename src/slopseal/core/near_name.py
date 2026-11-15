"""Check 2.11: near-name similarity to a top-N package.

WARN when a name is close to a popular package by any one of:
- Levenshtein distance <= `max_distance` (default 3, from policy);
- Jaro-Winkler similarity >= `min_jaro_winkler` (default 0.92, from policy);
- a single keyboard-adjacent substitution.

There is no age condition. A near-name WARN is a signal, not a block. Established packages
can have near names, so the decision to block belongs to 2.2 (typosquat) or policy.

A name equal to a top-N name passes, because it is that package.

Fail closed: an unknown registry state or an empty top-N list is BLOCK. A missing package
passes here, because the existence check (2.1) reports it.

Requirements: R-2.11, R-P-1. Layer 2. Pure.
"""

from __future__ import annotations

from collections.abc import Sequence

from slopseal.core.distance import levenshtein
from slopseal.core.names import normalize_name
from slopseal.core.similarity import jaro_winkler, keyboard_substitution
from slopseal.core.types import (
    CheckResult,
    Ecosystem,
    Level,
    RegistryMissing,
    RegistryRecord,
    RegistryResult,
    RegistryUnknown,
)

CHECK_ID = "near_name"


def check_near_name(
    result: RegistryResult,
    top_n: Sequence[str],
    *,
    max_distance: int,
    min_jaro_winkler: float,
) -> CheckResult:
    if max_distance < 0:
        raise ValueError("near-name max_distance must be non-negative")
    if not 0.0 <= min_jaro_winkler <= 1.0:
        raise ValueError("near-name min_jaro_winkler must be in [0, 1]")

    if isinstance(result, RegistryUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"registry state unknown: {result.reason}")
    if isinstance(result, RegistryMissing):
        return CheckResult(CHECK_ID, Level.PASS, "not applicable: package does not exist")
    if not isinstance(result, RegistryRecord):
        raise AssertionError("unreachable: RegistryResult is exhaustive")
    if not top_n:
        return CheckResult(CHECK_ID, Level.BLOCK, "top-N list is empty or unavailable")

    ecosystem: Ecosystem = result.ecosystem
    name = normalize_name(ecosystem, result.name)
    candidates = sorted({normalize_name(ecosystem, top) for top in top_n})
    if name in candidates:
        return CheckResult(CHECK_ID, Level.PASS, "name is itself a top-N package")

    hits: list[tuple[str, str]] = []
    for candidate in candidates:
        reasons = []
        distance = levenshtein(name, candidate)
        if distance <= max_distance:
            reasons.append(f"distance {distance}")
        similarity = jaro_winkler(name, candidate)
        if similarity >= min_jaro_winkler:
            reasons.append(f"jaro-winkler {similarity:.2f}")
        if keyboard_substitution(name, candidate):
            reasons.append("keyboard-adjacent substitution")
        if reasons:
            hits.append((candidate, ", ".join(reasons)))

    if not hits:
        return CheckResult(CHECK_ID, Level.PASS, "no near-name match to a top-N package")

    nearest = hits[0][0]
    return CheckResult(
        CHECK_ID,
        Level.WARN,
        f"'{result.name}' is close to popular package(s): "
        + "; ".join(f"{candidate} ({why})" for candidate, why in hits),
        remedy=f"Did you mean {nearest}?",
        evidence=(("matched", ", ".join(c for c, _ in hits)), ("count", len(hits))),
    )
