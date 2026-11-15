"""Check 2.3: slopsquat signature match.

A slopsquat signature is a known hallucinated name, a blend of two real tools
(for example `react-codeshift`, blended from jscodeshift and react-codemod), together
with the real package it imitates. Signatures are data from the policy, not a generic
blending heuristic. A generic rule flags legitimate names such as `flask-sqlalchemy`,
so v1 matches a curated list and states that limit openly.

A name matches a signature when its normalized form is within `max_distance` edits of the
signature pattern. A name that is itself a top-N package never matches, because the real
package is not a slopsquat.

Requirements: R-2.3. Layer 2. Pure.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from slopseal.core.distance import levenshtein
from slopseal.core.names import normalize_name
from slopseal.core.types import CheckResult, Ecosystem, Level

CHECK_ID = "slopsquat"


@dataclass(frozen=True)
class Signature:
    """One hallucinated name and the real package it imitates."""

    pattern: str
    mimics: str

    def __post_init__(self) -> None:
        if not self.pattern or not self.mimics:
            raise ValueError("slopsquat signature needs a non-empty pattern and mimics")


def check_slopsquat(
    ecosystem: Ecosystem,
    name: str,
    signatures: Sequence[Signature],
    top_n: Sequence[str],
    *,
    max_distance: int,
) -> CheckResult:
    if max_distance < 0:
        raise ValueError("slopsquat max_distance must be non-negative")

    normalized = normalize_name(ecosystem, name)
    top_names = {normalize_name(ecosystem, top) for top in top_n}
    if normalized in top_names:
        return CheckResult(CHECK_ID, Level.PASS, "name is a top-N package, not a signature")

    candidates = [
        (levenshtein(normalized, normalize_name(ecosystem, sig.pattern)), sig) for sig in signatures
    ]
    matches = [(distance, sig) for distance, sig in candidates if distance <= max_distance]
    if not matches:
        return CheckResult(CHECK_ID, Level.PASS, "no slopsquat signature matched")

    # Ties break on the signature text, so the result does not depend on list order.
    best_distance, best = min(
        matches,
        key=lambda pair: (pair[0], normalize_name(ecosystem, pair[1].pattern)),
    )
    mimics = normalize_name(ecosystem, best.mimics)
    return CheckResult(
        CHECK_ID,
        Level.HARD_BLOCK,
        f"'{name}' matches the slopsquat signature '{best.pattern}' "
        f"({best_distance} edit(s)); it imitates '{best.mimics}'",
        remedy=f"Did you mean {mimics}?",
        evidence=(
            ("distance", best_distance),
            ("signature", best.pattern),
            ("mimics", best.mimics),
        ),
    )
