"""Levenshtein edit distance, standard library only (ADR 0002).

Requirements: R-2.2, R-2.11. Layer 2. Pure.
"""

from __future__ import annotations


def levenshtein(a: str, b: str) -> int:
    """Minimum number of single-character insertions, deletions, and substitutions."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]
