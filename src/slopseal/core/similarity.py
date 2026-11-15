"""Similarity measures for near-name detection (check 2.11), standard library only.

- `jaro_winkler`: Jaro similarity with the usual common-prefix boost (prefix up to 4, scale 0.1).
- `keyboard_substitution`: True when two equal-length names differ at exactly one position,
  and the two characters there are neighbours on a QWERTY keyboard.

Requirements: R-2.11. Layer 2. Pure.
"""

from __future__ import annotations

_ROWS: tuple[tuple[str, float], ...] = (
    ("1234567890", 0.0),
    ("qwertyuiop", 0.5),
    ("asdfghjkl", 0.75),
    ("zxcvbnm", 1.25),
)
_KEY_POSITIONS: dict[str, tuple[int, float]] = {
    char: (row, offset + column)
    for row, (keys, offset) in enumerate(_ROWS)
    for column, char in enumerate(keys)
}


def jaro_winkler(a: str, b: str) -> float:
    """Jaro-Winkler similarity in [0, 1]. Identical strings score 1.0; empty vs non-empty 0.0."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0

    window = max(len(a), len(b)) // 2 - 1
    window = max(window, 0)
    a_matched = [False] * len(a)
    b_matched = [False] * len(b)
    matches = 0

    for i, char in enumerate(a):
        low = max(0, i - window)
        high = min(i + window + 1, len(b))
        for j in range(low, high):
            if not b_matched[j] and b[j] == char:
                a_matched[i] = True
                b_matched[j] = True
                matches += 1
                break

    if matches == 0:
        return 0.0

    transpositions = 0
    j = 0
    for i, matched in enumerate(a_matched):
        if matched:
            while not b_matched[j]:
                j += 1
            if a[i] != b[j]:
                transpositions += 1
            j += 1
    transpositions //= 2

    jaro = (matches / len(a) + matches / len(b) + (matches - transpositions) / matches) / 3

    prefix = 0
    for x, y in zip(a[:4], b[:4], strict=False):
        if x != y:
            break
        prefix += 1
    return jaro + prefix * 0.1 * (1 - jaro)


def keyboard_substitution(a: str, b: str) -> bool:
    """True when a and b are equal length, differ at exactly one position, and the two keys
    there are neighbours on the QWERTY layout (within one row and about one key apart)."""
    if len(a) != len(b):
        return False
    differing = [i for i, (x, y) in enumerate(zip(a, b, strict=True)) if x != y]
    if len(differing) != 1:
        return False
    x, y = a[differing[0]], b[differing[0]]
    if x not in _KEY_POSITIONS or y not in _KEY_POSITIONS:
        return False
    row_x, col_x = _KEY_POSITIONS[x]
    row_y, col_y = _KEY_POSITIONS[y]
    return abs(row_x - row_y) <= 1 and abs(col_x - col_y) <= 1.0
