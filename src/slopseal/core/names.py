"""Package name normalization, per ecosystem.

PyPI names compare under PEP 503 normalization: case-insensitive, and runs of `-`, `_`,
and `.` are equivalent. Other ecosystems compare lowercase. Names are never stripped:
surrounding whitespace is kept so it stays visible in comparisons.

Requirements: R-2.2. Layer 2.
"""

from __future__ import annotations

import re

from slopseal.core.types import Ecosystem

_PEP503_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    lowered = name.lower()
    if ecosystem is Ecosystem.PYPI:
        return _PEP503_SEPARATORS.sub("-", lowered)
    return lowered
