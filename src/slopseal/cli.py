"""Command-line entry point (reserved).

The `slopseal` console script is registered in pyproject.toml so the name and the
entry point exist from the first commit. Behavior arrives in Phase 1.

Requirements: R-1.1, R-1.3, R-1.5. Design: design.md sections 11 and 13.
Layer 5 (may import verdict and below).
"""

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Stub entry point. Fails closed: it never reports success."""
    del argv  # Unused until Phase 1.
    sys.stderr.write("slopseal: not implemented — Phase 1.\n")
    return 1
