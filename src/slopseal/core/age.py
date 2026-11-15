"""Package age, shared by the age-based checks (2.2, 2.4).

Requirements: R-2.2, R-2.4. Layer 2. Pure: `now` is injected.
"""

from __future__ import annotations

from datetime import datetime

_SECONDS_PER_DAY = 86_400.0


def age_days(now: datetime, first_published: datetime) -> float:
    """Days since first publication. A negative value means publication is ahead of `now`
    (clock skew). Callers treat negative as young, which fails closed."""
    return (now - first_published).total_seconds() / _SECONDS_PER_DAY
