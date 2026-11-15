"""Shared pytest configuration.

Property tests run at least 500 examples per property (R-PBT-1). For a faster local
loop, lower the count with SLOPSEAL_PBT_EXAMPLES. CI always uses 500.
"""

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "slopseal",
    max_examples=int(os.environ.get("SLOPSEAL_PBT_EXAMPLES", "500")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("slopseal")
