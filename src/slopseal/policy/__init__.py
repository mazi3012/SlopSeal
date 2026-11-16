"""Policy: load the fenced TOML block from the steering file, hash it, diff two policies.

Unknown or missing keys are policy errors (exit 78). See docs/adr/0001.

Requirements: R-1.4, R-5.7.4. Design: design.md section 7.
Layer 2.
"""

from slopseal.policy.invariants import enforce_floors
from slopseal.policy.loader import Policy, PolicyError, load_policy, load_policy_or_bundled_default
from slopseal.policy.diff import diff_policies