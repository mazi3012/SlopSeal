"""L1 deterministic checks, one module per check.

Each check is a pure function: data in, CheckResult out. No I/O, no clock reads,
no policy literals. Thresholds come from the policy object.

Requirements: R-2.1 .. R-2.11. Design: design.md sections 2 and 6.
Layer 2. Must not import semantic.
"""
