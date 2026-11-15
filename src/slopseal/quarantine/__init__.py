"""Quarantine: API-surface check, state machine, payload, escalation.

Every state has a path to a terminal state (ALLOWED, ESCALATED, ABANDONED).
A missing or corrupt state file is a new quarantine, never ALLOWED.

Requirements: R-Q-1 .. R-Q-7. Properties: P-SM-1 .. P-SM-5. Design: design.md section 9.
Layer 3.
"""
