"""Compare two parsed trust policies field by field.

The diff works on parsed Policy values, not on text. A reformatted policy with the same values
shows no changes. The policy_hash field is compared separately as a header line.

Requirements: R-5.7.4. Layer 2. Pure.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any

from slopseal.policy.loader import Policy


@dataclass(frozen=True)
class FieldChange:
    field: str
    old: Any
    new: Any


def diff_policies(old: Policy, new: Policy) -> list[FieldChange]:
    """Return one entry per policy field whose value differs. policy_hash is not a field here."""
    changes: list[FieldChange] = []
    for field in fields(Policy):
        if field.name == "policy_hash":
            continue
        before = getattr(old, field.name)
        after = getattr(new, field.name)
        if before != after:
            changes.append(FieldChange(field.name, before, after))
    return changes
