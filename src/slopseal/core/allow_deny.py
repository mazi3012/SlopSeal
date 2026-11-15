"""Check 2.8: allow-list and deny-list.

- A name on the deny list is BLOCK.
- A name on the allow list is PASS, with `exempt=True` in the evidence. The verdict layer
  reads that flag to decide which warning-level findings it may skip.
- A name on both lists is BLOCK. Deny wins, because a list conflict is a policy error
  that must fail closed.

Scope of the exemption (PRD, check 2.8 and R-2.8): an allow-list entry exempts a package
from WARN-level checks only. It never exempts from HARD_BLOCK or BLOCK, so an allow-list
entry cannot override a slopsquat, malware, or CVE finding. The verdict layer applies
that rule; this check only reports the flag.

Names are compared after ecosystem normalization (PEP 503 for PyPI).

Requirements: R-2.8. Layer 2. Pure.
"""

from __future__ import annotations

from collections.abc import Collection

from slopseal.core.names import normalize_name
from slopseal.core.types import CheckResult, Ecosystem, Level

CHECK_ID = "allow_deny"


def check_allow_deny(
    ecosystem: Ecosystem,
    name: str,
    *,
    allow: Collection[str],
    deny: Collection[str],
) -> CheckResult:
    normalized = normalize_name(ecosystem, name)
    allowed = {normalize_name(ecosystem, entry) for entry in allow}
    denied = {normalize_name(ecosystem, entry) for entry in deny}

    if normalized in denied:
        return CheckResult(
            CHECK_ID,
            Level.BLOCK,
            f"'{name}' is on the deny list"
            + (" (also on the allow list; deny wins)" if normalized in allowed else ""),
        )
    if normalized in allowed:
        return CheckResult(
            CHECK_ID,
            Level.PASS,
            f"'{name}' is on the allow list",
            evidence=(("exempt", True),),
        )
    return CheckResult(CHECK_ID, Level.PASS, "not on the allow or deny list")
