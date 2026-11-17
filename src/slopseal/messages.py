"""Fixed wording for what SlopSeal tells a developer or an agent (R-U-1).

The hook (stderr) and the MCP server (tool result text) both read this module, so the two
paths use the same words for the same decision. The wording is fixed. Metadata is never
written into these strings: package names, reasons, and advisory identifiers are JSON values,
written on their own lines, through `data_line` or the hook's JSON objects (R-G-10).

This module changes no decision. It only names the decisions the verdict layer already made.

Requirements: R-U-1, R-G-10, R-1.8. Layer 5. Pure.
"""

from __future__ import annotations

import json
from typing import Any

PROGRESS: tuple[str, ...] = (
    "SlopSeal: Checking dependencies before installation.",
    "SlopSeal: Analyzing package security and integrity.",
)

HEADLINES: dict[str, str] = {
    "allow": "SlopSeal: Package verified. Installation is permitted.",
    "block": "SlopSeal: Installation prevented. Security risks detected.",
    "quarantine": "SlopSeal: Package held for review. Verification is incomplete.",
    "rate_limited": "SlopSeal: Verification temporarily paused. Request limit reached.",
    "error": "SlopSeal: Unable to verify package. Installation is not permitted.",
    "unverifiable": "SlopSeal: Installation prevented. This install form cannot be verified.",
}

NEXT: dict[str, str] = {
    "allow": "Next: install the package at this exact version.",
    "block": (
        "Next: do not install this version. Choose a different package or version, "
        "or ask the user to review it."
    ),
    "quarantine": (
        "Next: verify again with the slopseal MCP tool and the quarantine_id, or ask a person "
        "to approve it with `slopseal escalate`."
    ),
    "rate_limited": (
        "Next: stop installing for up to 60 seconds. Retries in that time are counted and "
        "extend the wait. Do not change the package."
    ),
    "error": "Next: do not install. Fix the setup problem named in the reason, then retry.",
    "unverifiable": (
        "Next: write the command with exact versions and no wrappers, then verify each "
        "package with the slopseal MCP tool."
    ),
}


def verdict_category(outcome: str, check: str | None) -> str:
    """The message category for one verdict. It selects wording and never changes a decision.

    `outcome` is the verdict outcome (ALLOW, BLOCK, or QUARANTINE). `check` is the failing check,
    if any. The rate limit and the internal error are BLOCK outcomes, so the check tells them
    apart from a finding about the package (R-U-1).
    """
    if outcome == "ALLOW":
        return "allow"
    if outcome == "QUARANTINE":
        return "quarantine"
    if check == "rate_limit":
        return "rate_limited"
    if check == "internal_error":
        return "error"
    return "block"


def data_line(name: str, value: Any) -> str:
    """One `name: <JSON value>` line. The value is data, so it is never prose (R-G-10)."""
    return f"{name}: {json.dumps(value, ensure_ascii=False)}"
