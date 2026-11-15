"""Exit-75 payload and escalation artifact (PRD: Exit 75 Payload Schema).

The payload is what an agent reads on stdout when a quarantine happens. It contains no
numeric L2 confidence (P-SM-5). L2 confidence, when enabled, goes to the audit log only.

Requirements: R-Q-3, R-Q-4, R-Q-6. Properties: P-SM-4, P-SM-5. Layer 3.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from slopseal.quarantine.api_surface import ApiSurfaceResult

MISMATCH_API_ABSENT = "api_absent"
MISMATCH_L2_LOW_CONFIDENCE = "l2_low_confidence"
MAX_ALTERNATIVES = 5


def build_payload(
    *,
    quarantine_id: str,
    package: str,
    intent_purpose: str,
    surface: ApiSurfaceResult,
    alternatives: tuple[tuple[str, str], ...],
    retry_budget_remaining: int,
) -> dict[str, Any]:
    if retry_budget_remaining not in (0, 1):
        raise ValueError("retry_budget_remaining must be 0 or 1")
    return {
        "verdict": "QUARANTINE",
        "quarantine_id": quarantine_id,
        "package": package,
        "declared_intent": {"purpose": intent_purpose, "expected_api": surface.declared_api},
        "declared_api": surface.declared_api,
        "found_apis": list(surface.found_apis),
        "mismatch_type": MISMATCH_API_ABSENT,
        "missing_evidence": ["api_surface_mismatch"],
        "suggested_alternatives": [
            {"package": name, "reason": reason} for name, reason in alternatives[:MAX_ALTERNATIVES]
        ],
        "retry_budget_remaining": retry_budget_remaining,
        "escalation_command": f"slopseal escalate {quarantine_id} --approve --reason '<why>'",
    }


def build_escalation_artifact(
    *,
    payload: dict[str, Any],
    original_intent: dict[str, Any],
    retry_intents: list[dict[str, Any]],
    policy_hash: str,
    snapshot_id: str | None,
    escalated_at: datetime,
) -> dict[str, Any]:
    """Pending approval record. It shows the original intent and every retry intent, so a
    reviewer can see whether the agent tuned its intent to pass (threat T7)."""
    return {
        "status": "pending",
        "escalated_at": escalated_at.isoformat(),
        "payload": payload,
        "original_intent": original_intent,
        "retry_intents": retry_intents,
        "policy_hash": policy_hash,
        "snapshot_id": snapshot_id,
    }
