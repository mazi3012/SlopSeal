"""Check 2.10: maintainer reputation.

The v1 signals are deliberately narrow, because the registry's maintainer data is not yet
confirmed (PRD check 2.10 gives no rule):

- no maintainer listed: a finding;
- the newest maintainer account is younger than `min_account_age_days`: a finding.

Findings are reported at a required level (WARN or BLOCK, per policy). The level has no
default, so the policy must choose it.

Fail closed: maintainer data that is unknown, or has a negative count, or lists maintainers
without an account age, is BLOCK.

Requirements: R-2.10, R-P-1. Layer 2. Pure: the account age is computed by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass

from slopseal.core.types import CheckResult, Level

CHECK_ID = "maintainer"
_CONFIGURABLE_LEVELS = frozenset({Level.WARN, Level.BLOCK})


@dataclass(frozen=True)
class Maintainers:
    count: int
    newest_account_age_days: float | None


@dataclass(frozen=True)
class MaintainersUnknown:
    """Maintainer data could not be read. Fail closed: BLOCK."""

    reason: str


@dataclass(frozen=True)
class MaintainersNotPublished:
    """The source does not publish maintainer account age (live mode). WARN, not BLOCK.

    Only the live registry adapter returns this. Offline snapshots and failed lookups return
    Maintainers or MaintainersUnknown.
    """

    reason: str


MaintainerInput = Maintainers | MaintainersUnknown | MaintainersNotPublished


def check_maintainer(
    info: MaintainerInput,
    *,
    min_account_age_days: int,
    level: Level,
) -> CheckResult:
    if min_account_age_days < 0:
        raise ValueError("maintainer min_account_age_days must be non-negative")
    if level not in _CONFIGURABLE_LEVELS:
        raise ValueError("maintainer level must be WARN or BLOCK")

    if isinstance(info, MaintainersUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"maintainer data unknown: {info.reason}")
    if isinstance(info, MaintainersNotPublished):
        return CheckResult(
            CHECK_ID, Level.WARN, f"maintainer account age not published: {info.reason}"
        )
    if info.count < 0:
        return CheckResult(CHECK_ID, Level.BLOCK, "registry reported a negative maintainer count")
    if info.count > 0 and info.newest_account_age_days is None:
        return CheckResult(CHECK_ID, Level.BLOCK, "maintainer account age is unknown")

    findings: list[str] = []
    if info.count == 0:
        findings.append("no maintainer listed")
    if info.newest_account_age_days is not None and (
        info.newest_account_age_days < min_account_age_days
    ):
        findings.append(f"newest maintainer account is {info.newest_account_age_days:.1f} days old")

    if not findings:
        return CheckResult(CHECK_ID, Level.PASS, "maintainer signals within policy")
    return CheckResult(
        CHECK_ID,
        level,
        "; ".join(sorted(findings)),
        evidence=(("count", info.count), ("findings", len(findings))),
    )
