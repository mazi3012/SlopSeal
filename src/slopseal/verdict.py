"""verify_install: the entry point that ties the L1 checks, quarantine, and audit together.

Order (PRD "Verdict Resolution", design section 6). The first decisive step wins:

  1. version is known                                   (BLOCK if not)
  2. retry of an existing quarantine: terminal states return immediately; an open one
     continues to the checks below; an escalated one returns exit 75 with no new check
  3. L1 checks 2.1..2.11. Existence runs first. A HARD_BLOCK or BLOCK stops the pipeline.
  4. intent: the declared API must be among the exports of the exact version
       unknown exports -> BLOCK; absent -> QUARANTINE (api_absent)
  5. ALLOW, with WARN-level checks attached

Every returned decision is written to the audit log first. An ALLOW that cannot be logged is
not returned (fail closed). `verify_install` never raises. Any exception becomes BLOCK with
check `internal_error`, and the detail goes to the log only (design section 6).

Requirements: R-V-1..R-V-4, R-1.4, R-1.5, R-P-1, R-Q-1..R-Q-7. Properties: P-FC-1..P-FC-6.
Layer 4.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Any

from slopseal.audit.log import AuditLog
from slopseal.contract.types import ContractDigestMismatch, ContractUnknown, UnknownReason
from slopseal.core.allow_deny import check_allow_deny
from slopseal.core.cve import check_cve
from slopseal.core.distance import levenshtein
from slopseal.core.existence import check_existence
from slopseal.core.install_scripts import check_install_scripts
from slopseal.core.license import check_license
from slopseal.core.maintainer import check_maintainer
from slopseal.core.malware import check_malware
from slopseal.core.names import normalize_name
from slopseal.core.near_name import check_near_name
from slopseal.core.new_package import check_new_package
from slopseal.core.signatures import Signature, check_slopsquat
from slopseal.core.types import CheckResult, Ecosystem, Level
from slopseal.core.typosquat import check_typosquat
from slopseal.policy.loader import Policy
from slopseal.quarantine.api_surface import (
    ApiSurface,
    ApiSurfaceResult,
    check_contract,
    mismatch_block,
    unknown_block,
)
from slopseal.quarantine.payload import (
    MISMATCH_API_ABSENT,
    build_escalation_artifact,
    build_payload,
)
from slopseal.quarantine.rate_limit import Layer, RateLimiter, install_key
from slopseal.quarantine.state_machine import (
    QState,
    QuarantineState,
    QuarantineStore,
    effective_state,
    matches,
)
from slopseal.registry.source import RegistrySource

log = logging.getLogger("slopseal")

_LEVELS = {"warn": Level.WARN, "block": Level.BLOCK}
_SEPARATORS = ("-", "_", ".")
_REMEDY_DISTANCE = 3


class Outcome(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


_EXIT = {Outcome.ALLOW: 0, Outcome.BLOCK: 1, Outcome.QUARANTINE: 75}


@dataclass(frozen=True)
class Intent:
    purpose: str
    expected_api: str | None = None

    def to_json(self) -> dict[str, str | None]:
        return {"purpose": self.purpose, "expected_api": self.expected_api}


@dataclass(frozen=True)
class InstallRequest:
    ecosystem: Ecosystem
    package: str
    version: str | None = None
    intent: Intent | None = None
    quarantine_id: str | None = None
    bypass_reason: str | None = None
    # Which caller verifies the install. The rate limit counts one install once across layers.
    layer: Layer = Layer.OTHER


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    ecosystem: str
    package: str
    version: str
    reason: str
    checks_run: tuple[str, ...] = ()
    warnings: tuple[CheckResult, ...] = ()
    violation: CheckResult | None = None
    quarantine_id: str | None = None
    quarantine_payload: dict[str, Any] | None = None
    policy_hash: str = ""
    snapshot_id: str | None = None
    bypassed: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return _EXIT[self.outcome]


@dataclass(frozen=True)
class Context:
    policy: Policy
    source: RegistrySource
    store: QuarantineStore
    log: AuditLog
    now: datetime
    new_id: Callable[[], str]
    limiter: RateLimiter | None = None


def verify_install(request: InstallRequest, ctx: Context) -> Decision:
    """Return a Decision. Never raises; any failure is BLOCK (fail closed)."""
    try:
        decision = _verify(request, ctx)
        if (
            decision.outcome is Outcome.ALLOW
            and request.layer is Layer.HOOK
            and request.version is not None
            and ctx.limiter is not None
        ):
            # Save the credit before returning ALLOW. If this fails, the call is a BLOCK.
            ctx.limiter.note_hook_allow(
                install_key(request.ecosystem, request.package, request.version)
            )
        return decision
    except Exception as exc:  # fail-closed wrapper: every error becomes BLOCK
        log.error("internal error while verifying %s: %s", request.package, type(exc).__name__)
        return _internal_block(request, ctx)


def _internal_block(request: InstallRequest, ctx: Context) -> Decision:
    violation = CheckResult(
        "internal_error",
        Level.HARD_BLOCK,
        "internal error; the verdict is BLOCK. Detail is in the audit log.",
    )
    return Decision(
        outcome=Outcome.BLOCK,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=request.version or "",
        reason=violation.reason,
        violation=violation,
        policy_hash=ctx.policy.policy_hash,
        snapshot_id=ctx.source.snapshot_id,
    )


def _verify(request: InstallRequest, ctx: Context) -> Decision:
    eco = request.ecosystem
    name = request.package
    source = ctx.source
    snapshot_id = source.snapshot_id

    # Step 1: rate limit (PRD 4.7, R-G-11). Every attempt counts, except a shim attempt for an
    # install the hook already counted. The limit is not bypassable.
    if ctx.limiter is not None:
        key = install_key(eco, name, request.version) if request.version is not None else None
        rate = ctx.limiter.attempt(key, request.layer)
        if not rate.allowed:
            rate_version = request.version or source.latest_version(eco, name) or ""
            violation = CheckResult("rate_limit", Level.BLOCK, rate.reason)
            return _record(
                request,
                ctx,
                Decision(
                    outcome=Outcome.BLOCK,
                    ecosystem=eco.value,
                    package=name,
                    version=rate_version,
                    reason=rate.reason,
                    violation=violation,
                    policy_hash=ctx.policy.policy_hash,
                    snapshot_id=snapshot_id,
                ),
            )

    version = request.version or source.latest_version(eco, name)
    if version is None:
        return _block(
            request,
            ctx,
            "version",
            "no version given and no latest version is known for this package",
        )

    # ---- 2. retry of an existing quarantine ---------------------------------------------
    retry: QuarantineState | None = None
    if request.quarantine_id is not None:
        stored = ctx.store.load(request.quarantine_id)
        if stored is not None and matches(stored, eco, name, version):
            retry = stored

    if retry is not None:
        status = effective_state(retry, ctx.now)
        if status == QState.APPROVED:
            return _finish_allow(
                request,
                ctx,
                version,
                (),
                (),
                bypassed=True,
                reason=f"approved by a human: {retry.reason}",
                quarantine_id=retry.quarantine_id,
            )
        if status == QState.ALLOWED:
            return _finish_allow(
                request,
                ctx,
                version,
                (),
                (),
                reason="quarantine already allowed",
                quarantine_id=retry.quarantine_id,
            )
        if status in (QState.BLOCKED, QState.ABANDONED):
            return _block(
                request,
                ctx,
                "quarantine",
                f"quarantine is {status}; the original install was not allowed",
                quarantine_id=retry.quarantine_id,
            )
        if status == QState.ESCALATED:
            return _escalated_again(request, ctx, version, retry)
        # status == OPEN: the retry runs the checks below with the refined intent.

    # ---- 3. L1 checks -------------------------------------------------------------------
    results: list[CheckResult] = []
    registry = source.registry_result(eco, name)
    existence = check_existence(registry)
    results.append(existence)
    if existence.level >= Level.BLOCK:
        if existence.level is Level.HARD_BLOCK:
            remedy = _existence_remedy(eco, name, source)
            existence = replace(existence, remedy=remedy)
            results[-1] = existence
        return _verdict_block(request, ctx, version, results, snapshot_id, retry)

    results.extend(_run_l1(request, ctx, version))
    exempt = any(("exempt", True) in r.evidence for r in results if r.check == "allow_deny")
    blocking = [r for r in results if r.level >= Level.BLOCK]
    if blocking:
        return _verdict_block(request, ctx, version, results, snapshot_id, retry)

    warnings = tuple(r for r in results if r.level is Level.WARN and not exempt)
    checks_run = tuple(r.check for r in results)

    # ---- 4. intent: declared API must be exported by the exact version -------------------
    if request.intent is not None and request.intent.expected_api is not None:
        api = request.intent.expected_api
        contract_result = source.contract(eco, name, version)
        if isinstance(contract_result, ContractDigestMismatch):
            results.append(mismatch_block(contract_result))
            return _verdict_block(request, ctx, version, results, snapshot_id, retry)
        surface = check_contract(contract_result, api)
        if surface.outcome is ApiSurface.UNKNOWN:
            results.append(unknown_block(surface))
            return _verdict_block(
                request, ctx, version, results, snapshot_id, retry, extra=_unknown_extra(surface)
            )
        if surface.outcome is ApiSurface.ABSENT:
            return _quarantine(
                request,
                ctx,
                version,
                surface,
                warnings,
                checks_run,
                snapshot_id,
                retry,
            )

    # ---- 5. ALLOW ------------------------------------------------------------------------
    if retry is not None:
        ctx.store.save(replace(retry, state=QState.ALLOWED, reason="retry allowed"))
    return _finish_allow(
        request,
        ctx,
        version,
        warnings,
        checks_run,
        reason="all checks passed",
        quarantine_id=retry.quarantine_id if retry else None,
    )


def _run_l1(request: InstallRequest, ctx: Context, version: str) -> list[CheckResult]:
    eco = request.ecosystem
    name = request.package
    policy = ctx.policy
    source = ctx.source

    registry = source.registry_result(eco, name)
    top = source.top_n(eco)
    signatures = [Signature(pattern, mimics) for pattern, mimics in policy.slopsquat_signatures]
    scripts = source.install_scripts(eco, name, version)
    advisories = source.advisories(eco, name, version)
    licence = source.license(eco, name)
    maintainers = source.maintainers(eco, name)

    results = [
        check_typosquat(
            registry,
            top,
            ctx.now,
            max_distance=policy.typosquat_max_distance,
            max_age_days=policy.typosquat_max_age_days,
        ),
        check_slopsquat(
            eco,
            name,
            signatures,
            top,
            max_distance=policy.slopsquat_max_distance,
        ),
        check_new_package(
            registry,
            ctx.now,
            max_age_days=policy.new_package_max_age_days,
            max_releases=policy.new_package_max_releases,
            level=Level.HARD_BLOCK,
        ),
        check_install_scripts(scripts, level=_LEVELS[policy.level_install_scripts]),
        check_cve(advisories),
        check_malware(advisories),
        check_allow_deny(eco, name, allow=policy.allow, deny=policy.deny),
        check_license(
            licence,
            allow=policy.license_allow,
            deny=policy.license_deny,
            level=_LEVELS[policy.level_license],
            undeclared_level=_LEVELS[policy.level_license_undeclared],
        ),
        check_maintainer(
            maintainers,
            min_account_age_days=policy.maintainer_min_account_age_days,
            level=_LEVELS[policy.level_maintainer],
        ),
        check_near_name(
            registry,
            top,
            max_distance=policy.levenshtein_max,
            min_jaro_winkler=policy.jaro_winkler_min,
        ),
    ]
    return list(results)


def _existence_remedy(eco: Ecosystem, name: str, source: RegistrySource) -> str | None:
    """Suggest an existing package: the longest known name that is a prefix at a separator
    boundary (csv-parser-pro -> csv-parser), otherwise the nearest name within 3 edits."""
    target = normalize_name(eco, name)
    known = [normalize_name(eco, k) for k in source.known_names(eco)]
    prefixes = [k for k in known if any(target.startswith(k + sep) for sep in _SEPARATORS)]
    if prefixes:
        return f"Did you mean {max(prefixes, key=len)}?"
    nearest = sorted(
        ((levenshtein(target, k), k) for k in known if k != target),
        key=lambda pair: (pair[0], pair[1]),
    )
    if nearest and nearest[0][0] <= _REMEDY_DISTANCE:
        return f"Did you mean {nearest[0][1]}?"
    return None


def _verdict_block(
    request: InstallRequest,
    ctx: Context,
    version: str,
    results: list[CheckResult],
    snapshot_id: str | None,
    retry: QuarantineState | None,
    extra: dict[str, Any] | None = None,
) -> Decision:
    blocking = sorted(
        (r for r in results if r.level >= Level.BLOCK),
        key=lambda r: (-int(r.level), r.check),
    )
    violation = blocking[0]
    checks_run = tuple(r.check for r in results)
    decision = Decision(
        outcome=Outcome.BLOCK,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=version,
        reason=violation.reason,
        checks_run=checks_run,
        violation=violation,
        quarantine_id=retry.quarantine_id if retry else None,
        policy_hash=ctx.policy.policy_hash,
        snapshot_id=snapshot_id,
        extra=extra or {},
    )
    if retry is not None:
        ctx.store.save(replace(retry, state=QState.BLOCKED, reason=violation.reason))
    return _bypass_or_record(request, ctx, decision)


def _bypass_or_record(request: InstallRequest, ctx: Context, decision: Decision) -> Decision:
    """Apply --allow-unsafe only to a check block, and only with a stated reason (R-1.5)."""
    if request.bypass_reason is None:
        return _record(request, ctx, decision)
    reason = request.bypass_reason.strip()
    if not reason:
        violation = CheckResult(
            "bypass", Level.HARD_BLOCK, "--allow-unsafe needs a non-empty reason"
        )
        return _record(
            request, ctx, replace(decision, violation=violation, reason=violation.reason)
        )
    return _record(
        request,
        ctx,
        replace(
            decision,
            outcome=Outcome.ALLOW,
            bypassed=True,
            reason=f"bypassed by --allow-unsafe: {reason}",
            extra={
                "bypass_reason": reason,
                "original_violation": decision.violation.reason if decision.violation else "",
            },
        ),
    )


def _quarantine(
    request: InstallRequest,
    ctx: Context,
    version: str,
    surface: Any,
    warnings: tuple[CheckResult, ...],
    checks_run: tuple[str, ...],
    snapshot_id: str | None,
    retry: QuarantineState | None,
) -> Decision:
    eco = request.ecosystem
    name = request.package
    policy = ctx.policy
    api = surface.declared_api
    alternatives = tuple(
        (alt, f"exports {api} directly") for alt in ctx.source.alternatives(eco, api, name)
    )
    intent = request.intent
    purpose = intent.purpose if intent else ""

    if retry is None:
        quarantine_id = ctx.new_id()
        budget = policy.retry_budget
        state = ctx.store.create(
            quarantine_id=quarantine_id,
            ecosystem=eco,
            package=name,
            version=version,
            declared_api=api,
            now=ctx.now,
            max_seconds=policy.max_seconds,
            retry_budget=budget,
            reason="api_absent",
        )
        if budget == 0:
            return _escalate(
                request,
                ctx,
                version,
                state,
                surface,
                alternatives,
                purpose,
                warnings,
                checks_run,
                snapshot_id,
                retry_intents=[],
            )
        payload = build_payload(
            quarantine_id=quarantine_id,
            package=name,
            intent_purpose=purpose,
            surface=surface,
            alternatives=alternatives,
            retry_budget_remaining=budget,
        )
        decision = Decision(
            outcome=Outcome.QUARANTINE,
            ecosystem=eco.value,
            package=name,
            version=version,
            reason=f"declared API '{api}' is not exported by {name}=={version}",
            checks_run=checks_run,
            warnings=warnings,
            quarantine_id=quarantine_id,
            quarantine_payload=payload,
            policy_hash=policy.policy_hash,
            snapshot_id=snapshot_id,
            extra={"mismatch_type": MISMATCH_API_ABSENT},
        )
        return _record(request, ctx, decision)

    # The retry failed the API check: escalate, write the artifact, and stop (budget 0).
    return _escalate(
        request,
        ctx,
        version,
        retry,
        surface,
        alternatives,
        purpose,
        warnings,
        checks_run,
        snapshot_id,
        retry_intents=[intent],
    )


def _escalate(
    request: InstallRequest,
    ctx: Context,
    version: str,
    state: QuarantineState,
    surface: Any,
    alternatives: tuple[tuple[str, str], ...],
    purpose: str,
    warnings: tuple[CheckResult, ...],
    checks_run: tuple[str, ...],
    snapshot_id: str | None,
    retry_intents: list[Intent | None],
) -> Decision:
    policy = ctx.policy
    escalated = replace(
        state,
        state=QState.ESCALATED,
        retry_budget_remaining=0,
        reason="escalated: retry did not clear the API check",
    )
    ctx.store.save(escalated)
    payload = build_payload(
        quarantine_id=state.quarantine_id,
        package=request.package,
        intent_purpose=purpose,
        surface=surface,
        alternatives=alternatives,
        retry_budget_remaining=0,
    )
    artifact = build_escalation_artifact(
        payload=payload,
        original_intent=(request.intent.to_json() if request.intent else {}),
        retry_intents=[i.to_json() for i in retry_intents if i is not None],
        policy_hash=policy.policy_hash,
        snapshot_id=snapshot_id,
        escalated_at=ctx.now,
    )
    _write_artifact(ctx, state.quarantine_id, artifact)
    decision = Decision(
        outcome=Outcome.QUARANTINE,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=version,
        reason=f"escalated for human review: declared API '{surface.declared_api}' is not exported",
        checks_run=checks_run,
        warnings=warnings,
        quarantine_id=state.quarantine_id,
        quarantine_payload=payload,
        policy_hash=policy.policy_hash,
        snapshot_id=snapshot_id,
        extra={"mismatch_type": MISMATCH_API_ABSENT, "escalated": True},
    )
    return _record(request, ctx, decision)


def _escalated_again(
    request: InstallRequest, ctx: Context, version: str, state: QuarantineState
) -> Decision:
    """A retry against an escalated quarantine: exit 75, budget 0, no new check (P-SM-2).

    A quarantine whose window expired while still OPEN is escalated here. Its state is saved
    and its artifact is written once, so the expiry is recorded and not only inferred.
    """
    if state.state != QState.ESCALATED:
        escalated = replace(
            state,
            state=QState.ESCALATED,
            retry_budget_remaining=0,
            reason="escalated: window expired before a retry cleared the API check",
        )
        ctx.store.save(escalated)
        state = escalated
        expired_now = True
    else:
        expired_now = False
    result = ctx.source.contract(request.ecosystem, request.package, version)
    if isinstance(result, ContractDigestMismatch):
        # R-C-9: a mismatch blocks (exit 1) and writes no escalation artifact.
        mismatch = mismatch_block(result)
        return _block(
            request, ctx, mismatch.check, mismatch.reason, quarantine_id=state.quarantine_id
        )
    if isinstance(result, ContractUnknown):
        # R-C-9: any unknown contract blocks (exit 1), including one with partial names. It never
        # becomes api_absent, and no escalation artifact is written for it. The state was saved
        # above if the window expired.
        unknown = ApiSurfaceResult(ApiSurface.UNKNOWN, state.declared_api, (), result.reason)
        violation = unknown_block(unknown)
        return _block(
            request,
            ctx,
            violation.check,
            f"{violation.reason}; {_UNKNOWN_NEXT_STEP}",
            quarantine_id=state.quarantine_id,
            unknown_reason=result.reason,
        )
    surface = check_contract(result, state.declared_api)
    alternatives = tuple(
        (alt, f"exports {state.declared_api} directly")
        for alt in ctx.source.alternatives(request.ecosystem, state.declared_api, request.package)
    )
    payload = build_payload(
        quarantine_id=state.quarantine_id,
        package=request.package,
        intent_purpose=(request.intent.purpose if request.intent else ""),
        surface=surface,
        alternatives=alternatives,
        retry_budget_remaining=0,
    )
    if expired_now:
        artifact = build_escalation_artifact(
            payload=payload,
            original_intent={},
            retry_intents=[request.intent.to_json()] if request.intent else [],
            policy_hash=ctx.policy.policy_hash,
            snapshot_id=ctx.source.snapshot_id,
            escalated_at=ctx.now,
        )
        _write_artifact(ctx, state.quarantine_id, artifact)
    decision = Decision(
        outcome=Outcome.QUARANTINE,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=version,
        reason="quarantine is escalated; a human must approve it",
        quarantine_id=state.quarantine_id,
        quarantine_payload=payload,
        policy_hash=ctx.policy.policy_hash,
        snapshot_id=ctx.source.snapshot_id,
        extra={"mismatch_type": MISMATCH_API_ABSENT, "escalated": True},
    )
    return _record(request, ctx, decision)


_UNKNOWN_NEXT_STEP = (
    "next step: choose a version whose exports can be read, or review this package by hand"
)


def _unknown_extra_reason(reason: UnknownReason | None) -> dict[str, Any]:
    """The typed reason for the audit line, present only when the contract is UNKNOWN."""
    return {} if reason is None else {"unknown_reason": reason.value}


def _unknown_extra(surface: ApiSurfaceResult) -> dict[str, Any]:
    return _unknown_extra_reason(surface.reason)


def _write_artifact(ctx: Context, quarantine_id: str, artifact: dict[str, Any]) -> None:
    ctx.store.write_artifact(quarantine_id, artifact)


def _finish_allow(
    request: InstallRequest,
    ctx: Context,
    version: str,
    warnings: tuple[CheckResult, ...],
    checks_run: tuple[str, ...],
    *,
    reason: str,
    quarantine_id: str | None,
    bypassed: bool = False,
) -> Decision:
    decision = Decision(
        outcome=Outcome.ALLOW,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=version,
        reason=reason,
        checks_run=checks_run,
        warnings=warnings,
        quarantine_id=quarantine_id,
        policy_hash=ctx.policy.policy_hash,
        snapshot_id=ctx.source.snapshot_id,
        bypassed=bypassed,
    )
    return _record(request, ctx, decision)


def _block(
    request: InstallRequest,
    ctx: Context,
    check: str,
    reason: str,
    quarantine_id: str | None = None,
    unknown_reason: UnknownReason | None = None,
) -> Decision:
    violation = CheckResult(check, Level.BLOCK, reason)
    decision = Decision(
        outcome=Outcome.BLOCK,
        ecosystem=request.ecosystem.value,
        package=request.package,
        version=request.version or "",
        reason=reason,
        violation=violation,
        quarantine_id=quarantine_id,
        policy_hash=ctx.policy.policy_hash,
        snapshot_id=ctx.source.snapshot_id,
        extra=_unknown_extra_reason(unknown_reason),
    )
    return _bypass_or_record(request, ctx, decision)


def _record(request: InstallRequest, ctx: Context, decision: Decision) -> Decision:
    """Write the audit line. The line must be written before the decision is returned."""
    fields: dict[str, Any] = {
        "ecosystem": decision.ecosystem,
        "package": decision.package,
        "version": decision.version,
        "outcome": decision.outcome.value,
        "exit_code": decision.exit_code,
        "checks_run": list(decision.checks_run),
        "warnings": [w.check for w in decision.warnings],
        "warning_details": [{"check": w.check, "reason": w.reason} for w in decision.warnings],
        "policy_hash": decision.policy_hash,
        "snapshot_id": decision.snapshot_id,
        "reason": decision.reason,
    }
    if request.intent is not None:
        fields["intent"] = request.intent.to_json()
    if decision.quarantine_id is not None:
        fields["quarantine_id"] = decision.quarantine_id
    if decision.violation is not None:
        fields["blocked_by"] = decision.violation.check
    if "unknown_reason" in decision.extra:
        fields["unknown_reason"] = decision.extra["unknown_reason"]
    if decision.bypassed:
        fields["bypass"] = {"reason": decision.extra.get("bypass_reason", "")}
    ctx.log.append("verdict", ts=ctx.now, fields=fields)
    return decision
