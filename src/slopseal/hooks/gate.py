"""Verdict gate for the install hook: from detected installs to an exit code (R-G-1..R-G-5).

`decide` takes the installs that `on_install` found and returns the hook's exit code and the
text for stderr. The rules, in order:

- An install the hook cannot map to registry packages at exact versions is a problem
  (R-G-5). The hook cannot resolve a version or rewrite the command, so it refuses.
- Each distinct pinned package goes to `verify_install` once, with no intent (R-G-1). The
  rate limit counts each call (R-4.7).
- The exit code is 0 only when there is no problem and every decision is ALLOW (R-G-2).
  Anything else is 2. An outcome that is not ALLOW is never read as ALLOW, so an outcome
  added later still blocks (R-G-8).
- A setup error (policy, seal key, snapshot, or state directory) is a problem. Nothing is
  verified, so nothing is allowed (R-G-6).

Output is one fixed line, then one JSON object per problem with sorted keys. A reason can
come from package metadata, so it is a JSON string value with a length cap, never prose
(R-G-10). Stdout is not used (R-G-8).

Requirements: R-G-1..R-G-6, R-G-8, R-G-10. Property: P-G-1. Layer 5.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence

from slopseal.audit.seal import SealKeyError
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.hooks.on_install import BLOCK_EXIT, Detected, Evaluation
from slopseal.intercept.parse import Blocked, Install, parse
from slopseal.policy.loader import PolicyError
from slopseal.quarantine.rate_limit import Layer
from slopseal.runtime import ECOSYSTEMS, build_context
from slopseal.verdict import Context, Decision, InstallRequest, Outcome, verify_install

ALLOW_EXIT = 0
MAX_TEXT = 300
HEADER = (
    "BLOCKED by SlopSeal: this install is not allowed. Fix the problem below, "
    "or verify the package with the slopseal MCP tool first."
)

# Errors that building the context is known to raise. Each is a setup failure, so exit 2.
# `verify_install` never raises. Any other error ends the worker thread in `on_install`,
# which is also exit 2 (tech.md allows a bare `except Exception` only in verdict.py).
_SETUP_ERRORS = (PolicyError, SealKeyError, SnapshotIntegrityError, OSError)

# Tools whose installs `intercept.parse` can turn into exact registry packages.
_PARSEABLE = frozenset({"pip", "npm", "npx"})

_FIX_PIP = "Pin every package exactly, for example `pip install name==1.2.3`."
_FIX_NODE = "Pin every package exactly, for example `npm install name@1.2.3`."
_FIX_PLAIN = (
    "Run the install as a plain pip or npm command with exact versions, with no "
    "environment assignments, xargs, or shell expansion before it."
)
_FIX_OTHER = (
    "SlopSeal verifies pip and npm installs only. Use pip or npm with an exact version, "
    "or ask the user to run this install."
)
_FIX_BLOCKED = (
    "Do not install this package. Choose a different package, or ask the user to review it."
)
_FIX_SETUP = "Fix the SlopSeal setup problem named in the reason, then run the command again."

Verify = Callable[[InstallRequest, Context], Decision]
Build = Callable[[], Context]
Problem = dict[str, str]


def _cap(text: str) -> str:
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 3] + "..."


def _problem(check: str, reason: str, fix: str) -> Problem:
    return {"check": check, "reason": _cap(reason), "fix": _cap(fix)}


def _fix_for(tool: str) -> str:
    if tool == "pip":
        return _FIX_PIP
    if tool in {"npm", "npx"}:
        return _FIX_NODE
    return _FIX_PLAIN


def _classify(
    item: Detected, problems: list[Problem], packages: dict[tuple[str, str, str], None]
) -> None:
    """Turn one detected install into packages to verify, or into a problem."""
    if item.unverifiable is not None:
        problems.append(_problem("unverifiable_install", item.unverifiable, _FIX_PLAIN))
        return
    if item.tool not in _PARSEABLE:
        reason = f"{item.tool} installs are not verified by the hook"
        problems.append(_problem("unverifiable_install", reason, _FIX_OTHER))
        return
    parsed = parse(item.tool, list(item.args))
    if isinstance(parsed, Install):
        for name, version in parsed.specs:
            if version is None:
                problems.append(
                    _problem("unverifiable_install", f"{name} is not pinned", _fix_for(item.tool))
                )
            else:
                packages[(parsed.ecosystem, name, version)] = None
    elif isinstance(parsed, Blocked):
        problems.append(_problem("unverifiable_install", parsed.reason, _fix_for(item.tool)))
    else:
        reason = f"this {item.tool} command names no package that the hook can verify"
        problems.append(_problem("unverifiable_install", reason, _fix_for(item.tool)))


def _setup_problem(exc: Exception) -> Problem:
    if isinstance(exc, PolicyError):
        return _problem("policy_error", str(exc), _FIX_SETUP)
    if isinstance(exc, SnapshotIntegrityError):
        return _problem("snapshot_integrity", str(exc), _FIX_SETUP)
    if isinstance(exc, SealKeyError):
        return _problem("seal_key", str(exc), _FIX_SETUP)
    detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else type(exc).__name__
    return _problem(
        "state_directory", f"cannot use the SlopSeal state directory: {detail}", _FIX_SETUP
    )


def _decision_problem(decision: Decision) -> Problem | None:
    """None for ALLOW. Anything else is a problem, so an unknown outcome still blocks."""
    if decision.outcome is Outcome.ALLOW:
        return None
    base = {"package": decision.package, "version": decision.version}
    if decision.outcome is Outcome.QUARANTINE:
        payload = decision.quarantine_payload or {}
        quarantine_id = str(payload.get("quarantine_id") or decision.quarantine_id or "")
        mismatch = str(payload.get("mismatch_type") or "quarantine")
        step = (
            f"Verify again with the slopseal MCP tool using quarantine_id {quarantine_id} and "
            "a refined intent. If that fails, a person must approve it with `slopseal escalate`."
        )
        return {
            **base,
            "check": _cap(mismatch),
            "quarantine_id": _cap(quarantine_id),
            "reason": _cap(decision.reason),
            "next_step": _cap(step),
        }
    violation = decision.violation
    check = violation.check if violation is not None else "unknown"
    reason = violation.reason if violation is not None else decision.reason
    remedy = violation.remedy if violation is not None and violation.remedy else _FIX_BLOCKED
    return {**base, "check": _cap(check), "reason": _cap(reason), "fix": _cap(remedy)}


def _allow_lines(decisions: Sequence[Decision]) -> str:
    lines: list[str] = []
    for decision in decisions:
        lines.append(
            _cap(f"slopseal: ALLOW {decision.package}=={decision.version}: {decision.reason}")
        )
        lines.extend(
            _cap(f"slopseal: WARN {warning.check}: {warning.reason}")
            for warning in decision.warnings
        )
    return "".join(f"{line}\n" for line in lines)


def decide(
    found: Sequence[Detected],
    *,
    build: Build = build_context,
    verify: Verify = verify_install,
) -> Evaluation:
    """Return the hook's exit code and stderr text for the installs in one command."""
    problems: list[Problem] = []
    packages: dict[tuple[str, str, str], None] = {}
    for item in found:
        _classify(item, problems, packages)

    decisions: list[Decision] = []
    if packages:
        try:
            context = build()
        except _SETUP_ERRORS as exc:
            problems.append(_setup_problem(exc))
        else:
            for ecosystem, name, version in packages:
                request = InstallRequest(ECOSYSTEMS[ecosystem], name, version, layer=Layer.HOOK)
                decisions.append(verify(request, context))

    for decision in decisions:
        problem = _decision_problem(decision)
        if problem is not None:
            problems.append(problem)

    approved = (
        bool(found)
        and not problems
        and len(decisions) == len(packages) > 0
        and all(decision.outcome is Outcome.ALLOW for decision in decisions)
    )
    if approved:
        return Evaluation(ALLOW_EXIT, _allow_lines(decisions))
    if not problems:
        # Nothing was found to verify, so there is nothing to allow.
        problems.append(
            _problem("unverifiable_install", "no package could be verified", _FIX_PLAIN)
        )
    body = "".join(f"{json.dumps(problem, sort_keys=True)}\n" for problem in problems)
    return Evaluation(BLOCK_EXIT, f"{HEADER}\n{body}")
