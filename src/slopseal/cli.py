"""Command-line entry point.

Subcommands:
  check <package>          verify an install (verify_install). Exit 0, 1, 75, or 78.
  escalate <id>            approve an escalated quarantine (human step).
  abandon <id>             close an open or escalated quarantine without installing.
  audit verify             check the audit log chain and seals. Exit 0, 1, or 78.
  policy check [PATH]      validate the trust policy and its floors. Exit 0, 1, or 78.

Output contract (design section 13):
  stdout  QUARANTINE payload JSON only (agents parse it)
  stderr  one summary line; BLOCK writes a DependencyViolation JSON object
  78      policy, key, or state directory is unusable. No verdict is issued.

Environment (see .env.example):
  SLOPSEAL_OFFLINE_SNAPSHOT=1  use the signed offline snapshot and pin the clock to its as_of
  SLOPSEAL_SNAPSHOT_DIR        snapshot directory (default: src/slopseal/fixtures)
  SLOPSEAL_STATE_DIR           state directory (default: .slopseal)
  SLOPSEAL_POLICY_PATH         trust policy (default: .kiro/steering/dependency-trust.md)

Requirements: R-1.1, R-1.3, R-1.5, R-1.4, R-4.1, R-4.4, R-5.7.1a. Layer 5.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import SealKeyError, load_or_create_key
from slopseal.core.types import CheckResult, Ecosystem, Level
from slopseal.fixtures.loader import SnapshotIntegrityError, load_snapshot
from slopseal.policy.invariants import enforce_floors
from slopseal.policy.loader import Policy, PolicyError, load_policy
from slopseal.quarantine.state_machine import (
    QState,
    QuarantineStore,
    effective_state,
    new_quarantine_id,
)
from slopseal.registry.source import LiveSource, OfflineSource, RegistrySource
from slopseal.verdict import Context, Decision, InstallRequest, Intent, Outcome, verify_install

EXIT_ALLOW = 0
EXIT_BLOCK = 1
EXIT_QUARANTINE = 75
EXIT_POLICY = 78

DEFAULT_STATE_DIR = ".slopseal"
DEFAULT_POLICY = ".kiro/steering/dependency-trust.md"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
ECOSYSTEMS = {eco.value: eco for eco in Ecosystem}


class CliError(Exception):
    """A usage or environment problem that stops the command with exit 78 or 1."""

    def __init__(self, message: str, code: int = EXIT_POLICY) -> None:
        super().__init__(message)
        self.code = code


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def _build_source(state_dir: Path) -> tuple[RegistrySource, datetime]:
    if _env_flag("SLOPSEAL_OFFLINE_SNAPSHOT"):
        directory = Path(os.environ.get("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES)))
        snapshot = load_snapshot(directory)  # SnapshotIntegrityError is handled by the caller
        return OfflineSource(snapshot), snapshot.as_of
    return LiveSource(), datetime.now(UTC)


def _state_dir() -> Path:
    return Path(os.environ.get("SLOPSEAL_STATE_DIR", DEFAULT_STATE_DIR))


def _policy_path() -> Path:
    return Path(os.environ.get("SLOPSEAL_POLICY_PATH", DEFAULT_POLICY))


def _context(source: RegistrySource, now: datetime, state_dir: Path) -> Context:
    policy: Policy = _load_policy_or_exit()
    try:
        key = load_or_create_key(state_dir)
    except SealKeyError as exc:
        raise CliError(f"slopseal: {exc}; no verdict was issued") from exc
    return Context(
        policy=policy,
        source=source,
        store=QuarantineStore(state_dir),
        log=AuditLog(state_dir / "audit.jsonl", key),
        now=now,
        new_id=lambda: new_quarantine_id(os.urandom(13)),
    )


def _load_policy_or_exit() -> Policy:
    try:
        return load_policy(str(_policy_path()))
    except PolicyError as exc:
        raise CliError(f"slopseal: policy error: {exc}") from exc


def _violation_json(violation: CheckResult, package: str) -> dict[str, Any]:
    return {
        "check": violation.check,
        "package": package,
        "reason": violation.reason,
        "remedy": violation.remedy,
    }


def _emit_decision(decision: Decision) -> int:
    if decision.outcome is Outcome.QUARANTINE:
        print(json.dumps(decision.quarantine_payload, sort_keys=True))
        print(
            f"slopseal: QUARANTINE {decision.package}=={decision.version}: {decision.reason}",
            file=sys.stderr,
        )
    elif decision.outcome is Outcome.BLOCK:
        violation = decision.violation or CheckResult("unknown", Level.BLOCK, decision.reason)
        print(
            json.dumps(_violation_json(violation, decision.package), sort_keys=True),
            file=sys.stderr,
        )
    else:
        print(
            f"slopseal: ALLOW {decision.package}=={decision.version}: {decision.reason}",
            file=sys.stderr,
        )
        for warning in decision.warnings:
            print(f"slopseal: WARN {warning.check}: {warning.reason}", file=sys.stderr)
    return decision.exit_code


def cmd_check(args: argparse.Namespace) -> int:
    state_dir = _state_dir()
    source, now = _build_source(state_dir)
    context = _context(source, now, state_dir)

    if args.allow_unsafe and not (args.bypass_reason or "").strip():
        print(
            json.dumps(
                {
                    "check": "bypass",
                    "package": args.package,
                    "reason": "--allow-unsafe needs a non-empty --reason",
                    "remedy": None,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return EXIT_BLOCK

    intent = None
    if args.purpose or args.expected_api:
        intent = Intent(purpose=args.purpose or "", expected_api=args.expected_api)
    request = InstallRequest(
        ecosystem=ECOSYSTEMS[args.ecosystem],
        package=args.package,
        version=args.version,
        intent=intent,
        quarantine_id=args.quarantine_id,
        bypass_reason=args.bypass_reason if args.allow_unsafe else None,
    )
    decision = verify_install(request, context)
    return _emit_decision(decision)


def _store(state_dir: Path) -> QuarantineStore:
    return QuarantineStore(state_dir)


def cmd_escalate(args: argparse.Namespace) -> int:
    state_dir = _state_dir()
    store = _store(state_dir)
    state = store.load(args.quarantine_id)
    if state is None:
        raise CliError(f"no quarantine {args.quarantine_id}", EXIT_BLOCK)
    status = effective_state(state, _now())
    if status != QState.ESCALATED:
        raise CliError(
            f"quarantine is {status}; only an escalated quarantine can be approved", EXIT_BLOCK
        )
    reason = args.reason.strip() if args.reason else ""
    if not args.approve or not reason:
        raise CliError("approval needs --approve and a non-empty --reason", EXIT_BLOCK)

    store.save(
        replace(
            state, state=QState.APPROVED, retry_budget_remaining=0, reason=f"approved: {reason}"
        )
    )
    _mark_artifact(store, args.quarantine_id, "approved", reason)
    key = load_or_create_key(state_dir)
    AuditLog(state_dir / "audit.jsonl", key).append(
        "approval",
        ts=_now(),
        fields={
            "package": state.package,
            "version": state.version,
            "ecosystem": state.ecosystem,
            "quarantine_id": state.quarantine_id,
            "reason": reason,
            "outcome": "APPROVED",
            "checks_run": [],
        },
    )
    print(
        f"slopseal: approved {state.quarantine_id} ({state.package}=={state.version})",
        file=sys.stderr,
    )
    return EXIT_ALLOW


def cmd_abandon(args: argparse.Namespace) -> int:
    state_dir = _state_dir()
    store = _store(state_dir)
    state = store.load(args.quarantine_id)
    if state is None:
        raise CliError(f"no quarantine {args.quarantine_id}", EXIT_BLOCK)
    status = effective_state(state, _now())
    if status not in (QState.OPEN, QState.ESCALATED):
        raise CliError(f"quarantine is {status}; nothing to abandon", EXIT_BLOCK)
    reason = (args.reason or "agent proceeded with an alternative").strip()
    store.save(replace(state, state=QState.ABANDONED, reason=f"abandoned: {reason}"))
    key = load_or_create_key(state_dir)
    AuditLog(state_dir / "audit.jsonl", key).append(
        "abandon",
        ts=_now(),
        fields={
            "package": state.package,
            "version": state.version,
            "ecosystem": state.ecosystem,
            "quarantine_id": state.quarantine_id,
            "original_intent_api": state.declared_api,
            "reason": reason,
            "outcome": "ABANDONED",
            "checks_run": [],
        },
    )
    print(
        f"slopseal: abandoned {state.quarantine_id}; the original install was not allowed",
        file=sys.stderr,
    )
    return EXIT_ALLOW


def _mark_artifact(store: QuarantineStore, quarantine_id: str, status: str, reason: str) -> None:
    artifact = store.artifact(quarantine_id)
    if artifact is None:
        return
    artifact["status"] = status
    artifact["resolution"] = reason
    store.write_artifact(quarantine_id, artifact)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    state_dir = _state_dir()
    log_path = Path(args.log) if args.log else state_dir / "audit.jsonl"
    key_path = state_dir / "secret.key"
    if not log_path.exists():
        print(f"slopseal: audit log not found: {log_path}; cannot verify", file=sys.stderr)
        return EXIT_POLICY
    if not key_path.exists():
        print("slopseal: seal key not found; cannot verify seals", file=sys.stderr)
        return EXIT_POLICY
    try:
        key = key_path.read_bytes()
    except OSError as exc:
        print(f"slopseal: cannot read seal key: {exc.strerror}", file=sys.stderr)
        return EXIT_POLICY
    report = AuditLog(log_path, key).verify()
    print(f"slopseal: audit {report.describe()}", file=sys.stderr)
    return EXIT_ALLOW if report.ok else EXIT_BLOCK


def cmd_policy_check(args: argparse.Namespace) -> int:
    path = args.path or str(_policy_path())
    try:
        policy = load_policy(path)
    except PolicyError as exc:
        print(f"slopseal: policy error: {exc}", file=sys.stderr)
        return EXIT_POLICY
    violations = enforce_floors(policy)
    for violation in violations:
        print(f"slopseal: floor violated: {violation}", file=sys.stderr)
    if violations:
        return EXIT_BLOCK
    print(f"slopseal: policy ok (hash {policy.policy_hash[:12]})", file=sys.stderr)
    return EXIT_ALLOW


def _now() -> datetime:
    """Offline mode pins the clock to the snapshot's as_of, so runs are reproducible.
    Live mode uses the system clock."""
    if _env_flag("SLOPSEAL_OFFLINE_SNAPSHOT"):
        snapshot_dir = Path(os.environ.get("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES)))
        return load_snapshot(snapshot_dir).as_of
    return datetime.now(UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slopseal",
        description="Dependency trust firewall: every install gets a seal.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="verify an install")
    check.add_argument("package")
    check.add_argument("--ecosystem", choices=sorted(ECOSYSTEMS), default="pypi")
    check.add_argument("--version", default=None)
    check.add_argument(
        "--expected-api", default=None, help="API the agent expects, e.g. csv.reader"
    )
    check.add_argument("--purpose", default=None, help="what the agent needs the package for")
    check.add_argument("--quarantine-id", default=None, help="retry an open quarantine")
    check.add_argument("--allow-unsafe", action="store_true", help="override a block (audited)")
    check.add_argument(
        "--reason", dest="bypass_reason", default=None, help="required with --allow-unsafe"
    )
    check.set_defaults(handler=cmd_check)

    escalate = sub.add_parser("escalate", help="approve an escalated quarantine")
    escalate.add_argument("quarantine_id")
    escalate.add_argument("--approve", action="store_true")
    escalate.add_argument("--reason", default=None)
    escalate.set_defaults(handler=cmd_escalate)

    abandon = sub.add_parser("abandon", help="close a quarantine without installing")
    abandon.add_argument("quarantine_id")
    abandon.add_argument("--reason", default=None)
    abandon.set_defaults(handler=cmd_abandon)

    audit = sub.add_parser("audit", help="audit log commands")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="verify the hash chain and seals")
    verify.add_argument("--log", default=None)
    verify.set_defaults(handler=cmd_audit_verify)

    policy = sub.add_parser("policy", help="trust policy commands")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_check = policy_sub.add_parser("check", help="validate the policy and its floors")
    policy_check.add_argument("path", nargs="?", default=None)
    policy_check.set_defaults(handler=cmd_policy_check)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args))
    except CliError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except SnapshotIntegrityError as exc:
        # A snapshot that fails its checksums never produces an ALLOW (P-SN-1).
        violation = {
            "check": "snapshot_integrity",
            "package": getattr(args, "package", ""),
            "reason": f"snapshot failed integrity check: {exc}",
            "remedy": None,
        }
        print(json.dumps(violation, sort_keys=True), file=sys.stderr)
        return EXIT_BLOCK


if __name__ == "__main__":
    sys.exit(main())
