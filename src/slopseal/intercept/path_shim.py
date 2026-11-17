"""PATH shim for pip, npm, and npx. Verifies every install before the real tool runs.

The shim wrappers in a shim directory (see shims.py) call this module as
`python -m slopseal.intercept.path_shim <tool> <args...>`. The flow:

1. Parse the command. Non-install commands run the real tool unchanged.
2. Refuse installs the parser cannot verify (see parse.py).
3. Verify each pinned package with verify_install. Every package is checked, so the audit log
   records all of them.
4. Any BLOCK exits 1. Otherwise any QUARANTINE exits 75. Only when every package is ALLOW does
   the real tool run, and it replaces this process, so its own exit code reaches the caller.

Exit codes: 0 the real tool ran, 1 BLOCK, 75 QUARANTINE, 78 setup failure. No install runs
unless the exit code is 0 or the real tool was reached after ALLOW.

Environment:
  SLOPSEAL_SHIM_DIR                     the shim directory. It is skipped when the real tool is
                                        searched on PATH.
  SLOPSEAL_REAL_PIP / SLOPSEAL_REAL_NPM explicit path to the real tool (tests and demos).

The shim is advisory. A command that calls the real binary by absolute path skips it. See
THREAT_MODEL.md (T11).

Requirements: R-1.1, R-1.3, R-1.4. Layer 5.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from slopseal.audit.seal import SealKeyError
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.intercept.parse import Blocked, Passthrough, parse
from slopseal.messages import HEADLINES, NEXT, verdict_category
from slopseal.policy.loader import PolicyError
from slopseal.quarantine.rate_limit import Layer
from slopseal.runtime import ECOSYSTEMS, build_context, offline
from slopseal.verdict import Context, Decision, InstallRequest, Outcome, verify_install

TOOLS = ("pip", "npm", "npx")
EXIT_ALLOW = 0
EXIT_BLOCK = 1
EXIT_QUARANTINE = 75
EXIT_SETUP = 78
# Text that every shim wrapper contains. Used to skip wrappers when searching for the real tool.
SHIM_MARKER = b"slopseal.intercept.path_shim"


def is_shim_script(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    return SHIM_MARKER in head


def find_real_tool(tool: str, env: Mapping[str, str]) -> str | None:
    """Return the path of the real pip or npm, or None when it cannot be found."""
    override = env.get(f"SLOPSEAL_REAL_{tool.upper()}")
    if override:
        usable = os.path.isfile(override) and os.access(override, os.X_OK)
        return override if usable else None

    shim_dir = env.get("SLOPSEAL_SHIM_DIR")
    skip = os.path.realpath(shim_dir) if shim_dir else None
    for entry in env.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        if skip is not None and os.path.realpath(entry) == skip:
            continue
        candidate = os.path.join(entry, tool)
        if (
            os.path.isfile(candidate)
            and os.access(candidate, os.X_OK)
            and not is_shim_script(candidate)
        ):
            return candidate
    return None


def _json_line(stream: TextIO, payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True), file=stream)


def _emit_decision(decision: Decision) -> None:
    """Write one decision. Fixed wording first, then JSON values (R-U-1, R-G-10).

    Stdout carries only the QUARANTINE payload, which agents parse. Everything else is stderr.
    """
    violation = decision.violation
    category = verdict_category(decision.outcome.value, violation.check if violation else None)
    if decision.outcome is Outcome.QUARANTINE:
        _json_line(sys.stdout, decision.quarantine_payload or {})
        print(HEADLINES[category], file=sys.stderr)
        print(NEXT[category], file=sys.stderr)
        _json_line(
            sys.stderr,
            {
                "outcome": "QUARANTINE",
                "package": decision.package,
                "version": decision.version,
                "reason": decision.reason,
            },
        )
        return
    print(HEADLINES[category], file=sys.stderr)
    print(NEXT[category], file=sys.stderr)
    _json_line(
        sys.stderr,
        {
            "check": violation.check if violation else "unknown",
            "package": decision.package,
            "reason": violation.reason if violation else decision.reason,
            "remedy": violation.remedy if violation else None,
        },
    )


def _exec_real(real: str, tool: str, args: Sequence[str]) -> int:
    """Replace this process with the real tool. No shell is involved, so args pass verbatim."""
    try:
        os.execv(real, [tool, *args])  # noqa: S606 - argv list, no shell
    except OSError as exc:
        print(f"slopseal: cannot run real {tool} at {real}: {exc.strerror}", file=sys.stderr)
        return EXIT_SETUP


def _run_real(tool: str, args: Sequence[str], env: Mapping[str, str]) -> int:
    real = find_real_tool(tool, env)
    if real is None:
        print(f"slopseal: cannot find the real {tool} on PATH; nothing was run", file=sys.stderr)
        return EXIT_SETUP
    return _exec_real(real, tool, args)


def _log_resolution(
    context: Context,
    tool: str,
    original: Sequence[str],
    rewritten: Sequence[str],
    pins: Sequence[tuple[str, str]],
    outcome: str,
) -> None:
    """Audit the original and rewritten command (R-1.7). Raises OSError if it cannot be written."""
    context.log.append(
        "resolution",
        ts=context.now,
        fields={
            "tool": tool,
            "original_command": " ".join([tool, *original]),
            "rewritten_command": " ".join([tool, *rewritten]),
            "resolved": [{"package": name, "version": version} for name, version in pins],
            "outcome": outcome,
        },
    )


def run(argv: Sequence[str], env: Mapping[str, str]) -> int:
    if not argv or argv[0] not in TOOLS:
        print(f"usage: path_shim {{{'|'.join(TOOLS)}}} [args...]", file=sys.stderr)
        return EXIT_SETUP
    tool, args = argv[0], list(argv[1:])
    no_resolve = env.get("SLOPSEAL_NO_RESOLVE") == "1"
    if args[:1] == ["--no-resolve"]:
        no_resolve = True
        args = args[1:]
    # Resolve-then-pin runs only in live mode. Offline, an unpinned install stays refused.
    resolve = not offline() and not no_resolve

    parsed = parse(tool, args, allow_unpinned=resolve)
    if isinstance(parsed, Passthrough):
        return _run_real(tool, args, env)
    if isinstance(parsed, Blocked):
        _json_line(
            sys.stderr,
            {"check": "shim", "package": None, "reason": parsed.reason, "remedy": None},
        )
        return EXIT_BLOCK

    try:
        context = build_context()
    except SnapshotIntegrityError as exc:
        # A snapshot that fails its checksums never produces an ALLOW (P-SN-1).
        _json_line(
            sys.stderr,
            {"check": "snapshot_integrity", "package": None, "reason": str(exc), "remedy": None},
        )
        return EXIT_BLOCK
    except (PolicyError, SealKeyError) as exc:
        print(f"slopseal: {exc}; no install was run", file=sys.stderr)
        return EXIT_SETUP

    eco = ECOSYSTEMS[parsed.ecosystem]
    rewritten = list(args)
    pins: list[tuple[str, str]] = []
    placeable = len(parsed.positions) == len(parsed.specs)
    for index, (name, version) in enumerate(parsed.specs):
        if version is not None:
            pins.append((name, version))
            continue
        if not placeable:
            # Every unpinned spec must have a known position, or the rewrite cannot be placed.
            # Refuse rather than verify a different command than the one that would run.
            _json_line(
                sys.stderr,
                {
                    "check": "shim",
                    "package": name,
                    "reason": "cannot place the resolved version in this command; refused",
                    "remedy": None,
                },
            )
            return EXIT_BLOCK
        position = parsed.positions[index]
        latest = context.source.latest_version(eco, name)
        if latest is None:
            _json_line(
                sys.stderr,
                {
                    "check": "resolve",
                    "package": name,
                    "reason": f"could not resolve the latest version of {name}; refused",
                    "remedy": None,
                },
            )
            _log_unresolved(context, tool, args, name)
            return EXIT_BLOCK
        suffix = "==" if tool == "pip" else "@"
        rewritten[position] = f"{args[position]}{suffix}{latest}"
        pins.append((name, latest))

    decisions = [
        verify_install(
            InstallRequest(ecosystem=eco, package=name, version=version, layer=Layer.SHIM),
            context,
        )
        for name, version in pins
    ]
    if rewritten != args:
        outcome = _outcome(decisions)
        try:
            _log_resolution(context, tool, args, rewritten, pins, outcome)
        except OSError as exc:
            # An install that cannot be audited does not run (fail closed).
            print(f"slopseal: cannot write the audit log: {exc.strerror}", file=sys.stderr)
            return EXIT_SETUP

    blocked = [d for d in decisions if d.outcome is Outcome.BLOCK]
    if blocked:
        for decision in blocked:
            _emit_decision(decision)
        return EXIT_BLOCK
    held = [d for d in decisions if d.outcome is Outcome.QUARANTINE]
    if held:
        for decision in held:
            _emit_decision(decision)
        return EXIT_QUARANTINE

    print(HEADLINES["allow"], file=sys.stderr)
    for decision in decisions:
        _json_line(
            sys.stderr,
            {
                "outcome": "ALLOW",
                "package": decision.package,
                "version": decision.version,
                "reason": decision.reason,
                "warnings": [
                    {"check": warning.check, "reason": warning.reason}
                    for warning in decision.warnings
                ],
            },
        )
    return _run_real(tool, rewritten, env)


def _outcome(decisions: Sequence[Decision]) -> str:
    if any(d.outcome is Outcome.BLOCK for d in decisions):
        return "BLOCK"
    if any(d.outcome is Outcome.QUARANTINE for d in decisions):
        return "QUARANTINE"
    return "ALLOW"


def _log_unresolved(context: Context, tool: str, args: Sequence[str], name: str) -> None:
    # The block is already decided, and the install does not run, even if this write fails.
    with contextlib.suppress(OSError):
        _log_resolution(context, tool, args, args, [(name, "unresolved")], "BLOCK")


def main(argv: Sequence[str] | None = None) -> int:
    return run(list(sys.argv[1:] if argv is None else argv), os.environ)


if __name__ == "__main__":
    sys.exit(main())
