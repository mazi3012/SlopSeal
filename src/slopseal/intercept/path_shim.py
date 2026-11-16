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

import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from slopseal.audit.seal import SealKeyError
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.intercept.parse import Blocked, Passthrough, parse
from slopseal.policy.loader import PolicyError
from slopseal.runtime import ECOSYSTEMS, build_context
from slopseal.verdict import Decision, InstallRequest, Outcome, verify_install

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
    if decision.outcome is Outcome.QUARANTINE:
        _json_line(sys.stdout, decision.quarantine_payload or {})
        print(
            f"slopseal: QUARANTINE {decision.package}=={decision.version}: {decision.reason}",
            file=sys.stderr,
        )
        return
    violation = decision.violation
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


def run(argv: Sequence[str], env: Mapping[str, str]) -> int:
    if not argv or argv[0] not in TOOLS:
        print(f"usage: path_shim {{{'|'.join(TOOLS)}}} [args...]", file=sys.stderr)
        return EXIT_SETUP
    tool, args = argv[0], list(argv[1:])

    parsed = parse(tool, args)
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

    decisions = [
        verify_install(
            InstallRequest(ecosystem=ECOSYSTEMS[parsed.ecosystem], package=name, version=version),
            context,
        )
        for name, version in parsed.specs
    ]

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

    for decision in decisions:
        print(
            f"slopseal: ALLOW {decision.package}=={decision.version}: {decision.reason}",
            file=sys.stderr,
        )
        for warning in decision.warnings:
            print(f"slopseal: WARN {warning.check}: {warning.reason}", file=sys.stderr)
    return _run_real(tool, args, env)


def main(argv: Sequence[str] | None = None) -> int:
    return run(list(sys.argv[1:] if argv is None else argv), os.environ)


if __name__ == "__main__":
    sys.exit(main())
