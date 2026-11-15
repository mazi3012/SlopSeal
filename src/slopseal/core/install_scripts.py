"""Check 2.5: install-script detection.

An install script runs code on the developer's machine during install, before any
other check could look at the package. This check reports such scripts at a configured
level (WARN or BLOCK, per policy).

Rules, by hook kind:
- npm lifecycle hooks `preinstall`, `install`, `postinstall`: always a finding.
- `setup.py`, `build.rs`, `extconf.rb`: a finding only when the body contains an execution
  primitive from the table below. Substring matching is deliberately conservative.
- Any other hook kind is a finding. An unrecognized script is treated as dangerous.

Fail closed: an unknown script inventory (for example a failed download of the
artifact) is BLOCK, never PASS.

Script bodies are untrusted package content. They are only searched, never executed.

Requirements: R-2.5, R-P-1. Layer 2. Pure.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from slopseal.core.types import CheckResult, Level

CHECK_ID = "install_script"

ALWAYS_RUN_HOOKS = frozenset({"preinstall", "install", "postinstall"})

EXECUTION_PRIMITIVES: dict[str, tuple[str, ...]] = {
    "setup.py": ("exec(", "eval(", "os.system", "subprocess", "__import__", "base64"),
    "build.rs": ("command::new", "process::command", "std::process", "base64"),
    "extconf.rb": ("system(", "exec(", "eval(", "`", "base64"),
}

_CONFIGURABLE_LEVELS = frozenset({Level.WARN, Level.BLOCK})


@dataclass(frozen=True)
class InstallScript:
    """One install-time script. `body` is untrusted package content and is only searched."""

    hook: str
    body: str


@dataclass(frozen=True)
class ScriptsUnknown:
    """The script inventory could not be read (fail closed)."""

    reason: str


ScriptInventory = tuple[InstallScript, ...] | ScriptsUnknown


def _is_finding(script: InstallScript) -> bool:
    if script.hook in ALWAYS_RUN_HOOKS:
        return True
    primitives = EXECUTION_PRIMITIVES.get(script.hook)
    if primitives is None:
        return True  # Unrecognized hook kind: treat as dangerous.
    lowered = script.body.lower()
    return any(primitive in lowered for primitive in primitives)


def check_install_scripts(
    inventory: ScriptInventory,
    *,
    level: Level = Level.BLOCK,
) -> CheckResult:
    if level not in _CONFIGURABLE_LEVELS:
        raise ValueError("install-script level must be WARN or BLOCK")

    if isinstance(inventory, ScriptsUnknown):
        return CheckResult(CHECK_ID, Level.BLOCK, f"script inventory unknown: {inventory.reason}")

    findings = _hooks_with_findings(inventory)
    if not findings:
        return CheckResult(CHECK_ID, Level.PASS, "no install-time script that needs review")

    names = ", ".join(sorted(set(findings)))
    return CheckResult(
        CHECK_ID,
        level,
        f"install-time script(s) to review: {names}",
        evidence=(("hooks", names), ("count", len(findings))),
    )


def _hooks_with_findings(inventory: Sequence[InstallScript]) -> list[str]:
    return [script.hook for script in inventory if _is_finding(script)]
