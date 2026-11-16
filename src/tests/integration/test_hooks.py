# ruff: noqa: S603 - every argv here is built by the test, not from untrusted input.
"""Tests for the Kiro hook files and the install hook script (T11, R-1.1).

The hook runs as a subprocess with the payload on stdin, as Kiro runs it. The hook files are
checked against the documented Kiro schema keys, and each command path must resolve from the
repository root, where Kiro runs command hooks.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
HOOKS_DIR = REPO / ".kiro" / "hooks"
HOOK_SCRIPT = REPO / "scripts" / "hooks" / "on_install.py"

# Keys documented for a hook file (kiro.dev hooks reference, schema version v1).
ALLOWED_TOP_KEYS = {"version", "hooks"}
ALLOWED_HOOK_KEYS = {
    "name",
    "description",
    "trigger",
    "matcher",
    "action",
    "timeout",
    "enabled",
    "confirm",
}
ALLOWED_TRIGGERS = {
    "UserPromptSubmit",
    "Stop",
    "SessionStart",
    "PreToolUse",
    "PostToolUse",
    "PostFileCreate",
    "PostFileSave",
    "PostFileDelete",
    "PreTaskExec",
    "PostTaskExec",
    "Manual",
}


def _load(path: Path) -> dict[str, object]:
    data: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return data


@pytest.mark.parametrize("path", sorted(HOOKS_DIR.glob("*.json")), ids=lambda p: p.name)
def test_hook_file_uses_only_documented_keys_and_triggers(path: Path) -> None:
    data = _load(path)
    assert set(data) <= ALLOWED_TOP_KEYS
    assert data["version"] == "v1"
    hooks = data["hooks"]
    assert isinstance(hooks, list)
    assert hooks
    for hook in hooks:
        assert isinstance(hook, dict)
        assert set(hook) <= ALLOWED_HOOK_KEYS, set(hook) - ALLOWED_HOOK_KEYS
        assert hook["trigger"] in ALLOWED_TRIGGERS
        assert hook["action"]["type"] == "command"  # type: ignore[index]


@pytest.mark.parametrize("path", sorted(HOOKS_DIR.glob("*.json")), ids=lambda p: p.name)
def test_hook_command_paths_resolve_from_the_repository_root(path: Path) -> None:
    for hook in _load(path)["hooks"]:  # type: ignore[index, union-attr]
        argv = shlex.split(hook["action"]["command"])
        script_args = [arg for arg in argv if arg.endswith((".py", ".sh"))]
        assert script_args, argv
        for arg in script_args:
            assert (REPO / arg).is_file(), f"{arg} does not exist relative to the repo root"


def _run_hook(stdin: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT.relative_to(REPO))],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )


@pytest.mark.parametrize(
    "command",
    [
        "pip install requests==2.32.3",
        "python3 -m pip install requests",
        "npm install react-codeshift@1.0.0",
        "npm i left-pad",
        "npx evil",
        "npm exec evil",
        "npm x evil",
        "yarn add left-pad",
    ],
)
def test_install_commands_are_blocked_with_exit_2(command: str) -> None:
    payload = json.dumps({"tool_name": "execute_bash", "tool_input": {"command": command}})
    result = _run_hook(payload)
    assert result.returncode == 2
    assert "slopseal:" in result.stderr


@pytest.mark.parametrize("command", ["ls -la", "npm run build", "pytest -q", "git status"])
def test_non_install_commands_pass(command: str) -> None:
    payload = json.dumps({"tool_name": "execute_bash", "tool_input": {"command": command}})
    assert _run_hook(payload).returncode == 0


def test_unreadable_payload_blocks() -> None:
    result = _run_hook("this is not json")
    assert result.returncode == 2
