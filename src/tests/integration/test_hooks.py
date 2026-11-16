# ruff: noqa: S603 - every argv here is built by the test, not from untrusted input.
"""Tests for the Kiro hook files and the install hook script (T11, R-1.1).

The hook runs as a subprocess with the payload on stdin, as Kiro runs it. The hook files are
checked against the documented Kiro schema keys, and each command path must resolve from the
repository root, where Kiro runs command hooks.
"""

from __future__ import annotations

import json
import re
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


def _kiro_payload(
    command: object,
    *,
    description: str = "Run a shell command",
    tool_cwd: str | None = None,
    session_cwd: str = "/home/dev/project",
) -> str:
    """Build the stdin payload Kiro sends for an execute_bash tool call."""
    payload = {
        "session_id": "sess_0123",
        "hook_event_name": "PreToolUse",
        "cwd": session_cwd,
        "tool_name": "execute_bash",
        "tool_input": {
            "command": command,
            "description": description,
            "cwd": tool_cwd,
            "run_in_background": False,
            "timeout": None,
        },
    }
    return json.dumps(payload)


def _run_hook(stdin: str | bytes) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT.relative_to(REPO))],
        input=stdin,
        capture_output=True,
        text=isinstance(stdin, str),
        cwd=REPO,
        check=False,
    )


BLOCKED_COMMANDS = [
    # pip, pip3, python -m pip, and path-qualified forms
    "pip install requests==2.32.3",
    "pip3 install requests",
    "pip3.12 install x",
    "/home/dev/.venv/bin/pip install x",
    "python3 -m pip install requests",
    "python3.12 -m pip install x",
    "python -m pip download x",
    "python3 -m pip wheel x",
    "pip download x",
    "pip wheel x",
    # pipx, uv, uvx
    "pipx install black",
    "pipx run black",
    "pipx inject venv x",
    "uv add requests",
    "uv sync",
    "uv lock",
    "uv pip install requests",
    "uv run --with requests python x.py",
    "uv tool install ruff",
    "uv tool run ruff",
    "uvx ruff check",
    # other Python package managers
    "poetry add requests",
    "pdm add requests",
    "conda install numpy",
    "mamba install numpy",
    "micromamba install x",
    "easy_install requests",
    # npm family, npx, and other ecosystems
    "npm install react-codeshift@1.0.0",
    "npm i left-pad",
    "npx evil",
    "npm exec evil",
    "npm x evil",
    "npm ci",
    "yarn add left-pad",
    "pnpm add x",
    "pnpm dlx x",
    "cargo install ripgrep",
    "gem install rails",
    "go get x",
    "go install x@latest",
    # wrappers before the install
    "sudo pip install x",
    "sudo -E pip install x",
    "sudo -u root pip install x",
    "env pip install x",
    "env -i PATH=/usr/bin pip install x",
    "env FOO=1 pip install x",
    "FOO=bar pip install x",
    "FOO=1 BAR=2 npm install x",
    "nohup pip install x",
    "/usr/bin/env pip install x",
    "xargs pip install",
    "cat reqs.txt | xargs -I{} pip install {}",
    "uv run --python 3.12 pip install x",
    "uv --python 3.12 add x",
    "poetry run pip install x",
    "npm --prefix ./app install x",
    # shell strings and chains
    'bash -c "pip install x"',
    "sh -c 'npm install x'",
    'bash -lc "pip install x"',
    'sudo sh -c "pip install x"',
    'bash -c "sudo env FOO=1 pip install x && ls"',
    "ls && pip install x",
    "echo hi | pip install x",
    "true || npm i x",
    "cd app && pip install x",
    "false & pip install x",
    "ls; pip install x",
    "ls\npip install x",
    "echo $(pip install x)",
    "echo `pip install x`",
    "cat <(pip install x)",
    "echo x 2>&1 | pip install x",
    "env -S 'pip install x'",
    "sudo -- pip install x",
    "pi''p install x",
    "PIP install x",
    # unparseable command: the shell may still run part of it
    "echo 'unclosed",
]


BLOCK_MESSAGE = (
    "BLOCKED by SlopSeal: Direct installs are disabled. You must use the slopseal MCP tool "
    "to verify the package first.\n"
)


@pytest.mark.parametrize("command", BLOCKED_COMMANDS)
def test_install_commands_are_blocked_with_exit_2(command: str) -> None:
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 2, command
    assert result.stderr == BLOCK_MESSAGE


@pytest.mark.parametrize(
    "command",
    ["npm install game-engine-pro-ultra", "pip install requests"],
)
def test_direct_install_exits_2_and_names_the_mcp_tool(command: str) -> None:
    # R-1.8: agents must verify a package through the slopseal MCP tool, not a direct install.
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 2
    assert "slopseal MCP tool" in result.stderr


ALLOWED_COMMANDS = [
    "echo hello",
    "ls",
    "ls -la",
    "git status",
    "npm run build",
    "npm test",
    "pytest -q",
    "python3 -m pytest",
    "uv run pytest -k add",
    "uv run python -c 'print(1)'",
    "pip --version",
    "echo pip install x",
    'git commit -m "use pip install"',
    "grep -r 'pip install' docs",
    "ls # pip install x",
    "cat requirements.txt",
    "npm run install-hooks",
    "cd app && npm run build",
]


@pytest.mark.parametrize("command", ALLOWED_COMMANDS)
def test_non_install_commands_pass(command: str) -> None:
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_description_is_not_scanned() -> None:
    result = _run_hook(_kiro_payload("ls", description="pip install requests"))
    assert result.returncode == 0


def test_cwd_fields_are_not_scanned() -> None:
    result = _run_hook(
        _kiro_payload("ls", tool_cwd="/work/pip install x", session_cwd="/work/npm install x")
    )
    assert result.returncode == 0


def test_payload_without_command_scans_every_string() -> None:
    # Fallback: when tool_input.command is missing, a install in any string blocks the call.
    payload = {"tool_input": {"description": "pip install x"}}
    assert _run_hook(json.dumps(payload)).returncode == 2


def test_non_string_command_scans_every_string() -> None:
    result = _run_hook(_kiro_payload(["pip", "install", "x"], description="pip install x"))
    assert result.returncode == 2


@pytest.mark.parametrize(
    "stdin",
    [
        "this is not json",
        "",
        "[]",
        '{"tool_input": {"command": 5}}',
        '{"tool_input": {}}',
    ],
)
def test_unreadable_or_empty_payload_blocks(stdin: str) -> None:
    result = _run_hook(stdin)
    assert result.returncode == 2
    assert result.stderr == BLOCK_MESSAGE


def test_payload_that_is_not_utf8_blocks() -> None:
    result = _run_hook(b'{"tool_input": {"command": "ls \xff"}}')
    assert result.returncode == 2


def test_stalled_stdin_blocks_within_the_timeout() -> None:
    # The writer never closes stdin. The hook must give up and block, not hang.
    process = subprocess.Popen(
        [sys.executable, str(HOOK_SCRIPT.relative_to(REPO))],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO,
    )
    try:
        returncode = process.wait(timeout=10)
        stderr = process.stderr.read() if process.stderr else ""
    finally:
        if process.stdin:
            process.stdin.close()
        process.kill()
    assert returncode == 2
    assert stderr == BLOCK_MESSAGE


def _matcher(filename: str) -> str:
    hook = _load(HOOKS_DIR / filename)["hooks"][0]  # type: ignore[index]
    return str(hook["matcher"])


INSTALL_HOOK_FILE = "block-agent-installs.json"


def test_install_hook_matcher_is_execute_bash() -> None:
    assert _matcher(INSTALL_HOOK_FILE) == "execute_bash"


@pytest.mark.parametrize("tool_id", ["execute_bash"])
def test_install_hook_matcher_selects_the_shell_tool(tool_id: str) -> None:
    # The matcher is matched against the whole tool ID, so it must match exactly.
    assert re.fullmatch(_matcher(INSTALL_HOOK_FILE), tool_id)


@pytest.mark.parametrize(
    "tool_id", ["read_file", "fs_write", "mcp_git_status", "execute_bash_x", "execute_pwsh"]
)
def test_install_hook_matcher_does_not_select_other_tools(tool_id: str) -> None:
    assert not re.fullmatch(_matcher(INSTALL_HOOK_FILE), tool_id)


def test_policy_hook_matcher_selects_only_the_trust_policy() -> None:
    # PostFileSave matchers are a regex against the saved file path.
    matcher = _matcher("on-steering-change.json")
    assert re.search(matcher, ".kiro/steering/dependency-trust.md")
    assert not re.search(matcher, ".kiro/steering/dependency-trust.md.bak")
    assert not re.search(matcher, ".kiro/steering/product.md")
