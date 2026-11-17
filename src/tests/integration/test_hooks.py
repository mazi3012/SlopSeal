# ruff: noqa: S602, S603 - every argv and shell string here is built by the test (the shipped
# hook command from the repo, or a fixed stub), not from untrusted input.
"""Tests for the Kiro hook files and the install hook script (T11, R-1.1, R-G-1..R-G-9).

The hook runs as a subprocess with the payload on stdin, as Kiro runs it. Installs go through the
verdict pipeline against the offline snapshot, with a state directory private to each test. The
hook files are checked against the documented Kiro schema keys, and each command path must
resolve from the repository root, where Kiro runs command hooks.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
HOOKS_DIR = REPO / ".kiro" / "hooks"
HOOK_MODULE = "slopseal.hooks.on_install"

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


@pytest.fixture(autouse=True)
def _private_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test gets its own state directory (audit log, rate limit) and the offline snapshot."""
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.delenv("SLOPSEAL_POLICY_PATH", raising=False)
    monkeypatch.delenv("SLOPSEAL_SNAPSHOT_DIR", raising=False)


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
        command = hook["action"]["command"]
        modules = re.findall(r"-m ([A-Za-z_][\w.]*)", command)
        if modules:
            # The install hook runs a module inside a sh -c wrapper, so check the command text.
            for module in modules:
                assert importlib.util.find_spec(module) is not None, f"{module} not importable"
            continue
        argv = shlex.split(command)
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
        [sys.executable, "-m", HOOK_MODULE],
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
    "SlopSeal: Unable to verify package. Installation is not permitted. "
    "Verify the package with the slopseal MCP tool, then run the install again.\n"
)


# Every verdict-aware message starts with the first progress line (R-U-1).
PROGRESS_FIRST = "SlopSeal: Checking dependencies before installation."


def _problems(stderr: str) -> list[dict[str, str]]:
    """The JSON objects in a verdict-aware message. Prose lines are fixed wording (R-G-10)."""
    assert stderr.startswith(PROGRESS_FIRST), stderr
    return [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]


@pytest.mark.parametrize("command", BLOCKED_COMMANDS)
def test_install_commands_are_blocked_with_exit_2(command: str) -> None:
    # R-G-3, R-G-5: every command here is an unverifiable install or a package that fails a
    # check. v1 asserted the exact v1 message. The message now names the problem (R-G-3).
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 2, command
    assert result.stdout == ""
    assert result.stderr.startswith(PROGRESS_FIRST), result.stderr
    assert all("check" in problem for problem in _problems(result.stderr))


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
        [sys.executable, "-m", HOOK_MODULE],
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


# ---- Fail-closed wrapper (R-1.1): the shipped command, run through a shell as Kiro runs it. ----

WRAPPER_NOT_INSTALLED = 'SlopSeal is not installed for "python3".'


def _shipped_command() -> str:
    hook = _load(HOOKS_DIR / INSTALL_HOOK_FILE)["hooks"][0]  # type: ignore[index]
    return str(hook["action"]["command"])  # type: ignore[index]


def _run_shipped(payload_command: str, path: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _shipped_command(),
        shell=True,
        input=_kiro_payload(payload_command),
        capture_output=True,
        text=True,
        cwd=REPO,
        env={**os.environ, "PATH": path},
        check=False,
    )


def _isolated_path(directory: Path) -> str:
    # The wrapper starts with `sh -c`, so PATH needs sh. Link only sh, so python3 is absent
    # unless a test puts a stub there.
    shell = shutil.which("sh")
    assert shell is not None
    (directory / "sh").symlink_to(shell)
    return str(directory)


def _python3_stub(directory: Path, body: str) -> None:
    stub = directory / "python3"
    stub.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    os.chmod(stub, 0o700)


@pytest.mark.parametrize("payload_command", ["git status", "npm install game-engine-pro-ultra"])
def test_wrapper_blocks_every_command_when_slopseal_is_not_installed(
    tmp_path: Path, payload_command: str
) -> None:
    # A python3 that cannot import slopseal exits 1 (ModuleNotFoundError). The wrapper must
    # turn that into exit 2, so Kiro blocks the command instead of running it.
    _python3_stub(tmp_path, 'echo "ModuleNotFoundError: No module named slopseal" >&2\nexit 1')
    result = _run_shipped(payload_command, path=_isolated_path(tmp_path))
    assert result.returncode == 2
    assert WRAPPER_NOT_INSTALLED in result.stderr
    assert '"python3" -m pip install git+https://github.com/mazi3012/SlopSeal.git' in result.stderr


def test_wrapper_blocks_when_python3_is_missing(tmp_path: Path) -> None:
    # Shell exit 127 (command not found) is also an error state, so it blocks too.
    result = _run_shipped("git status", path=_isolated_path(tmp_path))
    assert result.returncode == 2
    assert WRAPPER_NOT_INSTALLED in result.stderr


def test_wrapper_passes_benign_commands_and_blocks_installs_when_installed() -> None:
    # Put the interpreter running this test first on PATH. It has slopseal installed.
    path = f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}"
    benign = _run_shipped("git status", path=path)
    assert benign.returncode == 0
    assert benign.stderr == ""
    install = _run_shipped("npm install game-engine-pro-ultra", path=path)
    assert install.returncode == 2
    assert install.stderr.startswith(PROGRESS_FIRST)
    verified = _run_shipped("pip install tinyfmt-kit==0.4.0", path=path)
    assert verified.returncode == 0, verified.stderr


# ---- Verdict-aware gate (R-G-1..R-G-8): the real pipeline against the offline snapshot. ----

ALLOWED_PIP = "tinyfmt-kit==0.4.0"  # in the snapshot, passes every check
ALLOWED_NPM = "colorkit@2.0.1"  # in the snapshot, passes every check


def _state_dir(tmp_path: Path) -> Path:
    return tmp_path / "state"


def _audit_lines(tmp_path: Path) -> list[str]:
    log = _state_dir(tmp_path) / "audit.jsonl"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _attempts(tmp_path: Path) -> int:
    path = _state_dir(tmp_path) / "ratelimit.json"
    return len(json.loads(path.read_text(encoding="utf-8"))["attempts"]) if path.exists() else 0


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (f"pip install {ALLOWED_PIP}", '"package": "tinyfmt-kit"'),
        (f"npm install {ALLOWED_NPM}", '"package": "colorkit"'),
        (f"npx {ALLOWED_NPM}", '"package": "colorkit"'),
        ("python3 -m pip install csv-parser==1.2.0 --quiet", '"package": "csv-parser"'),
        (f"sudo pip install {ALLOWED_PIP}", '"package": "tinyfmt-kit"'),
        (f"cd app && pip install {ALLOWED_PIP} | tail -n 1", '"package": "tinyfmt-kit"'),
        (f'bash -c "pip install {ALLOWED_PIP}"', '"package": "tinyfmt-kit"'),
    ],
)
def test_r_g_2_verified_install_exits_0(command: str, expected: str) -> None:
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert "SlopSeal: Package verified. Installation is permitted." in result.stderr
    assert expected in result.stderr


def test_r_g_2_every_package_in_a_chain_is_verified(tmp_path: Path) -> None:
    command = f"pip install {ALLOWED_PIP} && npm install {ALLOWED_NPM}"
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 0, result.stderr
    assert '"package": "tinyfmt-kit"' in result.stderr
    assert '"package": "colorkit"' in result.stderr
    assert len(_audit_lines(tmp_path)) == 3  # genesis and one verdict per package


def test_r_g_3_blocked_package_names_check_reason_and_fix() -> None:
    result = _run_hook(_kiro_payload("pip install csv-parser-pro==0.1.0"))
    assert result.returncode == 2
    assert result.stdout == ""
    (problem,) = _problems(result.stderr)
    assert problem["check"] == "existence"
    assert problem["package"] == "csv-parser-pro"
    assert problem["version"] == "0.1.0"
    assert problem["reason"]
    assert problem["fix"] == "Did you mean csv-parser?"  # the check's remedy


def test_r_g_3_block_without_a_remedy_gets_the_fallback_fix() -> None:
    result = _run_hook(_kiro_payload("npm install react-codeshift@1.0.0"))
    assert result.returncode == 2
    (problem,) = _problems(result.stderr)
    assert problem["check"] == "malware"
    assert problem["fix"].startswith("Do not install this package")


def test_r_g_3_one_blocked_package_blocks_the_whole_command(tmp_path: Path) -> None:
    command = f"pip install {ALLOWED_PIP} && pip install csv-parser-pro==0.1.0"
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 2
    assert [problem["package"] for problem in _problems(result.stderr)] == ["csv-parser-pro"]
    assert len(_audit_lines(tmp_path)) == 3  # both packages were verified and logged


@pytest.mark.parametrize(
    ("command", "fix_part"),
    [
        ("pip install requests", "name==1.2.3"),
        ("pip install tinyfmt-kit>=0.4", "name==1.2.3"),
        ("npm install left-pad", "name@1.2.3"),
        ("pip install -r requirements.txt", "name==1.2.3"),
        ("pip install ./local-pkg", "name==1.2.3"),
        ("pip install https://example.invalid/x.whl", "name==1.2.3"),
        ("pip install", "name==1.2.3"),
        ("pip download tinyfmt-kit==0.4.0", "name==1.2.3"),
        ("npm install", "name@1.2.3"),
        ("uv add requests", "pip or npm"),
        ("cargo install ripgrep", "pip or npm"),
        ("pnpm add x", "pip or npm"),
        (f"FOO=1 pip install {ALLOWED_PIP}", "environment assignments"),
        (f"PIP_INDEX_URL=http://example.invalid pip install {ALLOWED_PIP}", "environment"),
        (f"export PIP_INDEX_URL=http://example.invalid; pip install {ALLOWED_PIP}", "environment"),
        (f"env FOO=1 pip install {ALLOWED_PIP}", "environment"),
        (f"cat reqs.txt | xargs pip install {ALLOWED_PIP}", "xargs"),
        ("echo 'unclosed", "plain pip or npm"),
    ],
)
def test_r_g_5_unverifiable_install_exits_2_with_a_fix(
    command: str, fix_part: str, tmp_path: Path
) -> None:
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    problems = _problems(result.stderr)
    assert problems
    assert all(problem["check"] == "unverifiable_install" for problem in problems)
    assert all(
        fix_part in problem["fix"] or "environment" in problem["fix"] for problem in problems
    )
    assert _audit_lines(tmp_path) == []  # nothing was verified, so nothing was logged


def test_r_g_5_a_verified_package_does_not_excuse_an_unverifiable_one(tmp_path: Path) -> None:
    result = _run_hook(_kiro_payload(f"pip install {ALLOWED_PIP} && uv add requests"))
    assert result.returncode == 2
    assert [problem["check"] for problem in _problems(result.stderr)] == ["unverifiable_install"]


def test_r_g_5_the_hook_does_not_resolve_an_unpinned_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # R-1.7 resolves in the shim. The hook cannot rewrite the command, so even live mode refuses.
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "0")
    result = _run_hook(_kiro_payload("pip install requests"))
    assert result.returncode == 2
    assert "not pinned" in _problems(result.stderr)[0]["reason"]


def test_r_g_6_install_in_a_payload_without_command_text_is_refused() -> None:
    payload = {"tool_input": {"description": f"pip install {ALLOWED_PIP}"}}
    result = _run_hook(json.dumps(payload))
    assert result.returncode == 2
    (problem,) = _problems(result.stderr)
    assert problem["check"] == "unverifiable_install"
    assert "no command text" in problem["reason"]


def test_r_g_7_non_install_command_writes_nothing(tmp_path: Path) -> None:
    result = _run_hook(_kiro_payload("ls -la"))
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert not _state_dir(tmp_path).exists()  # no verdict, no audit line, no rate-limit attempt


def test_r_g_1_each_distinct_package_counts_as_one_attempt(tmp_path: Path) -> None:
    command = f"pip install {ALLOWED_PIP}; pip install {ALLOWED_PIP}; npm install {ALLOWED_NPM}"
    result = _run_hook(_kiro_payload(command))
    assert result.returncode == 0, result.stderr
    assert _attempts(tmp_path) == 2


def test_r_g_1_the_rate_limit_applies_to_the_hook(tmp_path: Path) -> None:
    # R-4.7: every attempt counts, so enough attempts in a minute turn an ALLOW into a block.
    limit = 10
    codes = [
        _run_hook(_kiro_payload(f"pip install {ALLOWED_PIP}")).returncode for _ in range(limit + 1)
    ]
    assert codes[:limit] == [0] * limit
    assert codes[limit] == 2


def test_r_g_6_policy_error_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = tmp_path / "policy.md"
    broken.write_text("no policy block here\n", encoding="utf-8")
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(broken))
    result = _run_hook(_kiro_payload(f"pip install {ALLOWED_PIP}"))
    assert result.returncode == 2
    assert [problem["check"] for problem in _problems(result.stderr)] == ["policy_error"]


def test_r_g_6_tampered_snapshot_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copy = tmp_path / "snapshot"
    shutil.copytree(REPO / "src" / "slopseal" / "fixtures", copy)
    with (copy / "registry_snapshot.json").open("a", encoding="utf-8") as handle:
        handle.write(" ")
    monkeypatch.setenv("SLOPSEAL_SNAPSHOT_DIR", str(copy))
    result = _run_hook(_kiro_payload(f"pip install {ALLOWED_PIP}"))
    assert result.returncode == 2
    assert [problem["check"] for problem in _problems(result.stderr)] == ["snapshot_integrity"]


def test_r_g_6_unusable_state_directory_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(blocker / "state"))
    result = _run_hook(_kiro_payload(f"pip install {ALLOWED_PIP}"))
    assert result.returncode == 2
    assert result.stdout == ""
    assert _problems(result.stderr)


def _run_patched(body: str) -> subprocess.CompletedProcess[str]:
    """Run on_install.main() after the test code in `body` has patched the module."""
    script = "import sys\nfrom slopseal.hooks import on_install\n"
    script += textwrap.dedent(body) + "\nsys.exit(on_install.main())\n"
    return subprocess.run(
        [sys.executable, "-c", script],
        input=_kiro_payload(f"pip install {ALLOWED_PIP}"),
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=30,
        check=False,
    )


def test_r_g_6_an_unexpected_error_in_the_decision_exits_2() -> None:
    result = _run_patched(
        """
        def boom(raw, decide=None):
            raise RuntimeError("boom")
        on_install.evaluate = boom
        """
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert BLOCK_MESSAGE in result.stderr


def test_r_g_6_a_decision_that_misses_the_deadline_exits_2() -> None:
    result = _run_patched(
        """
        import time
        def slow(raw, decide=None):
            time.sleep(60)
        on_install.evaluate = slow
        on_install.DEADLINE_SECONDS = 0.5
        """
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == BLOCK_MESSAGE


def test_r_g_11_hook_then_shim_counts_the_install_once(tmp_path: Path) -> None:
    # The agent's command passes the hook, then runs through the PATH shim. Both layers see the
    # same install. The rate limit counts it once (R-G-11). The real pip is `true` here.
    true_bin = shutil.which("true")
    assert true_bin is not None
    hook = _run_hook(_kiro_payload(f"pip install {ALLOWED_PIP}"))
    assert hook.returncode == 0, hook.stderr
    assert _attempts(tmp_path) == 1
    shim = subprocess.run(
        [sys.executable, "-m", "slopseal.intercept.path_shim", "pip", "install", ALLOWED_PIP],
        env={**os.environ, "SLOPSEAL_REAL_PIP": true_bin},
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert shim.returncode == 0, shim.stderr
    assert '"package": "tinyfmt-kit"' in shim.stderr
    assert _attempts(tmp_path) == 1
