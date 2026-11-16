"""Tests for the MCP startup hook registration (R-1.9).

The bootstrap writes the install hook config into the workspace when the file is missing. The
hook command runs slopseal with the interpreter that runs the server (sys.executable), so it
works under uvx, pipx, or a local venv. Tests run the bootstrap in tmp_path only, so they never
write into the repository.
"""

from __future__ import annotations

import io
import json
import shlex
import subprocess
import sys
from importlib import resources
from pathlib import Path

import pytest

from slopseal.mcp.server import (
    REGISTERED_MESSAGE,
    bootstrap_install_hook,
    install_hook_command,
    render_install_hook_config,
)

REPO = Path(__file__).resolve().parents[3]
REPO_HOOK = REPO / ".kiro" / "hooks" / "block-agent-installs.json"
HOOK_RELATIVE = Path(".kiro") / "hooks" / "block-agent-installs.json"


def _command_of(path: Path) -> str:
    return str(json.loads(path.read_text(encoding="utf-8"))["hooks"][0]["action"]["command"])


def test_bootstrap_creates_hook_config_in_empty_workspace(tmp_path: Path) -> None:
    err = io.StringIO()
    assert bootstrap_install_hook(tmp_path, stderr=err) is True

    target = tmp_path / HOOK_RELATIVE
    assert target.is_file()
    hook = json.loads(target.read_text(encoding="utf-8"))["hooks"][0]
    assert hook["matcher"] == "execute_bash"
    assert target.read_bytes() == render_install_hook_config(sys.executable)
    assert err.getvalue() == REGISTERED_MESSAGE + "\n"
    assert REGISTERED_MESSAGE == "SlopSeal MCP: Auto-registered security hook in workspace."


def test_generated_hook_contains_the_running_interpreter(tmp_path: Path) -> None:
    bootstrap_install_hook(tmp_path, stderr=io.StringIO())
    # The command is: sh -c <script> sh <interpreter>. The script reads the interpreter as $1.
    argv = shlex.split(_command_of(tmp_path / HOOK_RELATIVE))
    assert argv[:2] == ["sh", "-c"]
    assert argv[3:] == ["sh", sys.executable]
    assert "slopseal.hooks.on_install" in argv[2]


def test_interpreter_path_stays_one_argument() -> None:
    weird = "/opt/my envs/it's/python"
    argv = shlex.split(install_hook_command(weird))
    assert len(argv) == 5
    assert argv[4] == weird


def test_hostile_interpreter_path_cannot_run_code(tmp_path: Path) -> None:
    # The path tries to end the quoting and run `touch`. The script must treat it as one
    # argument: the run fails with exit 2 and the marker file is never created.
    marker = tmp_path / "PWNED"
    hostile = f"/nonexistent/x'; touch {marker}; '/python"
    argv = shlex.split(install_hook_command(hostile))
    result = subprocess.run(argv, input="", capture_output=True, text=True, check=False)  # noqa: S603
    assert result.returncode == 2
    assert not marker.exists()
    assert hostile in result.stderr


def test_bootstrap_writes_nothing_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bootstrap_install_hook(tmp_path, stderr=io.StringIO())
    assert capsys.readouterr().out == ""


def test_existing_hook_config_is_not_overwritten(tmp_path: Path) -> None:
    target = tmp_path / HOOK_RELATIVE
    target.parent.mkdir(parents=True)
    target.write_text('{"version": "v1", "hooks": []}\n', encoding="utf-8")

    err = io.StringIO()
    assert bootstrap_install_hook(tmp_path, stderr=err) is False
    assert target.read_text(encoding="utf-8") == '{"version": "v1", "hooks": []}\n'
    assert err.getvalue() == ""


def test_unwritable_workspace_fails_silently_without_raising(tmp_path: Path) -> None:
    # A regular file where the .kiro directory belongs makes the write fail on any filesystem,
    # including as root, where a read-only chmod would not.
    (tmp_path / ".kiro").write_text("not a directory", encoding="utf-8")

    err = io.StringIO()
    assert bootstrap_install_hook(tmp_path, stderr=err) is False
    assert "could not register security hook" in err.getvalue()
    assert not (tmp_path / HOOK_RELATIVE).exists()


def test_packaged_hook_config_is_byte_identical_to_repo_hook() -> None:
    # The package cannot read the repo's .kiro/ directory, so it ships a copy. This fails if the
    # two drift apart.
    packaged = resources.files("slopseal.hooks").joinpath("block-agent-installs.json")
    assert REPO_HOOK.read_bytes() == packaged.read_bytes()


def test_repo_hook_is_the_default_render_for_python3() -> None:
    # The repo's own hook uses python3. Re-run `render_install_hook_config("python3")` to update
    # it if the wrapper changes.
    assert REPO_HOOK.read_bytes() == render_install_hook_config("python3")
