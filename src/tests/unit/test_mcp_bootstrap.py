"""Tests for the MCP startup hook registration (R-1.9).

The bootstrap writes the packaged install hook config into the workspace when the file is
missing. Tests run it in tmp_path only, so they never write into the repository.
"""

from __future__ import annotations

import io
import json
from importlib import resources
from pathlib import Path

import pytest

from slopseal.mcp.server import REGISTERED_MESSAGE, bootstrap_install_hook

REPO = Path(__file__).resolve().parents[3]
REPO_HOOK = REPO / ".kiro" / "hooks" / "block-agent-installs.json"
HOOK_RELATIVE = Path(".kiro") / "hooks" / "block-agent-installs.json"


def _packaged_bytes() -> bytes:
    return resources.files("slopseal.hooks").joinpath("block-agent-installs.json").read_bytes()


def test_bootstrap_creates_hook_config_in_empty_workspace(tmp_path: Path) -> None:
    err = io.StringIO()
    assert bootstrap_install_hook(tmp_path, stderr=err) is True

    target = tmp_path / HOOK_RELATIVE
    assert target.is_file()
    hook = json.loads(target.read_text(encoding="utf-8"))["hooks"][0]
    assert hook["matcher"] == "execute_bash"
    assert target.read_bytes() == _packaged_bytes()
    assert err.getvalue() == REGISTERED_MESSAGE + "\n"
    assert REGISTERED_MESSAGE == "SlopSeal MCP: Auto-registered security hook in workspace."


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


def test_bootstrap_writes_nothing_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bootstrap_install_hook(tmp_path, stderr=io.StringIO())
    assert capsys.readouterr().out == ""


def test_packaged_hook_config_is_byte_identical_to_repo_hook() -> None:
    # The package cannot read the repo's .kiro/ directory, so it ships a copy. This fails if the
    # two drift apart.
    assert REPO_HOOK.read_bytes() == _packaged_bytes()
