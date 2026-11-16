# ruff: noqa: S603 - every argv here is built by the test, not from untrusted input.
"""Integration tests for slopseal-mcp over stdio, and for the Kiro Power files (R-1.8).

Each test runs the server as a subprocess, as an MCP client does. The state directory is a
temporary directory, so no test writes to the repo's .slopseal.
Requirements: R-1.8, R-1.3, R-V-1.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from slopseal import __version__

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"


def _env(state: Path, policy: Path = POLICY) -> dict[str, str]:
    # Mirrors mcp.json: offline snapshot, the repo's policy, a temporary state directory.
    env = dict(os.environ)
    env.update(
        SLOPSEAL_OFFLINE_SNAPSHOT="1",
        SLOPSEAL_SNAPSHOT_DIR=str(REPO / "src" / "slopseal" / "fixtures"),
        SLOPSEAL_STATE_DIR=str(state),
        SLOPSEAL_POLICY_PATH=str(policy),
    )
    return env


def _session(messages: list[dict[str, Any] | str], env: dict[str, str]) -> list[dict[str, Any]]:
    stdin = "\n".join(m if isinstance(m, str) else json.dumps(m) for m in messages) + "\n"
    result = subprocess.run(
        [sys.executable, "-m", "slopseal.mcp.server"],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    # Stdout carries only protocol messages: every line must be one JSON-RPC object.
    replies: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        message = json.loads(line)
        assert message["jsonrpc"] == "2.0"
        replies.append(message)
    return replies


def _call(request_id: int, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "verify_install", "arguments": arguments},
    }


INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


def test_full_session_allows_a_clean_package_and_blocks_malware(state: Path) -> None:
    replies = _session(
        [
            INIT,
            INITIALIZED,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            _call(3, {"ecosystem": "pypi", "package": "tinyfmt-kit", "version": "0.4.0"}),
            _call(4, {"ecosystem": "npm", "package": "react-codeshift", "version": "1.0.0"}),
        ],
        _env(state),
    )
    by_id = {reply["id"]: reply for reply in replies}
    assert set(by_id) == {1, 2, 3, 4}  # the notification gets no reply

    assert by_id[1]["result"]["serverInfo"]["version"] == __version__
    assert [t["name"] for t in by_id[2]["result"]["tools"]] == ["verify_install"]

    allowed = by_id[3]["result"]
    assert allowed["isError"] is False
    assert allowed["structuredContent"]["outcome"] == "ALLOW"

    blocked = by_id[4]["result"]
    assert blocked["isError"] is True
    assert blocked["structuredContent"]["outcome"] == "BLOCK"
    assert blocked["structuredContent"]["exit_code"] == 1


def test_bypass_argument_is_refused_end_to_end(state: Path) -> None:
    args = {"ecosystem": "pypi", "package": "tinyfmt-kit", "version": "0.4.0"}
    replies = _session(
        [INIT, _call(2, {**args, "bypass_reason": "urgent"})],
        _env(state),
    )
    by_id = {reply["id"]: reply for reply in replies}
    assert by_id[2]["error"]["code"] == -32602
    assert "result" not in by_id[2]


def test_missing_policy_gives_no_verdict_and_never_an_allow(state: Path, tmp_path: Path) -> None:
    missing = tmp_path / "no-such-policy.md"
    replies = _session(
        [
            INIT,
            _call(2, {"ecosystem": "pypi", "package": "tinyfmt-kit", "version": "0.4.0"}),
        ],
        _env(state, policy=missing),
    )
    result = {reply["id"]: reply for reply in replies}[2]["result"]
    assert result["isError"] is True
    assert "no verdict was issued" in result["content"][0]["text"]
    assert "structuredContent" not in result


def test_oversize_line_is_refused_and_its_tail_is_never_run(state: Path) -> None:
    # The tail of the oversize line is a valid tool call. It must not run.
    tail = json.dumps(_call(2, {"ecosystem": "pypi", "package": "tinyfmt-kit", "version": "0.4.0"}))
    oversize = " " * (64 * 1024 + 10) + tail
    replies = _session([oversize, INIT], _env(state))
    assert len(replies) == 2
    assert replies[0]["error"]["code"] == -32600
    assert replies[1]["id"] == 1


def test_unparseable_line_is_answered_and_the_session_continues(state: Path) -> None:
    replies = _session(
        ["this is not json", INIT],
        _env(state),
    )
    assert replies[0]["error"]["code"] == -32700
    assert replies[1]["id"] == 1


# ---- The Kiro Power files at the repo root ----


def _load_json(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((REPO / name).read_text(encoding="utf-8"))
    return data


def test_plugin_manifest_has_the_required_fields() -> None:
    plugin = _load_json("plugin.json")
    assert plugin["name"] == "slopseal"
    assert plugin["version"] == __version__
    assert plugin["keywords"]
    assert plugin["description"]
    assert plugin["author"]["name"]


def test_mcp_config_runs_the_slopseal_mcp_entry_point_with_uvx() -> None:
    server = _load_json("mcp.json")["mcpServers"]["slopseal"]
    assert server["type"] == "stdio"
    assert server["command"] == "uvx"
    assert server["args"][-1] == "slopseal-mcp"
    assert server["args"][:2] == ["--from", "."]
    # Offline is the default. The config keeps it explicit so no package name leaves the machine.
    assert server["env"]["SLOPSEAL_OFFLINE_SNAPSHOT"] == "1"


def test_console_script_is_declared_in_pyproject() -> None:
    import tomllib

    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["scripts"]["slopseal-mcp"] == "slopseal.mcp.server:main"


def test_power_description_names_the_only_tool_and_the_outcomes() -> None:
    text = (REPO / "POWER.md").read_text(encoding="utf-8")
    assert "`verify_install`" in text
    for outcome in ("ALLOW", "BLOCK", "QUARANTINE"):
        assert outcome in text
    assert "bypass" not in text.lower().split("## limits")[0]
