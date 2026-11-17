# ruff: noqa: S603 - every argv here is built by the test, not from untrusted input.
"""Messaging scenarios (R-U-1): the five outcomes a developer or agent sees.

Each scenario runs the real code path: the hook's `evaluate` with the real gate, and the real
`slopseal-mcp` server process over stdio. Everything is offline, against the bundled snapshot,
with a temporary state directory. No test installs a package or touches a live registry.

Each test checks two things. The wording matches the decision the code made, and the decision
itself is unchanged (the exit code, the outcome, the isError flag, and the check name).

Requirements: R-U-1, R-G-2..R-G-8, R-G-10, R-1.8.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from slopseal.hooks.on_install import BLOCK_MESSAGE, evaluate
from slopseal.messages import HEADLINES, NEXT, PROGRESS

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
FIXTURES = REPO / "src" / "slopseal" / "fixtures"

ALLOW_TEXT = HEADLINES["allow"]
BLOCK_TEXT = HEADLINES["block"]
QUARANTINE_TEXT = HEADLINES["quarantine"]
RATE_TEXT = HEADLINES["rate_limited"]
ERROR_TEXT = HEADLINES["error"]
UNVERIFIABLE_TEXT = HEADLINES["unverifiable"]
FIXED_LINES = frozenset({*PROGRESS, *HEADLINES.values(), *NEXT.values()})


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(root))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.setenv("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES))
    return root


def _hook(command: str) -> tuple[int, str]:
    payload = json.dumps({"tool_name": "execute_bash", "tool_input": {"command": command}})
    result = evaluate(payload)
    return result.exit_code, result.stderr


def _hook_json(stderr: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]


def _server(lines: list[bytes], state: Path, policy: Path = POLICY) -> list[dict[str, Any]]:
    env = dict(os.environ)
    env.update(
        SLOPSEAL_OFFLINE_SNAPSHOT="1",
        SLOPSEAL_SNAPSHOT_DIR=str(FIXTURES),
        SLOPSEAL_STATE_DIR=str(state),
        SLOPSEAL_POLICY_PATH=str(policy),
        PYTHONPATH=str(REPO / "src"),
    )
    result = subprocess.run(
        [sys.executable, "-m", "slopseal.mcp.server"],
        input=b"".join(line + b"\n" for line in lines),
        capture_output=True,
        cwd=REPO,
        env=env,
        timeout=120,
        check=False,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def _verify(
    request_id: int, package: str, version: str, ecosystem: str = "pypi", **extra: str
) -> bytes:
    arguments = {"ecosystem": ecosystem, "package": package, "version": version, **extra}
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "verify_install", "arguments": arguments},
    }
    return json.dumps(message).encode("utf-8")


def _tool_result(reply: dict[str, Any]) -> dict[str, Any]:
    assert "result" in reply, reply
    return reply["result"]


# 1. Approved package --------------------------------------------------------------------


def test_approved_package_says_permitted_and_keeps_allow(state: Path) -> None:
    replies = _server([_verify(1, "csv-parser", "1.2.0")], state)
    result = _tool_result(replies[0])
    assert result["isError"] is False
    assert result["structuredContent"]["outcome"] == "ALLOW"
    assert result["content"][0]["text"].startswith(ALLOW_TEXT + "\n")
    assert 'package: "csv-parser"' in result["content"][0]["text"]

    code, stderr = _hook("pip install csv-parser==1.2.0")
    assert code == 0
    assert stderr.splitlines()[:2] == list(PROGRESS)
    assert stderr.splitlines()[2] == ALLOW_TEXT
    assert _hook_json(stderr)[0]["outcome"] == "ALLOW"
    assert "BLOCK" not in stderr


# 2. Blocked package ---------------------------------------------------------------------


def test_blocked_package_names_the_check_and_the_next_step(state: Path) -> None:
    result = _tool_result(_server([_verify(1, "flsk", "1.0.0")], state)[0])
    text = result["content"][0]["text"]
    assert result["isError"] is True
    assert result["structuredContent"]["outcome"] == "BLOCK"
    assert result["structuredContent"]["violation"]["check"] == "typosquat"
    assert text.startswith(BLOCK_TEXT + "\n")
    assert 'check: "typosquat"' in text
    assert NEXT["block"] in text

    code, stderr = _hook("pip install flsk==1.0.0")
    assert code == 2
    assert stderr.splitlines()[2] == BLOCK_TEXT
    problem = _hook_json(stderr)[0]
    assert problem["check"] == "typosquat"
    assert problem["package"] == "flsk"
    assert problem["version"] == "1.0.0"


def test_advisory_identifiers_are_shown_and_no_severity_is_invented(state: Path) -> None:
    result = _tool_result(_server([_verify(1, "urlnorm", "0.9.0", ecosystem="npm")], state)[0])
    text = result["content"][0]["text"]
    assert result["structuredContent"]["outcome"] == "BLOCK"
    assert result["structuredContent"]["violation"]["check"] == "cve"
    assert 'advisory_ids: ["GHSA-fixture-urlnorm-0001"]' in text
    # The advisory source in the snapshot gives no severity field that the verdict carries.
    assert "severity" not in text.lower()

    code, stderr = _hook("npm install urlnorm@0.9.0")
    assert code == 2
    assert "severity" not in stderr.lower()
    assert _hook_json(stderr)[0]["check"] == "cve"


# 3. Quarantined package -----------------------------------------------------------------


def test_quarantined_package_is_held_with_its_id(state: Path) -> None:
    replies = _server(
        [
            _verify(
                1,
                "colorkit",
                "2.0.1",
                ecosystem="npm",
                expected_api="doesNotExist",
                purpose="colour text",
            )
        ],
        state,
    )
    result = _tool_result(replies[0])
    text = result["content"][0]["text"]
    quarantine_id = result["structuredContent"]["quarantine_id"]
    assert result["isError"] is True
    assert result["structuredContent"]["outcome"] == "QUARANTINE"
    assert text.startswith(QUARANTINE_TEXT + "\n")
    assert f'quarantine_id: "{quarantine_id}"' in text
    assert NEXT["quarantine"] in text


# 4. Rate-limited request ----------------------------------------------------------------


def test_rate_limited_mcp_request_says_paused_and_does_not_blame_the_package(state: Path) -> None:
    replies = _server([_verify(i, "csv-parser", "1.2.0") for i in range(1, 12)], state)
    last = _tool_result(replies[-1])
    text = last["content"][0]["text"]
    assert last["isError"] is True
    assert last["structuredContent"]["outcome"] == "BLOCK"
    assert last["structuredContent"]["violation"]["check"] == "rate_limit"
    assert text.startswith(RATE_TEXT + "\n")
    assert "Do not change the package." in text
    assert "Choose a different" not in text
    assert "Security risks" not in text


def test_rate_limited_hook_command_says_paused_and_does_not_blame_the_package(state: Path) -> None:
    limit = 10
    for _ in range(limit):
        assert _hook("pip install csv-parser==1.2.0")[0] == 0
    code, stderr = _hook("pip install csv-parser==1.2.0")
    assert code == 2
    assert stderr.splitlines()[2] == RATE_TEXT
    assert _hook_json(stderr)[0]["check"] == "rate_limit"
    assert "Choose a different" not in stderr


# 5. Verification error ------------------------------------------------------------------


def test_verification_error_on_mcp_says_not_permitted(state: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken-policy.md"
    broken.write_text("no policy block in this file\n", encoding="utf-8")
    replies = _server([_verify(1, "csv-parser", "1.2.0")], state, policy=broken)
    result = _tool_result(replies[0])
    text = result["content"][0]["text"]
    assert result["isError"] is True
    assert "structuredContent" not in result  # no verdict exists, so no verdict is reported
    assert text.startswith(ERROR_TEXT + "\n")
    assert "no verdict was issued" in text
    assert "ALLOW" not in text.split("\n")[0]


def test_unreadable_hook_payload_says_not_permitted(state: Path) -> None:
    result = evaluate("not json")
    assert result.exit_code == 2
    assert result.stderr == BLOCK_MESSAGE + "\n"
    assert BLOCK_MESSAGE.startswith(ERROR_TEXT)


def test_setup_error_in_the_hook_says_not_permitted(
    state: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    broken = tmp_path / "broken-policy.md"
    broken.write_text("no policy block in this file\n", encoding="utf-8")
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(broken))
    code, stderr = _hook("pip install csv-parser==1.2.0")
    assert code == 2
    assert stderr.splitlines()[2] == ERROR_TEXT
    assert _hook_json(stderr)[0]["check"] == "policy_error"


# Cross-cutting rules -----------------------------------------------------------------------


def test_unverifiable_form_is_not_called_a_security_risk(state: Path) -> None:
    code, stderr = _hook("pip install csv-parser")
    assert code == 2
    assert stderr.splitlines()[2] == UNVERIFIABLE_TEXT
    assert "Security risks" not in stderr


@pytest.mark.parametrize(
    "command",
    [
        "pip install flsk==1.0.0",
        "pip install csv-parser",
        "pip install csv-parser==9.9.9",
        "pip install csv-parser==1.2.0 semverx==4.0.1",
    ],
)
def test_every_prose_line_is_fixed_wording(state: Path, command: str) -> None:
    """R-G-10 and R-U-1: metadata only ever appears inside JSON, never in a prose line."""
    _, stderr = _hook(command)
    for line in stderr.splitlines():
        if not line.startswith("{"):
            assert line in FIXED_LINES, line
