"""Integration tests for the CLI exit-code and output contract.

Requirements: R-1.1, R-1.3, R-1.4, R-1.5, R-4.1, R-4.4, R-5.7.1a.
Each test runs `main()` in-process against the offline snapshot and a temporary state directory.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slopseal.cli import main

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(state))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    return state


def test_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0


def test_allow_exits_zero_and_writes_a_summary_to_stderr(
    env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check", "tinyfmt-kit", "--version", "0.4.0"]) == 0
    captured = capsys.readouterr()
    assert "ALLOW tinyfmt-kit==0.4.0" in captured.err
    assert captured.out == ""


def test_block_exits_one_with_a_dependency_violation_on_stderr(
    env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check", "csv-parser-pro", "--version", "0.1.0"]) == 1
    violation = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert set(violation) == {"check", "package", "reason", "remedy"}
    assert violation["check"] == "existence"
    assert violation["remedy"] == "Did you mean csv-parser?"


def test_quarantine_exits_75_with_the_payload_on_stdout(
    env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["check", "csv-parser", "--version", "1.2.0", "--expected-api", "csv.reader"])
    captured = capsys.readouterr()
    assert code == 75
    payload = json.loads(captured.out)
    assert payload["verdict"] == "QUARANTINE"
    assert payload["retry_budget_remaining"] == 1


def test_missing_policy_exits_78(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", "/no/such/policy.md")
    assert main(["check", "csv-parser", "--version", "1.2.0"]) == 78
    assert "policy error" in capsys.readouterr().err


def test_weakened_policy_fails_policy_check_with_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    weakened = tmp_path / "policy.md"
    weakened.write_text(
        POLICY.read_text(encoding="utf-8").replace(
            "typosquat_max_distance = 2", "typosquat_max_distance = 1"
        ),
        encoding="utf-8",
    )
    assert main(["policy", "check", str(weakened)]) == 1
    assert "below the floor 2" in capsys.readouterr().err


def test_committed_policy_passes_policy_check(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["policy", "check", str(POLICY)]) == 0


def test_audit_verify_exits_zero_on_a_clean_log(env: Path) -> None:
    main(["check", "tinyfmt-kit", "--version", "0.4.0"])
    assert main(["audit", "verify"]) == 0


def test_audit_verify_exits_one_on_tampering(env: Path) -> None:
    main(["check", "tinyfmt-kit", "--version", "0.4.0"])
    log = env / "audit.jsonl"
    text = log.read_text(encoding="utf-8").replace('"outcome": "ALLOW"', '"outcome": "BLOCK"', 1)
    log.write_text(text, encoding="utf-8")
    assert main(["audit", "verify"]) == 1


def test_audit_verify_exits_78_when_the_log_is_missing(env: Path) -> None:
    assert main(["audit", "verify"]) == 78


def test_allow_unsafe_without_reason_is_refused(
    env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check", "reqeusts", "--version", "1.0.0", "--allow-unsafe"]) == 1
    assert "needs a non-empty --reason" in capsys.readouterr().err


def test_escalate_requires_an_escalated_quarantine(env: Path) -> None:
    assert main(["check", "csv-parser", "--version", "1.2.0", "--expected-api", "csv.reader"]) == 75
    stored = next((env / "quarantine").glob("qs_*.json"))
    qid = json.loads(stored.read_text(encoding="utf-8"))["quarantine_id"]
    assert main(["escalate", qid, "--approve", "--reason", "too early"]) == 1
