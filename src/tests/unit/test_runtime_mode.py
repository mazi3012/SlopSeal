"""Tests for offline and live mode selection (R-P-3, THREAT_MODEL section 5).

Unset means offline, so package names do not leave the machine by default. Only the exact
value "0" selects live mode. The CLI --live flag does the same for one process. No test here
reaches the network: the live source is replaced with one whose fetch always fails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from slopseal import runtime
from slopseal.cli import main
from slopseal.registry.live import LiveSource
from slopseal.registry.source import OfflineSource

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"


def _no_network(url: str, body: bytes | None) -> bytes | None:
    raise OSError("network is disabled in tests")


@pytest.mark.parametrize(
    ("value", "expected_offline"),
    [(None, True), ("1", True), ("0", False), ("", True), ("yes", True), ("false", True)],
)
def test_only_exact_zero_selects_live(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected_offline: bool
) -> None:
    if value is None:
        monkeypatch.delenv("SLOPSEAL_OFFLINE_SNAPSHOT", raising=False)
    else:
        monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", value)
    assert runtime.offline() is expected_offline


def test_live_mode_builds_a_live_source_with_the_snapshot_top_n(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "0")
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setattr(
        runtime, "LiveSource", lambda **kwargs: LiveSource(fetch=_no_network, **kwargs)
    )
    context = runtime.build_context(tmp_path)
    assert isinstance(context.source, LiveSource)
    assert context.source.top_n(runtime.Ecosystem.PYPI)  # the snapshot's top-N list, not empty


def test_offline_mode_builds_the_snapshot_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("SLOPSEAL_OFFLINE_SNAPSHOT", raising=False)
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    context = runtime.build_context(tmp_path)
    assert isinstance(context.source, OfflineSource)


def test_cli_live_flag_queries_live_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Record the variable first, so monkeypatch restores it after the test. The CLI sets it
    # directly, and that must not leak into later tests.
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.delenv("SLOPSEAL_OFFLINE_SNAPSHOT")
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        runtime, "LiveSource", lambda **kwargs: LiveSource(fetch=_no_network, **kwargs)
    )
    code = main(["check", "requests", "--version", "2.32.3", "--live"])
    captured = capsys.readouterr()
    assert code == 1
    violation = json.loads(captured.err.strip().splitlines()[-1])
    assert violation["check"] == "existence"
    assert "registry state unknown" in violation["reason"]
