"""Tests for `slopseal audit html` (R-5.7.1, R-5.7.2).

Each test writes a real hash-chained, sealed log, then renders it. Package names, reasons, and
README-like text in the log are hostile on purpose, to prove they are escaped.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from slopseal.audit.log import AuditLog, line_checks
from slopseal.audit.seal import load_or_create_key
from slopseal.cli import main

TS = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
POLICY_HASH = "ab" * 32


def _verdict(
    log: AuditLog,
    *,
    package: str,
    version: str,
    outcome: str,
    reason: str,
    checks: list[str],
    blocked_by: str | None = None,
    warnings: list[dict[str, str]] | None = None,
) -> None:
    fields: dict[str, object] = {
        "ecosystem": "pypi",
        "package": package,
        "version": version,
        "outcome": outcome,
        "exit_code": {"ALLOW": 0, "BLOCK": 1, "QUARANTINE": 75}[outcome],
        "checks_run": checks,
        "warnings": [w["check"] for w in warnings or []],
        "warning_details": warnings or [],
        "policy_hash": POLICY_HASH,
        "snapshot_id": "slopseal-fixture-v1",
        "reason": reason,
    }
    if blocked_by:
        fields["blocked_by"] = blocked_by
    log.append("verdict", ts=TS, fields=fields)


@pytest.fixture
def state(tmp_path: Path) -> Path:
    state_dir = tmp_path / "state"
    key = load_or_create_key(state_dir)
    log = AuditLog(state_dir / "audit.jsonl", key)
    _verdict(
        log,
        package="requests",
        version="2.34.2",
        outcome="ALLOW",
        reason="all checks passed",
        checks=["existence", "typosquat", "maintainer"],
        warnings=[{"check": "maintainer", "reason": "account age not published"}],
    )
    _verdict(
        log,
        package="csv-parser-pro",
        version="0.1.0",
        outcome="BLOCK",
        reason="does not exist in the pypi registry",
        checks=["existence"],
        blocked_by="existence",
    )
    _verdict(
        log,
        package="csv-parser",
        version="1.2.0",
        outcome="QUARANTINE",
        reason="api csv.reader is not exported",
        checks=["existence", "api_surface"],
    )
    return state_dir


def _render(state_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    import os

    out = tmp_path / "receipt.html"
    os.environ["SLOPSEAL_STATE_DIR"] = str(state_dir)
    try:
        code = main(["audit", "html", "--out", str(out)])
    finally:
        os.environ.pop("SLOPSEAL_STATE_DIR", None)
    capsys.readouterr()
    return code, out.read_text(encoding="utf-8")


def test_each_verdict_has_a_badge_checks_policy_hash_and_seal(
    state: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, page = _render(state, tmp_path, capsys)
    assert code == 0
    assert "badge allow" in page
    assert "badge block" in page
    assert "badge quarantine" in page
    assert page.count("Policy hash:") == 3
    assert POLICY_HASH in page
    # Three verdicts, each sealed. The genesis line is the only line without a seal.
    assert page.count("seal verified") == 3
    assert "Audit log verified." in page
    assert "<li>existence</li>" in page
    assert "<li>api_surface</li>" in page
    assert "WARN maintainer: account age not published" in page
    assert "blocked by: existence" in page


def test_untrusted_log_text_is_escaped_not_rendered(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state_dir = tmp_path / "state"
    key = load_or_create_key(state_dir)
    log = AuditLog(state_dir / "audit.jsonl", key)
    _verdict(
        log,
        package="<script>alert(1)</script>",
        version="1.0.0",
        outcome="BLOCK",
        reason='<img src=x onerror="alert(2)"> & "quotes"',
        checks=["malware"],
        blocked_by="malware",
    )
    code, page = _render(state_dir, tmp_path, capsys)
    assert code == 0
    assert "<script>alert" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=&quot;alert(2)&quot;&gt; &amp; &quot;quotes&quot;" in page


def test_page_has_no_scripts_links_images_or_external_requests(
    state: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, page = _render(state, tmp_path, capsys)
    for forbidden in (
        "<script",
        "<link",
        "<img",
        "<iframe",
        " src=",
        " href=",
        "url(",
        "@import",
        "http://",
        "https://",
    ):
        assert forbidden not in page, forbidden


def test_light_and_dark_mode_are_both_defined(
    state: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, page = _render(state, tmp_path, capsys)
    assert "prefers-color-scheme: dark" in page
    assert "color-scheme: light dark" in page


def test_tampered_line_marks_the_receipt_as_failed(
    state: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log_path = state / "audit.jsonl"
    lines = log_path.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if '"outcome": "BLOCK"' in line)
    lines[index] = lines[index].replace('"outcome": "BLOCK"', '"outcome": "ALLOW"', 1)
    log_path.write_text("\n".join(lines) + "\n")
    code, page = _render(state, tmp_path, capsys)
    assert code == 1
    assert "Audit log failed verification." in page
    assert "chain broken" in page or "seal invalid" in page


def test_stdout_stays_empty_and_file_is_written(
    state: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(state))
    out = tmp_path / "r.html"
    assert main(["audit", "html", "--out", str(out)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "wrote receipt" in captured.err
    assert out.read_text().startswith("<!doctype html>")


def test_missing_log_exits_78_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "empty"))
    out = tmp_path / "r.html"
    assert main(["audit", "html", "--out", str(out)]) == 78
    assert not out.exists()


def test_line_checks_report_every_line_independently(state: Path) -> None:
    lines = (state / "audit.jsonl").read_text().splitlines()
    checks = line_checks(lines, (state / "secret.key").read_bytes())
    assert len(checks) == len(lines)
    assert all(c.chain_ok for c in checks)
    assert re.fullmatch(r"ok", checks[1].seal)
