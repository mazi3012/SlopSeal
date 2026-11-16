"""Live-mode end-to-end tests against recorded registry responses (R-P-3, R-2.10).

The responses under src/tests/fixtures/live/ were recorded from PyPI and OSV. A local HTTP server
serves them, so these tests never touch the network. The top-N list is the checksummed
snapshot's list, as in production.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from slopseal import runtime
from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.cli import main
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QuarantineStore
from slopseal.registry.live import LiveSource
from slopseal.verdict import Context, InstallRequest, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
RECORDED = REPO / "src" / "tests" / "fixtures" / "live"
SNAPSHOT = REPO / "src" / "slopseal" / "fixtures"


def _read(name: str) -> bytes:
    return (RECORDED / name).read_bytes()


@dataclass
class Routes:
    table: dict[str, tuple[int, bytes]] = field(default_factory=dict)


@pytest.fixture
def routes() -> Iterator[tuple[Routes, str]]:
    state = Routes()

    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            if self.command == "POST":
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
            status, body = state.table.get(self.path, (404, b"{}"))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._serve()

        def do_POST(self) -> None:  # noqa: N802
            self._serve()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _recorded_routes(state: Routes, *, osv_status: int = 200) -> None:
    state.table["/pypi/requests/json"] = (200, _read("pypi_requests.json"))
    state.table["/pypi/requests/2.33.0/json"] = (200, _read("pypi_requests_2.33.0.json"))
    state.table["/pypi/csv-parser-pro/json"] = (404, b"{}")
    state.table["/osv"] = (osv_status, _read("osv_requests_2.33.0.json"))


def _source(base: str) -> LiveSource:
    snapshot = load_snapshot(SNAPSHOT)
    top = {eco: snapshot.top_n(eco) for eco in (Ecosystem.PYPI, Ecosystem.NPM)}
    return LiveSource(
        top_n=top,
        pypi_base=f"{base}/pypi",
        npm_base=f"{base}/npm",
        osv_url=f"{base}/osv",
        timeout=5.0,
    )


def _context(tmp: Path, source: LiveSource) -> Context:
    key = load_or_create_key(tmp)
    return Context(
        policy=load_policy(str(POLICY)),
        source=source,
        store=QuarantineStore(tmp),
        log=AuditLog(tmp / "audit.jsonl", key),
        now=datetime(2026, 11, 18, tzinfo=UTC),
        new_id=lambda: "qid",
        limiter=None,
    )


def test_live_popular_package_is_allowed_with_a_maintainer_warning(
    routes: tuple[Routes, str], tmp_path: Path
) -> None:
    state, base = routes
    _recorded_routes(state)
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "requests", "2.33.0"),
        _context(tmp_path, _source(base)),
    )
    assert decision.outcome is Outcome.ALLOW
    assert [w.check for w in decision.warnings] == ["maintainer"]
    assert "not published" in decision.warnings[0].reason
    line = json.loads((tmp_path / "audit.jsonl").read_text().strip().splitlines()[-1])
    assert line["event"] == "verdict"
    assert line["outcome"] == "ALLOW"
    assert line["warnings"] == ["maintainer"]
    assert line["warning_details"][0]["check"] == "maintainer"
    assert "not published" in line["warning_details"][0]["reason"]


def test_live_nonexistent_name_is_blocked_at_existence(
    routes: tuple[Routes, str], tmp_path: Path
) -> None:
    state, base = routes
    _recorded_routes(state)
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "csv-parser-pro", "0.1.0"),
        _context(tmp_path, _source(base)),
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "existence"


def test_live_is_blocked_when_osv_is_unreachable(
    routes: tuple[Routes, str], tmp_path: Path
) -> None:
    state, base = routes
    _recorded_routes(state, osv_status=503)
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "requests", "2.33.0"),
        _context(tmp_path, _source(base)),
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "cve"


def test_cli_live_allow_prints_the_warning_and_exits_zero(
    routes: tuple[Routes, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state, base = routes
    _recorded_routes(state)
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.delenv("SLOPSEAL_OFFLINE_SNAPSHOT")
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        runtime,
        "LiveSource",
        lambda **kwargs: _source(base),
    )
    code = main(["check", "requests", "--version", "2.33.0", "--live"])
    err = capsys.readouterr().err
    assert code == 0
    assert "ALLOW requests==2.33.0" in err
    assert "WARN maintainer" in err
