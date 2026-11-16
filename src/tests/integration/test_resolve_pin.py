"""Resolve-then-pin tests (R-1.7).

The live registry is replaced by a fetch function that answers from recorded PyPI and OSV
responses (src/tests/fixtures/live/). The npm packument is a small hand-written answer, because
no npm response was recorded; the test says so. execv is recorded, not run.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.intercept import path_shim
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QuarantineStore
from slopseal.registry.live import LiveSource
from slopseal.verdict import Context

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
RECORDED = REPO / "src" / "tests" / "fixtures" / "live"
SNAPSHOT = REPO / "src" / "slopseal" / "fixtures"
PYPI = "https://pypi.org/pypi"
NPM = "https://registry.npmjs.org"
OSV = "https://api.osv.dev/v1/query"


def _recorded(name: str) -> bytes:
    return (RECORDED / name).read_bytes()


def _pypi_answers() -> dict[str, bytes | Exception]:
    return {
        f"{PYPI}/requests/json": _recorded("pypi_requests.json"),
        f"{PYPI}/requests/2.33.0/json": _recorded("pypi_requests_2.33.0.json"),
        f"{PYPI}/requests/2.34.2/json": _recorded("pypi_requests_2.34.2.json"),
        f"{PYPI}/csv-parser-pro/json": OSError("404 is answered by the test"),
    }


def _fetch_from(answers: dict[str, bytes | Exception]):  # type: ignore[no-untyped-def]
    def fetch(url: str, body: bytes | None) -> bytes | None:
        answer = answers.get(url)
        if answer is None:
            raise OSError(f"no recorded answer for {url}")
        if isinstance(answer, Exception):
            raise answer
        return answer

    return fetch


def _live_source(answers: dict[str, bytes | Exception]) -> LiveSource:
    snapshot = load_snapshot(SNAPSHOT)
    top = {eco: snapshot.top_n(eco) for eco in (Ecosystem.PYPI, Ecosystem.NPM)}
    return LiveSource(top_n=top, fetch=_fetch_from(answers))


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


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    execs: list[list[str]] = []
    monkeypatch.setattr(path_shim.os, "execv", lambda path, argv: execs.append([path, *argv]))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "0")  # live mode
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    state = {"answers": _pypi_answers(), "execs": execs, "tmp": tmp_path}

    def set_context(**kwargs: object) -> None:
        answers = state["answers"]
        assert isinstance(answers, dict)
        if "osv" in kwargs:
            answers[OSV] = kwargs["osv"]  # type: ignore[assignment]
        source = _live_source(answers)
        context = _context(tmp_path, source)
        monkeypatch.setattr(path_shim, "build_context", lambda: context)

    state["set_context"] = set_context
    # A real executable in the test's temp directory. System paths differ across runners.
    real = tmp_path / "real-tool"
    real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real.chmod(0o755)
    state["real"] = str(real)
    state["env"] = {"SLOPSEAL_REAL_PIP": str(real), "SLOPSEAL_REAL_NPM": str(real), "PATH": ""}
    return state


def _audit_events(tmp: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in (tmp / "audit.jsonl").read_text().splitlines()]


def test_live_unpinned_pip_install_is_pinned_verified_and_run(harness: dict[str, object]) -> None:
    harness["set_context"](osv=_recorded("osv_requests_2.34.2.json"))  # type: ignore[operator]
    tmp = harness["tmp"]
    assert isinstance(tmp, Path)
    path_shim.run(["pip", "install", "requests"], harness["env"])  # type: ignore[arg-type]
    assert harness["execs"] == [[harness["real"], "pip", "install", "requests==2.34.2"]]  # type: ignore[index]
    events = _audit_events(tmp)
    resolution = [e for e in events if e["event"] == "resolution"]
    assert len(resolution) == 1
    assert resolution[0]["original_command"] == "pip install requests"
    assert resolution[0]["rewritten_command"] == "pip install requests==2.34.2"
    assert resolution[0]["outcome"] == "ALLOW"
    verdicts = [e for e in events if e["event"] == "verdict"]
    assert verdicts[-1]["version"] == "2.34.2"
    assert verdicts[-1]["outcome"] == "ALLOW"


def test_offline_unpinned_install_is_refused_and_nothing_runs(
    harness: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    code = path_shim.run(["pip", "install", "requests"], harness["env"])  # type: ignore[arg-type]
    assert code == 1
    assert harness["execs"] == []  # type: ignore[comparison-overlap]


@pytest.mark.parametrize("flag_form", ["argument", "environment"])
def test_no_resolve_keeps_the_refusal(
    harness: dict[str, object], monkeypatch: pytest.MonkeyPatch, flag_form: str
) -> None:
    harness["set_context"](osv=_recorded("osv_requests_2.33.0.json"))  # type: ignore[operator]
    env = dict(harness["env"])  # type: ignore[arg-type]
    if flag_form == "argument":
        argv = ["pip", "--no-resolve", "install", "requests"]
    else:
        env["SLOPSEAL_NO_RESOLVE"] = "1"
        argv = ["pip", "install", "requests"]
    assert path_shim.run(argv, env) == 1
    assert harness["execs"] == []  # type: ignore[comparison-overlap]


def test_unresolvable_latest_version_is_refused_and_audited(harness: dict[str, object]) -> None:
    harness["set_context"]()  # type: ignore[operator]  # no OSV or PyPI answer for this name
    tmp = harness["tmp"]
    assert isinstance(tmp, Path)
    code = path_shim.run(["pip", "install", "csv-parser-pro"], harness["env"])  # type: ignore[arg-type]
    assert code == 1
    assert harness["execs"] == []  # type: ignore[comparison-overlap]
    resolution = [e for e in _audit_events(tmp) if e["event"] == "resolution"]
    assert resolution
    assert resolution[-1]["outcome"] == "BLOCK"


def test_resolved_version_that_fails_verification_does_not_run(harness: dict[str, object]) -> None:
    malicious = {
        "vulns": [{"id": "MAL-2026-0001", "summary": "fixture malicious", "database_specific": {}}]
    }
    harness["set_context"](osv=json.dumps(malicious).encode())  # type: ignore[operator]  # 2.34.2
    tmp = harness["tmp"]
    assert isinstance(tmp, Path)
    code = path_shim.run(["pip", "install", "requests"], harness["env"])  # type: ignore[arg-type]
    assert code == 1
    assert harness["execs"] == []  # type: ignore[comparison-overlap]
    resolution = [e for e in _audit_events(tmp) if e["event"] == "resolution"]
    assert resolution[-1]["outcome"] == "BLOCK"
    assert resolution[-1]["rewritten_command"] == "pip install requests==2.34.2"


def test_already_pinned_install_is_not_rewritten_or_logged(harness: dict[str, object]) -> None:
    harness["set_context"](osv=_recorded("osv_requests_2.33.0.json"))  # type: ignore[operator]
    tmp = harness["tmp"]
    assert isinstance(tmp, Path)
    path_shim.run(["pip", "install", "requests==2.33.0"], harness["env"])  # type: ignore[arg-type]
    assert harness["execs"] == [[harness["real"], "pip", "install", "requests==2.33.0"]]  # type: ignore[index]
    assert not [e for e in _audit_events(tmp) if e["event"] == "resolution"]


def test_live_unpinned_npm_install_is_resolved_with_an_npm_answer(
    harness: dict[str, object],
) -> None:
    """Hand-written npm packument (no npm response was recorded). OSV answers {} (no advisory)."""
    packument = {
        "time": {"created": "2018-01-01T00:00:00.000Z"},
        "dist-tags": {"latest": "1.4.0"},
        "versions": {"1.4.0": {"license": "ISC", "scripts": {}}},
    }
    answers = _pypi_answers()
    answers[f"{NPM}/uuidkit"] = json.dumps(packument).encode()
    answers[OSV] = b"{}"
    snapshot = load_snapshot(SNAPSHOT)
    top = {eco: snapshot.top_n(eco) for eco in (Ecosystem.PYPI, Ecosystem.NPM)}
    tmp = harness["tmp"]
    assert isinstance(tmp, Path)
    context = _context(tmp, LiveSource(top_n=top, fetch=_fetch_from(answers)))
    with mock.patch.object(path_shim, "build_context", return_value=context):
        path_shim.run(["npm", "install", "uuidkit"], harness["env"])  # type: ignore[arg-type]
    assert harness["execs"] == [[harness["real"], "npm", "install", "uuidkit@1.4.0"]]  # type: ignore[index]
