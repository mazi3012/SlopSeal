"""Tests for the live registry adapter (R-P-3).

A local HTTP server stands in for PyPI, npm, and OSV. The tests use the real urllib code path,
including timeouts, status codes, size limits, and malformed bodies. Nothing reaches the
internet. Each failure must become an explicit unknown value, never a safe default.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.advisory import Advisories, AdvisoryUnknown, Severity
from slopseal.core.install_scripts import InstallScript, ScriptsUnknown
from slopseal.core.license import LicenseUnknown
from slopseal.core.maintainer import MaintainersNotPublished
from slopseal.core.types import Ecosystem, RegistryMissing, RegistryRecord, RegistryUnknown
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QuarantineStore
from slopseal.registry import live
from slopseal.registry.live import LiveSource
from slopseal.verdict import Context, InstallRequest, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"


@dataclass
class Route:
    status: int = 200
    body: bytes = b"{}"
    delay: float = 0.0


@dataclass
class Fake:
    routes: dict[str, Route] = field(default_factory=dict)
    posts: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


@pytest.fixture
def fake() -> Iterator[tuple[Fake, str]]:
    state = Fake()

    class Handler(BaseHTTPRequestHandler):
        def _serve(self, body: bytes | None) -> None:
            route = state.routes.get(self.path, Route(status=404, body=b"{}"))
            if route.delay:
                time.sleep(route.delay)
            if body is not None:
                state.posts.append((self.path, json.loads(body)))
            self.send_response(route.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(route.body)))
            self.end_headers()
            self.wfile.write(route.body)

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            self._serve(None)

        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            length = int(self.headers.get("Content-Length", "0"))
            self._serve(self.rfile.read(length))

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


def _source(base: str, **kwargs: Any) -> LiveSource:
    return LiveSource(
        pypi_base=f"{base}/pypi",
        npm_base=f"{base}/npm",
        osv_url=f"{base}/osv",
        **kwargs,
    )


def _json_body(data: object) -> bytes:
    return json.dumps(data).encode("utf-8")


PYPI_REQUESTS = {
    "info": {
        "version": "2.32.3",
        "license": "Apache-2.0",
        "classifiers": [],
    },
    "releases": {
        "2.31.0": [{"upload_time_iso_8601": "2023-05-22T15:12:44.173Z", "filename": "a.tar.gz"}],
        "2.32.3": [
            {
                "upload_time_iso_8601": "2024-05-29T15:37:47.027Z",
                "filename": "r-2.32.3-py3-none-any.whl",
            },
            {
                "upload_time_iso_8601": "2024-05-29T15:37:48.000Z",
                "filename": "requests-2.32.3.tar.gz",
            },
        ],
        "9.9.9-empty": [],
    },
}


# ---- existence and versions ----------------------------------------------------------------


def test_pypi_record_has_earliest_publish_time_and_nonempty_release_count(
    fake: tuple[Fake, str],
) -> None:
    state, base = fake
    state.routes["/pypi/requests/json"] = Route(body=_json_body(PYPI_REQUESTS))
    result = _source(base).registry_result(Ecosystem.PYPI, "requests")
    assert isinstance(result, RegistryRecord)
    assert result.first_published == datetime(2023, 5, 22, 15, 12, 44, 173000, tzinfo=UTC)
    assert result.release_count == 2


def test_pypi_404_is_missing_not_unknown(fake: tuple[Fake, str]) -> None:
    _, base = fake
    result = _source(base).registry_result(Ecosystem.PYPI, "csv-parser-pro")
    assert isinstance(result, RegistryMissing)


@pytest.mark.parametrize(
    "route",
    [
        Route(status=500, body=b"{}"),
        Route(status=200, body=b"not json"),
        Route(status=200, body=_json_body({"info": {}})),
        Route(status=200, body=_json_body({"releases": {"1.0": [{"filename": "x"}]}})),
    ],
    ids=["server-error", "malformed-json", "missing-releases", "missing-publish-time"],
)
def test_bad_registry_responses_are_unknown(fake: tuple[Fake, str], route: Route) -> None:
    state, base = fake
    state.routes["/pypi/requests/json"] = route
    result = _source(base).registry_result(Ecosystem.PYPI, "requests")
    assert isinstance(result, RegistryUnknown)


def test_timeout_is_unknown(fake: tuple[Fake, str]) -> None:
    state, base = fake
    state.routes["/pypi/requests/json"] = Route(body=_json_body(PYPI_REQUESTS), delay=2.0)
    started = time.monotonic()
    result = _source(base, timeout=0.2).registry_result(Ecosystem.PYPI, "requests")
    assert isinstance(result, RegistryUnknown)
    assert time.monotonic() - started < 1.5


def test_connection_refused_is_unknown() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    source = _source(f"http://127.0.0.1:{closed_port}", timeout=2.0)
    assert isinstance(source.registry_result(Ecosystem.PYPI, "requests"), RegistryUnknown)


def test_oversized_body_is_unknown(fake: tuple[Fake, str], monkeypatch: pytest.MonkeyPatch) -> None:
    state, base = fake
    monkeypatch.setattr(live, "MAX_BYTES", 64)
    state.routes["/pypi/requests/json"] = Route(body=_json_body(PYPI_REQUESTS))
    assert isinstance(_source(base).registry_result(Ecosystem.PYPI, "requests"), RegistryUnknown)


def test_npm_record_uses_time_created_and_scoped_names(fake: tuple[Fake, str]) -> None:
    state, base = fake
    packument = {
        "time": {"created": "2011-03-15T14:48:23.315Z"},
        "versions": {"1.0.0": {}, "1.1.0": {}},
        "dist-tags": {"latest": "1.1.0"},
    }
    state.routes["/npm/@scope%2Fpkg"] = Route(body=_json_body(packument))
    result = _source(base).registry_result(Ecosystem.NPM, "@scope/pkg")
    assert isinstance(result, RegistryRecord)
    assert result.release_count == 2
    assert result.first_published == datetime(2011, 3, 15, 14, 48, 23, 315000, tzinfo=UTC)


def test_unsupported_ecosystem_is_unknown(fake: tuple[Fake, str]) -> None:
    _, base = fake
    assert isinstance(_source(base).registry_result(Ecosystem.CARGO, "serde"), RegistryUnknown)


def test_non_http_scheme_is_refused_before_any_request() -> None:
    source = LiveSource(pypi_base="file:///etc", npm_base="file:///etc")
    assert isinstance(source.registry_result(Ecosystem.PYPI, "requests"), RegistryUnknown)


def test_latest_version_is_none_when_unknown(fake: tuple[Fake, str]) -> None:
    state, base = fake
    state.routes["/pypi/requests/json"] = Route(status=500)
    assert _source(base).latest_version(Ecosystem.PYPI, "requests") is None
    state.routes["/pypi/requests/json"] = Route(body=_json_body(PYPI_REQUESTS))
    assert _source(base).latest_version(Ecosystem.PYPI, "requests") == "2.32.3"


# ---- install-time code ---------------------------------------------------------------------


def test_pypi_universal_wheel_means_no_install_time_code(fake: tuple[Fake, str]) -> None:
    state, base = fake
    state.routes["/pypi/requests/2.32.3/json"] = Route(
        body=_json_body({"urls": PYPI_REQUESTS["releases"]["2.32.3"]})
    )
    assert _source(base).install_scripts(Ecosystem.PYPI, "requests", "2.32.3") == ()


def test_pypi_sdist_only_version_is_unknown(fake: tuple[Fake, str]) -> None:
    state, base = fake
    sdist_only = [{"filename": "pkg-1.0.tar.gz"}]
    state.routes["/pypi/pkg/1.0/json"] = Route(body=_json_body({"urls": sdist_only}))
    result = _source(base).install_scripts(Ecosystem.PYPI, "pkg", "1.0")
    assert isinstance(result, ScriptsUnknown)


def test_pypi_missing_version_is_unknown(fake: tuple[Fake, str]) -> None:
    _, base = fake
    result = _source(base).install_scripts(Ecosystem.PYPI, "requests", "0.0.1")
    assert isinstance(result, ScriptsUnknown)


def test_npm_install_hooks_are_read_from_the_version(fake: tuple[Fake, str]) -> None:
    state, base = fake
    packument = {
        "versions": {
            "1.0.0": {"scripts": {"postinstall": "node setup.js", "test": "jest"}},
            "1.1.0": {"scripts": {}},
        }
    }
    state.routes["/npm/evil"] = Route(body=_json_body(packument))
    source = _source(base)
    assert source.install_scripts(Ecosystem.NPM, "evil", "1.0.0") == (
        InstallScript(hook="postinstall", body="node setup.js"),
    )
    assert source.install_scripts(Ecosystem.NPM, "evil", "1.1.0") == ()
    assert isinstance(source.install_scripts(Ecosystem.NPM, "evil", "9.9.9"), ScriptsUnknown)


# ---- advisories ----------------------------------------------------------------------------


def test_osv_request_names_the_exact_version_and_ecosystem(fake: tuple[Fake, str]) -> None:
    state, base = fake
    state.routes["/osv"] = Route(body=_json_body({}))
    result = _source(base).advisories(Ecosystem.NPM, "react-codeshift", "1.0.0")
    assert result == Advisories(())
    assert state.posts == [
        (
            "/osv",
            {"package": {"name": "react-codeshift", "ecosystem": "npm"}, "version": "1.0.0"},
        )
    ]


def test_osv_malware_and_cve_records_are_mapped(fake: tuple[Fake, str]) -> None:
    state, base = fake
    body = {
        "vulns": [
            {
                "id": "MAL-2026-0001",
                "summary": "known malicious",
                "database_specific": {"severity": "HIGH"},
            },
            {
                "id": "GHSA-x",
                "summary": "prototype pollution",
                "database_specific": {"severity": "CRITICAL"},
            },
            {"id": "GHSA-y"},
        ]
    }
    state.routes["/osv"] = Route(body=_json_body(body))
    result = _source(base).advisories(Ecosystem.NPM, "urlnorm", "0.9.0")
    assert isinstance(result, Advisories)
    ids = [(item.advisory_id, item.severity) for item in result.items]
    assert ids == [
        ("MAL-2026-0001", Severity.HIGH),
        ("GHSA-x", Severity.CRITICAL),
        ("GHSA-y", Severity.UNKNOWN),
    ]


def test_paged_osv_result_is_unknown_not_partial(fake: tuple[Fake, str]) -> None:
    state, base = fake
    state.routes["/osv"] = Route(body=_json_body({"vulns": [], "next_page_token": "abc"}))
    assert isinstance(_source(base).advisories(Ecosystem.PYPI, "x", "1.0"), AdvisoryUnknown)


def test_osv_failure_is_unknown(fake: tuple[Fake, str]) -> None:
    state, base = fake
    state.routes["/osv"] = Route(status=503, body=b"{}")
    assert isinstance(_source(base).advisories(Ecosystem.PYPI, "x", "1.0"), AdvisoryUnknown)


# ---- license and maintainers ---------------------------------------------------------------


def test_pypi_license_from_field_or_classifier(fake: tuple[Fake, str]) -> None:
    state, base = fake
    source = _source(base)
    state.routes["/pypi/a/json"] = Route(
        body=_json_body({"info": {"license": "MIT"}, "releases": {}})
    )
    state.routes["/pypi/b/json"] = Route(
        body=_json_body(
            {
                "info": {
                    "license": "",
                    "classifiers": ["License :: OSI Approved :: Apache Software License"],
                },
                "releases": {},
            }
        )
    )
    state.routes["/pypi/c/json"] = Route(
        body=_json_body({"info": {"license": "x" * 200}, "releases": {}})
    )
    state.routes["/pypi/d/json"] = Route(body=_json_body({"info": {"license": ""}, "releases": {}}))
    assert source.license(Ecosystem.PYPI, "a") == "MIT"
    assert source.license(Ecosystem.PYPI, "b") == "Apache-2.0"
    assert isinstance(source.license(Ecosystem.PYPI, "c"), LicenseUnknown)
    assert source.license(Ecosystem.PYPI, "d") is None


def test_maintainer_age_is_reported_as_not_published_not_as_unknown(
    fake: tuple[Fake, str],
) -> None:
    _, base = fake
    result = _source(base).maintainers(Ecosystem.NPM, "lodash")
    assert isinstance(result, MaintainersNotPublished)


# ---- the verdict in live mode --------------------------------------------------------------


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


def test_live_slopsquat_name_blocks_at_the_existence_check(
    fake: tuple[Fake, str], tmp_path: Path
) -> None:
    _, base = fake  # no route: the registry answers 404
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "csv-parser-pro", "0.1.0"),
        _context(tmp_path, _source(base)),
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "existence"
