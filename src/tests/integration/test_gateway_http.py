"""Package source gateway over real HTTP on loopback (R-GW-1 to R-GW-4).

The server runs in a thread on 127.0.0.1 with an OS-chosen port. The verdict is the real
`verify_install` on the offline snapshot. The upstream is a fake, so nothing leaves the machine.
Requirements: R-GW-1, R-GW-2, R-GW-3, R-GW-4.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from slopseal.gateway.server import Artifact, make_server
from slopseal.runtime import build_context
from slopseal.verdict import Decision

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
BODY = b"wheel bytes for csv-parser 1.2.0"


class FakeUpstream:
    def artifact(self, eco, name, version):  # type: ignore[no-untyped-def]
        return Artifact("https://files.example/csv-parser.whl", hashlib.sha256(BODY).hexdigest())

    def fetch(self, url: str) -> bytes:
        return BODY


class BrokenUpstream(FakeUpstream):
    def fetch(self, url: str) -> bytes:
        raise TimeoutError("registry timed out")


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Start a gateway on loopback and yield its base URL. The server is stopped afterwards."""
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.setenv("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES))
    ctx = build_context(tmp_path / "state", rate_limited=False)
    server = make_server("127.0.0.1", 0, ctx, FakeUpstream())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _get(url: str) -> tuple[int, bytes, str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - loopback only
            return response.status, response.read(), response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers.get("Content-Type", "")


def test_allowed_package_is_served_over_http(gateway: str) -> None:
    status, body, content_type = _get(f"{gateway}/v1/pypi/csv-parser/1.2.0/artifact")
    assert status == 200
    assert body == BODY
    assert content_type == "application/octet-stream"


def test_blocked_package_gets_403_json_and_no_bytes(gateway: str) -> None:
    status, body, content_type = _get(f"{gateway}/v1/pypi/flsk/1.0.0/artifact")
    payload = json.loads(body)
    assert status == 403
    assert content_type == "application/json"
    assert payload["outcome"] == "BLOCK"
    assert payload["check"] == "typosquat"
    assert BODY not in body


def test_bad_route_gets_422(gateway: str) -> None:
    status, body, _ = _get(f"{gateway}/v1/pypi/csv-parser/%3E%3D1.0/artifact")
    assert status == 422
    assert json.loads(body)["outcome"] == "INVALID_REQUEST"


def test_wrong_method_is_not_served(gateway: str) -> None:
    request = urllib.request.Request(  # noqa: S310 - loopback only
        f"{gateway}/v1/pypi/csv-parser/1.2.0/artifact", data=b"x", method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=10)  # noqa: S310 - loopback only
    assert error.value.code >= 400


def test_upstream_failure_over_http_gets_502_and_no_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.setenv("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES))
    ctx = build_context(tmp_path / "state", rate_limited=False)
    server = make_server("127.0.0.1", 0, ctx, BrokenUpstream())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        status, body, _ = _get(f"http://{host}:{port}/v1/pypi/csv-parser/1.2.0/artifact")
        assert status == 502
        assert BODY not in body
    finally:
        server.shutdown()
        server.server_close()


def test_unexpected_verifier_error_gets_503_and_no_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.setenv("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES))
    ctx = build_context(tmp_path / "state", rate_limited=False)

    def failing_verify(request, context) -> Decision:  # type: ignore[no-untyped-def]
        raise OSError("state directory vanished")

    server = make_server("127.0.0.1", 0, ctx, FakeUpstream(), verify=failing_verify)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        status, body, _ = _get(f"http://{host}:{port}/v1/pypi/csv-parser/1.2.0/artifact")
        assert status == 503
        assert json.loads(body)["outcome"] == "GATEWAY_ERROR"
        assert BODY not in body
    finally:
        server.shutdown()
        server.server_close()
