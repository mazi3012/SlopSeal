"""Package source gateway: the serve-only-ALLOW rules (R-GW-1 to R-GW-5).

The verdict is the real `verify_install` on the offline snapshot. The upstream is a fake, so no
test reaches a registry. Where a verdict must be a particular outcome, a stub `verify` returns it.
Requirements: R-GW-1, R-GW-2, R-GW-3, R-GW-4, R-GW-5.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from http import HTTPStatus
from pathlib import Path

import pytest

from slopseal.core.types import Ecosystem
from slopseal.gateway.server import (
    Artifact,
    Route,
    handle_artifact,
    make_server,
    parse_route,
)
from slopseal.quarantine.rate_limit import RateLimiter
from slopseal.runtime import build_context
from slopseal.verdict import Decision, Outcome

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
BODY = b"wheel bytes for csv-parser 1.2.0"
DIGEST = hashlib.sha256(BODY).hexdigest()


class FakeUpstream:
    """A stand-in registry adapter. It records what the gateway asked for."""

    def __init__(
        self,
        artifact: Artifact | None | str = "default",
        data: bytes = BODY,
        fetch_error: BaseException | None = None,
    ) -> None:
        self._artifact = (
            Artifact("https://files.example/csv-parser.whl", DIGEST)
            if artifact == "default"
            else artifact
        )
        self._data = data
        self._fetch_error = fetch_error
        self.resolved: list[tuple[str, str, str]] = []
        self.fetched: list[str] = []

    def artifact(self, eco: Ecosystem, name: str, version: str) -> Artifact | None:
        self.resolved.append((eco.value, name, version))
        return self._artifact

    def fetch(self, url: str) -> bytes:
        self.fetched.append(url)
        if self._fetch_error is not None:
            raise self._fetch_error
        return self._data


@pytest.fixture
def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.setenv("SLOPSEAL_SNAPSHOT_DIR", str(FIXTURES))
    return build_context(tmp_path / "state", rate_limited=False)


def _route(name: str = "csv-parser", version: str = "1.2.0", eco: str = "pypi") -> Route:
    return Route(eco, name, version)


def _stub(outcome: Outcome, reason: str = "stub") -> object:
    def verify(request, context):  # type: ignore[no-untyped-def]
        return Decision(
            outcome=outcome,
            ecosystem=request.ecosystem.value,
            package=request.package,
            version=request.version or "",
            reason=reason,
            quarantine_id="qs_stub" if outcome is Outcome.QUARANTINE else None,
        )

    return verify


# ---- route parsing (R-GW-1, input validation) ------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/v1/pypi/csv-parser/1.2.0/artifact", Route("pypi", "csv-parser", "1.2.0")),
        ("/v1/npm/%40scope%2Fpkg/2.0.0/artifact", Route("npm", "@scope/pkg", "2.0.0")),
        ("/v1/pypi/csv-parser/1.2.0/artifact?x=1", Route("pypi", "csv-parser", "1.2.0")),
    ],
)
def test_valid_routes_parse(path: str, expected: Route) -> None:
    assert parse_route(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/v1/cargo/serde/1.0.0/artifact",  # ecosystem outside v1
        "/v1/pypi/csv-parser/>=1.0/artifact",  # not an exact version
        "/v1/npm/@scope/pkg/2.0.0/artifact",  # unencoded slash splits the route
        "/v1/pypi/csv-parser/1.2.0",  # missing the artifact segment
        "/v1/pypi/csv parser/1.2.0/artifact",  # invalid name
        "/v2/pypi/csv-parser/1.2.0/artifact",  # wrong version prefix
        "/",
    ],
)
def test_invalid_routes_are_refused(path: str) -> None:
    assert parse_route(path) is None


# ---- ALLOW: bytes only with a matching digest (R-GW-1, R-GW-2) -------------------------------


def test_allow_with_matching_digest_serves_the_bytes(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream()
    response = handle_artifact(ctx, upstream, _route())
    assert response.status == HTTPStatus.OK
    assert response.body == BODY
    assert upstream.fetched == ["https://files.example/csv-parser.whl"]


def test_digest_mismatch_sends_no_bytes(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream(data=b"tampered bytes")
    response = handle_artifact(ctx, upstream, _route())
    assert response.status == HTTPStatus.BAD_GATEWAY
    assert json.loads(response.body)["outcome"] == "DIGEST_MISMATCH"
    assert b"tampered" not in response.body


def test_missing_published_digest_is_refused_before_fetching(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream(artifact=Artifact("https://files.example/x.whl", None))
    response = handle_artifact(ctx, upstream, _route())
    assert response.status == HTTPStatus.FORBIDDEN
    assert json.loads(response.body)["outcome"] == "NO_DIGEST"
    assert upstream.fetched == []


def test_no_artifact_is_not_found(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream(artifact=None)
    response = handle_artifact(ctx, upstream, _route())
    assert response.status == HTTPStatus.NOT_FOUND
    assert upstream.fetched == []


def test_upstream_error_is_bad_gateway_with_no_bytes(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream(fetch_error=TimeoutError("registry timed out"))
    response = handle_artifact(ctx, upstream, _route())
    assert response.status == HTTPStatus.BAD_GATEWAY
    assert response.body != BODY


# ---- refusals: BLOCK, QUARANTINE, RATE_LIMITED never send bytes (R-GW-1) ---------------------


def test_block_verdict_sends_no_bytes_and_does_not_resolve(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream()
    response = handle_artifact(ctx, upstream, _route(name="flsk", version="1.0.0"))
    body = json.loads(response.body)
    assert response.status == HTTPStatus.FORBIDDEN
    assert body["outcome"] == "BLOCK"
    assert body["check"] == "typosquat"
    assert "next" in body
    assert upstream.resolved == []
    assert upstream.fetched == []


def test_quarantine_verdict_sends_no_bytes_and_names_the_id(ctx) -> None:  # type: ignore[no-untyped-def]
    upstream = FakeUpstream()
    response = handle_artifact(ctx, upstream, _route(), verify=_stub(Outcome.QUARANTINE))
    body = json.loads(response.body)
    assert response.status == HTTPStatus.FORBIDDEN
    assert body["outcome"] == "QUARANTINE"
    assert body["quarantine_id"] == "qs_stub"
    assert upstream.fetched == []


def test_rate_limited_request_sends_no_bytes(ctx, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    limited = replace(ctx, limiter=RateLimiter(tmp_path / "state", 1))
    upstream = FakeUpstream()
    first = handle_artifact(limited, upstream, _route())
    second = handle_artifact(limited, upstream, _route())
    assert first.status == HTTPStatus.OK
    body = json.loads(second.body)
    assert second.status == HTTPStatus.FORBIDDEN
    assert body["check"] == "rate_limit"
    assert "Do not change the package" in body["next"]
    assert len(upstream.fetched) == 1  # only the allowed request fetched bytes


# ---- counted and audited (R-GW-5) -----------------------------------------------------------


def test_every_gateway_request_is_written_to_the_audit_log(ctx, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    handle_artifact(ctx, FakeUpstream(), _route())
    handle_artifact(ctx, FakeUpstream(), _route(name="flsk", version="1.0.0"))
    lines = (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    verdicts = [json.loads(x) for x in lines if '"event": "verdict"' in x]
    assert [v["outcome"] for v in verdicts] == ["ALLOW", "BLOCK"]


# ---- binding (R-GW-4) -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "192.168.1.10", "example.com"],  # noqa: S104 - the refusal is under test
)
def test_non_loopback_bind_is_refused_by_default(ctx, host: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="loopback"):
        make_server(host, 0, ctx, FakeUpstream())
