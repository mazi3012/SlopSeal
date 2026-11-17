"""Verdict-level tests for the typed reasons limit, network, and no_digest (R-C-5, R-C-8).

Each test runs verify_install with a live contract path, and asserts the BLOCK, exit 1, the typed
reason in the decision and the audit line, and that the verdict never gives QUARANTINE or ALLOW.

The L1 facts (existence, scripts, CVE, and so on) come from the checksummed snapshot, through
`LiveContractSource`. Only the contract comes from `LiveSource`, with a fake registry and an
injected artifact fetch, so no test touches the network.

Requirements: R-C-5, R-C-8. Property: P-C-2 (UNKNOWN never allows).
"""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import tempfile
import urllib.error
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.contract.fetch import download
from slopseal.contract.types import ContractResult, ContractUnknown, UnknownReason
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.policy.loader import load_policy
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry.live import LiveSource
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
AS_OF = datetime(2026, 11, 18, tzinfo=UTC)
VERSION_PATH = "/csv-parser/1.2.0/json"
ARTIFACT_URL = "https://files.pythonhosted.org/packages/c/csv_parser-1.2.0-py3-none-any.whl"


class LiveContractSource(OfflineSource):
    """L1 facts from the snapshot. The contract comes from the live source under test."""

    def __init__(self, snapshot: object, live: LiveSource) -> None:
        super().__init__(snapshot)  # type: ignore[arg-type]
        self._live = live

    def contract(self, eco: Ecosystem, name: str, version: str) -> ContractResult:
        return self._live.contract(eco, name, version)


class _Body:
    """A response for download(): status 200 and fixed bytes."""

    status = 200

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def read(self, amount: int = -1) -> bytes:
        return self._data.read(amount)

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _refuse(request: object, timeout: float) -> _Body:
    raise urllib.error.URLError("connection refused")


def _wheel_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("csv_parser/__init__.py", b"reader = None\n")
    return buffer.getvalue()


def _version_json(digests: dict[str, str]) -> bytes:
    document: dict[str, Any] = {
        "urls": [
            {
                "filename": "csv_parser-1.2.0-py3-none-any.whl",
                "url": ARTIFACT_URL,
                "packagetype": "bdist_wheel",
                "digests": digests,
            }
        ]
    }
    return json.dumps(document).encode("utf-8")


def _registry(body: bytes) -> Any:
    """A fake registry: the version document for csv-parser 1.2.0, and nothing else."""

    def fetch(url: str, _body: bytes | None) -> bytes | None:
        if url.endswith(VERSION_PATH):
            return body
        raise OSError("no network in this test")

    return fetch


def _context(state: Path, source: OfflineSource, now: datetime = AS_OF) -> Context:
    counter = itertools.count(1)
    return Context(
        policy=load_policy(str(POLICY)),
        source=source,
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", load_or_create_key(state)),
        now=now,
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
    )


def _request() -> InstallRequest:
    return InstallRequest(
        ecosystem=Ecosystem.PYPI,
        package="csv-parser",
        version="1.2.0",
        intent=Intent(purpose="parse CSV", expected_api="csv.reader"),
    )


def _audit_records(state: Path) -> list[dict[str, Any]]:
    lines = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def _assert_typed_block(decision: Any, state: Path, reason: UnknownReason) -> None:
    assert decision.outcome is Outcome.BLOCK
    assert decision.exit_code == 1
    assert decision.violation is not None
    assert decision.violation.check == "api_surface"
    assert f"(reason: {reason.value})" in decision.violation.reason
    assert decision.quarantine_payload is None
    records = [r for r in _audit_records(state) if _contains_key(r, "unknown_reason")]
    assert records, "the audit line must carry the typed reason"
    assert any(r.get("fields", r).get("unknown_reason") == reason.value for r in records)


def test_r_c_5_limit_blocks_with_exit_1_at_the_verdict() -> None:
    """An artifact over the compressed limit is limit. The verdict is BLOCK, exit 1."""
    snapshot = load_snapshot(FIXTURES)
    live = LiveSource(
        fetch=_registry(_version_json({"sha256": "ab" * 32})),
        artifact_fetch=lambda url, eco: download(url, eco, max_bytes=8, opener=_serve(b"x" * 64)),
    )
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        decision = verify_install(_request(), _context(state, LiveContractSource(snapshot, live)))
        _assert_typed_block(decision, state, UnknownReason.LIMIT)


def test_r_c_5_network_blocks_with_exit_1_at_the_verdict() -> None:
    """A failed artifact download is network. The verdict is BLOCK, exit 1."""
    snapshot = load_snapshot(FIXTURES)
    live = LiveSource(
        fetch=_registry(_version_json({"sha256": "ab" * 32})),
        artifact_fetch=lambda url, eco: download(url, eco, opener=_refuse),
    )
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        decision = verify_install(_request(), _context(state, LiveContractSource(snapshot, live)))
        _assert_typed_block(decision, state, UnknownReason.NETWORK)


def test_r_c_5_no_digest_blocks_with_exit_1_and_downloads_nothing() -> None:
    """A registry with no usable digest is no_digest. No artifact is downloaded."""
    snapshot = load_snapshot(FIXTURES)
    downloads: list[str] = []

    def artifact_fetch(url: str, eco: Ecosystem) -> bytes | ContractUnknown:
        downloads.append(url)
        return _wheel_bytes()

    live = LiveSource(fetch=_registry(_version_json({})), artifact_fetch=artifact_fetch)
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        decision = verify_install(_request(), _context(state, LiveContractSource(snapshot, live)))
        _assert_typed_block(decision, state, UnknownReason.NO_DIGEST)
    assert downloads == []


def _serve(data: bytes) -> Any:
    def open_request(request: object, timeout: float) -> _Body:
        return _Body(data)

    return open_request


def test_r_c_8_live_path_verifies_the_digest_and_stops_at_the_extraction_step() -> None:
    """With a matching digest, the live path downloads and verifies, then returns UNKNOWN.

    The extraction step is a stub until R-C-2 lands, so the result is never a complete contract.
    The cache receives nothing. `exports()` stays None.
    """
    data = _wheel_bytes()
    digest = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "contracts"
        live = LiveSource(
            fetch=_registry(_version_json({"sha256": digest})),
            artifact_fetch=lambda url, eco: download(url, eco, opener=_serve(data)),
            cache_root=cache,
        )
        result = live.contract(Ecosystem.PYPI, "csv-parser", "1.2.0")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR
        assert live.exports(Ecosystem.PYPI, "csv-parser", "1.2.0") is None
        assert not cache.exists() or list(cache.iterdir()) == []


def test_r_c_8_a_registry_digest_mismatch_blocks_with_exit_1() -> None:
    """A downloaded artifact that does not match the registry digest is HARD_BLOCK, exit 1."""
    snapshot = load_snapshot(FIXTURES)
    live = LiveSource(
        fetch=_registry(_version_json({"sha256": "00" * 32})),
        artifact_fetch=lambda url, eco: download(url, eco, opener=_serve(_wheel_bytes())),
    )
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        decision = verify_install(_request(), _context(state, LiveContractSource(snapshot, live)))
        assert decision.outcome is Outcome.BLOCK
        assert decision.exit_code == 1
        assert decision.violation is not None
        assert decision.violation.check == "contract_digest"
