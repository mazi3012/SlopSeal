"""Unit tests for the pipeline's order of steps (R-C-1, R-C-4, R-C-6). Property: P-C-3, P-C-6.

The extractor is an injected stub here. The archive check and the fetch are injected too, so the
tests check the order, not the subprocess. Requirements: R-C-1, R-C-4, R-C-6.
"""

from __future__ import annotations

import hashlib
import io
import tempfile
import zipfile
from pathlib import Path

from slopseal.contract import cache
from slopseal.contract.digest import PublishedDigest
from slopseal.contract.pipeline import obtain_contract
from slopseal.contract.runner import ArchiveOk
from slopseal.contract.types import (
    ContractComplete,
    ContractDigestMismatch,
    ContractUnknown,
    UnknownReason,
)
from slopseal.core.types import Ecosystem

WHEEL = io.BytesIO()
with zipfile.ZipFile(WHEEL, "w") as _archive:
    _archive.writestr("pkg/__init__.py", b"def parse(): pass\n")
GOOD = WHEEL.getvalue()
PUBLISHED = PublishedDigest("sha256", hashlib.sha256(GOOD).hexdigest())
URL = "https://files.pythonhosted.org/packages/p/pkg-1.0-py3-none-any.whl"


class Recorder:
    def __init__(self, returns: object = None) -> None:
        self.calls: list[str] = []
        self._returns = returns

    def fetch(self, url: str, ecosystem: Ecosystem) -> object:
        self.calls.append("fetch")
        return self._returns if self._returns is not None else GOOD

    def archive(self, path: Path, kind: str) -> object:
        self.calls.append("archive")
        return ArchiveOk("")

    def extract(self, path: Path, kind: str, root: str) -> object:
        self.calls.append("extract")
        return ContractComplete(("parse",))


def _run(root: Path, recorder: Recorder, published: object = PUBLISHED) -> object:
    return obtain_contract(
        Ecosystem.PYPI,
        URL,
        published,  # type: ignore[arg-type]
        kind="wheel",
        cache_root=root,
        extract=recorder.extract,  # type: ignore[arg-type]
        fetch=recorder.fetch,  # type: ignore[arg-type]
        archive_check=recorder.archive,  # type: ignore[arg-type]
    )


def test_r_c_1_the_happy_path_runs_in_order_and_caches_the_result() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        recorder = Recorder()
        result = _run(root, recorder)
        assert result == ContractComplete(("parse",))
        assert recorder.calls == ["fetch", "archive", "extract"]
        assert cache.load(root, f"sha256-{PUBLISHED.hexdigest}") == ContractComplete(("parse",))


def test_r_c_6_a_cache_hit_makes_no_download() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _run(root, Recorder())
        second = Recorder()
        assert _run(root, second) == ContractComplete(("parse",))
        assert second.calls == []


def test_r_c_1_a_digest_mismatch_blocks_before_the_archive_is_read_and_caches_nothing() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        recorder = Recorder(returns=GOOD + b"tampered")
        result = _run(root, recorder)
        assert isinstance(result, ContractDigestMismatch)
        assert recorder.calls == ["fetch"]  # no archive check and no extraction
        assert not (root / cache.CACHE_DIR).exists()


def test_r_c_1_a_download_error_is_network_and_nothing_else_runs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        recorder = Recorder(returns=ContractUnknown(UnknownReason.NETWORK, "down"))
        result = _run(Path(tmp), recorder)
        assert result == ContractUnknown(UnknownReason.NETWORK, "down")
        assert recorder.calls == ["fetch"]


def test_r_c_1_an_unusable_published_digest_is_no_digest_and_nothing_else_runs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        recorder = Recorder()
        result = _run(
            Path(tmp), recorder, published=ContractUnknown(UnknownReason.NO_DIGEST, "none")
        )
        assert result == ContractUnknown(UnknownReason.NO_DIGEST, "none")
        assert recorder.calls == []
