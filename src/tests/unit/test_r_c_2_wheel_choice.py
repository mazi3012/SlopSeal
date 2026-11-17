"""R-C-2: which artifact the live source picks for a PyPI version.

A `none-any` wheel is preferred. Otherwise the first wheel filename in ascending byte order is
used. A version with only an sdist is UNKNOWN with reason sdist_only, and the sdist is never
downloaded. The download is replaced by a recorder, so no test touches the network.

Requirements: R-C-2. Property: P-C-2 (UNKNOWN never allows) is checked at the verdict in P-C-8.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from slopseal.contract.types import ContractUnknown, UnknownReason
from slopseal.core.types import Ecosystem
from slopseal.registry.live import LiveSource

DIGEST = {"sha256": "ab" * 32}
VERSION_PATH = "/pkg/1.0/json"


def _file(filename: str, packagetype: str = "bdist_wheel") -> dict[str, object]:
    return {
        "filename": filename,
        "url": f"https://files.pythonhosted.org/packages/x/{filename}",
        "packagetype": packagetype,
        "digests": DIGEST,
    }


def _source(files: list[dict[str, object]], fetched: list[str]) -> LiveSource:
    body = json.dumps({"urls": files}).encode("utf-8")

    def fetch(url: str, _body: bytes | None) -> bytes | None:
        if url.endswith(VERSION_PATH):
            return body
        raise OSError("no network in this test")

    def artifact_fetch(url: str, eco: Ecosystem) -> ContractUnknown:
        fetched.append(url)
        return ContractUnknown(UnknownReason.NETWORK, "recorded, not downloaded")

    return LiveSource(fetch=fetch, artifact_fetch=artifact_fetch, cache_root=None)


def test_r_c_2_a_none_any_wheel_is_preferred() -> None:
    fetched: list[str] = []
    files = [
        _file("pkg-1.0-cp311-cp311-linux_x86_64.whl"),
        _file("pkg-1.0-py3-none-any.whl"),
        _file("pkg-1.0-cp310-cp310-linux_x86_64.whl"),
    ]
    _source(files, fetched).contract(Ecosystem.PYPI, "pkg", "1.0")
    assert fetched == ["https://files.pythonhosted.org/packages/x/pkg-1.0-py3-none-any.whl"]


def test_r_c_2_without_a_none_any_wheel_the_first_name_in_byte_order_is_used() -> None:
    fetched: list[str] = []
    files = [
        _file("pkg-1.0-cp311-cp311-linux_x86_64.whl"),
        _file("pkg-1.0-cp310-cp310-linux_x86_64.whl"),
    ]
    _source(files, fetched).contract(Ecosystem.PYPI, "pkg", "1.0")
    assert fetched == [
        "https://files.pythonhosted.org/packages/x/pkg-1.0-cp310-cp310-linux_x86_64.whl"
    ]


def test_r_c_2_an_sdist_only_version_is_sdist_only_and_is_not_downloaded() -> None:
    fetched: list[str] = []
    files = [_file("pkg-1.0.tar.gz", packagetype="sdist")]
    result = _source(files, fetched).contract(Ecosystem.PYPI, "pkg", "1.0")
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.SDIST_ONLY
    assert fetched == []


def test_r_c_2_a_version_with_no_files_is_parse_error() -> None:
    fetched: list[str] = []
    result = _source([], fetched).contract(Ecosystem.PYPI, "pkg", "1.0")
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.PARSE_ERROR
    assert fetched == []


def test_r_c_2_the_cache_is_not_written_for_an_unknown_contract() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "contracts"
        files = [_file("pkg-1.0-py3-none-any.whl")]
        body = json.dumps({"urls": files}).encode("utf-8")

        def fetch(url: str, _body: bytes | None) -> bytes | None:
            if url.endswith(VERSION_PATH):
                return body
            raise OSError("no network in this test")

        live = LiveSource(
            fetch=fetch,
            artifact_fetch=lambda url, eco: ContractUnknown(UnknownReason.NETWORK, "recorded"),
            cache_root=root,
        )
        assert live.exports(Ecosystem.PYPI, "pkg", "1.0") is None
        assert not root.exists()
