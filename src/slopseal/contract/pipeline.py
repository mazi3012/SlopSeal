"""Obtain a contract for one artifact: cache, fetch, verify, safe archive check, extract, cache.

The order is fixed, and the tests check it (R-C-1, R-C-6, P-C-3, P-C-6):

1. A published digest that is unusable gives no_digest, and nothing else runs.
2. A cache hit for that digest returns the stored contract. No download happens.
3. The artifact is downloaded (network or limit errors return here).
4. The digest is verified. A mismatch returns BLOCK here. The archive is not opened.
5. The archive safety check runs in the worker (unsafe or over-limit gives UNKNOWN here).
6. The extractor runs. It is injected, because it lands in a later step.
7. Only a complete contract is written to the cache, and only with a VerifiedDigest.

The extractor is a parameter. A `cache_root` of None turns the cache off for that call.

Requirements: R-C-1, R-C-4, R-C-6. Layer 1 (adapter).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from slopseal.contract import cache
from slopseal.contract.digest import PublishedDigest, verify_artifact
from slopseal.contract.fetch import download
from slopseal.contract.runner import ArchiveOk, run_archive_check
from slopseal.contract.types import (
    ContractComplete,
    ContractDigestMismatch,
    ContractResult,
    ContractUnknown,
)
from slopseal.core.types import Ecosystem

Fetch = Callable[[str, Ecosystem], bytes | ContractUnknown]
ArchiveCheck = Callable[[Path, str], ArchiveOk | ContractUnknown]
Extract = Callable[[Path, str, str], ContractComplete | ContractUnknown]


def fetch_artifact(url: str, ecosystem: Ecosystem) -> bytes | ContractUnknown:
    """The default artifact fetch: the allowlisted, size-capped download of fetch.py."""
    return download(url, ecosystem)


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def obtain_contract(
    ecosystem: Ecosystem,
    artifact_url: str,
    published: PublishedDigest | ContractUnknown,
    *,
    kind: str,
    cache_root: Path | None,
    extract: Extract,
    fetch: Fetch = fetch_artifact,
    archive_check: ArchiveCheck | None = None,
) -> ContractResult:
    if isinstance(published, ContractUnknown):
        return published
    check = archive_check if archive_check is not None else run_archive_check
    if cache_root is not None:
        cached = cache.load(cache_root, f"{published.algorithm}-{published.hexdigest}")
        if cached is not None:
            return cached
    data = fetch(artifact_url, ecosystem)
    if isinstance(data, ContractUnknown):
        return data
    verified = verify_artifact(data, published)
    if isinstance(verified, ContractDigestMismatch):
        return verified
    with tempfile.TemporaryDirectory(prefix="slopseal-contract-") as directory:
        artifact = Path(directory) / "artifact"
        _write_private(artifact, data)
        checked = check(artifact, kind)
        if isinstance(checked, ContractUnknown):
            return checked
        result = extract(artifact, kind, checked.root)
        if isinstance(result, ContractComplete) and cache_root is not None:
            cache.store(cache_root, verified, result.exports)
        return result
