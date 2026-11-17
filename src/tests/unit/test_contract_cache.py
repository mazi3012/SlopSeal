"""Unit tests for the contract cache (R-C-6). Property: P-C-6.

Requirements: R-C-6. The 100 ms bound on a hit is measured here on the same machine.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path

import pytest

from slopseal.contract import cache
from slopseal.contract.digest import PublishedDigest, VerifiedDigest
from slopseal.contract.limits import CACHE_HIT_MILLISECONDS
from slopseal.contract.types import ContractComplete

DATA = b"wheel bytes"
KEY_HEX = hashlib.sha256(DATA).hexdigest()
KEY = f"sha256-{KEY_HEX}"
EXPORTS = ("parse", "parse_file")


def _verified() -> VerifiedDigest:
    from slopseal.contract.digest import verify_artifact

    result = verify_artifact(DATA, PublishedDigest("sha256", KEY_HEX))
    assert isinstance(result, VerifiedDigest)
    return result


def test_r_c_6_store_then_load_returns_the_same_exports() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        assert cache.load(root, KEY) == ContractComplete(EXPORTS)


def test_r_c_6_only_a_verified_digest_can_be_stored() -> None:
    with tempfile.TemporaryDirectory() as tmp, pytest.raises(TypeError):
        cache.store(Path(tmp), KEY, EXPORTS)  # type: ignore[arg-type]


def test_r_c_6_a_cache_hit_returns_within_the_bound() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        timings = []
        for _ in range(5):
            start = time.perf_counter()
            assert cache.load(root, KEY) == ContractComplete(EXPORTS)
            timings.append((time.perf_counter() - start) * 1000)
        assert min(timings) < CACHE_HIT_MILLISECONDS


def test_r_c_6_an_entry_with_a_wrong_hash_is_discarded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        path = root / cache.CACHE_DIR / f"{KEY}.json"
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["exports"] = ["evil"]
        path.write_text(json.dumps(entry), encoding="utf-8")
        assert cache.load(root, KEY) is None
        assert not path.exists()


def test_r_c_6_an_entry_from_another_extractor_version_is_discarded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        path = root / cache.CACHE_DIR / f"{KEY}.json"
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["extractor_version"] = "contract-extractor/old"
        del entry["entry_sha256"]
        entry["entry_sha256"] = cache._entry_hash(
            {k: v for k, v in entry.items() if k != "entry_sha256"}
        )
        path.write_text(json.dumps(entry), encoding="utf-8")
        assert cache.load(root, KEY) is None
        assert not path.exists()


def test_r_c_6_a_malformed_key_never_reaches_the_file_system() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for key in (
            "../escape",
            "sha256-../../x",
            "SHA256-" + KEY_HEX,
            "md5-" + KEY_HEX,
            "sha256-" + "A" * 64,
            "sha256-ab",
        ):
            assert cache.load(root, key) is None
        assert not (root / cache.CACHE_DIR).exists()


def test_r_c_6_an_unknown_export_name_in_an_entry_is_discarded() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        path = root / cache.CACHE_DIR / f"{KEY}.json"
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["exports"] = ["has space"]
        entry["entry_sha256"] = cache._entry_hash(
            {k: v for k, v in entry.items() if k != "entry_sha256"}
        )
        path.write_text(json.dumps(entry), encoding="utf-8")
        assert cache.load(root, KEY) is None
