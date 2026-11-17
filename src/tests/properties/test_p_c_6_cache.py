"""P-C-6: the cache never returns a bad entry, and a mismatched download leaves no entry.

Requirements: R-C-6. Hypothesis runs 500 examples per property (conftest.py profile).

A single-byte change to an entry is either a miss or the original exports, never other exports.
A key outside the exact `<algorithm>-<lowercase hex>` form never touches the file system.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from slopseal.contract import cache
from slopseal.contract.digest import PublishedDigest, VerifiedDigest, verify_artifact
from slopseal.contract.types import ContractComplete

DATA = b"cached artifact"
KEY_HEX = hashlib.sha256(DATA).hexdigest()
KEY = f"sha256-{KEY_HEX}"
EXPORTS = ("parse", "parse_file", "read")


def _verified() -> VerifiedDigest:
    result = verify_artifact(DATA, PublishedDigest("sha256", KEY_HEX))
    assert isinstance(result, VerifiedDigest)
    return result


@given(
    position=st.integers(min_value=0, max_value=10_000),
    delta=st.integers(min_value=1, max_value=255),
)
def test_p_c_6_a_one_byte_change_to_an_entry_is_a_miss_or_the_original(
    position: int, delta: int
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        path = root / cache.CACHE_DIR / f"{KEY}.json"
        raw = bytearray(path.read_bytes())
        index = position % len(raw)
        raw[index] = (raw[index] + delta) % 256
        path.write_bytes(bytes(raw))
        result = cache.load(root, KEY)
        assert result is None or result == ContractComplete(EXPORTS)
        if result is None:
            assert not path.exists()


@given(version=st.text(alphabet="abcdefgh/-0123", min_size=1, max_size=12))
def test_p_c_6_another_extractor_version_is_a_miss(version: str) -> None:
    if version == cache.EXTRACTOR_VERSION:
        return
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cache.store(root, _verified(), EXPORTS)
        path = root / cache.CACHE_DIR / f"{KEY}.json"
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["extractor_version"] = version
        entry["entry_sha256"] = cache._entry_hash(
            {k: v for k, v in entry.items() if k != "entry_sha256"}
        )
        path.write_text(json.dumps(entry), encoding="utf-8")
        assert cache.load(root, KEY) is None


@given(
    key=st.sampled_from(
        [
            "../evil",
            "sha256-../evil",
            "sha256-" + "a" * 63,
            "sha256-" + "A" * 64,
            "md5-" + "0" * 32,
            "sha256-" + "0" * 64 + "/x",
            "",
            "sha256-" + "0" * 64 + "\n",
            "sha512-" + "0" * 64,
        ]
    )
)
def test_p_c_6_a_malformed_key_is_a_miss_and_never_touches_the_file_system(key: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        decoy = root / "evil.json"
        decoy.write_text(json.dumps({"key": "../evil"}), encoding="utf-8")
        before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
        assert cache.load(root, key) is None
        assert sorted(str(p.relative_to(root)) for p in root.rglob("*")) == before


def test_p_c_6_a_mismatched_download_leaves_no_entry() -> None:
    """Mutant (d) writes before the digest check; this test finds the file it leaves behind."""
    from slopseal.contract.pipeline import obtain_contract
    from slopseal.contract.types import ContractDigestMismatch
    from slopseal.core.types import Ecosystem

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        result = obtain_contract(
            Ecosystem.PYPI,
            "https://files.pythonhosted.org/packages/p/x.whl",
            PublishedDigest("sha256", KEY_HEX),
            kind="wheel",
            cache_root=root,
            extract=lambda p, k, r: ContractComplete(EXPORTS),
            fetch=lambda url, eco: DATA + b"!",
            archive_check=lambda p, k: None,  # type: ignore[arg-type,return-value]
        )
        assert isinstance(result, ContractDigestMismatch)
        assert not (root / cache.CACHE_DIR).exists()
