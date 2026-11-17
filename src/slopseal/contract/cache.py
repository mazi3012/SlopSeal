"""Contract cache keyed by the verified artifact digest (R-C-6, P-C-6). Standard library only.

An entry lives in `<state dir>/contracts/<algorithm>-<hex>.json`. The key is the published digest
the artifact verified against, never the URL. Each entry stores the key, the extractor version,
the complete export list, and `entry_sha256`, the SHA-256 of the canonical JSON of the other
fields.

`store` takes a `VerifiedDigest`, so an entry cannot be written for an unverified artifact.
`load` deletes and misses on any failure: a hash mismatch, a key mismatch, another extractor
version, an unreadable or malformed file, or an invalid export name. A key that does not have the
exact `<algorithm>-<lowercase hex>` form never reaches the file system.

Requirements: R-C-6. Layer 1 (adapter).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from slopseal.contract.digest import HEX_LENGTH, VerifiedDigest
from slopseal.contract.types import ContractComplete, valid_name
from slopseal.fsutil import ensure_private_dir

CACHE_DIR = "contracts"
EXTRACTOR_VERSION = "contract-extractor/0"
SCHEMA = 1
_KEY = re.compile(r"^(sha256|sha384|sha512)-([0-9a-f]+)$")


def valid_key(key: str) -> bool:
    """True only for `<known algorithm>-<lowercase hex of the exact length>`."""
    match = _KEY.fullmatch(key) if isinstance(key, str) else None
    if match is None:
        return False
    return len(match.group(2)) == HEX_LENGTH[match.group(1)]


def _canonical(fields: dict[str, object]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(fields: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(fields)).hexdigest()


def _path(root: Path, key: str) -> Path:
    return root / CACHE_DIR / f"{key}.json"


def store(root: Path, verified: VerifiedDigest, exports: tuple[str, ...]) -> None:
    """Write one complete contract. Only a VerifiedDigest is accepted (R-C-6)."""
    if not isinstance(verified, VerifiedDigest):
        raise TypeError("only a verified digest can be cached")
    key = verified.key
    if not valid_key(key):
        raise ValueError("cache key does not have the required form")
    fields: dict[str, object] = {
        "schema": SCHEMA,
        "key": key,
        "extractor_version": EXTRACTOR_VERSION,
        "exports": list(ContractComplete(exports).exports),
    }
    entry = dict(fields, entry_sha256=_entry_hash(fields))
    directory = root / CACHE_DIR
    ensure_private_dir(directory)
    handle, temp_name = tempfile.mkstemp(dir=directory, prefix=".entry-", suffix=".json")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(entry, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, _path(root, key))
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def load(root: Path, key: str) -> ContractComplete | None:
    """A cached complete contract, or None (a miss). A bad entry is deleted."""
    if not valid_key(key):
        return None
    path = _path(root, key)
    if not path.is_file():
        return None
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(entry, dict):
            raise ValueError("entry is not an object")
        stored_hash = entry.pop("entry_sha256")
        fields: dict[str, object] = entry
        if fields.get("schema") != SCHEMA or fields.get("key") != key:
            raise ValueError("entry does not match its key")
        if fields.get("extractor_version") != EXTRACTOR_VERSION:
            raise ValueError("entry was written by another extractor version")
        if stored_hash != _entry_hash(fields):
            raise ValueError("entry hash does not match its content")
        exports = fields.get("exports")
        if not isinstance(exports, list) or not all(isinstance(e, str) for e in exports):
            raise ValueError("exports are malformed")
        if not all(valid_name(name) for name in exports):
            raise ValueError("an export name fails the name check")
        return ContractComplete(tuple(exports))
    except (OSError, ValueError, KeyError, TypeError):
        path.unlink(missing_ok=True)
        return None
