"""Seal key and verdict seals (design section 10; Open Decision 6, resolved).

v1 seals are HMAC-SHA256 (symmetric, integrity-only). Anyone who can verify a seal can also
forge one. Public verifiability (Ed25519) is a roadmap item (ADR 0002).

Key lifecycle: 32 bytes from os.urandom, written to `secret.key` with mode 0600, created with
O_CREAT | O_EXCL so two processes cannot race to write different keys. The key is never
printed, logged, or put in a payload. If the key cannot be read or created, the caller must
exit 78 and issue no seal.

Requirements: R-5.7.2. Properties: P-AU-2. Layer 3.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

KEY_NAME = "secret.key"
KEY_BYTES = 32


class SealKeyError(Exception):
    """The seal key is missing, unreadable, or has the wrong shape. Callers exit 78."""


def load_or_create_key(root: Path) -> bytes:
    path = root / KEY_NAME
    root.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _read_key(path)
    except OSError as exc:
        raise SealKeyError(f"cannot create seal key: {exc.strerror or exc}") from exc
    key = os.urandom(KEY_BYTES)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())
    return key


def _read_key(path: Path) -> bytes:
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise SealKeyError(f"cannot read seal key: {exc.strerror or exc}") from exc
    if len(key) != KEY_BYTES:
        raise SealKeyError("seal key has the wrong length")
    return key


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_fields(
    *,
    package: str,
    version: str,
    checks_run: list[str],
    verdict: str,
    timestamp: str,
    policy_hash: str,
) -> dict[str, Any]:
    """The fields a seal covers (R-5.7.2)."""
    return {
        "package": package,
        "version": version,
        "checks_run": checks_run,
        "verdict": verdict,
        "timestamp": timestamp,
        "policy_hash": policy_hash,
    }


def sign(key: bytes, data: Any) -> str:
    return hmac.new(key, canonical(data), hashlib.sha256).hexdigest()


def verify(key: bytes, data: Any, digest: str) -> bool:
    return hmac.compare_digest(sign(key, data), digest)
