"""Anchor receipt verification (R-AR-1, ADR 0005, D2 sections 6.1 and 6.5, AC-30).

`verify_receipt` returns Verified only when the Ed25519 signature checks out over the
domain-separated canonical payload, the key is in the caller's pinned key set, and the four
bound fields (installation_id, key_id, seq, head_hash) equal what the service expects. Every
other case returns Invalid. The function is pure: no I/O, no clock, no quota or log change.
What the service does on Invalid (halt, section 6.2) belongs to M1 and D2-d.

This module needs the `sign` extra (cryptography==50.0.2). The default install never imports it.

Requirements: R-AR-1. Layer 2. Pure.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALG = "Ed25519"
RECEIPT_DOMAIN = b"slopseal-receipt-v1\n"


@dataclass(frozen=True)
class Receipt:
    """A sink receipt as received. `signature` is the raw 64-byte Ed25519 signature."""

    alg: str
    key_id: str
    installation_id: str
    sink_id: str
    seq: int
    head_hash: str
    issued_at: str
    signature: bytes

    def signed_payload(self) -> bytes:
        """The bytes the signature covers: the receipt domain, then the canonical JSON fields."""
        fields = {
            "alg": self.alg,
            "head_hash": self.head_hash,
            "installation_id": self.installation_id,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "seq": self.seq,
            "sink_id": self.sink_id,
        }
        body = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return RECEIPT_DOMAIN + body.encode("utf-8")


@dataclass(frozen=True)
class Verified:
    installation_id: str
    key_id: str
    seq: int
    head_hash: str


@dataclass(frozen=True)
class Invalid:
    """Why a receipt was refused. `reason` is a short code, never free text from the receipt."""

    reason: str


def _well_formed(receipt: Receipt) -> bool:
    texts = (
        receipt.alg,
        receipt.key_id,
        receipt.installation_id,
        receipt.sink_id,
        receipt.head_hash,
        receipt.issued_at,
    )
    if not all(isinstance(value, str) and value for value in texts):
        return False
    if not isinstance(receipt.seq, int) or isinstance(receipt.seq, bool) or receipt.seq < 0:
        return False
    return isinstance(receipt.signature, bytes)


def verify_receipt(
    receipt: Receipt,
    expected_installation_id: str,
    expected_key_id: str,
    expected_seq: int,
    expected_head_hash: str,
    *,
    pinned_keys: Mapping[str, Ed25519PublicKey],
) -> Verified | Invalid:
    """Check one sink receipt against the service's own expectations (R-AR-1, AC-30).

    `pinned_keys` maps key_id to the receipt-purpose public key pinned at `init`. A key_id that
    is not in the map is Invalid. The signature is checked before the bound fields, so a field
    mismatch is only reported for a receipt the pinned key really signed.
    """
    if receipt.alg != ALG:
        return Invalid("alg")
    if not _well_formed(receipt):
        return Invalid("malformed")

    public_key = pinned_keys.get(receipt.key_id)
    if public_key is None:
        return Invalid("unknown_key")
    try:
        public_key.verify(receipt.signature, receipt.signed_payload())
    except InvalidSignature:
        return Invalid("signature")

    if receipt.installation_id != expected_installation_id:
        return Invalid("installation_id")
    if receipt.key_id != expected_key_id:
        return Invalid("key_id")
    if receipt.seq != expected_seq:
        return Invalid("seq")
    if receipt.head_hash != expected_head_hash:
        return Invalid("head_hash")
    return Verified(
        installation_id=receipt.installation_id,
        key_id=receipt.key_id,
        seq=receipt.seq,
        head_hash=receipt.head_hash,
    )
