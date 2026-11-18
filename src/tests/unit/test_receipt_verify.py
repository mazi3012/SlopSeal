"""Anchor receipt verification, unit level (R-AR-1, D2 AC-30, ADR 0005).

Needs the `sign` extra (cryptography==50.0.2).
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from slopseal.sign.verify import (
    RECEIPT_DOMAIN,
    Invalid,
    Receipt,
    Verified,
    verify_receipt,
)

KEY_ID = "sink-receipt-key-1"
INSTALLATION = "inst-A"
SINK = "sink-1"
HEAD = "ab" * 32
SEQ = 7
ISSUED = "2026-11-17T12:00:00Z"


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _receipt(private: Ed25519PrivateKey, **fields: Any) -> Receipt:
    """A receipt that `private` signed over the given fields.

    The fields are signed as given, so a receipt for another installation carries a valid
    signature. To tamper with a signed receipt, use dataclasses.replace after signing.
    """
    values: dict[str, Any] = {
        "alg": "Ed25519",
        "key_id": KEY_ID,
        "installation_id": INSTALLATION,
        "sink_id": SINK,
        "seq": SEQ,
        "head_hash": HEAD,
        "issued_at": ISSUED,
    }
    values.update(fields)
    unsigned = Receipt(**values, signature=b"")
    return dataclasses.replace(unsigned, signature=private.sign(unsigned.signed_payload()))


def _verify(
    receipt: Receipt,
    private: Ed25519PrivateKey,
    *,
    installation: str = INSTALLATION,
    key_id: str = KEY_ID,
    seq: int = SEQ,
    head: str = HEAD,
) -> Verified | Invalid:
    return verify_receipt(
        receipt,
        installation,
        key_id,
        seq,
        head,
        pinned_keys={KEY_ID: private.public_key()},
    )


# AC-30 case 1: valid signature and every bound field matches.


def test_r_ar_1_ac30_valid_receipt_with_matching_fields_is_verified() -> None:
    private = _key()

    result = _verify(_receipt(private), private)

    assert result == Verified(installation_id=INSTALLATION, key_id=KEY_ID, seq=SEQ, head_hash=HEAD)


# AC-30 case 2: validly signed receipt that belongs to another installation.


def test_r_ar_1_ac30_valid_signature_for_another_installation_is_invalid() -> None:
    private = _key()
    other = _receipt(private, installation_id="inst-B")

    result = _verify(other, private)

    assert result == Invalid("installation_id")


# AC-30 case 3: tampered signature.


def test_r_ar_1_ac30_tampered_signature_is_invalid() -> None:
    private = _key()
    good = _receipt(private)
    flipped = bytes([good.signature[0] ^ 0x01]) + good.signature[1:]

    result = _verify(dataclasses.replace(good, signature=flipped), private)

    assert result == Invalid("signature")


def test_r_ar_1_ac30_field_altered_after_signing_is_invalid() -> None:
    private = _key()
    good = _receipt(private)

    result = _verify(dataclasses.replace(good, seq=SEQ + 1), private, seq=SEQ + 1)

    assert result == Invalid("signature")


# AC-30 case 4: the four bound fields are all checked, not only installation_id.


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"seq": SEQ + 1}, "seq"),
        ({"head": "cd" * 32}, "head_hash"),
    ],
)
def test_r_ar_1_ac30_correct_installation_but_wrong_seq_or_head_is_invalid(
    kwargs: dict[str, Any], reason: str
) -> None:
    private = _key()

    result = _verify(_receipt(private), private, **kwargs)

    assert result == Invalid(reason)


# Rules from ADR 0005 section 4, checked before any field comparison.


def test_r_ar_1_unpinned_key_is_invalid() -> None:
    private = _key()
    receipt = _receipt(private)

    result = verify_receipt(
        receipt,
        INSTALLATION,
        KEY_ID,
        SEQ,
        HEAD,
        pinned_keys={"some-other-key": private.public_key()},
    )

    assert result == Invalid("unknown_key")


def test_r_ar_1_other_algorithm_is_invalid() -> None:
    private = _key()

    result = _verify(_receipt(private, alg="RS256"), private)

    assert result == Invalid("alg")


def test_r_ar_1_approval_signature_cannot_be_replayed_as_receipt() -> None:
    """A signature over the approval domain (no receipt prefix) must not verify as a receipt."""
    private = _key()
    base = _receipt(private)
    payload = base.signed_payload()
    assert payload.startswith(RECEIPT_DOMAIN)
    approval_payload = b"slopseal-approval-v1\n" + payload[len(RECEIPT_DOMAIN) :]
    replayed = dataclasses.replace(base, signature=private.sign(approval_payload))

    assert _verify(replayed, private) == Invalid("signature")
