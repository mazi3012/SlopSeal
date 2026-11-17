"""Unit tests for digest parsing and verification (R-C-1, T23). Property: P-C-3.

Requirements: R-C-1. The PyPI sha256 and the npm SRI strongest-value rule are checked directly.
"""

from __future__ import annotations

import base64
import hashlib

from slopseal.contract.digest import (
    PublishedDigest,
    VerifiedDigest,
    published_from_npm_integrity,
    published_from_pypi,
    verify_artifact,
)
from slopseal.contract.types import ContractDigestMismatch, ContractUnknown, UnknownReason

DATA = b"artifact bytes"


def _sri(algorithm: str, data: bytes = DATA) -> str:
    raw = hashlib.new(algorithm, data).digest()
    return f"{algorithm}-{base64.b64encode(raw).decode()}"


def test_r_c_1_pypi_sha256_is_read_as_lowercase_hex() -> None:
    value = hashlib.sha256(DATA).hexdigest().upper()
    published = published_from_pypi({"sha256": value})
    assert published == PublishedDigest("sha256", value.lower())


def test_r_c_1_pypi_without_sha256_is_no_digest() -> None:
    for digests in ({}, {"md5": "00"}, {"sha256": "abc"}, {"sha256": 5}):
        result = published_from_pypi(digests)  # type: ignore[arg-type]
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.NO_DIGEST


def test_r_c_1_npm_strongest_supported_value_is_chosen() -> None:
    integrity = f"{_sri('sha256')} {_sri('sha512')}"
    published = published_from_npm_integrity(integrity)
    assert isinstance(published, PublishedDigest)
    assert published.algorithm == "sha512"
    assert published.hexdigest == hashlib.sha512(DATA).hexdigest()


def test_r_c_1_npm_sha384_is_supported() -> None:
    published = published_from_npm_integrity(_sri("sha384"))
    assert isinstance(published, PublishedDigest)
    assert published.algorithm == "sha384"


def test_r_c_1_npm_sha1_only_is_no_digest() -> None:
    # sha1 is never trusted. An sha1 value is ignored, and with nothing else it is no_digest.
    # The test data is an sha1 value on purpose: it must be rejected, never trusted.
    sha1 = "sha1-" + base64.b64encode(hashlib.sha1(DATA).digest()).decode()  # noqa: S324
    result = published_from_npm_integrity(sha1)
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NO_DIGEST


def test_r_c_1_npm_malformed_or_missing_is_no_digest() -> None:
    for integrity in (None, 5, "", "sha512-!!!notbase64", "sha512-" + "AAAA", "sha512"):
        result = published_from_npm_integrity(integrity)
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.NO_DIGEST


def test_r_c_1_verify_matches_the_correct_bytes() -> None:
    published = PublishedDigest("sha256", hashlib.sha256(DATA).hexdigest())
    verified = verify_artifact(DATA, published)
    assert isinstance(verified, VerifiedDigest)
    assert verified.key == f"sha256-{hashlib.sha256(DATA).hexdigest()}"


def test_r_c_1_verify_refuses_other_bytes() -> None:
    published = PublishedDigest("sha256", hashlib.sha256(DATA).hexdigest())
    result = verify_artifact(DATA + b"!", published)
    assert isinstance(result, ContractDigestMismatch)
