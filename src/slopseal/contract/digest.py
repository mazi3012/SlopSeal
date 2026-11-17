"""Published digest parsing and verification (R-C-1, T23, P-C-3). Standard library only.

The registry publishes one digest per artifact. PyPI gives a sha256 hex value. npm gives an SRI
string (`integrity`) that may list several algorithms, each `<alg>-<base64>`. The algorithm named
in the string is used, and the strongest supported one wins. npm `shasum` (sha1) is never read.

A digest is verified before the archive is read. A mismatch is ContractDigestMismatch (BLOCK). An
unusable published digest is ContractUnknown with reason no_digest.

`VerifiedDigest` can only be made by `verify_artifact`, after the bytes matched. The cache accepts
only a `VerifiedDigest`, so an entry cannot be written for an unverified artifact (R-C-6).

Requirements: R-C-1, R-C-6. Property: P-C-3. Layer 1 (adapter).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field

from slopseal.contract.types import ContractDigestMismatch, ContractUnknown, UnknownReason

# Supported algorithms: the hex length of the digest, and its strength (higher is stronger).
HEX_LENGTH = {"sha256": 64, "sha384": 96, "sha512": 128}
STRENGTH = {"sha256": 1, "sha384": 2, "sha512": 3}
_TOKEN = object()


@dataclass(frozen=True)
class PublishedDigest:
    """A digest the registry published for one artifact, as lowercase hex."""

    algorithm: str
    hexdigest: str


@dataclass(frozen=True)
class VerifiedDigest:
    """Proof that artifact bytes matched the published digest. Only `verify_artifact` makes one."""

    algorithm: str
    hexdigest: str
    _token: object = field(repr=False, compare=False)

    @property
    def key(self) -> str:
        return f"{self.algorithm}-{self.hexdigest}"


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(c in "0123456789abcdef" for c in value)


def published_from_pypi(digests: Mapping[str, object]) -> PublishedDigest | ContractUnknown:
    """The sha256 of a PyPI file (`urls[].digests.sha256`). Anything else is no_digest."""
    value = digests.get("sha256")
    if not isinstance(value, str) or not _is_hex(value.lower(), HEX_LENGTH["sha256"]):
        return ContractUnknown(UnknownReason.NO_DIGEST, "registry gave no usable sha256 digest")
    return PublishedDigest("sha256", value.lower())


def published_from_npm_integrity(integrity: object) -> PublishedDigest | ContractUnknown:
    """The strongest supported value of an npm SRI string. sha1 and unknown algorithms are ignored.

    A supported algorithm whose value is malformed is no_digest, not a fallback to another entry.
    """
    if not isinstance(integrity, str):
        return ContractUnknown(UnknownReason.NO_DIGEST, "registry gave no integrity string")
    best: PublishedDigest | None = None
    for token in integrity.split():
        algorithm, separator, encoded = token.partition("-")
        if not separator or algorithm not in HEX_LENGTH:
            continue
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return ContractUnknown(UnknownReason.NO_DIGEST, "integrity value is malformed")
        if len(raw) * 2 != HEX_LENGTH[algorithm]:
            return ContractUnknown(UnknownReason.NO_DIGEST, "integrity value has the wrong length")
        candidate = PublishedDigest(algorithm, raw.hex())
        if best is None or STRENGTH[algorithm] > STRENGTH[best.algorithm]:
            best = candidate
    if best is None:
        return ContractUnknown(
            UnknownReason.NO_DIGEST, "integrity string has no sha512, sha384, or sha256 value"
        )
    return best


def verify_artifact(
    data: bytes, published: PublishedDigest
) -> VerifiedDigest | ContractDigestMismatch:
    """Compare the artifact's digest with the published one, in constant time (T23)."""
    actual = hashlib.new(published.algorithm, data).hexdigest()
    if hmac.compare_digest(actual.encode("ascii"), published.hexdigest.encode("ascii")):
        return VerifiedDigest(published.algorithm, published.hexdigest, _TOKEN)
    return ContractDigestMismatch(
        published.algorithm, "artifact bytes do not match the registry digest"
    )
