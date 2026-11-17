"""P-C-3: a digest mismatch always gives BLOCK, and a correct digest always verifies.

Requirements: R-C-1, T23. Hypothesis runs 500 examples per property (conftest.py profile).

The pipeline is called with a fake fetch and spy archive and extractor. Only the digest, the
archive order, and the cache are under test. Mutants that break this property are recorded in
the pull request.
"""

from __future__ import annotations

import base64
import hashlib
import tempfile
from pathlib import Path

from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.contract.digest import (
    PublishedDigest,
    VerifiedDigest,
    published_from_npm_integrity,
    verify_artifact,
)
from slopseal.contract.pipeline import obtain_contract
from slopseal.contract.runner import ArchiveOk
from slopseal.contract.types import ContractComplete, ContractDigestMismatch, ContractUnknown
from slopseal.core.types import Ecosystem

ALGORITHMS = ("sha256", "sha384", "sha512")
URL = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
payloads = st.binary(min_size=0, max_size=300)
algorithms = st.sampled_from(ALGORITHMS)


def _published(algorithm: str, data: bytes) -> PublishedDigest:
    return PublishedDigest(algorithm, hashlib.new(algorithm, data).hexdigest())


def _npm_sri(algorithm: str, data: bytes) -> str:
    return f"{algorithm}-{base64.b64encode(hashlib.new(algorithm, data).digest()).decode()}"


@given(data=payloads, algorithm=algorithms)
def test_p_c_3_a_correct_digest_verifies(data: bytes, algorithm: str) -> None:
    """P-C-3 (positive half): matching bytes verify, for every accepted algorithm and form."""
    published = _published(algorithm, data)
    assert isinstance(verify_artifact(data, published), VerifiedDigest)
    via_sri = published_from_npm_integrity(_npm_sri(algorithm, data))
    assert isinstance(via_sri, PublishedDigest)
    assert via_sri.algorithm == algorithm
    assert isinstance(verify_artifact(data, via_sri), VerifiedDigest)


@given(
    data=payloads,
    algorithm=algorithms,
    change=st.integers(min_value=0, max_value=3),
    where=st.integers(min_value=0, max_value=10_000),
)
def test_p_c_3_a_changed_artifact_is_a_mismatch_and_blocks(
    data: bytes, algorithm: str, change: int, where: int
) -> None:
    """P-C-3: a changed byte, truncation, or extension is a mismatch, and the pipeline blocks."""
    published = _published(algorithm, data)
    if change == 0 or not data:
        tampered = data + b"!"  # extension
    elif change == 1:
        tampered = data[:-1]  # truncation
    else:
        position = where % len(data)
        tampered = data[:position] + bytes([data[position] ^ 0x01]) + data[position + 1 :]
    assume(tampered != data)

    archive_calls: list[str] = []
    extract_calls: list[str] = []

    def fetch(url: str, ecosystem: Ecosystem) -> bytes:
        return tampered

    def archive(path: Path, kind: str) -> ArchiveOk:
        archive_calls.append("archive")
        return ArchiveOk("")

    def extract(path: Path, kind: str, root: str) -> ContractComplete:
        extract_calls.append("extract")
        return ContractComplete(("parse",))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        result = obtain_contract(
            Ecosystem.NPM,
            URL,
            published,
            kind="npm",
            cache_root=root,
            extract=extract,
            fetch=fetch,
            archive_check=archive,
        )
        assert isinstance(result, ContractDigestMismatch)
        assert archive_calls == []
        assert extract_calls == []
        assert not (root / "contracts").exists()


@given(data=payloads, algorithm=algorithms)
def test_p_c_3_a_digest_that_differs_only_in_its_last_character_is_a_mismatch(
    data: bytes, algorithm: str
) -> None:
    """Mutant (a) compares only a prefix. A last-character difference must still be a mismatch."""
    published = _published(algorithm, data)
    last = published.hexdigest[-1]
    other = "0" if last != "0" else "1"
    wrong = PublishedDigest(algorithm, published.hexdigest[:-1] + other)
    assert isinstance(verify_artifact(data, wrong), ContractDigestMismatch)


def test_p_c_3_unknown_is_never_returned_for_a_mismatch() -> None:
    """Mutant (b) maps a mismatch to UNKNOWN. The result type must stay ContractDigestMismatch."""
    published = _published("sha256", b"x")
    assert not isinstance(verify_artifact(b"y", published), ContractUnknown)
