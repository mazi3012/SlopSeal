"""Property tests for snapshot integrity (P-SN-1) and read-only query behaviour.

Requirements: R-P-2, R-P-1. Properties: P-SN-1, P-SN-2.
Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from slopseal.core.types import Ecosystem, RegistryMissing, RegistryRecord, RegistryUnknown
from slopseal.fixtures.loader import (
    DATA_FILES,
    MANIFEST_NAME,
    SnapshotIntegrityError,
    load_snapshot,
)

FIXTURES = Path(__file__).resolve().parents[3] / "src" / "slopseal" / "fixtures"


def _copy(target: Path) -> Path:
    for name in (*DATA_FILES, MANIFEST_NAME):
        shutil.copy(FIXTURES / name, target / name)
    return target


def test_committed_snapshot_loads() -> None:
    assert load_snapshot(FIXTURES).snapshot_id == "slopseal-fixture-v1"


@given(
    file_index=st.integers(min_value=0, max_value=len(DATA_FILES) - 1),
    offset=st.integers(min_value=0, max_value=10_000),
)
def test_p_sn_1_any_single_byte_change_fails_closed(file_index: int, offset: int) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = _copy(Path(tmp))
        target = directory / DATA_FILES[file_index]
        data = bytearray(target.read_bytes())
        position = offset % len(data)
        data[position] = data[position] ^ 0x01
        target.write_bytes(bytes(data))
        with pytest.raises(SnapshotIntegrityError, match="checksum mismatch"):
            load_snapshot(directory)


def test_p_sn_1_missing_data_file_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = _copy(Path(tmp))
        (directory / DATA_FILES[0]).unlink()
        with pytest.raises(SnapshotIntegrityError, match="missing data file"):
            load_snapshot(directory)


def test_p_sn_1_unlisted_json_file_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = _copy(Path(tmp))
        (directory / "extra.json").write_text("{}", encoding="utf-8")
        with pytest.raises(SnapshotIntegrityError, match="unlisted data file"):
            load_snapshot(directory)


def test_documented_limit_manifest_and_data_edited_together_still_load() -> None:
    """A repo writer can change a data file and the manifest together. The checksum manifest
    does not stop that (THREAT_MODEL section 6). This test records the limit."""
    import hashlib
    import json

    with tempfile.TemporaryDirectory() as tmp:
        directory = _copy(Path(tmp))
        registry = directory / "registry_snapshot.json"
        document = json.loads(registry.read_text(encoding="utf-8"))
        document["packages"]["pypi"]["csv-parser"]["versions"]["1.2.0"]["exports"] = ["csv.reader"]
        registry.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
        manifest = directory / MANIFEST_NAME
        listed = json.loads(manifest.read_text(encoding="utf-8"))
        listed["files"]["registry_snapshot.json"] = hashlib.sha256(
            registry.read_bytes()
        ).hexdigest()
        manifest.write_text(json.dumps(listed, indent=2, sort_keys=True), encoding="utf-8")
        assert load_snapshot(directory) is not None


@given(name=st.sampled_from(["csv-parser", "csv_parser", "CSV-PARSER", "Csv.Parser"]))
def test_p_sn_2_pypi_names_resolve_under_pep503(name: str) -> None:
    snapshot = load_snapshot(FIXTURES)
    result = snapshot.registry_result(Ecosystem.PYPI, name)
    assert isinstance(result, RegistryRecord)


def test_absent_package_is_missing_and_unlisted_is_unknown() -> None:
    snapshot = load_snapshot(FIXTURES)
    assert isinstance(snapshot.registry_result(Ecosystem.PYPI, "csv-parser-pro"), RegistryMissing)
    assert isinstance(snapshot.registry_result(Ecosystem.PYPI, "never-listed"), RegistryUnknown)


@given(version=st.text(min_size=1, max_size=10))
def test_p_sn_2_unlisted_version_has_no_exports(version: str) -> None:
    assume(version != "1.2.0")
    snapshot = load_snapshot(FIXTURES)
    assert snapshot.exports(Ecosystem.PYPI, "csv-parser", version) is None
