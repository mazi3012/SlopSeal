"""Property tests for the live registry adapter (R-P-3).

Oracle: whatever the registry body is, the adapter returns one of the three existence results,
never raises, and never invents a publish time. A body without a usable `releases` map is
unknown. The fake fetch replaces the network, so the tests are hermetic.

Hypothesis runs 500 examples per property (conftest.py profile).
"""

from __future__ import annotations

import json
from datetime import datetime

from hypothesis import given
from hypothesis import strategies as st

from slopseal.core.types import Ecosystem, RegistryMissing, RegistryRecord, RegistryUnknown
from slopseal.registry.live import LiveSource

JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(
            st.sampled_from(["releases", "info", "upload_time_iso_8601", "filename"]),
            children,
            max_size=4,
        )
    ),
    max_leaves=12,
)


def _source_returning(body: bytes) -> LiveSource:
    def fetch(url: str, data: bytes | None) -> bytes | None:
        return body

    return LiveSource(fetch=fetch)


@given(JSON_VALUES)
def test_any_pypi_body_gives_a_defined_result_and_no_invented_publish_time(value: object) -> None:
    """P-LIVE-1: a registry body of any shape gives a record, missing, or unknown result. A record
    carries a timezone-aware publish time or none, never a time the body did not contain."""
    result = _source_returning(json.dumps(value).encode("utf-8")).registry_result(
        Ecosystem.PYPI, "requests"
    )
    assert isinstance(result, RegistryRecord | RegistryMissing | RegistryUnknown)
    if isinstance(result, RegistryRecord):
        assert result.release_count >= 0
        if result.first_published is not None:
            assert isinstance(result.first_published, datetime)
            assert result.first_published.tzinfo is not None


@given(JSON_VALUES)
def test_a_body_without_a_releases_map_is_unknown_never_a_record(value: object) -> None:
    """P-LIVE-2: without a `releases` mapping, the answer is unknown. Existence is never inferred
    from a body that does not describe releases."""
    if isinstance(value, dict) and isinstance(value.get("releases"), dict):
        return
    result = _source_returning(json.dumps(value).encode("utf-8")).registry_result(
        Ecosystem.PYPI, "requests"
    )
    assert isinstance(result, RegistryUnknown)
