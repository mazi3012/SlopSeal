"""P-C-4: ABSENT needs a complete contract (Python, hypothesis).

For a generated wheel built from a known list of symbols:
(a) if the extractor returns ABSENT for a probe, the extraction was complete and the probe is not
    in the known list. A complete extraction is a name set with no dynamic form. A dynamic file
    raises Dynamic, so it never gives ABSENT.
(b) if the file has a dynamic pattern from R-C-2, every probe is UNKNOWN (Dynamic), never ABSENT and
    never PRESENT.
(c) every symbol in the known list is PRESENT when the file has no dynamic pattern.

The oracle is the generator's own symbol list, not the extractor. Requirements: R-C-2, R-C-5.
Hypothesis runs 500 examples per property (conftest.py profile). Do not lower the count.
"""

from __future__ import annotations

import io
import keyword
import tempfile
import zipfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from slopseal.contract import worker

NAME_LIMIT = 100_000
FILE_LIMIT = 5 * 1024 * 1024
# "pkg" is the generated package name, always present as a module path. Keywords are not names.
SYMBOL = st.from_regex(r"[a-z][a-z0-9]{0,7}", fullmatch=True).filter(
    lambda s: s != "pkg" and not keyword.iskeyword(s)
)
SYMBOLS = st.lists(SYMBOL, min_size=1, max_size=6, unique=True)
LAYOUT = st.sampled_from(["defs", "assign", "literal_all"])
# Each entry is a dynamic pattern from R-C-2 (the Python list). None of them is in the known list.
DYNAMIC_PATTERNS = st.sampled_from(
    [
        "def __getattr__(name):\n    raise AttributeError(name)\n",
        "def __dir__():\n    return []\n",
        "__all__ = [n for n in dir()]\n",
        "import sys\nsetattr(sys.modules[__name__], 'zz_hidden', 1)\n",
        "for zz_hidden in ['a']:\n    pass\n",
        "from os import *\n",
    ]
)


def _module(symbols: list[str], layout: str) -> str:
    if layout == "defs":
        return "".join(f"def {symbol}():\n    pass\n" for symbol in symbols)
    if layout == "assign":
        return "".join(f"{symbol} = 1\n" for symbol in symbols)
    return f"__all__ = {symbols!r}\n"


def _wheel(source: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/__init__.py", source)
        archive.writestr(
            "pkg-1.0.dist-info/RECORD", "pkg/__init__.py,,\npkg-1.0.dist-info/RECORD,,\n"
        )
    return buffer.getvalue()


def _extract(source: str) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg-1.0-py3-none-any.whl"
        path.write_bytes(_wheel(source))
        return worker.extract_wheel(str(path), FILE_LIMIT, NAME_LIMIT)


@given(symbols=SYMBOLS, layout=LAYOUT, probe=SYMBOL)
def test_p_c_4_c_every_known_symbol_is_present_without_a_dynamic_pattern(
    symbols: list[str], layout: str, probe: str
) -> None:
    names = set(_extract(_module(symbols, layout)))
    for symbol in symbols:
        assert symbol in names, "a known symbol must be PRESENT (bare name)"
        assert f"pkg.{symbol}" in names, "a known symbol must be PRESENT (qualified name)"


@given(symbols=SYMBOLS, layout=LAYOUT, probe=SYMBOL)
def test_p_c_4_a_absent_only_from_a_complete_contract(
    symbols: list[str], layout: str, probe: str
) -> None:
    """A probe outside the known list is ABSENT: the extraction completed without it."""
    names = set(_extract(_module(symbols, layout)))
    if probe in symbols:
        return
    assert probe not in names
    assert f"pkg.{probe}" not in names


@given(symbols=SYMBOLS, layout=LAYOUT, pattern=DYNAMIC_PATTERNS)
def test_p_c_4_b_a_dynamic_file_is_unknown_for_every_probe(
    symbols: list[str], layout: str, pattern: str
) -> None:
    source = _module(symbols, layout) + pattern
    with pytest.raises(worker.Dynamic):
        _extract(source)
