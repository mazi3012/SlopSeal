"""P-C-8, rule Q1 (Python module writes): no synthetic artifact with a write form gives ABSENT.

Each form below changes a module's names at run time. Each is placed at random among otherwise
modelled `def` statements, once at module level and once inside a function body (a function may
run at import time). The extraction raises Dynamic for every probe, so no probe is ABSENT.

The oracle is the list of forms in this file, not the extractor. The control file, with no form,
must complete, so the test cannot pass by making every file dynamic.

Mutant M-Q1 (the Python reference check is skipped) must fail this property. Its run and result
are recorded in the pull request.

Requirements: R-C-2 (completeness rule Q1). Property: P-C-8.
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

FILE_LIMIT = 5 * 1024 * 1024
NAME_LIMIT = 100_000
NAMES = st.lists(
    st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True).filter(
        lambda s: s not in ("pkg", "sys", "os") and not keyword.iskeyword(s)
    ),
    min_size=1,
    max_size=5,
    unique=True,
)
# Q1: writes to a module's names. Each is a module-level statement, and it is also tried in a body.
Q1_FORMS = [
    "import sys\nalias = sys.modules[__name__]\n",
    "import sys\nsetattr(sys.modules[__name__], 'zz_x', 1)\n",
    "globals()['zz_x'] = 1\n",
    "globals().update({'zz_x': 1})\n",
    "vars()['zz_x'] = 1\n",
    "def module_dict(m):\n    m.__dict__['zz_x'] = 1\n",
    "exec('zz_x = 1')\n",
    "eval('1')\n",
]
Q1 = st.sampled_from(Q1_FORMS)
PLACEMENT = st.sampled_from(["module", "function"])


def _modelled(names: list[str]) -> list[str]:
    return [f"def {name}():\n    pass\n" for name in names]


def _with_form(names: list[str], form: str, placement: str, position: int) -> str:
    statements = _modelled(names)
    if placement == "module":
        statements.insert(position % (len(statements) + 1), form)
    else:
        body = "".join(f"    {line}\n" for line in form.splitlines())
        statements.insert(position % (len(statements) + 1), f"def _hook():\n{body}")
    return "".join(statements)


def _extract(source: str) -> list[str]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/__init__.py", source)
        archive.writestr(
            "pkg-1.0.dist-info/RECORD", "pkg/__init__.py,,\npkg-1.0.dist-info/RECORD,,\n"
        )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg-1.0-py3-none-any.whl"
        path.write_bytes(buffer.getvalue())
        return worker.extract_wheel(str(path), FILE_LIMIT, NAME_LIMIT)


@given(names=NAMES, form=Q1, placement=PLACEMENT, position=st.integers(0, 10))
def test_p_c_8_q1_a_python_write_form_is_dynamic_for_every_probe(
    names: list[str], form: str, placement: str, position: int
) -> None:
    source = _with_form(names, form, placement, position)
    with pytest.raises(worker.Dynamic):
        _extract(source)


@given(names=NAMES)
def test_p_c_8_q1_control_without_a_write_form_completes(names: list[str]) -> None:
    """The control: the same file with no write form is complete, so the rule is not blanket."""
    extracted = set(_extract("".join(_modelled(names))))
    for name in names:
        assert f"pkg.{name}" in extracted
