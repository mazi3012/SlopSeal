"""R-C-2: Python export extraction from a wheel, parsed with ast and never executed.

Each test builds a wheel in memory and calls the worker's extract_wheel. The worker imports nothing
from the artifact, so calling it in-process is safe: it only parses text. Requirements: R-C-2,
R-C-5. Properties: P-C-4 and P-C-8 are in src/tests/properties.
"""

from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path

import pytest

from slopseal.contract import worker

NAME_LIMIT = 100_000
FILE_LIMIT = 5 * 1024 * 1024


def _wheel(files: dict[str, str | bytes], record: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
        if record is None:
            record = "".join(f"{name},,\n" for name in files) + "pkg-1.0.dist-info/RECORD,,\n"
        archive.writestr("pkg-1.0.dist-info/RECORD", record)
    return buffer.getvalue()


def _extract(files: dict[str, str | bytes], *, record: str | None = None, names: int = NAME_LIMIT):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg-1.0-py3-none-any.whl"
        path.write_bytes(_wheel(files, record))
        return worker.extract_wheel(str(path), FILE_LIMIT, names)


def test_r_c_2_defs_imports_and_package_paths_are_named() -> None:
    names = _extract(
        {
            "pkg/__init__.py": "from .core import parse\ndef top():\n    pass\n_hidden = 1\n",
            "pkg/core.py": "def parse():\n    pass\n",
        }
    )
    assert "parse" in names  # bare name of a top-level package symbol
    assert "pkg.parse" in names
    assert "pkg.top" in names
    assert "pkg.core.parse" in names
    assert "pkg.core" in names  # module path
    assert "pkg" in names
    assert "pkg._hidden" not in names  # underscore names are not in set B


def test_r_c_2_literal_all_keeps_underscore_names() -> None:
    names = _extract({"pkg/__init__.py": "__all__ = ['a', '_private']\nb = 1\n"})
    assert {"pkg.a", "pkg._private", "pkg.b", "a", "_private", "b"} <= set(names)


def test_r_c_2_literal_all_additions_are_read() -> None:
    source = "__all__ = ['a']\n__all__ += ['b']\n__all__.extend(['c'])\n__all__.append('d')\n"
    names = _extract({"pkg/__init__.py": source})
    assert {"a", "b", "c", "d"} <= set(names)


def test_r_c_2_branches_of_if_and_try_are_unioned() -> None:
    source = (
        "try:\n"
        "    from x import a\n"
        "except ImportError:\n"
        "    b = None\n"
        "if True:\n"
        "    def c():\n"
        "        pass\n"
        "else:\n"
        "    d = 1\n"
        "finally_ = 2\n"
    )
    names = _extract({"pkg/__init__.py": source})
    assert {"pkg.a", "pkg.b", "pkg.c", "pkg.d", "pkg.finally_"} <= set(names)


def test_r_c_2_a_loop_inside_a_function_is_not_module_level() -> None:
    source = "def f(items):\n    for item in items:\n        pass\n"
    assert "pkg.f" in _extract({"pkg/__init__.py": source})


@pytest.mark.parametrize(
    "source",
    [
        "__all__ = [n for n in ['a']]\n",
        "__all__ = list(dir())\n",
        "__all__ = ['a']\n__all__ += names\n",
        "__all__ = ['a']\n__all__.extend(names)\n",
        "__all__ = ['a']\n__all__.remove('a')\n",
        "__all__ = ['a']\n__all__[0] = 'b'\n",
        "__all__ = ['a']\ndef g():\n    __all__.append('b')\n",
        "import sys\nsetattr(sys.modules[__name__], 'x', 1)\n",
        "import sys\nalias = sys.modules[__name__]\n",
        "globals()['x'] = 1\n",
        "globals().update({'x': 1})\n",
        "vars()['x'] = 1\n",
        "def f(m):\n    m.__dict__['x'] = 1\n",
        "exec('x = 1')\n",
        "eval('1')\n",
        "from sys import modules\n",
        "x = 1\nglobal x\n",
        "x = 1\ndel x\n",
        "def __getattr__(name):\n    raise AttributeError(name)\n",
        "def __dir__():\n    return []\n",
        "for n in ['a']:\n    pass\n",
        "while False:\n    pass\n",
        "with open('x') as handle:\n    pass\n",
        "a, b = 1, 2\n",
        "x = 1\nx += 1\n",
        "(y := 1)\n",
        "match 1:\n    case 1:\n        pass\n",
    ],
)
def test_r_c_2_each_dynamic_form_gives_dynamic_exports(source: str) -> None:
    with pytest.raises(worker.Dynamic):
        _extract({"pkg/__init__.py": source})


def test_r_c_2_star_import_inside_the_artifact_adds_its_names() -> None:
    names = _extract(
        {
            "pkg/__init__.py": "from .core import *\n",
            "pkg/core.py": "def parse():\n    pass\n",
        }
    )
    assert "pkg.parse" in names


def test_r_c_2_star_import_outside_the_artifact_is_dynamic() -> None:
    with pytest.raises(worker.Dynamic):
        _extract({"pkg/__init__.py": "from os import *\n"})


def test_r_c_2_star_import_with_a_second_hop_is_dynamic() -> None:
    files = {
        "pkg/__init__.py": "from .a import *\n",
        "pkg/a.py": "from .b import *\n",
        "pkg/b.py": "def parse():\n    pass\n",
    }
    with pytest.raises(worker.Dynamic):
        _extract(files)


def test_r_c_2_a_compiled_extension_is_dynamic() -> None:
    files = {"pkg/__init__.py": "x = 1\n", "pkg/_speed.cpython-311-x86_64-linux-gnu.so": b"junk"}
    with pytest.raises(worker.Dynamic):
        _extract(files)


def test_r_c_2_a_file_that_does_not_parse_raises_syntax_error() -> None:
    """ast.parse raises SyntaxError. The worker's entry point maps it to parse_error."""
    with pytest.raises(SyntaxError):
        _extract({"pkg/__init__.py": "def (\n"})


def test_r_c_2_a_wheel_without_record_is_parse_error() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/__init__.py", "x = 1\n")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg.whl"
        path.write_bytes(buffer.getvalue())
        with pytest.raises(worker.Unsafe):
            worker.extract_wheel(str(path), FILE_LIMIT, NAME_LIMIT)


def test_r_c_2_a_module_missing_from_record_is_parse_error() -> None:
    files = {"pkg/__init__.py": "x = 1\n", "pkg/extra.py": "y = 2\n"}
    record = "pkg/__init__.py,,\npkg-1.0.dist-info/RECORD,,\n"
    with pytest.raises(worker.Unsafe):
        _extract(files, record=record)


def test_r_c_2_a_record_listing_a_missing_module_is_parse_error() -> None:
    record = "pkg/__init__.py,,\npkg/gone.py,,\npkg-1.0.dist-info/RECORD,,\n"
    with pytest.raises(worker.Unsafe):
        _extract({"pkg/__init__.py": "x = 1\n"}, record=record)


def test_r_c_2_a_name_longer_than_256_is_parse_error() -> None:
    with pytest.raises(worker.Unsafe):
        _extract({"pkg/__init__.py": f"__all__ = [{'a' * 257!r}]\n"})


def test_r_c_2_a_name_with_whitespace_is_parse_error() -> None:
    with pytest.raises(worker.Unsafe):
        _extract({"pkg/__init__.py": "__all__ = ['a b']\n"})


def test_r_c_2_too_many_names_is_limit() -> None:
    with pytest.raises(worker.Limit):
        _extract({"pkg/__init__.py": "__all__ = ['a', 'b', 'c']\n"}, names=2)


def test_r_c_2_a_source_file_over_the_size_limit_is_limit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg.whl"
        path.write_bytes(_wheel({"pkg/__init__.py": "x = 1\n" + "# pad\n" * 1000}))
        with pytest.raises(worker.Limit):
            worker.extract_wheel(str(path), 64, NAME_LIMIT)


def test_r_c_2_dist_info_is_ignored_and_data_purelib_is_installed() -> None:
    files = {
        "pkg/__init__.py": "x = 1\n",
        "pkg-1.0.data/scripts/tool.py": "def run():\n    pass\n",
        "pkg-1.0.data/purelib/extra.py": "def helper():\n    pass\n",
    }
    names = _extract(files)
    assert "extra" in names
    assert "extra.helper" in names
    assert "run" not in names
    assert "pkg.run" not in names


def test_r_c_2_stub_files_are_read_as_modules() -> None:
    names = _extract({"pkg/__init__.py": "x = 1\n", "pkg/types.pyi": "def stub() -> None: ...\n"})
    assert "pkg.types.stub" in names
