"""The archive worker as a real subprocess with resource limits (R-C-4, POSIX).

Requirements: R-C-4. Property: P-C-5 (the subprocess path). Skipped on non-POSIX systems.
"""

from __future__ import annotations

import io
import os
import stat
import tempfile
import zipfile
from pathlib import Path

import pytest

from slopseal.contract import runner as runner_module
from slopseal.contract.limits import MAX_COMPRESSED_BYTES
from slopseal.contract.runner import ArchiveOk, run_archive_check, run_extract
from slopseal.contract.types import ContractComplete, ContractUnknown, UnknownReason

pytestmark = pytest.mark.skipif(os.name != "posix", reason="archive checks need POSIX limits")


def _wheel(path: Path, members: list[tuple[str, bytes, int | None]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data)
    return path


def test_r_c_4_a_valid_wheel_passes_in_the_subprocess() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "pkg.whl", [("pkg/__init__.py", b"x = 1\n", None)])
        result = run_archive_check(path, "wheel")
        assert result == ArchiveOk("")


def test_r_c_4_a_hostile_wheel_is_parse_error_from_the_subprocess() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "bad.whl", [("pkg/link", b"/etc/passwd", stat.S_IFLNK | 0o777)])
        result = run_archive_check(path, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR


def test_r_c_4_the_wall_time_limit_is_limit() -> None:
    """A timeout kills the worker and reports limit. A tiny timeout forces it on any machine."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "pkg.whl", [("pkg/__init__.py", b"x = 1\n", None)])
        result = run_archive_check(path, "wheel", timeout=0.0001)
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_4_an_artifact_over_the_compressed_limit_is_limit_without_a_read() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "huge.whl"
        with path.open("wb") as handle:
            handle.truncate(MAX_COMPRESSED_BYTES + 1)
        result = run_archive_check(path, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_4_an_unknown_kind_is_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = _wheel(Path(tmp) / "pkg.whl", [("pkg/a.py", b"", None)])
        with pytest.raises(ValueError, match="unknown artifact kind"):
            run_archive_check(path, "sdist")


def test_r_c_4_the_worker_output_is_json_and_nothing_else() -> None:
    """Stdout carries one JSON object. Other output would be parse_error."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/a.py", b"x = 1\n")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg.whl"
        path.write_bytes(buffer.getvalue())
        assert run_archive_check(path, "wheel") == ArchiveOk("")


# R-C-4: worker outcomes. Each test points the runner at a wrapper script. The wrapper loads the
# real worker module and then forces one outcome, so the mapping runs in a real subprocess.

_REAL_WORKER = Path(runner_module.WORKER)


def _wrapper(directory: Path, body: str) -> Path:
    script = directory / "fake_worker.py"
    script.write_text(
        "import importlib.util, sys\n"
        f"_spec = importlib.util.spec_from_file_location('worker', {str(_REAL_WORKER)!r})\n"
        "worker = importlib.util.module_from_spec(_spec)\n"
        "_spec.loader.exec_module(worker)\n" + body,
        encoding="utf-8",
    )
    return script


def _artifact(directory: Path) -> Path:
    path = directory / "pkg.tgz"
    path.write_bytes(b"placeholder")
    return path


def test_r_c_4_a_worker_killed_by_a_signal_is_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        monkeypatch.setattr(
            runner_module,
            "WORKER",
            _wrapper(base, "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n"),
        )
        result = run_archive_check(_artifact(base), "npm")
        assert result == ContractUnknown(
            UnknownReason.LIMIT, "archive check was stopped by a limit"
        )


def test_r_c_4_a_worker_stopped_by_the_cpu_limit_is_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """RLIMIT_CPU delivers SIGXCPU to the worker, which the parent sees as a signal kill."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        body = (
            "import resource\n"
            "resource.setrlimit(resource.RLIMIT_CPU, (1, 1))\n"
            "while True:\n"
            "    pass\n"
        )
        monkeypatch.setattr(runner_module, "WORKER", _wrapper(base, body))
        result = run_archive_check(_artifact(base), "npm")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_4_a_memory_error_in_the_worker_is_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    body = (
        "def boom(*args, **kwargs):\n"
        "    raise MemoryError()\n"
        "worker.check_zip = boom\n"
        "sys.exit(worker.main(sys.argv[1:]))\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        monkeypatch.setattr(runner_module, "WORKER", _wrapper(base, body))
        result = run_archive_check(_artifact(base), "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_4_a_non_limit_nonzero_exit_is_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        monkeypatch.setattr(runner_module, "WORKER", _wrapper(base, "sys.exit(3)\n"))
        result = run_archive_check(_artifact(base), "npm")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR


def test_r_c_4_worker_root_that_escapes_is_parse_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker's root is re-validated by the parent: "../../etc" is rejected."""
    body = (
        "worker.check_npm = lambda *a, **k: {'status': 'ok', 'root': '../../etc'}\n"
        "worker.check_zip = worker.check_npm\n"
        "sys.exit(worker.main(sys.argv[1:]))\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        monkeypatch.setattr(runner_module, "WORKER", _wrapper(base, body))
        result = run_archive_check(_artifact(base), "npm")
        assert result == ContractUnknown(
            UnknownReason.PARSE_ERROR, "archive root is outside the artifact directory"
        )


@pytest.mark.parametrize("root", ["/etc", "pkg/../../x", "..", "a\\b", "pkg\u0000x"])
def test_r_c_4_every_unsafe_root_form_is_parse_error(
    monkeypatch: pytest.MonkeyPatch, root: str
) -> None:
    body = (
        f"worker.check_zip = lambda *a, **k: {{'status': 'ok', 'root': {root!r}}}\n"
        "sys.exit(worker.main(sys.argv[1:]))\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        monkeypatch.setattr(runner_module, "WORKER", _wrapper(base, body))
        result = run_archive_check(_artifact(base), "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR


def test_r_c_4_a_relative_package_root_inside_the_directory_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = (
        "worker.check_npm = lambda *a, **k: {'status': 'ok', 'root': 'package'}\n"
        "sys.exit(worker.main(sys.argv[1:]))\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        monkeypatch.setattr(runner_module, "WORKER", _wrapper(base, body))
        assert run_archive_check(_artifact(base), "npm") == ArchiveOk("package")


# R-C-2: the extract mode of the worker, as a real subprocess.


def _record_wheel(directory: Path, files: dict[str, str]) -> Path:
    path = directory / "pkg-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
        record = "".join(f"{name},,\n" for name in files) + "pkg-1.0.dist-info/RECORD,,\n"
        archive.writestr("pkg-1.0.dist-info/RECORD", record)
    return path


def test_r_c_2_extraction_runs_in_the_subprocess_and_returns_complete_names() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        wheel = _record_wheel(Path(tmp), {"pkg/__init__.py": "def parse():\n    pass\n"})
        result = run_extract(wheel, "wheel")
        assert isinstance(result, ContractComplete)
        assert "parse" in result.exports
        assert "pkg.parse" in result.exports


def test_r_c_2_a_dynamic_module_is_dynamic_exports_from_the_subprocess() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        wheel = _record_wheel(
            Path(tmp), {"pkg/__init__.py": "import sys\nsetattr(sys.modules[__name__], 'x', 1)\n"}
        )
        result = run_extract(wheel, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.DYNAMIC_EXPORTS


def test_r_c_2_a_syntax_error_is_parse_error_from_the_subprocess() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        wheel = _record_wheel(Path(tmp), {"pkg/__init__.py": "def (\n"})
        result = run_extract(wheel, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR


def test_r_c_2_too_many_names_from_the_subprocess_is_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_module, "MAX_CONTRACT_NAMES", 1)
    with tempfile.TemporaryDirectory() as tmp:
        wheel = _record_wheel(
            Path(tmp), {"pkg/__init__.py": "def a():\n    pass\ndef b():\n    pass\n"}
        )
        result = run_extract(wheel, "wheel")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.LIMIT


def test_r_c_2_extraction_of_an_npm_kind_is_refused_here() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "pkg.tgz"
        artifact.write_bytes(b"placeholder")
        result = run_extract(artifact, "npm")
        assert isinstance(result, ContractUnknown)
        assert result.reason is UnknownReason.PARSE_ERROR
