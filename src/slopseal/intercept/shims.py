"""Write the pip and npm wrapper scripts that route installs through the PATH shim.

Usage: python -m slopseal.intercept.shims <directory>

Put the directory first on PATH, for example `export PATH="<directory>:$PATH"`. Each wrapper
runs the same Python interpreter that wrote it, so the shim uses the SlopSeal install that
created it.

Requirements: R-1.1. Layer 5.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

from slopseal.intercept.path_shim import TOOLS


def write_shims(directory: Path, python: str = sys.executable) -> list[Path]:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for tool in TOOLS:
        path = directory / tool
        script = (
            "#!/bin/sh\n"
            f"SLOPSEAL_SHIM_DIR={shlex.quote(str(directory))}\n"
            "export SLOPSEAL_SHIM_DIR\n"
            f'exec {shlex.quote(python)} -m slopseal.intercept.path_shim {tool} "$@"\n'
        )
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
        written.append(path)
    return written


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m slopseal.intercept.shims <directory>", file=sys.stderr)
        return 2
    for path in write_shims(Path(argv[0])):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
