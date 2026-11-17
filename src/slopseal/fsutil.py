"""Private state directories and files (R-FS-1).

State directories are created 0700 and state and lock files are created 0600. The modes are set
explicitly, so the result does not depend on the process umask.

Only the leaf directory passed to `ensure_private_dir` gets the 0700 mode. Missing parent
directories are created by `mkdir` with default permissions, as Python documents. Callers should
pass the state directory itself as the leaf.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> None:
    """Create `path` as a 0700 directory if it is missing. An existing directory keeps its mode."""
    path.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)


def open_private_file(path: Path) -> IO[str]:
    """Open `path` for read and append, creating it as 0600 if it is missing."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
    return os.fdopen(fd, "a+", encoding="utf-8")
