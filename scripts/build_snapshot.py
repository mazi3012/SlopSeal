"""Regenerate or verify the snapshot checksum manifest.

Usage:
  python scripts/build_snapshot.py          # write manifest.json from the data files
  python scripts/build_snapshot.py --check  # exit 1 if the manifest does not match the files

The data files are the source of truth and are edited by hand. This script never edits them.
It only records their sha256 values in `manifest.json` (Open Decision 6, resolved).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from slopseal.fixtures.loader import MANIFEST_NAME, build_manifest

FIXTURES = Path(__file__).resolve().parents[1] / "src" / "slopseal" / "fixtures"


def main(argv: list[str]) -> int:
    manifest = build_manifest(FIXTURES)
    target = FIXTURES / MANIFEST_NAME
    if "--check" in argv:
        current = json.loads(target.read_text(encoding="utf-8")) if target.exists() else None
        if current != manifest:
            print(f"build_snapshot: {target} does not match the data files", file=sys.stderr)
            return 1
        print(f"build_snapshot: {target} matches the data files")
        return 0
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"build_snapshot: wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
