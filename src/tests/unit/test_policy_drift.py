"""Drift guard: the bundled default policy must be byte-identical to the repo policy.

The package ships `src/slopseal/defaults/dependency-trust.md` as the zero-config fallback. The
repo keeps `.kiro/steering/dependency-trust.md` as the policy people edit. If the two diverge,
a new workspace gets a different policy than the one this repo reviews. This test fails on any
difference.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
REPO_POLICY = REPO_ROOT / ".kiro" / "steering" / "dependency-trust.md"
BUNDLED_POLICY = REPO_ROOT / "src" / "slopseal" / "defaults" / "dependency-trust.md"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_bundled_default_policy_is_byte_identical_to_repo_policy() -> None:
    repo_digest = _sha256(REPO_POLICY)
    bundled_digest = _sha256(BUNDLED_POLICY)
    assert repo_digest == bundled_digest, (
        f"{REPO_POLICY.relative_to(REPO_ROOT)} and "
        f"{BUNDLED_POLICY.relative_to(REPO_ROOT)} differ "
        f"(sha256 {repo_digest} vs {bundled_digest}). "
        "Update both files so they are byte-identical. Copy the repo policy over the bundled "
        "default."
    )
