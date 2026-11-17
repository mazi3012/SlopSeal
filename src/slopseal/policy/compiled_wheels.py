"""Reviewed exception for a compiled wheel (install-time code cannot be ruled out otherwise).

A PyPI version with no universal wheel may run code at install time, so the registry adapter
blocks it by default. This module decides whether one reviewed exception covers a release on
this host. It returns None when the exception applies, and the refusal reason otherwise.

The exception applies only when all of these hold:
1. The package and version are in `ALLOWED_COMPILED_WHEELS` (invariants) and in the policy.
2. The host is a reviewed platform: linux-x86_64 with glibc, or macos-arm64.
3. The release names the reviewed publisher as its source or homepage URL.
4. The reviewed wheel for this platform is in the release, and its sha256 equals the pin.

An sdist alone, a missing wheel, or any other digest refuses. The exception does not run or
check the OSV advisories. The live CVE check runs as usual, so "OSV-clean" is still enforced.

Limits: this decides the verdict. It cannot change how pip installs. To keep pip from falling
back to an sdist, install with `--only-binary` and `--require-hashes` from the lock file
(requirements/sign.lock).

Requirements: policy PR (ADR 0005 dependency). Layer 2. Pure apart from `host_platform`.
"""

from __future__ import annotations

import os
import platform
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from slopseal.policy.invariants import ALLOWED_COMPILED_WHEELS, ALLOWED_PLATFORMS
from slopseal.policy.loader import CompiledWheelException

_SCHEME = re.compile(r"^https?://")


def host_platform() -> str | None:
    """The reviewed platform key for this host, or None when the host is not reviewed."""
    if sys.platform == "darwin" and platform.machine() == "arm64":
        return "macos-arm64"
    if sys.platform.startswith("linux") and platform.machine() == "x86_64":
        try:
            glibc = os.confstr("CS_GNU_LIBC_VERSION")
        except (ValueError, OSError):
            return None
        return "linux-x86_64" if glibc else None
    return None


def _normalise_url(url: str) -> str:
    """Lowercase, no scheme, no `www.`, no trailing slash or `.git`: `github.com/owner/repo`."""
    text = _SCHEME.sub("", url.strip().lower()).rstrip("/")
    text = text.removeprefix("www.")
    return text.removesuffix(".git")


def _normal_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def compiled_wheel_refusal(
    name: str,
    version: str,
    release: Mapping[str, Any],
    exceptions: Sequence[CompiledWheelException],
    platform_key: str | None,
) -> str | None:
    """None when a reviewed exception covers this release. Otherwise the refusal reason."""
    wanted = _normal_name(name)
    entry = next((e for e in exceptions if _normal_name(e.name) == wanted), None)
    if entry is None:
        return "no reviewed exception for this package"
    if (entry.name, entry.version) not in ALLOWED_COMPILED_WHEELS:
        return f"{entry.name} {entry.version} is not allowlisted"
    if version != entry.version:
        return f"version {version} is not the reviewed version {entry.version}"
    if platform_key is None or platform_key not in ALLOWED_PLATFORMS:
        return "this host platform has no reviewed wheel"
    pin = next((p for p in entry.pins if p.platform == platform_key), None)
    if pin is None:
        return f"no reviewed wheel for platform {platform_key}"

    info = release.get("info")
    info = info if isinstance(info, dict) else {}
    urls = info.get("project_urls")
    urls = urls if isinstance(urls, dict) else {}
    candidates = [urls.get("source"), urls.get("homepage"), info.get("home_page")]
    publishers = {_normalise_url(u) for u in candidates if isinstance(u, str) and u}
    if entry.publisher not in publishers:
        return "publisher does not match the reviewed publisher"

    files = release.get("urls")
    files = [f for f in files if isinstance(f, dict)] if isinstance(files, list) else []
    match = [f for f in files if f.get("filename") == pin.filename]
    if not match:
        return f"reviewed wheel {pin.filename} is not in the release (sdist fallback refused)"
    digests = match[0].get("digests")
    digest = digests.get("sha256") if isinstance(digests, dict) else None
    if digest != pin.sha256:
        return "reviewed wheel digest does not match the pinned digest"
    return None
