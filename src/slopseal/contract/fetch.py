"""Download one artifact: https only, host allowlist (also after redirects), size cap, timeout.

Any failure of the request is ContractUnknown with reason network. A body over the cap is
ContractUnknown with reason limit. The bytes are not parsed here. The digest check comes next,
in digest.py, before any archive is read (R-C-1).

Requirements: R-C-1, R-C-4. Layer 1 (adapter). Standard library only.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from http.client import HTTPMessage
from typing import IO, Protocol, cast

from slopseal.contract.limits import DOWNLOAD_WALL_SECONDS, MAX_COMPRESSED_BYTES
from slopseal.contract.types import ContractUnknown, UnknownReason
from slopseal.core.types import Ecosystem

ALLOWED_HOSTS: Mapping[Ecosystem, frozenset[str]] = {
    Ecosystem.PYPI: frozenset({"files.pythonhosted.org"}),
    Ecosystem.NPM: frozenset({"registry.npmjs.org"}),
}
USER_AGENT = "slopseal-contract/0 (+https://github.com/mazi3012/SlopSeal)"
_CHUNK = 1 << 16


class FetchRefused(Exception):
    """A redirect or URL that leaves the allowlist, or is not https. Mapped to network."""


def _host_allowed(url: str, allowed: frozenset[str]) -> bool:
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and parts.hostname in allowed


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect whose target is not https on the allowlist (R-C-1)."""

    def __init__(self, allowed: frozenset[str]) -> None:
        self._allowed = allowed

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _host_allowed(newurl, self._allowed):
            raise FetchRefused("redirect leaves the allowlist")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _Response(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def __enter__(self) -> _Response: ...

    def __exit__(self, *exc: object) -> None: ...


# An opener takes a request and a timeout, and returns a response context manager.
Opener = Callable[[urllib.request.Request, float], _Response]


def _default_opener(allowed: frozenset[str]) -> Opener:
    director = urllib.request.build_opener(_CheckedRedirects(allowed))

    def open_request(request: urllib.request.Request, timeout: float) -> _Response:
        return cast(_Response, director.open(request, timeout=timeout))

    return open_request


def download(
    url: str,
    ecosystem: Ecosystem,
    *,
    max_bytes: int = MAX_COMPRESSED_BYTES,
    timeout: float = DOWNLOAD_WALL_SECONDS,
    opener: Opener | None = None,
) -> bytes | ContractUnknown:
    """The artifact bytes, or ContractUnknown with network or limit."""
    allowed = ALLOWED_HOSTS[ecosystem]
    if not _host_allowed(url, allowed):
        return ContractUnknown(UnknownReason.NETWORK, "artifact URL is not https on the allowlist")
    active: Opener = opener if opener is not None else _default_opener(allowed)
    request = urllib.request.Request(  # noqa: S310 - https and allowlist checked above
        url, headers={"User-Agent": USER_AGENT}
    )
    try:
        with active(request, timeout) as response:
            if response.status != 200:
                return ContractUnknown(UnknownReason.NETWORK, "artifact request did not return 200")
            body = bytearray()
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    return ContractUnknown(
                        UnknownReason.LIMIT, "artifact is larger than the compressed limit"
                    )
    except (urllib.error.URLError, OSError, FetchRefused, ValueError):
        return ContractUnknown(UnknownReason.NETWORK, "artifact download failed")
    return bytes(body)
