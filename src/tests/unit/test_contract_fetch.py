"""Unit tests for the artifact download (R-C-1, R-C-4). Fake openers only; no network.

Requirements: R-C-1, R-C-4. Per-reason tests for network and limit: test_contract_reasons.py.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from http.client import HTTPMessage

from slopseal.contract.fetch import FetchRefused, _CheckedRedirects, download
from slopseal.contract.types import ContractUnknown, UnknownReason
from slopseal.core.types import Ecosystem

PYPI_URL = "https://files.pythonhosted.org/packages/x/y/pkg-1.0-py3-none-any.whl"
NPM_URL = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self._body = body

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            chunk, self._body = self._body, b""
            return chunk
        chunk, self._body = self._body[:amount], self._body[amount:]
        return chunk

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class Spy:
    def __init__(
        self, response: FakeResponse | None = None, error: BaseException | None = None
    ) -> None:
        self.calls = 0
        self._response = response
        self._error = error

    def __call__(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        self.calls += 1
        if self._error is not None:
            raise self._error
        assert self._response is not None
        return self._response


def test_r_c_1_a_plain_http_url_is_refused_without_a_request() -> None:
    spy = Spy(FakeResponse(b"x"))
    result = download("http://files.pythonhosted.org/x.whl", Ecosystem.PYPI, opener=spy)
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NETWORK
    assert spy.calls == 0


def test_r_c_1_a_host_off_the_allowlist_is_refused_without_a_request() -> None:
    spy = Spy(FakeResponse(b"x"))
    result = download("https://evil.example/x.whl", Ecosystem.PYPI, opener=spy)
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NETWORK
    assert spy.calls == 0


def test_r_c_1_the_npm_host_is_allowed_for_npm_only() -> None:
    body = download(NPM_URL, Ecosystem.NPM, opener=Spy(FakeResponse(b"tgz")))
    assert body == b"tgz"
    refused = download(NPM_URL, Ecosystem.PYPI, opener=Spy(FakeResponse(b"tgz")))
    assert isinstance(refused, ContractUnknown)
    assert refused.reason is UnknownReason.NETWORK


def test_r_c_1_a_redirect_off_the_allowlist_is_refused() -> None:
    handler = _CheckedRedirects(frozenset({"files.pythonhosted.org"}))
    request = urllib.request.Request(PYPI_URL)
    try:
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            HTTPMessage(),
            "https://evil.example/x.whl",  # type: ignore[arg-type]
        )
    except FetchRefused:
        return
    raise AssertionError("a redirect off the allowlist was not refused")


def test_r_c_1_a_redirect_to_plain_http_is_refused() -> None:
    handler = _CheckedRedirects(frozenset({"files.pythonhosted.org"}))
    request = urllib.request.Request(PYPI_URL)
    try:
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            HTTPMessage(),
            "http://files.pythonhosted.org/x.whl",  # type: ignore[arg-type]
        )
    except FetchRefused:
        return
    raise AssertionError("a plain-http redirect was not refused")


def test_r_c_4_a_body_over_the_cap_is_limit() -> None:
    result = download(PYPI_URL, Ecosystem.PYPI, max_bytes=10, opener=Spy(FakeResponse(b"x" * 11)))
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.LIMIT


def test_r_c_4_a_body_at_the_cap_is_returned() -> None:
    body = download(PYPI_URL, Ecosystem.PYPI, max_bytes=10, opener=Spy(FakeResponse(b"x" * 10)))
    assert body == b"x" * 10


def test_r_c_1_a_non_200_status_is_network() -> None:
    result = download(PYPI_URL, Ecosystem.PYPI, opener=Spy(FakeResponse(b"", status=404)))
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NETWORK


def test_r_c_1_a_transport_error_is_network() -> None:
    error = urllib.error.URLError("connection refused")
    result = download(PYPI_URL, Ecosystem.PYPI, opener=Spy(error=error))
    assert isinstance(result, ContractUnknown)
    assert result.reason is UnknownReason.NETWORK
