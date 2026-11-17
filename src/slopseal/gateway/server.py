"""Package source gateway MVP: serve a package artifact only when SlopSeal says ALLOW.

Route: `GET /v1/<ecosystem>/<name>/<version>/artifact`. `name` is percent-encoded, so a scoped
npm name such as `@scope/pkg` is sent as `%40scope%2Fpkg`.

For each request:
1. The route and the names are validated with the same patterns as the MCP tool. Bad input is 422.
2. `verify_install` runs for the exact package and version, with the same context, rate limit,
   and audit log as the hook and the MCP tool (R-GW-5). Anything other than ALLOW is 403, with a
   JSON body that names the outcome, the check, and the next step, and no bytes (R-GW-1).
3. The upstream adapter gives the artifact URL and the registry's published SHA-256. Without a
   published digest the request is refused (R-GW-2).
4. The bytes are fetched and their SHA-256 must match the published digest. Only then are the
   bytes sent (R-GW-2).

Any failure to produce a verdict, resolve, or fetch returns an error status and no bytes
(R-GW-3). An OSError, ValueError, KeyError, or TypeError from the adapter returns 503. Other
exceptions end the request before any response is written, so no bytes are sent.

The server binds to loopback unless the caller passes `allow_remote=True` (R-GW-4).

Requirements: R-GW-1..R-GW-6. Layer 5. Stdlib only (ADR 0002).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.parse import unquote

from slopseal.core.types import Ecosystem
from slopseal.mcp.server import PACKAGE_PATTERN, TOOL_ECOSYSTEMS, VERSION_PATTERN
from slopseal.messages import NEXT, verdict_category
from slopseal.quarantine.rate_limit import Layer
from slopseal.runtime import ECOSYSTEMS
from slopseal.verdict import Context, Decision, InstallRequest, Outcome, verify_install

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ARTIFACT_TYPE = "application/octet-stream"
JSON_TYPE = "application/json"


@dataclass(frozen=True)
class Artifact:
    """Where the upstream keeps one artifact, and the digest the registry published for it."""

    url: str
    sha256: str | None


class Upstream(Protocol):
    """The upstream registry adapter. It is injected, so tests never reach a live registry."""

    def artifact(self, eco: Ecosystem, name: str, version: str) -> Artifact | None: ...

    def fetch(self, url: str) -> bytes: ...


Verify = Callable[[InstallRequest, Context], Decision]


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str


@dataclass(frozen=True)
class Route:
    ecosystem: str
    name: str
    version: str


def parse_route(path: str) -> Route | None:
    """Return the route, or None for any path that is not a valid artifact request."""
    parts = path.split("?", 1)[0].split("/")
    if len(parts) != 6 or parts[0] != "" or parts[1] != "v1" or parts[5] != "artifact":
        return None
    ecosystem, name, version = parts[2], unquote(parts[3]), parts[4]
    if ecosystem not in TOOL_ECOSYSTEMS:
        return None
    if PACKAGE_PATTERN.fullmatch(name) is None or VERSION_PATTERN.fullmatch(version) is None:
        return None
    return Route(ecosystem, name, version)


def _json(status: HTTPStatus | int, payload: dict[str, Any]) -> Response:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    return Response(int(status), body, JSON_TYPE)


def _refusal(decision: Decision) -> Response:
    """A 403 for a verdict that is not ALLOW. It names the outcome and the next step (R-U-1)."""
    violation = decision.violation
    check = violation.check if violation is not None else None
    category = verdict_category(decision.outcome.value, check)
    return _json(
        HTTPStatus.FORBIDDEN,
        {
            "outcome": decision.outcome.value,
            "package": decision.package,
            "version": decision.version,
            "check": check,
            "reason": decision.reason,
            "quarantine_id": decision.quarantine_id,
            "next": NEXT[category],
        },
    )


def handle_artifact(
    ctx: Context,
    upstream: Upstream,
    route: Route,
    *,
    verify: Verify = verify_install,
) -> Response:
    """Return the response for one artifact request. Pure apart from the injected collaborators."""
    ecosystem: Ecosystem = ECOSYSTEMS[route.ecosystem]
    decision = verify(InstallRequest(ecosystem, route.name, route.version, layer=Layer.OTHER), ctx)
    if decision.outcome is not Outcome.ALLOW:
        return _refusal(decision)

    artifact = upstream.artifact(ecosystem, route.name, route.version)
    if artifact is None:
        return _json(
            HTTPStatus.NOT_FOUND,
            {"outcome": "NO_ARTIFACT", "package": route.name, "version": route.version},
        )
    if artifact.sha256 is None:
        return _json(
            HTTPStatus.FORBIDDEN,
            {
                "outcome": "NO_DIGEST",
                "package": route.name,
                "version": route.version,
                "next": "The registry published no SHA-256 for this artifact. It is not served.",
            },
        )
    try:
        data = upstream.fetch(artifact.url)
    except OSError:
        return _json(
            HTTPStatus.BAD_GATEWAY,
            {"outcome": "UPSTREAM_ERROR", "package": route.name, "version": route.version},
        )
    if hashlib.sha256(data).hexdigest() != artifact.sha256.lower():
        return _json(
            HTTPStatus.BAD_GATEWAY,
            {"outcome": "DIGEST_MISMATCH", "package": route.name, "version": route.version},
        )
    return Response(int(HTTPStatus.OK), data, ARTIFACT_TYPE)


def _handler_class(ctx: Context, upstream: Upstream, verify: Verify) -> type:
    class GatewayHandler(BaseHTTPRequestHandler):
        server_version = "slopseal-gateway"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - the name is fixed by http.server
            response = self._respond()
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            self.wfile.write(response.body)

        def _respond(self) -> Response:
            route = parse_route(self.path)
            if route is None:
                return _json(HTTPStatus.UNPROCESSABLE_ENTITY, {"outcome": "INVALID_REQUEST"})
            try:
                return handle_artifact(ctx, upstream, route, verify=verify)
            except (OSError, ValueError, KeyError, TypeError):
                # Setup or adapter failure: 503, no bytes (R-GW-3). Other exceptions are not
                # caught here (tech.md allows a bare `except Exception` only in verdict.py). They
                # end the request before any response is written, so no bytes are sent.
                return _json(HTTPStatus.SERVICE_UNAVAILABLE, {"outcome": "GATEWAY_ERROR"})

        def log_message(self, format: str, *args: object) -> None:
            """Keep the request line out of stderr. Verdicts are in the audit log already."""

    return GatewayHandler


def make_server(
    host: str,
    port: int,
    ctx: Context,
    upstream: Upstream,
    *,
    verify: Verify = verify_install,
    allow_remote: bool = False,
) -> ThreadingHTTPServer:
    """Build the server without starting it. The caller runs `serve_forever`.

    Refuses a non-loopback host unless `allow_remote` is set (R-GW-4).
    """
    if host not in LOOPBACK_HOSTS and not allow_remote:
        raise ValueError(f"refusing to bind the gateway to {host!r}; use a loopback address")
    return ThreadingHTTPServer((host, port), _handler_class(ctx, upstream, verify))
