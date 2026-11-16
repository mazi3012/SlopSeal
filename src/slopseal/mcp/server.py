"""slopseal-mcp: a stdio MCP server that exposes one tool, verify_install.

The server speaks newline-delimited JSON-RPC 2.0 on stdin and stdout, as the MCP stdio transport
requires (protocol 2025-06-18, with 2025-03-26 accepted). Stdout carries only protocol messages.
Logs go to stderr.

The tool wraps verify_install (R-1.3) and runs the same deterministic checks as `slopseal check`.
It never installs anything. The tool result is an error (isError true) for BLOCK and QUARANTINE,
and for any failure to produce a verdict, so a client does not read those as approval.

Fail closed: when the policy, seal key, or snapshot cannot be loaded, the tool reports no verdict.
It does not return ALLOW. An unexpected exception ends the process, and the client then sees no
result. Nothing is returned as ALLOW by default.

Requirements: R-1.8, R-1.3, R-V-1, R-V-4. Layer 5.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from collections.abc import Callable
from typing import Any, BinaryIO

from slopseal import __version__
from slopseal.audit.seal import SealKeyError
from slopseal.fixtures.loader import SnapshotIntegrityError
from slopseal.policy.loader import PolicyError
from slopseal.runtime import ECOSYSTEMS, build_context, state_dir
from slopseal.verdict import Decision, InstallRequest, Intent, Outcome, verify_install

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")
SERVER_NAME = "slopseal-mcp"
TOOL_NAME = "verify_install"
MAX_MESSAGE_BYTES = 64 * 1024

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602

# v1 scope is pip and npm (R-1.1, PRD scope). Other ecosystems are refused at the schema.
TOOL_ECOSYSTEMS = ("pypi", "npm")

PACKAGE_PATTERN = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._/@+-]{0,213}")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
QUARANTINE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")

INSTRUCTIONS = (
    "Call verify_install with the exact version before installing a package. Install only when "
    "the outcome is ALLOW. A BLOCK or QUARANTINE outcome means the install must not run."
)

TOOL_DEFINITION: dict[str, Any] = {
    "name": TOOL_NAME,
    "title": "Verify a package install",
    "description": (
        "Run SlopSeal's deterministic checks on one exact package version before it is "
        "installed. Returns ALLOW, BLOCK, or QUARANTINE. This tool does not install anything. "
        "An isError result means the install must not run."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "ecosystem": {
                "type": "string",
                "enum": list(TOOL_ECOSYSTEMS),
                "description": "pypi for pip, npm for npm.",
            },
            "package": {
                "type": "string",
                "minLength": 1,
                "maxLength": 214,
                "description": "Package name as the install command gives it.",
            },
            "version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "description": "The exact version to verify, for example 1.2.3.",
            },
            "purpose": {
                "type": "string",
                "maxLength": 500,
                "description": "Why the package is needed. Optional.",
            },
            "expected_api": {
                "type": "string",
                "maxLength": 200,
                "description": "A symbol the code will import from the package. Optional.",
            },
            "quarantine_id": {
                "type": "string",
                "maxLength": 64,
                "description": "The id from an earlier QUARANTINE, when retrying. Optional.",
            },
        },
        "required": ["ecosystem", "package", "version"],
        "additionalProperties": False,
    },
    "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
}


class NoVerdict(Exception):
    """The verifier could not run, so no verdict exists. The caller must treat it as BLOCK."""


Verifier = Callable[[InstallRequest], Decision]


class ProtocolError(Exception):
    """A JSON-RPC error to return to the client. Carries the code and message."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def parse_arguments(arguments: Any) -> InstallRequest:
    """Validate tool arguments and build the request. Bad input is a protocol error."""
    if not isinstance(arguments, dict):
        raise ProtocolError(JSONRPC_INVALID_PARAMS, "arguments must be an object")
    allowed = {"ecosystem", "package", "version", "purpose", "expected_api", "quarantine_id"}
    unknown = set(arguments) - allowed
    if unknown:
        raise ProtocolError(JSONRPC_INVALID_PARAMS, f"unknown argument: {sorted(unknown)[0]}")
    for key in ("ecosystem", "package", "version"):
        if not isinstance(arguments.get(key), str) or not arguments[key]:
            raise ProtocolError(JSONRPC_INVALID_PARAMS, f"{key} is required")
    ecosystem = arguments["ecosystem"]
    if ecosystem not in TOOL_ECOSYSTEMS:
        raise ProtocolError(JSONRPC_INVALID_PARAMS, "ecosystem must be pypi or npm")
    package = arguments["package"]
    if PACKAGE_PATTERN.fullmatch(package) is None:
        raise ProtocolError(JSONRPC_INVALID_PARAMS, "package name has invalid characters")
    version = arguments["version"]
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ProtocolError(JSONRPC_INVALID_PARAMS, "version must be an exact version")
    purpose = _optional_text(arguments, "purpose", 500)
    expected_api = _optional_text(arguments, "expected_api", 200)
    quarantine_id = _optional_text(arguments, "quarantine_id", 64)
    if quarantine_id is not None and QUARANTINE_ID_PATTERN.fullmatch(quarantine_id) is None:
        raise ProtocolError(JSONRPC_INVALID_PARAMS, "quarantine_id has invalid characters")
    intent = None
    if purpose is not None or expected_api is not None:
        intent = Intent(purpose=purpose or "", expected_api=expected_api)
    return InstallRequest(
        ecosystem=ECOSYSTEMS[ecosystem],
        package=package,
        version=version,
        intent=intent,
        quarantine_id=quarantine_id,
    )


def _optional_text(arguments: dict[str, Any], key: str, limit: int) -> str | None:
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise ProtocolError(JSONRPC_INVALID_PARAMS, f"{key} must be text up to {limit} characters")
    return value


def tool_result(decision: Decision) -> dict[str, Any]:
    """Build the MCP tool result for a verdict. Only ALLOW is a success."""
    violation = decision.violation
    payload: dict[str, Any] = {
        "outcome": decision.outcome.value,
        "exit_code": decision.exit_code,
        "ecosystem": decision.ecosystem,
        "package": decision.package,
        "version": decision.version,
        "reason": decision.reason,
        "violation": None
        if violation is None
        else {
            "check": violation.check,
            "level": violation.level.name,
            "reason": violation.reason,
            "remedy": violation.remedy,
        },
        "warnings": [{"check": w.check, "reason": w.reason} for w in decision.warnings],
        "quarantine_id": decision.quarantine_id,
        "quarantine": decision.quarantine_payload
        if decision.outcome is Outcome.QUARANTINE
        else None,
    }
    summary = f"{decision.outcome.value} {decision.package}=={decision.version}: {decision.reason}"
    return {
        "content": [{"type": "text", "text": summary}],
        "structuredContent": payload,
        "isError": decision.outcome is not Outcome.ALLOW,
    }


def no_verdict_result(reason: str) -> dict[str, Any]:
    """Tool error for a run that produced no verdict. The install must not run."""
    return {
        "content": [{"type": "text", "text": f"no verdict was issued: {reason}. Do not install."}],
        "isError": True,
    }


class Server:
    """Dispatches one JSON-RPC message at a time. It holds no state between messages."""

    def __init__(self, verifier: Verifier) -> None:
        self._verifier = verifier

    def handle(self, raw: bytes) -> dict[str, Any] | None:
        """Return the response for one message, or None for a notification or a response."""
        if len(raw) > MAX_MESSAGE_BYTES:
            return _error(None, JSONRPC_INVALID_REQUEST, "message is too large")
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return _error(None, JSONRPC_PARSE_ERROR, "parse error")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, JSONRPC_INVALID_REQUEST, "not a JSON-RPC 2.0 message")
        if "method" not in message:
            # A response to a request from this server. The server sends none, so ignore it.
            return None
        method = message["method"]
        if "id" not in message:
            # A notification such as notifications/initialized. It gets no reply.
            return None
        request_id = message["id"]
        params = message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return _error(request_id, JSONRPC_INVALID_REQUEST, "malformed request")
        try:
            return _result(request_id, self._dispatch(method, params))
        except ProtocolError as exc:
            return _error(request_id, exc.code, exc.message)

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [TOOL_DEFINITION]}
        if method == "tools/call":
            return self._call_tool(params)
        raise ProtocolError(JSONRPC_METHOD_NOT_FOUND, f"method not found: {method}")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        if params.get("name") != TOOL_NAME:
            raise ProtocolError(JSONRPC_INVALID_PARAMS, f"unknown tool: {params.get('name')}")
        request = parse_arguments(params.get("arguments", {}))
        try:
            decision = self._verifier(request)
        except NoVerdict as exc:
            return no_verdict_result(str(exc))
        return tool_result(decision)


def verify_with_runtime(request: InstallRequest) -> Decision:
    """Build the verdict context from the environment and run verify_install.

    The policy and state paths come from SLOPSEAL_POLICY_PATH and SLOPSEAL_STATE_DIR, or their
    defaults, which are relative to the working directory. A missing policy falls back to the
    bundled default. Any other error is a NoVerdict.
    """
    try:
        context = build_context()
    except PolicyError as exc:
        raise NoVerdict(
            f"policy error ({exc}); use SLOPSEAL_POLICY_PATH to specify another file"
        ) from exc
    except SealKeyError as exc:
        raise NoVerdict(f"seal key in {state_dir()} is unusable ({exc})") from exc
    except SnapshotIntegrityError as exc:
        raise NoVerdict(f"snapshot failed its checksum ({exc})") from exc
    return verify_install(request, context)


def _discard_rest_of_line(stdin: BinaryIO) -> None:
    while True:
        chunk = stdin.readline(MAX_MESSAGE_BYTES)
        if not chunk or chunk.endswith(b"\n"):
            return


def serve(stdin: BinaryIO, stdout: BinaryIO, verifier: Verifier) -> None:
    """Read one message per line from stdin and write one reply per line to stdout."""
    server = Server(verifier)
    while True:
        line = stdin.readline(MAX_MESSAGE_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_MESSAGE_BYTES and not line.endswith(b"\n"):
            # Discard the rest of the oversize line, so its tail is never read as a request.
            _discard_rest_of_line(stdin)
            response: dict[str, Any] | None = _error(
                None, JSONRPC_INVALID_REQUEST, "message is too large"
            )
        else:
            response = server.handle(line.rstrip(b"\r\n"))
        if response is not None:
            stdout.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
            stdout.flush()


def main() -> int:
    level = os.environ.get("SLOPSEAL_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        stream=sys.stderr, level=level, format="slopseal-mcp %(levelname)s %(message)s"
    )
    serve(sys.stdin.buffer, sys.stdout.buffer, verify_with_runtime)
    return 0


if __name__ == "__main__":
    sys.exit(main())
