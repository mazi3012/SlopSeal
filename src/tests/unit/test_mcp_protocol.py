"""Unit tests for the slopseal-mcp JSON-RPC layer (R-1.8).

The verifier is replaced with a fake, so these tests cover the protocol, argument validation, and
the mapping from verdict to tool result. The real checks run in the integration tests.
Requirements: R-1.8, R-1.3, R-V-1, R-V-4.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from slopseal.core.types import CheckResult, Ecosystem, Level
from slopseal.mcp.server import (
    MAX_MESSAGE_BYTES,
    NoVerdict,
    ProtocolError,
    Server,
    parse_arguments,
)
from slopseal.verdict import Decision, InstallRequest, Intent, Outcome


def _decision(outcome: Outcome, **extra: Any) -> Decision:
    return Decision(
        outcome=outcome,
        ecosystem="pypi",
        package="tinyfmt-kit",
        version="0.4.0",
        reason=str(extra.pop("reason", "all checks passed")),
        **extra,
    )


class Recorder:
    """A fake verifier that records each request and returns a fixed decision."""

    def __init__(self, decision: Decision | None = None, error: Exception | None = None) -> None:
        self.requests: list[InstallRequest] = []
        self._decision = decision
        self._error = error

    def __call__(self, request: InstallRequest) -> Decision:
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        assert self._decision is not None
        return self._decision


def _call(server: Server, arguments: dict[str, Any]) -> dict[str, Any]:
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "verify_install", "arguments": arguments},
    }
    response = server.handle(json.dumps(message).encode())
    assert response is not None
    return response


VALID = {"ecosystem": "pypi", "package": "tinyfmt-kit", "version": "0.4.0"}


def test_initialize_echoes_a_supported_protocol_version() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}},
    }
    response = server.handle(json.dumps(message).encode())
    assert response is not None
    result = response["result"]
    assert result["protocolVersion"] == "2025-03-26"
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"]["name"] == "slopseal-mcp"


def test_initialize_answers_an_unknown_version_with_the_server_default() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "1999-01-01"},
    }
    response = server.handle(json.dumps(message).encode())
    assert response is not None
    assert response["result"]["protocolVersion"] == "2025-06-18"


def test_initialized_notification_gets_no_reply() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    raw = b'{"jsonrpc":"2.0","method":"notifications/initialized"}'
    assert server.handle(raw) is None


def test_tools_list_exposes_only_verify_install_without_a_bypass() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    response = server.handle(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
    assert response is not None
    tools = response["result"]["tools"]
    assert [tool["name"] for tool in tools] == ["verify_install"]
    schema = tools[0]["inputSchema"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"ecosystem", "package", "version"}
    assert "bypass_reason" not in schema["properties"]
    assert "allow_unsafe" not in schema["properties"]


def test_ping_returns_an_empty_result() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    response = server.handle(b'{"jsonrpc":"2.0","id":3,"method":"ping"}')
    assert response == {"jsonrpc": "2.0", "id": 3, "result": {}}


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"not json", -32700),
        (b"[]", -32600),
        (b'{"id":1,"method":"tools/list"}', -32600),
        (b'{"jsonrpc":"2.0","id":1,"method":"resources/list"}', -32601),
        (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}', -32600),
        (b"\xff\xfe", -32700),
    ],
)
def test_malformed_messages_get_a_json_rpc_error(raw: bytes, code: int) -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    response = server.handle(raw)
    assert response is not None
    assert response["error"]["code"] == code


def test_oversized_message_is_refused_before_parsing() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    response = server.handle(b" " * (MAX_MESSAGE_BYTES + 1))
    assert response is not None
    assert response["error"]["code"] == -32600


def test_a_client_response_is_ignored() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    assert server.handle(b'{"jsonrpc":"2.0","id":9,"result":{}}') is None


def test_unknown_tool_is_a_protocol_error() -> None:
    server = Server(Recorder(_decision(Outcome.ALLOW)))
    message = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "install_package", "arguments": VALID},
    }
    response = server.handle(json.dumps(message).encode())
    assert response is not None
    assert response["error"]["code"] == -32602


def test_allow_is_a_success_result() -> None:
    recorder = Recorder(_decision(Outcome.ALLOW))
    response = _call(Server(recorder), VALID)
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["outcome"] == "ALLOW"
    assert result["structuredContent"]["exit_code"] == 0
    assert result["content"][0]["text"] == "ALLOW tinyfmt-kit==0.4.0: all checks passed"


def test_block_is_an_error_result_with_the_failed_check() -> None:
    violation = CheckResult("malware", Level.HARD_BLOCK, "malware record", "pick another version")
    decision = _decision(Outcome.BLOCK, violation=violation, reason="malware record")
    result = _call(Server(Recorder(decision)), VALID)["result"]
    assert result["isError"] is True
    payload = result["structuredContent"]
    assert payload["outcome"] == "BLOCK"
    assert payload["exit_code"] == 1
    assert payload["violation"] == {
        "check": "malware",
        "level": "HARD_BLOCK",
        "reason": "malware record",
        "remedy": "pick another version",
    }


def test_quarantine_carries_its_payload_and_is_an_error_result() -> None:
    decision = _decision(
        Outcome.QUARANTINE,
        quarantine_id="q-123",
        quarantine_payload={"quarantine_id": "q-123", "exports": ["a"]},
        reason="api_absent",
    )
    result = _call(Server(Recorder(decision)), VALID)["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["outcome"] == "QUARANTINE"
    assert result["structuredContent"]["exit_code"] == 75
    assert result["structuredContent"]["quarantine"] == {"quarantine_id": "q-123", "exports": ["a"]}


def test_a_block_result_does_not_expose_a_quarantine_payload() -> None:
    decision = _decision(Outcome.BLOCK, quarantine_payload={"secret": "x"})
    payload = _call(Server(Recorder(decision)), VALID)["result"]["structuredContent"]
    assert payload["quarantine"] is None


def test_no_verdict_is_an_error_result_not_an_allow() -> None:
    recorder = Recorder(error=NoVerdict("trust policy is missing"))
    result = _call(Server(recorder), VALID)["result"]
    assert result["isError"] is True
    assert "no verdict was issued" in result["content"][0]["text"]
    assert "structuredContent" not in result


def test_optional_arguments_build_an_intent() -> None:
    recorder = Recorder(_decision(Outcome.ALLOW))
    _call(Server(recorder), {**VALID, "purpose": "parse dates", "expected_api": "parse"})
    request = recorder.requests[0]
    assert request.intent == Intent(purpose="parse dates", expected_api="parse")
    assert request.ecosystem is Ecosystem.PYPI
    assert request.version == "0.4.0"


def test_no_optional_arguments_means_no_intent() -> None:
    recorder = Recorder(_decision(Outcome.ALLOW))
    _call(Server(recorder), VALID)
    assert recorder.requests[0].intent is None
    assert recorder.requests[0].quarantine_id is None


def test_quarantine_id_is_passed_for_a_retry() -> None:
    recorder = Recorder(_decision(Outcome.ALLOW))
    _call(Server(recorder), {**VALID, "quarantine_id": "q-abc_1"})
    assert recorder.requests[0].quarantine_id == "q-abc_1"


@pytest.mark.parametrize(
    "arguments",
    [
        {"package": "tinyfmt-kit", "version": "0.4.0"},
        {"ecosystem": "pypi", "version": "0.4.0"},
        {"ecosystem": "pypi", "package": "tinyfmt-kit"},
        {**VALID, "ecosystem": "cargo"},
        {**VALID, "package": "tiny fmt"},
        {**VALID, "package": "tinyfmt-kit; rm -rf /"},
        {**VALID, "version": ">=0.4"},
        {**VALID, "version": ""},
        {**VALID, "bypass_reason": "trust me"},
        {**VALID, "allow_unsafe": True},
        {**VALID, "purpose": "x" * 501},
        {**VALID, "expected_api": 5},
        {**VALID, "quarantine_id": "../escape"},
    ],
)
def test_invalid_arguments_are_rejected_before_any_check_runs(arguments: dict[str, Any]) -> None:
    recorder = Recorder(_decision(Outcome.ALLOW))
    response = _call(Server(recorder), arguments)
    assert response["error"]["code"] == -32602
    assert recorder.requests == []


@pytest.mark.parametrize("package", ["tinyfmt-kit", "@scope/pkg", "zope.interface", "a_b+c"])
def test_valid_package_names_are_accepted(package: str) -> None:
    request = parse_arguments({**VALID, "package": package})
    assert request.package == package


def test_arguments_must_be_an_object() -> None:
    with pytest.raises(ProtocolError, match="arguments must be an object"):
        parse_arguments(["pypi"])
