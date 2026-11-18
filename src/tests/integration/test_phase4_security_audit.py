# ruff: noqa: S603 - every argv here is built by the test, not from untrusted input.
"""Phase 4 security audit: integration tests against the production code paths.

Every test calls the real production entry points: the hook's `evaluate` with the real gate,
`verify_install` with the real `Context` from `runtime.build_context`, the real `RateLimiter`,
the real `AuditLog`, and the real `slopseal-mcp` server process. Only the network is replaced:
`LiveSource` receives a `fetch` function that returns recorded or hand-written bodies, so no test
reaches a live registry. No test installs a package, and no test runs a command it parses.

Two kinds of test live here:

- Plain tests confirm a security property that holds today.
- Tests marked `xfail(strict=True)` state the secure behaviour for a finding in
  reports/SlopSeal_PHASE4_SECURITY_AUDIT.md (F-xx ids). They fail today, which xfail records.
  When a fix lands, the test passes, strict xfail turns that into a failure, and the marker
  must be removed. No production code is patched to make any of them pass.

Failure-injection doubles (`_ExplodingSource`, `_FailingCredit`) exist only in this file. They
are passed in through `Context`, the same seam the production code uses.

Requirements: R-G-1..R-G-8, R-P-1, R-P-3, R-4.7, R-5.7.1, R-5.7.2, R-1.8.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from slopseal.audit.log import AuditLog, _line_hash
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.hooks.on_install import evaluate, scan_command
from slopseal.policy.invariants import enforce_floors
from slopseal.policy.loader import load_policy
from slopseal.quarantine.rate_limit import Layer, RateLimiter
from slopseal.registry.live import LiveFailure, LiveSource
from slopseal.runtime import build_context
from slopseal.verdict import Context, InstallRequest, Intent, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
PYPI = "https://pypi.org/pypi"
NPM = "https://registry.npmjs.org"
OSV = "https://api.osv.dev/v1/query"
NOW = datetime(2026, 11, 17, tzinfo=UTC)
TOP = {Ecosystem.PYPI: ("requests", "numpy", "flask", "django"), Ecosystem.NPM: ("lodash",)}


# ---- shared setup -------------------------------------------------------------------------


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fresh state directory, the repo policy, and the offline snapshot, as the hook sees them."""
    root = tmp_path / "state"
    monkeypatch.setenv("SLOPSEAL_STATE_DIR", str(root))
    monkeypatch.setenv("SLOPSEAL_POLICY_PATH", str(POLICY))
    monkeypatch.setenv("SLOPSEAL_OFFLINE_SNAPSHOT", "1")
    monkeypatch.delenv("SLOPSEAL_SNAPSHOT_DIR", raising=False)
    return root


def _hook(command: str) -> tuple[int, str]:
    payload = json.dumps({"tool_name": "execute_bash", "tool_input": {"command": command}})
    result = evaluate(payload)
    return result.exit_code, result.stderr


def _pypi_doc(
    name: str,
    version: str,
    *,
    wheel: str = "-py3-none-any.whl",
    first: str = "2015-01-01T00:00:00Z",
) -> dict[str, Any]:
    files = [
        {
            "filename": f"{name}-{version}{wheel}",
            "upload_time_iso_8601": first,
            "url": "https://files.example/x",
            "digests": {"sha256": "00" * 32},
            "packagetype": "bdist_wheel" if wheel.endswith(".whl") else "sdist",
        }
    ]
    releases = {f"0.{i}": files for i in range(20)}
    releases[version] = files
    return {
        "info": {"version": version, "license": "Apache-2.0", "classifiers": []},
        "releases": releases,
        "urls": files,
    }


Route = dict[Any, Any]


def _fetch(routes: Route) -> Callable[[str, bytes | None], bytes | None]:
    """The network seam of LiveSource. A value of None is a 404; an exception is raised."""

    def fetch(url: str, body: bytes | None) -> bytes | None:
        key: Any = url if body is None else (url, json.loads(body)["package"]["name"])
        value = routes[key] if key in routes else routes.get(url)
        if isinstance(value, BaseException):
            raise value
        if value is None:
            return None
        return value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")

    return fetch


def _live_ctx(state: Path, routes: Route) -> Context:
    ctx = build_context(state, rate_limited=False)
    return replace(ctx, source=LiveSource(top_n=TOP, fetch=_fetch(routes)), now=NOW)


GOOD = _pypi_doc("goodlib", "2.0.0")
GOOD_ROUTES: Route = {
    f"{PYPI}/goodlib/json": GOOD,
    f"{PYPI}/goodlib/2.0.0/json": GOOD,
    (OSV, "goodlib"): {"vulns": []},
}


def _osv(*vulns: dict[str, Any]) -> Route:
    return {**GOOD_ROUTES, (OSV, "goodlib"): {"vulns": list(vulns)}}


def _server_env(state: Path) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        SLOPSEAL_OFFLINE_SNAPSHOT="1",
        SLOPSEAL_SNAPSHOT_DIR=str(FIXTURES),
        SLOPSEAL_STATE_DIR=str(state),
        SLOPSEAL_POLICY_PATH=str(POLICY),
        PYTHONPATH=str(REPO / "src"),
    )
    return env


def _server(lines: list[bytes], env: dict[str, str], cwd: Path = REPO) -> tuple[list[Any], int]:
    result = subprocess.run(
        [sys.executable, "-m", "slopseal.mcp.server"],
        input=b"".join(line + b"\n" for line in lines),
        capture_output=True,
        cwd=cwd,
        env=env,
        timeout=120,
        check=False,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()], (
        result.returncode
    )


def _call(request_id: int, arguments: Any) -> bytes:
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "verify_install", "arguments": arguments},
    }
    return json.dumps(message).encode("utf-8")


PING = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode("utf-8")
CSV_PARSER = {"ecosystem": "pypi", "package": "csv-parser", "version": "1.2.0"}


# ---- 1. installation hook (R-G-1..R-G-8) --------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("pip install csv-parser==1.2.0", 0),
        ("pip install csv-parser==1.2.0 semverx==4.0.1", 0),
        ("npm install colorkit@2.0.1", 0),
        ("pip install csv-parser==1.2.0 flsk==1.0.0", 2),  # one typosquat blocks the command
        ("python3 -m pip install flsk==1.0.0", 2),
        ("sudo -H pip install flsk==1.0.0", 2),
        ("bash -c 'pip install flsk==1.0.0'", 2),
        ("echo ok && pip install flsk==1.0.0", 2),
        ("pip install csv-parser-pro==1.0.0", 2),  # does not exist
        ("npm install react-codeshift@1.0.0", 2),  # malware record
        ("npm install urlnorm@0.9.0", 2),  # critical advisory
        ("pip install flask-pydantic-core==0.1.0", 2),  # install script
        ("pip install requests==2.32.3", 2),  # not covered by the snapshot: unknown blocks
        ("pip install csv-parser==9.9.9", 2),  # version unknown
    ],
)
def test_r_g_2_hook_exit_follows_every_verdict(state: Path, command: str, expected: int) -> None:
    exit_code, _ = _hook(command)
    assert exit_code == expected


@pytest.mark.parametrize(
    "command",
    [
        "pip install csv-parser",
        "pip install 'csv-parser>=1.0'",
        "pip install -r requirements.txt",
        "pip install -e .",
        "pip install --index-url http://127.0.0.1:9/ csv-parser==1.2.0",
        "npm install",
        "npm ci",
        "npm install colorkit@^2.0.0",
        "X=1 pip install csv-parser==1.2.0",
        "uv pip install csv-parser==1.2.0",
        "yarn add colorkit@2.0.1",
    ],
)
def test_r_g_5_hook_refuses_installs_it_cannot_verify(state: Path, command: str) -> None:
    exit_code, stderr = _hook(command)
    assert exit_code == 2
    assert "unverifiable_install" in stderr


@pytest.mark.parametrize(
    "raw", [None, "", "not json", "{}", json.dumps({"tool_input": {}}), "[" * 100_000]
)
def test_r_g_6_hook_blocks_unreadable_payloads(raw: str | None) -> None:
    assert evaluate(raw).exit_code == 2


def test_r_g_4_rate_limited_install_is_blocked_by_hook(state: Path) -> None:
    limit = load_policy(str(POLICY)).max_installs_per_minute
    codes = [_hook("pip install csv-parser==1.2.0")[0] for _ in range(limit + 1)]
    assert codes == [0] * limit + [2]


@pytest.mark.xfail(strict=True, reason="F-01: wrappers and install verbs the hook does not see")
@pytest.mark.parametrize(
    "command",
    [
        "timeout 60 pip install flsk==1.0.0",
        "stdbuf -o0 pip install flsk==1.0.0",
        "eval 'pip install flsk==1.0.0'",
        "$(echo pip) install flsk==1.0.0",
        "find . -maxdepth 0 -exec pip install flsk==1.0.0 ;",
        "python3 -m pip.__main__ install flsk==1.0.0",
        "pip-sync requirements.txt",
        "npm update",
        "npm isntall flsk@1.0.0",
        "npm create vite@latest app",
        "yarn",
        "bun add flsk",
    ],
)
def test_f01_hook_detects_wrapped_or_aliased_installs(command: str) -> None:
    assert scan_command(command), f"the hook would let this run unverified: {command}"


@pytest.mark.xfail(strict=True, reason="F-02: a QUARANTINE verdict is not enforced by the hook")
def test_f02_hook_respects_open_quarantine(state: Path) -> None:
    ctx = build_context()
    quarantined = verify_install(
        InstallRequest(Ecosystem.NPM, "colorkit", "2.0.1", intent=Intent("colour", "notExported")),
        ctx,
    )
    assert quarantined.outcome is Outcome.QUARANTINE
    exit_code, _ = _hook("npm install colorkit@2.0.1")
    assert exit_code == 2


# ---- 2. verification engine, live adapter with a mocked network (R-P-1, R-P-3) ----------


def test_r_p_3_clean_package_is_allowed(state: Path) -> None:
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "goodlib", "2.0.0"), _live_ctx(state, GOOD_ROUTES)
    )
    assert decision.outcome is Outcome.ALLOW


@pytest.mark.parametrize(
    ("routes", "name", "version", "check"),
    [
        ({f"{PYPI}/ghost/json": None}, "ghost", "1.0.0", "existence"),
        (
            _osv({"id": "GHSA-1", "database_specific": {"severity": "HIGH"}}),
            "goodlib",
            "2.0.0",
            "cve",
        ),
        (_osv({"id": "GHSA-2"}), "goodlib", "2.0.0", "cve"),  # severity missing
        (_osv({"id": "MAL-2026-1"}), "goodlib", "2.0.0", "malware"),
        (
            {**GOOD_ROUTES, (OSV, "goodlib"): {"vulns": [], "next_page_token": "x"}},
            "goodlib",
            "2.0.0",
            "cve",
        ),
        ({**GOOD_ROUTES, (OSV, "goodlib"): TimeoutError("t")}, "goodlib", "2.0.0", "cve"),
        ({f"{PYPI}/goodlib/json": TimeoutError("t")}, "goodlib", "2.0.0", "existence"),
        ({f"{PYPI}/goodlib/json": LiveFailure("HTTP 503")}, "goodlib", "2.0.0", "existence"),
        ({f"{PYPI}/goodlib/json": b"{oops"}, "goodlib", "2.0.0", "existence"),
        ({f"{PYPI}/goodlib/json": {"info": {}}}, "goodlib", "2.0.0", "existence"),
        ({**GOOD_ROUTES, f"{PYPI}/goodlib/json": b"null"}, "goodlib", "2.0.0", "existence"),
        ({**GOOD_ROUTES, f"{PYPI}/goodlib/9.9.9/json": None}, "goodlib", "9.9.9", "install_script"),
    ],
    ids=[
        "not-found",
        "high-advisory",
        "unknown-severity",
        "malware",
        "osv-paged",
        "osv-timeout",
        "registry-timeout",
        "registry-503",
        "malformed-json",
        "missing-field",
        "json-null",
        "unknown-version",
    ],
)
def test_r_p_1_missing_or_bad_evidence_never_allows(
    state: Path, routes: Route, name: str, version: str, check: str
) -> None:
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, name, version), _live_ctx(state, routes)
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == check


def test_r_p_1_sdist_only_blocks_because_setup_py_may_run(state: Path) -> None:
    doc = _pypi_doc("sdistlib", "1.0.0", wheel=".tar.gz")
    routes: Route = {
        f"{PYPI}/sdistlib/json": doc,
        f"{PYPI}/sdistlib/1.0.0/json": doc,
        (OSV, "sdistlib"): {"vulns": []},
    }
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "sdistlib", "1.0.0"), _live_ctx(state, routes)
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "install_script"


def test_r_p_1_npm_postinstall_blocks(state: Path) -> None:
    doc = {
        "time": {"created": "2015-01-01T00:00:00Z"},
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "license": "MIT",
                "scripts": {"postinstall": "node x.js"},
                "dist": {"tarball": "https://x/t.tgz", "integrity": "sha512-AA=="},
            }
        },
    }
    routes: Route = {f"{NPM}/scriptpkg": doc, (OSV, "scriptpkg"): {"vulns": []}}
    decision = verify_install(
        InstallRequest(Ecosystem.NPM, "scriptpkg", "1.0.0"), _live_ctx(state, routes)
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "install_script"


def test_r_2_2_young_typosquat_blocks(state: Path) -> None:
    doc = _pypi_doc("reqursts", "1.0.0", first="2026-11-01T00:00:00Z")
    routes: Route = {
        f"{PYPI}/reqursts/json": {**doc, "releases": {"1.0.0": doc["urls"]}},
        f"{PYPI}/reqursts/1.0.0/json": doc,
        (OSV, "reqursts"): {"vulns": []},
    }
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "reqursts", "1.0.0"), _live_ctx(state, routes)
    )
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check in {"typosquat", "new_package"}


class _ExplodingSource:
    """Failure injection: the real source, except that the advisory lookup raises."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.snapshot_id = real.snapshot_id
        self.as_of = real.as_of

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def advisories(self, *_: Any) -> Any:
        raise RuntimeError("simulated adapter crash")


def test_t13_adapter_exception_becomes_block(state: Path) -> None:
    ctx = build_context(rate_limited=False)
    ctx = replace(ctx, source=_ExplodingSource(ctx.source))
    decision = verify_install(InstallRequest(Ecosystem.PYPI, "csv-parser", "1.2.0"), ctx)
    assert decision.outcome is Outcome.BLOCK
    assert decision.violation is not None
    assert decision.violation.check == "internal_error"


@pytest.mark.xfail(
    strict=True, reason="F-09: an internal-error verdict is not written to the audit log"
)
def test_f09_internal_error_is_audited(state: Path) -> None:
    ctx = build_context(rate_limited=False)
    ctx = replace(ctx, source=_ExplodingSource(ctx.source))
    verify_install(InstallRequest(Ecosystem.PYPI, "csv-parser", "1.2.0"), ctx)
    log = state / "audit.jsonl"
    assert log.exists()
    assert "internal_error" in log.read_text()


class _FailingCredit(RateLimiter):
    """Failure injection: the real limiter, except that saving the hook credit fails."""

    def note_hook_allow(self, key: str) -> None:
        raise OSError("disk full")


@pytest.mark.xfail(strict=True, reason="F-10: audit log says ALLOW when the caller received BLOCK")
def test_f10_audit_matches_returned_decision(state: Path) -> None:
    ctx = build_context()
    ctx = replace(ctx, limiter=_FailingCredit(state, 10))
    decision = verify_install(
        InstallRequest(Ecosystem.PYPI, "csv-parser", "1.2.0", layer=Layer.HOOK), ctx
    )
    assert decision.outcome is Outcome.BLOCK
    last = json.loads((state / "audit.jsonl").read_text().splitlines()[-1])
    assert last["outcome"] == decision.outcome.value


# ---- 3. rate limiter (R-4.7) --------------------------------------------------------------


def test_r_4_7_configured_limit_is_ten_and_enforced(state: Path) -> None:
    policy = load_policy(str(POLICY))
    assert policy.max_installs_per_minute == 10
    ctx = build_context()
    outcomes = [
        verify_install(InstallRequest(Ecosystem.PYPI, "csv-parser", "1.2.0"), ctx)
        for _ in range(11)
    ]
    assert [d.outcome for d in outcomes[:10]] == [Outcome.ALLOW] * 10
    assert outcomes[10].outcome is Outcome.BLOCK
    assert outcomes[10].violation is not None
    assert outcomes[10].violation.check == "rate_limit"


def test_r_4_7_window_boundary(tmp_path: Path) -> None:
    t0 = datetime(2026, 11, 17, 12, tzinfo=UTC)
    clock = [t0]
    early = RateLimiter(tmp_path / "a", 1, clock=lambda: clock[0])
    assert early.attempt().allowed
    clock[0] = t0 + timedelta(seconds=60) - timedelta(microseconds=1)
    assert not early.attempt().allowed  # still inside the window

    clock[0] = t0
    exact = RateLimiter(tmp_path / "b", 1, clock=lambda: clock[0])
    assert exact.attempt().allowed
    clock[0] = t0 + timedelta(seconds=60)
    assert exact.attempt().allowed  # the first attempt has expired


def test_r_4_7_blocked_attempts_count(tmp_path: Path) -> None:
    t0 = datetime(2026, 11, 17, 12, tzinfo=UTC)
    clock = [t0]
    limiter = RateLimiter(tmp_path, 1, clock=lambda: clock[0])
    assert limiter.attempt().allowed
    clock[0] = t0 + timedelta(seconds=30)
    assert not limiter.attempt().allowed
    clock[0] = t0 + timedelta(seconds=61)
    assert not limiter.attempt().allowed  # the blocked attempt at +30s is still in the window


def _limited_attempt(root: str, limit: int, barrier: Any, queue: Any) -> None:
    barrier.wait()
    queue.put(RateLimiter(Path(root), limit).attempt().allowed)


def test_r_4_7_concurrent_processes_cannot_exceed_limit(tmp_path: Path) -> None:
    limit = load_policy(str(POLICY)).max_installs_per_minute
    mp = multiprocessing.get_context("fork")
    workers = 40
    barrier = mp.Barrier(workers)
    queue = mp.Queue()
    procs = [
        mp.Process(target=_limited_attempt, args=(str(tmp_path), limit, barrier, queue))
        for _ in range(workers)
    ]
    for proc in procs:
        proc.start()
    results = [queue.get(timeout=60) for _ in range(workers)]
    for proc in procs:
        proc.join(timeout=60)
    assert sum(results) == limit
    stamps = json.loads((tmp_path / "ratelimit.json").read_text())["attempts"]
    assert len(stamps) == workers


@pytest.mark.parametrize("body", ["{not json", "[]", '{"attempts": "x"}', '{"attempts": ["bad"]}'])
def test_r_4_7_corrupt_state_blocks(tmp_path: Path, body: str) -> None:
    (tmp_path / "ratelimit.json").write_text(body)
    assert not RateLimiter(tmp_path, 10).attempt().allowed


def test_f07_rate_limited_hook_message_is_not_a_package_rejection(state: Path) -> None:
    for _ in range(10):
        _hook("pip install csv-parser==1.2.0")
    exit_code, stderr = _hook("pip install csv-parser==1.2.0")
    assert exit_code == 2
    assert "Choose a different package" not in stderr


# ---- 4. MCP server (R-1.8, R-1.3) ---------------------------------------------------------


def test_r_1_8_mcp_verdicts_and_errors_are_machine_readable(tmp_path: Path) -> None:
    replies, code = _server(
        [
            _call(1, CSV_PARSER),
            _call(2, CSV_PARSER),
            _call(3, {"ecosystem": "pypi", "package": "flsk", "version": "1.0.0"}),
            _call(4, {"ecosystem": "pypi", "package": "csv-parser"}),
            _call(5, {"ecosystem": "cargo", "package": "serde", "version": "1.0.0"}),
            _call(6, {**CSV_PARSER, "version": ">=1.0"}),
            _call(7, {**CSV_PARSER, "force": True}),
            _call(8, "not-an-object"),
            b"{bad json",
            PING,
        ],
        _server_env(tmp_path),
    )
    assert code == 0
    by_id = {reply["id"]: reply for reply in replies}
    first, second = by_id[1]["result"], by_id[2]["result"]
    assert first["isError"] is False
    assert first["structuredContent"]["outcome"] == "ALLOW"
    assert first["structuredContent"] == second["structuredContent"]  # duplicates agree
    blocked = by_id[3]["result"]
    assert blocked["isError"] is True
    assert blocked["structuredContent"]["violation"]["check"] == "typosquat"
    for request_id in (4, 5, 6, 7, 8):
        assert by_id[request_id]["error"]["code"] == -32602
    assert by_id[None]["error"]["code"] == -32700
    assert by_id[99]["result"] == {}  # still responsive after the bad requests


def test_r_4_7_mcp_rate_limit_is_an_error_result(tmp_path: Path) -> None:
    replies, _ = _server([_call(i, CSV_PARSER) for i in range(11)], _server_env(tmp_path))
    last = replies[-1]["result"]
    assert last["isError"] is True
    assert last["structuredContent"]["outcome"] == "BLOCK"
    assert last["structuredContent"]["violation"]["check"] == "rate_limit"


@pytest.mark.xfail(strict=True, reason="F-05: deeply nested JSON ends the MCP server process")
def test_f05_mcp_survives_deeply_nested_json(tmp_path: Path) -> None:
    replies, code = _server([b"[" * 50_000, PING], _server_env(tmp_path))
    assert code == 0
    assert any(reply.get("id") == 99 for reply in replies)


@pytest.mark.xfail(
    strict=True, reason="F-06: a state-directory OSError ends the MCP server process"
)
def test_f06_mcp_survives_unusable_state_dir(tmp_path: Path) -> None:
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    replies, code = _server([_call(1, CSV_PARSER), PING], _server_env(blocker))
    assert code == 0
    assert replies
    assert replies[0]["result"]["isError"] is True
    assert any(reply.get("id") == 99 for reply in replies)


@pytest.mark.xfail(
    strict=True, reason="F-12: the shipped power mcp.json gives no verdict in a new workspace"
)
def test_f12_shipped_power_config_gives_verdicts(tmp_path: Path) -> None:
    config = json.loads((REPO / "power-upload" / "mcp.json").read_text())["mcpServers"]["slopseal"]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), **config["env"])
    replies, _ = _server([_call(1, CSV_PARSER)], env, cwd=tmp_path)
    assert "structuredContent" in replies[0]["result"]


# ---- 5. audit log and receipts (R-5.7.1, R-5.7.2) -----------------------------------------


def _populated_log(state: Path) -> tuple[Path, bytes]:
    ctx = build_context(rate_limited=False)
    for name, version in [("csv-parser", "1.2.0"), ("flsk", "1.0.0"), ("semverx", "4.0.1")]:
        verify_install(InstallRequest(Ecosystem.PYPI, name, version), ctx)
    return state / "audit.jsonl", load_or_create_key(state)


def _rechain(records: list[dict[str, Any]]) -> str:
    """Recompute seq, prev_hash, and line_hash for every line. Uses no key."""
    previous, lines = "0" * 64, []
    for seq, record in enumerate(records):
        body = {k: v for k, v in record.items() if k != "line_hash"}
        body.update(seq=seq, prev_hash=previous)
        body["line_hash"] = _line_hash(previous, body)
        previous = body["line_hash"]
        lines.append(json.dumps(body, sort_keys=True))
    return "\n".join(lines) + "\n"


def test_r_5_7_1_every_verdict_is_recorded_with_its_fields(state: Path) -> None:
    log, key = _populated_log(state)
    records = [json.loads(line) for line in log.read_text().splitlines()]
    verdicts = [r for r in records if r["event"] == "verdict"]
    assert [(r["package"], r["version"], r["outcome"]) for r in verdicts] == [
        ("csv-parser", "1.2.0", "ALLOW"),
        ("flsk", "1.0.0", "BLOCK"),
        ("semverx", "4.0.1", "ALLOW"),
    ]
    assert verdicts[1]["blocked_by"] == "typosquat"
    assert all(r["ts"] and r["policy_hash"] and r["seal"] for r in verdicts)
    assert key.hex() not in log.read_text()
    assert AuditLog(log, key).verify().ok


def test_r_5_7_2_sealed_field_edit_is_detected(state: Path) -> None:
    log, key = _populated_log(state)
    records = [json.loads(line) for line in log.read_text().splitlines()]
    records[2]["outcome"] = "ALLOW"
    log.write_text(_rechain(records))
    report = AuditLog(log, key).verify()
    assert not report.ok
    assert report.failure_check == "seal does not verify"


def _append_many(path: str, key_hex: str, count: int, barrier: Any) -> None:
    log = AuditLog(Path(path), bytes.fromhex(key_hex))
    barrier.wait()
    for index in range(count):
        log.append(
            "verdict",
            ts=datetime.now(UTC),
            fields={"package": f"p{os.getpid()}", "version": str(index), "outcome": "ALLOW"},
        )


def test_r_5_7_1_concurrent_appends_keep_the_chain(tmp_path: Path) -> None:
    key = load_or_create_key(tmp_path)
    path = tmp_path / "audit.jsonl"
    mp = multiprocessing.get_context("fork")
    barrier = mp.Barrier(20)
    procs = [
        mp.Process(target=_append_many, args=(str(path), key.hex(), 10, barrier)) for _ in range(20)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=60)
    report = AuditLog(path, key).verify()
    assert report.ok
    assert report.lines == 201


@pytest.mark.xfail(strict=True, reason="F-03: unsealed fields and line deletion pass verification")
@pytest.mark.parametrize("edit", ["reason", "delete-line"])
def test_f03_keyless_rewrite_is_detected(state: Path, edit: str) -> None:
    log, key = _populated_log(state)
    records = [json.loads(line) for line in log.read_text().splitlines()]
    if edit == "reason":
        records[2]["reason"] = "all checks passed"
        records[2]["blocked_by"] = "none"
    else:
        del records[2]
    log.write_text(_rechain(records))
    assert not AuditLog(log, key).verify().ok


@pytest.mark.xfail(strict=True, reason="F-04: removing the newest lines is not detected")
def test_f04_truncation_is_detected(state: Path) -> None:
    log, key = _populated_log(state)
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:-2]) + "\n")
    assert not AuditLog(log, key).verify().ok


@pytest.mark.xfail(strict=True, reason="F-08: offline audit timestamps are the snapshot date")
def test_f08_audit_timestamp_is_wall_clock(state: Path) -> None:
    log, _ = _populated_log(state)
    as_of = build_context(rate_limited=False).source.as_of
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert all(r["ts"] != as_of.isoformat() for r in records if r["event"] == "verdict")


# ---- 6. policy (R-1.4, T6) ----------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason="F-11: weakening edits pass the policy guard")
@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('install_scripts = "block"', 'install_scripts = "warn"'),
        ("max_installs_per_minute = 10", "max_installs_per_minute = 100000"),
    ],
)
def test_f11_policy_guard_rejects_weakening(tmp_path: Path, old: str, new: str) -> None:
    weakened = tmp_path / "dependency-trust.md"
    text = POLICY.read_text()
    assert old in text
    weakened.write_text(text.replace(old, new))
    assert enforce_floors(load_policy(str(weakened)))
