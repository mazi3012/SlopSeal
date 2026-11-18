# SlopSeal Phase 4: Production Security Audit

- Date: 2026-11-17
- Repository: `mazi3012/SlopSeal`, branch `main`, commit `b440fe1`
- Version under test: `slopseal 1.0.0`. The copy installed in the hook interpreter (`/root/.cache/uv/archive-v0/LwSUfuk7Unf2EFeM`) is byte-identical to `src/slopseal` (`diff -rq` reported no differences).
- Scope: production code under `src/slopseal`, the shipped hook and MCP configs, and the trust policy. No production code was changed. No package was installed. No live registry was queried by any test.

---

## 1. Executive summary

SlopSeal fails closed reliably **when it is asked**. Every missing, malformed, timed-out, or ambiguous registry or advisory answer I tested became BLOCK. No error path produced ALLOW. The rate limiter is accurate and race-free across processes. The audit log keeps a valid chain under concurrent writers.

The weak point is whether SlopSeal is asked at all, and whether its records can be trusted afterward. The agent-facing hook misses common command forms, so a known typosquat that is blocked as `pip install flsk==1.0.0` runs unverified as `timeout 60 pip install flsk==1.0.0`. The agent can also change the policy, the rate-limit state, and the audit log, all of which live in files it can write. Some of those edits pass the built-in integrity checks.

| Severity | Count | Findings |
|---|---|---|
| CRITICAL | 1 | F-01 hook detection bypasses |
| HIGH | 6 | F-02 QUARANTINE not enforced at install; F-03 keyless audit rewrite; F-11 policy weakening accepted; F-13 `npm install <pkg>` installs package.json; F-14 transitive deps and index redirection (documented); F-16 agent can read the seal key and reset state |
| MEDIUM | 6 | F-04 truncation; F-05 and F-06 MCP crashes; F-07 rate-limit signalling; F-08 pinned audit timestamps; F-12 shipped MCP config gives no verdict |
| LOW | 3 | F-09, F-10, F-20 |
| INFO | 4 | F-17, F-18, F-19, F-21 |

**Readiness:** not ready to act as a security boundary against an untrusted or adversarial agent. It is a useful fail-closed guard against accidental or hallucinated installs that the agent issues in plain `pip install` / `npm install` form (section 14).

---

## 2. Production architecture map

```
                         Kiro agent
                             │
     ┌───────────────────────┴───────────────────────────┐
     │ (A) MCP tool call                                 │ (B) execute_bash "pip install x==1"
     ▼                                                   ▼
 slopseal-mcp  (mcp/server.py)                 Kiro PreToolUse hook
   serve() ─ stdin line loop, one at a time     .kiro/hooks/block-agent-installs.json
   Server.handle() ─ JSON-RPC 2.0                 matcher: execute_bash, timeout 30 s
   parse_arguments() ─ schema + regex checks      sh -c '"$1" -m slopseal.hooks.on_install …'
   verify_with_runtime()                                 │
     │                                           hooks/on_install.py
     │                                             main() → _read_stdin (3 s) → _evaluate_in_worker (25 s)
     │                                             evaluate() → _payload_commands → scan_command()
     │                                               (shlex split, wrappers, bash -c, python -m pip)
     │                                             no install found → exit 0 (command runs)
     │                                             install found  → hooks/gate.py decide()
     │                                               _classify → intercept/parse.py parse()
     │                                               (pin required; -r/-e/index/URL/path refused)
     │                                               non pip/npm/npx tool → refused
     ▼                                                   ▼
            runtime.build_context()  ── policy/loader.py  (env → .kiro/steering → bundled)
                                     ── audit/seal.py     load_or_create_key(.slopseal/secret.key)
                                     ── fixtures/loader.py load_snapshot (checksummed)
                                     ── OfflineSource (default)  |  LiveSource (SLOPSEAL_OFFLINE_SNAPSHOT=0)
                                     ── RateLimiter(.slopseal/ratelimit.json, policy limit)
                                     ── QuarantineStore(.slopseal/…), AuditLog(.slopseal/audit.jsonl)
                                                   │
                                     verdict.verify_install()   (never raises; except → BLOCK internal_error)
                                       1 rate limit  (quarantine/rate_limit.py, flock + atomic replace)
                                       2 version known?
                                       3 quarantine retry state (MCP only; hook never sends an id)
                                       4 L1 checks core/*: existence → typosquat, slopsquat, new_package,
                                         install_scripts, cve, malware, allow_deny, license,
                                         maintainer, near_name
                                       5 intent / contract check (only if expected_api given → MCP only)
                                       6 ALLOW (+ hook credit) | BLOCK | QUARANTINE
                                       every returned verdict → _record() → AuditLog.append()
                                                   │
                         ┌─────────────────────────┴───────────────┐
                         ▼                                         ▼
          MCP result: structuredContent,            hook: exit 0 only if every package ALLOW,
          isError = (outcome != ALLOW)              else exit 2 + JSON problem lines on stderr

 (C) PATH shim (intercept/path_shim.py) – same pipeline for pip/npm/npx on PATH.
     Not installed in this sandbox (`command -v pip` → /root/.pyenv/shims/pip).
```

Live registry path (`registry/live.py`): `urllib`, 10 s timeout, 10 MB cap, no retries. PyPI JSON, npm registry, OSV `/v1/query` for the exact version. Every failure becomes a typed `*Unknown` value, and checks treat that as BLOCK.

### Production code vs tests, fixtures, and utilities

| Kind | Paths |
|---|---|
| Production | `src/slopseal/{verdict,runtime,cli}.py`, `hooks/{on_install,gate}.py`, `hooks/block-agent-installs.json`, `mcp/server.py`, `intercept/{parse,path_shim,shims}.py`, `core/*.py`, `registry/{live,source}.py`, `quarantine/*.py`, `audit/*.py`, `policy/*.py`, `contract/*.py`, `defaults/dependency-trust.md`, `.kiro/steering/dependency-trust.md` (runtime policy) |
| Production data (demo) | `src/slopseal/fixtures/*.json`, which is the **default** data source in offline mode (23 demo packages) |
| Shipped config | `power-upload/mcp.json`, `power-upload/POWER.md`, `.kiro/hooks/*.json` |
| Tests | `src/tests/{unit,integration,properties}`, `src/tests/fixtures/live/*.json` (recorded responses) |
| Dev utilities | `scripts/*.py`, `scripts/*.sh`, `.pre-commit-config.yaml`, `.github/workflows/*` |
| Audit probes (outside the repo) | `/projects/sandbox/audit_probes/probe_*.py` |

---

## 3. Files and functions inspected

| File | Functions |
|---|---|
| `hooks/on_install.py` | `scan_command`, `_blocked_text`, `_blocked_argv`, `_blocked_command`, `_node_blocked`, `_uv_blocked`, `evaluate`, `_evaluate_in_worker`, `main` |
| `hooks/gate.py` | `decide`, `_classify`, `_decision_problem`, `_setup_problem` |
| `intercept/parse.py` | `parse`, `parse_pip`, `parse_npm`, `parse_exec` |
| `mcp/server.py` | `Server.handle`, `_dispatch`, `_call_tool`, `parse_arguments`, `tool_result`, `no_verdict_result`, `verify_with_runtime`, `serve`, `bootstrap_install_hook` |
| `verdict.py` | `verify_install`, `_verify`, `_run_l1`, `_verdict_block`, `_bypass_or_record`, `_quarantine`, `_escalate`, `_record`, `_internal_block` |
| `runtime.py` | `build_context`, `offline`, `now` |
| `quarantine/rate_limit.py` | `RateLimiter.attempt`, `_attempt_locked`, `note_hook_allow`, `_read`, `_write`, `_live` |
| `audit/log.py`, `audit/seal.py`, `audit/receipt.py` | `AuditLog.append`, `verify`, `_sealed_fields`, `line_checks`; `load_or_create_key`, `sign`, `verify`; `render_receipt` |
| `registry/live.py`, `registry/source.py`, `fixtures/loader.py` | `LiveSource.*`, `_http`; `OfflineSource.*`; `Snapshot.registry_result` |
| `core/` | `existence`, `cve`, `malware`, `advisory`, `install_scripts`, `allow_deny`, `types` |
| `policy/` | `loader.load_policy_or_bundled_default`, `invariants.enforce_floors`; `scripts/policy_guard.py`, `scripts/policy_checks.sh` |
| `cli.py` | `cmd_escalate`, `--allow-unsafe` handling |
| Docs used as claims to check | `docs/THREAT_MODEL.md`, `defaults/dependency-trust.md` |

---

## 4. Installation hook findings

Method: I called `scan_command()` (the hook's detector) and `evaluate()` (the full hook with the real gate, offline snapshot, temporary state directory) on command strings. Nothing was executed. One live check went through the real Kiro hook: `pip install --dry-run --no-index csv-parser==1.2.0` was **blocked** before execution (`pip option --dry-run is not understood by SlopSeal; refused`). The live hook is therefore active in this workspace.

| Question | Result |
|---|---|
| 1. Reliably detects installs | Plain forms yes. Many common forms no (F-01). |
| 2. `pip install` / `npm install` | Yes, including `pip3.12`, `python3 -m pip`, `python3 -I -m pip`, `/usr/bin/pip`, `sudo`, `bash -c`, `&&` chains, `p""ip` quoting. |
| 3. Requirements files and manifests | `pip install -r`, `npm install` (bare), `npm ci`, `pip install .`, `-e` are refused. **But** `npm install <pinned>` also installs everything in `package.json` (F-13), and `pip-sync`, bare `yarn`, and `npm update` are not detected (F-01). |
| 4. Command variations bypass | Yes, see F-01. |
| 5. Multiple packages | All-or-nothing: `pip install csv-parser==1.2.0 flsk==1.0.0` → exit 2. Correct. |
| 6. Exact versions | Unpinned, ranges (`>=`, `^`) are refused. A nonexistent version (`csv-parser==9.9.9`) is blocked, with a misleading reason (F-19). |
| 7. Blocks BLOCK / QUARANTINE / rate-limited / error | BLOCK yes. Rate-limited yes (as BLOCK). Internal or setup error yes. **QUARANTINE no**: the hook never sees it (F-02). |
| 8. Install after a verification failure | Yes, via F-01 forms, via F-02 for a quarantined package, or after the agent edits the policy or state (F-11, F-16). |

Hook evaluation evidence (`probe_hook.py`, real gate):

```
exit=0 'pip install csv-parser==1.2.0'
exit=2 'pip install csv-parser==1.2.0 flsk==1.0.0'   {"check": "typosquat", ... "fix": "Did you mean flask?"}
exit=2 'pip install csv-parser-pro==1.0.0'           {"check": "existence", ...}
exit=2 'npm install react-codeshift@1.0.0'           {"check": "malware", ...}
exit=2 'pip install -r requirements.txt'             {"check": "unverifiable_install", ...}
exit=2 'npm install'                                 {"check": "unverifiable_install", ...}
exit=0 'npm update'
exit=0 'timeout 60 pip install flsk==1.0.0'
exit=0 '$(echo pip) install flsk==1.0.0'
malformed payloads (None, "not json", "{}", no command, non-string command, 100k "[") → exit=2 for all
```

---

## 5. Verification engine findings

Method: `verify_install()` with the real `Context` from `build_context()`. Offline scenarios use the bundled snapshot. Live scenarios use the production `LiveSource`, with only its `fetch` network function replaced by canned responses (`probe_live.py`, and the new tests).

| Scenario | Outcome | Check |
|---|---|---|
| Legitimate package (live mock / offline `csv-parser==1.2.0`) | ALLOW (WARN `maintainer` in live) | – |
| Package does not exist (404 / snapshot `absent`) | BLOCK | existence (HARD_BLOCK, "Did you mean csv-parser?") |
| Package not in the offline snapshot (`requests==2.32.3`) | BLOCK | existence ("registry state unknown") |
| HIGH / CRITICAL advisory | BLOCK | cve |
| MODERATE advisory only | ALLOW | – (policy: only critical/high block) |
| Advisory with no severity, or CVSS vector only | BLOCK | cve ("unknown severity") |
| `MAL-` record | BLOCK | malware (HARD_BLOCK) |
| OSV paged result / OSV timeout | BLOCK | cve |
| Registry timeout / HTTP 503 / malformed JSON / missing field / `null` body | BLOCK | existence ("registry state unknown") |
| sdist only (setup.py may run) | BLOCK | install_script |
| npm `postinstall` | BLOCK | install_script |
| setup.py with exec primitives (`flask-pydantic-core`) | BLOCK | install_script |
| Version missing (CLI only, MCP requires it) | latest version resolved, then checked | – |
| Version that does not exist (`9.9.9`) | BLOCK | cve / install_script ("unknown"), see F-19 |
| Invalid version string via MCP (`>=1.0`) | JSON-RPC −32602 | rejected before verification |
| Conflicting requirements | not applicable: only exact pins are accepted; ranges are refused | – |
| Typosquat, young (`flsk`, `nunpy`, `reqursts` at 16 days) | BLOCK | typosquat |
| Near-name, old (`reqursts` at 6 years) | ALLOW with WARN `near_name` | by design (R-2.11 is WARN) |
| Adapter raises an exception | BLOCK | internal_error |

Normalization: `CSV_Parser==1.2.0` and `csv-parser==1.2.0` get the same verdict (PEP 503 in the checks and in `install_key`). The audit log records the name as typed (F-20).

**Missing evidence is never converted to ALLOW.** I found no path where an unknown value passes.

**Outcome model.** The engine has three outcomes: ALLOW, BLOCK, QUARANTINE (`verdict.Outcome`). The five-way model in the audit brief does not exist in the code:

| Brief | Implementation |
|---|---|
| ALLOW | `ALLOW`, exit 0, `isError: false` |
| BLOCK | `BLOCK` with `violation.check` = the failed check |
| QUARANTINE | `QUARANTINE`, exit 75, only when `expected_api` is declared and absent |
| RATE_LIMITED | `BLOCK` with `violation.check == "rate_limit"`, no retry time (F-07) |
| ERROR | `BLOCK` with `violation.check == "internal_error"` (engine), or an MCP `isError` text result with no `structuredContent` ("no verdict was issued") for setup errors, or a JSON-RPC error for bad arguments, or a dead server process (F-05, F-06) |

None of these is an ALLOW, so the distinction is not a fail-open risk. It is a signalling problem for the agent (F-07).

---

## 6. Rate limiter findings

| Check | Evidence | Result |
|---|---|---|
| Configured limit | `.kiro/steering/dependency-trust.md` and the bundled default both have `max_installs_per_minute = 10`; `load_policy_or_bundled_default()` returns 10 | Confirmed: 10 |
| Enforcement | 11 sequential `verify_install` calls → 10 ALLOW, 11th BLOCK `rate_limit` | Correct |
| Window maths | Limit 1: attempt at t0; at t0+59.999999 s blocked; on a fresh limiter, at t0+60.000000 s allowed (`now - stamp < 60 s`) | Correct |
| Expiry | Old stamps are dropped on each read, and credits older than 60 s or from the future are dropped | Correct |
| Concurrency | 40 processes behind a barrier on one state dir → exactly 10 allowed, 30 blocked, 40 stamps recorded | Atomic (flock on `ratelimit.lock`, `os.replace` of the state file) |
| State reset between requests | State is a file per state dir and persists across processes | Not reset, except when the file is deleted (F-16) |
| Corrupt state | `{not json`, `[]`, wrong types → blocked, file left in place | Fails closed |
| Structured response | `BLOCK` + `violation.check: "rate_limit"` | Machine-readable, but not a distinct outcome (F-07) |
| Retry timing | None given | Missing (F-07) |
| Blocked attempts | Counted, so a client that retries keeps itself locked out (attempt at +30 s still blocks at +61 s) | By design (PRD 4.7), but undocumented to the agent |
| Wording | MCP verification with no install returns `"rate limit of 10 installs per minute exceeded"`; stamps are called "install attempts" | Verification requests are described as installs (F-07) |
| Double counting | The documented flow (MCP verify, then `pip install`) counts twice: 5 verify+install pairs used the full limit; the 6th pair was blocked on both calls | Effective limit is 5 installs/min via the recommended flow (F-07) |

---

## 7. Concurrency and MCP findings

Evidence from the real `python -m slopseal.mcp.server` process (`probe_mcp.py`, new tests):

| Check | Result |
|---|---|
| Processing model | Single-threaded stdio loop: one message at a time. In-process races are not possible. Cross-process shared state (rate limit, audit log, key) uses flock, `O_EXCL`, and atomic replace. |
| Malformed tool arguments | Missing version, unknown ecosystem, range version, bad characters, extra key, non-object → JSON-RPC −32602. Bad JSON → −32700. Server keeps responding (ping after them succeeds). |
| Duplicate requests | Identical `structuredContent` for repeated `csv-parser==1.2.0` calls. |
| Outcomes the agent can read | `structuredContent.outcome`, `violation.check`, `isError`. In this Kiro session the client showed the agent only the text line (`MCP tool error: BLOCK flsk==1.0.0: …`), so the text summary is what the agent acts on. |
| Policy / key / snapshot errors | Structured `isError` text "no verdict was issued … Do not install." (no `structuredContent`). |
| Deeply nested JSON (50,000 `[`) | **Server process exits 1** with `RecursionError`; the following ping gets no reply (F-05). |
| State dir unusable (`OSError`) | **Server process exits 1** with `FileExistsError` (F-06). |
| Registry timeouts | Converted to unknown → BLOCK; there is no retry, so no retry loop exists. |
| Retry loops | None in the server, adapter, or hook. The MCP `instructions` do not tell the agent how to handle `rate_limit` (F-07). |
| BLOCK / QUARANTINE vs temporary errors | All non-ALLOW results have `isError: true`. The client cannot tell a temporary rate limit from a policy rejection without parsing the check name or the text. |

Live check through the MCP tool available in this session: `flsk==1.0.0` returned `BLOCK … does not exist in the pypi registry` and `requests==2.32.3` returned `BLOCK … advisories with unknown severity: PYSEC-2026-1872, PYSEC-2026-2275`. These answers come from live PyPI/OSV, not the bundled snapshot (where `flsk` exists and is a typosquat). The session's MCP config is not visible to me (F-21).

---

## 8. Audit receipt findings

Format: JSONL. Line 0 is a genesis entry. Each line has `prev_hash`, `line_hash = sha256(prev_hash + canonical(line))` (no key), and an HMAC-SHA256 `seal` over six fields: `package, version, checks_run, verdict, timestamp, policy_hash`. The key is 32 random bytes in `.slopseal/secret.key`, mode 0600.

| Check | Result |
|---|---|
| Every verdict recorded | Yes for every returned ALLOW/BLOCK/QUARANTINE, including rate-limit BLOCKs. No for `internal_error` BLOCKs, MCP "no verdict" results, and argument errors (F-09). |
| Package, exact version, decision, findings | Yes: `package`, `version`, `outcome`, `blocked_by`, `reason`, `warnings`, `warning_details`, `checks_run`, `policy_hash`, `snapshot_id`. |
| Timestamp | Recorded, but in the default offline mode every line has the snapshot date `2026-11-18T00:00:00+00:00`, not the time of the verdict (F-08). |
| Concurrency | 20 processes × 10 appends → 201 lines, chain verifies. |
| Secrets | Key bytes do not appear in the log. HTML receipt escapes every value. |
| Tamper detection, sealed field (`outcome` BLOCK→ALLOW + rehash) | Detected: `FAILED at seq 2: seal does not verify`. |
| Tamper detection, single-line edit without rehash | Detected: `line_hash does not match`. |
| Edit `reason`/`blocked_by`, rehash, **no key** | **Passes verification** (F-03). |
| Delete a BLOCK record, renumber, rehash, **no key** | **Passes verification** (F-03). |
| Remove the `bypass` record of an `--allow-unsafe` ALLOW, **no key** | **Passes verification** (F-03). |
| Truncate the newest 3 lines | **Passes verification** (F-04). |
| Change outcome and re-seal **with the key** | Passes. The key is readable by the agent's OS user (F-16). |
| Audit vs caller consistency | When saving the hook credit fails after ALLOW is logged, the caller gets BLOCK but the log says ALLOW (F-10). |

Conclusion: the seal gives integrity for six fields against someone without the key. The rest of each record, the set of records, and their order have no keyed protection. The receipt is tamper-evident against accidental edits and naive single-line edits. It is not tamper-evident against a deliberate keyless rewrite, and not at all against the agent, which can read the key.

---

## 9. Phase 3 test-to-production mapping

**The Phase 3 report is not available to this audit.** I searched the filesystem (`find / -xdev -iname "*phase*"`, excluding system paths) and found no Phase 3 report or test game. The workspace contains only the SlopSeal repository. I did not reconstruct or guess its contents.

The table below maps the production components to what currently exercises them for real, so the Phase 3 rows can be filled in against it once the report is supplied.

| Production component | Exercised for real by | Real integration? | Remaining gap |
|---|---|---|---|
| Kiro hook (`on_install` + `gate`) | `test_hooks.py`, `test_hook_gate.py`, new `test_r_g_*`, one live hook block in this session | Yes, against the offline snapshot; one live Kiro check | Detection gaps (F-01, F-13); QUARANTINE not carried (F-02) |
| MCP server | `test_mcp_server.py`, `test_mcp_protocol.py`, new MCP tests (real subprocess) | Yes, offline | Crash paths (F-05, F-06); shipped config (F-12) |
| `verify_install` + L1 checks | Unit and property tests; new tests | Yes | Property suite not run here (no Hypothesis) |
| Live registry adapter | `test_live_source.py`, `test_live_recorded.py`, new tests | Mocked network only | No live run in tests (by rule); the live MCP answers in section 7 are the only live evidence |
| Rate limiter | `test_r_4_7_rate_limit.py` (property, not run), new tests incl. 40-process race | Yes, real file locking | Signalling (F-07), deletion reset (F-16) |
| Audit log / receipt | `test_p_au_audit.py` (property, not run), `test_audit_receipt.py`, new tests | Yes | F-03, F-04, F-08, F-16 |
| Policy guard | `test_p_fc_8_policy.py` (property, not run), new F-11 tests | Yes | Levels and ceilings are not guarded (F-11) |

Phase 3 rows to add when the report is available: `| Phase 3 test | Production component tested | Real integration? | Remaining gap |`.

---

## 10. Integration test results

New file: `src/tests/integration/test_phase4_security_audit.py` (87 test cases).

- 62 cases confirm a property that holds today.
- 25 cases are `xfail(strict=True)`. Each one asserts the secure behaviour for a finding and fails today. I re-ran them with `--runxfail` and confirmed that each fails on its stated assertion, not on an unrelated error. When a fix lands, the test passes and strict xfail reports it, so the marker must be removed.
- Only the network seam (`LiveSource(fetch=…)`) and two failure-injection doubles passed through `Context` are substituted. No production function is patched.

Environment notes:

- The sandbox Python that has `slopseal` has no `pytest`. I used the pre-installed toolchain interpreter `/inner_container/opt/toolchains/.pyenv/versions/3.11.15/bin/python3` (pytest 9.1.1) with `PYTHONPATH=src`. Nothing was installed.
- `hypothesis` is not installed anywhere, and `src/tests/conftest.py` imports it. I ran with `--noconftest`. **The 30 property-test files in `src/tests/properties` were not run.**

Commands and actual results:

```
$ PYTHONPATH=src python3 -m pytest --noconftest -q -p no:cacheprovider src/tests/unit src/tests/integration
# before adding the new file:
694 passed in 25.62s
# after adding the new file:
756 passed, 25 xfailed in 25.79s

$ PYTHONPATH=src python3 -m pytest --noconftest -q -p no:cacheprovider src/tests/integration/test_phase4_security_audit.py
62 passed, 25 xfailed in 1.11s

$ PYTHONPATH=src python3 -m pytest --noconftest -q -p no:cacheprovider --runxfail -k "f0 or f1" src/tests/integration/test_phase4_security_audit.py
# every xfail case fails on its own assertion (e.g. "assert [] where [] = scan_command('timeout 60 pip install flsk==1.0.0')",
# "assert 1 == 0" for the MCP exit code, "VerifyReport(ok=True, lines=3 ...)" for the keyless delete)

$ ruff check src/tests/integration/test_phase4_security_audit.py && ruff format --check src/tests/integration/test_phase4_security_audit.py
All checks passed!
1 file already formatted
```

`mypy` covers `src/slopseal` only, which I did not change, so I did not run it.

The live-mode claims rest on mocked HTTP. The two live MCP answers in section 7 are the only evidence about live behaviour; they show that live mode answers, not that it is correct.

---

## 11. Security findings by severity

### CRITICAL

#### F-01 Hook misses common install command forms
- **Affected:** `hooks/on_install.py`: `WRAPPERS` (line 71), `_blocked_command` (279), `_node_blocked` (338), `NODE_INSTALL_VERBS` (93), `_PIP` (64), the `-m pip` match (297).
- **Evidence:** detection is an allow-list of wrapper names and verbs. Unknown wrappers end detection, the first word must literally name a package manager, and only `install/i/add/ci` (+ exec verbs) count for npm.
- **Reproduction:** `scan_command()` returns `[]` (not an install) for: `timeout 60 pip install …`, `stdbuf -o0 pip …`, `ionice`, `flock`, `chroot`, `watch`, `su -c '…'`, `ssh host pip …`, `eval 'pip install …'`, `$(echo pip) install …`, `P=pip; $P install …`, `find … -exec pip install …`, `python3 -m pip.__main__ install …`, `pip-sync requirements.txt`, bare `yarn`, `npm update` / `npm up`, npm's own aliases `npm isntall` / `npm in` / `npm instal`, `npm install-test`, `npm create …`, `npm init <pkg>`, `pnpm create`, `pnpx`, `bun add`, `bunx`, `corepack pnpm add`. Full hook: `evaluate('timeout 60 pip install flsk==1.0.0')` → **exit 0**, while `pip install flsk==1.0.0` → exit 2 (typosquat). Tests: `test_f01_*` (12 xfail cases).
- **Impact:** a typosquat, malware, or vulnerable package installs without any check, by accident or on purpose. `THREAT_MODEL.md` T11 documents only script files, `python -c`, and `curl | sh` as out of scope. These forms are not documented. No PATH shim is active in this environment to catch them.
- **Fix:** invert the logic to fail closed. Block any simple command whose argv contains an installer name or a known install verb anywhere (not only at command position) unless it matches a verified form. Treat `eval`, `$(`, backticks, `$VAR` in command position, `find -exec`, `ssh`, `su -c`, and unknown wrappers before an installer word as unverifiable. Match `python -m pip*` by prefix. Add all npm install aliases and `update/up/upgrade/create/init <x>/install-test/it`, plus `pip-sync`, `bun`, `bunx`, `pnpx`, `corepack`, and bare `yarn`/`pnpm`.

### HIGH

#### F-02 QUARANTINE is not enforced at install time; "human" approval is unauthenticated
- **Affected:** `hooks/gate.py` `decide` (requests carry no intent or `quarantine_id`); `verdict._verify` step 4 runs only when `expected_api` is set; `cli.cmd_escalate`.
- **Evidence:** the hook calls `verify_install` without intent, so it never runs the API check and never looks up an open quarantine.
- **Reproduction:** MCP-style `verify_install(colorkit 2.0.1, expected_api="doesNotExist")` → `QUARANTINE qs_…`; immediately after, `evaluate("npm install colorkit@2.0.1")` → **exit 0, "ALLOW … all checks passed"**. Test: `test_f02_hook_respects_open_quarantine`. Also, `slopseal escalate <id> --approve --reason x` is an ordinary shell command the hook does not gate, and nothing checks that a human ran it.
- **Impact:** the agent's install proceeds after SlopSeal said the package does not provide what the agent expects. This is the hallucinated-API case SlopSeal is meant to stop.
- **Fix:** have the hook refuse an install of an `(ecosystem, name, version)` that has an OPEN or ESCALATED quarantine in the store. Require approval to come from outside the agent's reach (an interactive confirmation, or a signature from a key the agent cannot read).

#### F-03 Audit log can be rewritten without the key
- **Affected:** `audit/log.py` `_sealed_fields` (42), `_line_hash`, `verify` (142).
- **Evidence:** `line_hash` is an unkeyed SHA-256. The seal covers only six fields, and not `seq`, `prev_hash`, `reason`, `blocked_by`, `warnings`, `ecosystem`, `intent`, `quarantine_id`, or `bypass`.
- **Reproduction (`probe_audit.py`, tests `test_f03_*`):** edit `reason`/`blocked_by` of a BLOCK and rehash → `verified 7 line(s)`; delete the BLOCK line, renumber, rehash → `verified 6 line(s)`; strip the `bypass` record from an `--allow-unsafe` ALLOW → `verified 7 line(s)`.
- **Impact:** evidence of a block or of an audited override can be removed without detection. `THREAT_MODEL.md` T10 lists the hash chain and seals as the mitigation for "edited or truncated".
- **Fix:** seal the whole canonical record including `seq` and `prev_hash` (HMAC over the same bytes as `line_hash`, or make `line_hash` an HMAC). Then a rewrite needs the key.

#### F-11 Policy weakening is accepted at runtime and by the guard
- **Affected:** `runtime.build_context` → `policy/loader.load_policy_or_bundled_default` (no floor check at runtime); `policy/invariants.FLOORS` (no level floors, no rate-limit ceiling); `.kiro/hooks/on-steering-change.json` (reports, does not revert).
- **Reproduction:** a copy of the policy with `install_scripts = "warn"` and `max_installs_per_minute = 100000` → `scripts/policy_guard.py` **exit 0, "ok"**. With `SLOPSEAL_POLICY_PATH` pointing at it, `flask-pydantic-core==0.1.0` (setup.py with exec primitives) → **ALLOW** with a WARN. Tests: `test_f11_*`. The repository policy file was not modified.
- **Impact:** the agent can edit `.kiro/steering/dependency-trust.md` (it is an ordinary workspace file) and the next verdict uses the weaker policy. The policy hash in each seal changes, so the change is visible afterward but not prevented. T6 relies on the property suite and pre-commit, which only run on save or commit.
- **Fix:** run `enforce_floors` in `build_context` and refuse to issue verdicts on violation. Add floors for `levels.*` (block-only where the PRD says block) and a ceiling for `max_installs_per_minute`. Consider pinning the policy hash to a value the agent cannot change.

#### F-13 `npm install <pinned>` also installs all of package.json
- **Affected:** `hooks/gate.py` / `intercept/parse.parse_npm`: only named specs are verified.
- **Evidence:** npm reifies the whole project tree, not only the named package. The [npm-install docs](https://docs.npmjs.com/cli/v11/commands/npm-install/) describe the command as installing a package together with what it depends on, and users report that [`npm install <package>` also installs every dependency in package.json](https://stackoverflow.com/questions/55836397/npm-install-package-installs-package-plus-entire-package-json). Content was rephrased for compliance with licensing restrictions.
- **Reproduction:** not executed (running npm is outside the audit rules). `evaluate("npm install colorkit@2.0.1")` → exit 0 regardless of what `package.json` contains.
- **Impact:** an agent writes an unverified dependency into `package.json` and then runs an allowed pinned install. The protection that refuses bare `npm install` is bypassed.
- **Fix:** refuse npm installs when a `package.json` or lockfile in the working directory declares packages that are not verified, or verify the declared set.

#### F-14 Transitive dependencies and index redirection (documented, still open)
- **Affected:** whole pipeline; `on_install.py` docstring ("a package index set outside the command … is not inspected"); `THREAT_MODEL.md` T16 and section 6.
- **Evidence:** only the named package is verified. Its dependencies and their install scripts run unchecked. `pip.conf`, `.npmrc`, and inherited `PIP_INDEX_URL` are not inspected, so a verified name can be fetched from another index.
- **Impact:** a verified ALLOW does not mean the code that runs was verified.
- **Fix:** R-G-12 (dependency check). Refuse installs when a pip or npm config in scope sets an index.

#### F-16 Agent can read the seal key and reset state
- **Affected:** `runtime.build_context` (state dir `.slopseal` in the workspace); `audit/seal.load_or_create_key`; `quarantine/rate_limit`.
- **Evidence:** the key, the audit log, the rate-limit state, and the quarantine store are files under the workspace, owned by the agent's user. `rm .slopseal/ratelimit.json` or `cat .slopseal/secret.key` name no package manager, so by construction `scan_command` returns no install and the hook allows them (not executed here).
- **Reproduction:** deleting `ratelimit.json` resets the limit (`limit 1: True False` → after delete `True`). With the key, BLOCK→ALLOW plus re-seal → `verified 7 line(s)`.
- **Impact:** the rate limit and the audit trail do not hold against the agent. `THREAT_MODEL.md` assumes the local tamperer does not hold the key, but the agent is local and can read it.
- **Fix:** keep the key and state outside the agent's writable area (another OS user, OS keychain, or a separate service). Make the hook refuse shell commands that touch the state directory.

### MEDIUM

#### F-04 Truncation of the newest records is not detected
- **Affected:** `audit/log.AuditLog.verify`.
- **Reproduction:** remove the last 3 lines → `verified 4 line(s)`. Test: `test_f04_truncation_is_detected`.
- **Fix:** anchor the head (`seq`, `line_hash`) outside the log: a sealed head file, a periodic external checkpoint, or the receipt itself.

#### F-05 MCP server dies on deeply nested JSON
- **Affected:** `mcp/server.Server.handle` (235) catches `UnicodeDecodeError, ValueError` only.
- **Reproduction:** a 50,000-character `[` line → process exits 1 with `RecursionError`; the next ping gets no reply. Test: `test_f05_*`.
- **Impact:** availability only; there is no ALLOW. The agent loses the verifier for the rest of the session. The hook already handles this case (`evaluate` catches `RecursionError`).
- **Fix:** also catch `RecursionError` and return −32700.

#### F-06 MCP server dies on state-directory errors
- **Affected:** `mcp/server.verify_with_runtime` (288) does not catch `OSError` from `build_context`.
- **Reproduction:** `SLOPSEAL_STATE_DIR` pointing at a file → exit 1, `FileExistsError`. Test: `test_f06_*`.
- **Fix:** map `OSError` to `NoVerdict`, as `gate._setup_problem` already does for the hook.

#### F-07 Rate limiting is signalled as a package rejection
- **Affected:** `verdict._verify` step 1; `quarantine/rate_limit._attempt_locked` (144–147); `hooks/gate._decision_problem` (151); `mcp/server.INSTRUCTIONS`.
- **Evidence:** the outcome is `BLOCK` with exit code 1 and no retry time. The hook's fix text for a rate-limited package is `_FIX_BLOCKED`: "Do not install this package. Choose a different package, or ask the user to review it." The message says "installs" for MCP verifications that installed nothing. MCP verify + hook install counts twice.
- **Reproduction:** test `test_f07_*`; `probe_rate.py` pair test (6th verify+install pair blocked).
- **Impact:** an agent told to choose a different package may pick a look-alike. A retrying agent extends its own lockout because blocked attempts count. The documented flow halves the effective limit.
- **Fix:** add a distinct outcome or a `retryable: true` + `retry_after_seconds` field, give `rate_limit` its own remedy text ("wait N seconds; do not change the package"), say "verification requests", count an MCP verify and the following hook install of the same key once (the credit mechanism already exists for hook→shim), and document the behaviour in the MCP `instructions`.

#### F-08 Offline audit timestamps are the snapshot date
- **Affected:** `runtime.build_context` (`clock = snapshot.as_of`, line 86) → `verdict._record` (`ts=ctx.now`).
- **Reproduction:** every verdict line has `ts = 2026-11-18T00:00:00+00:00`. Test: `test_f08_*`.
- **Impact:** the sealed timestamp says nothing about when a verdict happened, so the log cannot order or date events.
- **Fix:** keep the pinned clock for check logic and record the wall-clock time in `ts` (and in the seal). Store `snapshot_as_of` separately.

#### F-12 Shipped MCP config gives no verdict in a fresh workspace
- **Affected:** `power-upload/mcp.json` (`SLOPSEAL_POLICY_PATH=.kiro/steering/dependency-trust.md`, `SLOPSEAL_SNAPSHOT_DIR=src/slopseal/fixtures`, both relative to the user's workspace).
- **Reproduction:** server started with that env in an empty directory → "no verdict was issued: policy error (policy file unreadable …)". Because the env var is set, the bundled-default fallback is skipped. Test: `test_f12_*`.
- **Impact:** fails closed, but every MCP verification fails for a user who installs the power as shipped.
- **Fix:** drop the two path variables from `mcp.json` and rely on the bundled fallbacks.

### LOW

- **F-09 Failed attempts are not all audited.** `verify_install`'s exception path (`verdict.py` line 154) returns `internal_error` without an audit line, and MCP no-verdict and argument errors are not logged. Test: `test_f09_*`. Fix: append a best-effort `error` event.
- **F-10 Audit says ALLOW when the caller got BLOCK.** `_record` runs before `note_hook_allow` (line 150); if the credit write fails, the log keeps ALLOW. Test: `test_f10_*`. Fix: save the credit before recording, or append a correcting line.
- **F-20 Names are logged as typed.** `CSV_Parser` and `csv-parser` produce different `package` values for the same package. Fix: also log the normalized name.

### INFO

- **F-17 The default data source is a 23-package demo snapshot.** Offline is the default, and every real package is BLOCKed as "not covered by this snapshot" (for example `requests==2.32.3`). Safe, but the product needs live mode or a real snapshot to be usable.
- **F-18 Live mode blocks advisories without a `database_specific.severity` field.** This is common for PYSEC records; live `requests==2.32.3` returned "unknown severity: PYSEC-2026-1872, PYSEC-2026-2275". Fail-closed, but the reason hides the real severity. Consider parsing the CVSS vector.
- **F-19 A nonexistent version is reported as an advisory or script "unknown"**, not as "version does not exist". The verdict is correct and the reason is misleading.
- **F-21 Hook and MCP can run with different configurations.** The hook inherits Kiro's environment, while the MCP server gets the env from its own config. In this session the MCP answered from live registries; the hook's mode is not observable without running an install. Identical commands could get different verdicts from the two paths.

### Confirmed strengths (no finding)

- No error, timeout, malformed response, or missing field produced ALLOW, in 20 live-adapter scenarios and all offline scenarios.
- Pinning is required. `-r`, `-e`, index flags, URLs, local paths, and ranges are refused.
- Multi-package commands are all-or-nothing.
- The hook fails closed on unreadable payloads, timeouts, and worker crashes.
- The rate limiter is exact at the 60 s boundary and atomic across 40 processes. Corrupt state blocks.
- Audit appends are serialized: 200 concurrent appends kept a valid chain. Sealed-field edits are detected. The key never appears in output. The HTML receipt escapes all values.
- MCP argument validation is strict, and the server stays responsive after ordinary bad requests.

---

## 12. Recommended remediation plan

Waiting for approval before any production change. Suggested order:

1. **F-01** Fail-closed hook detection (wrappers, `eval`, substitutions, npm aliases and verbs, `pip-sync`, `bun`, `python -m pip*`). Turn the `test_f01_*` cases into passing tests.
2. **F-02** Hook consults the quarantine store; move approval out of the agent's reach.
3. **F-16 + F-11** Move key and state out of the agent-writable workspace, gate commands touching it, and enforce policy floors (including levels and a rate ceiling) at runtime.
4. **F-03 + F-04** Seal the full record including `seq`/`prev_hash`, and anchor the head.
5. **F-13 + F-14** Refuse npm installs in a directory with unverified `package.json`/lockfile entries; refuse installs when pip/npm config sets an index; schedule R-G-12.
6. **F-05, F-06, F-12** MCP robustness fixes and the shipped config. These are small and low-risk.
7. **F-07, F-08** Rate-limit signalling and wall-clock timestamps.
8. LOW and INFO items.

After each step: remove the matching `xfail` markers, then run unit, integration, and the property suite (with Hypothesis installed through the normal dev setup).

---

## 13. Remaining limitations of this audit

- The Phase 3 report was not available, so section 9 has no Phase 3 rows.
- The property suite (30 files, Hypothesis) was not run, because Hypothesis is not installed and I did not install packages.
- Live registry behaviour was tested with mocked HTTP. The only live evidence is two MCP answers from this session's server, whose configuration I could not see.
- F-13 rests on npm's documented behaviour. npm was not run.
- The PATH shim was reviewed only at the docstring level, and it is not installed in this environment.
- `contract/` (artifact download and extraction sandbox) and `semantic/` (L2) were not audited in depth. Both are reached only when an `expected_api` is declared (contract) or L2 is enabled (off by default).
- Windows and macOS behaviour was not tested; the sandbox is Linux.

---

## 14. Overall readiness assessment

| Question | Answer |
|---|---|
| Does a verification ever wrongly ALLOW because evidence is missing or an error occurred? | No case found. |
| Does the hook stop a plainly written `pip install` / `npm install` of a bad package? | Yes. |
| Can an agent install a blocked package anyway? | Yes, with trivial command variations (F-01), after a QUARANTINE (F-02), or after editing the policy or state files (F-11, F-16). |
| Is the rate limit 10 verification requests per minute and enforced? | Yes, 10 per rolling 60 s, atomic across processes. The agent can reset it by deleting a file, and the documented flow counts each install twice. |
| Are receipts cryptographically tamper-evident? | Partly. Six fields are HMAC-sealed. Other fields, record deletion, and truncation are not protected, and the key is readable by the agent. |
| Do passing offline tests prove the live product works? | No. They prove the engine's fail-closed logic. The bypasses above all pass the existing suite. |

**Verdict:** the verification engine is sound. The enforcement and audit layers around it are not yet a security boundary against an agent that is careless in phrasing or deliberately evasive. Fix F-01, F-02, F-11, and F-16 before relying on SlopSeal to stop an untrusted agent.
