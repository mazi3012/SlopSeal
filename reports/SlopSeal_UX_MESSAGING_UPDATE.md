# SlopSeal UX Messaging Update

- Branch: `feat/hook-messaging`, created from `main` (`b440fe1`)
- Requirement: R-U-1 (added to `.kiro/specs/seal-v2/requirements.md`)
- Scope: wording only. No change to any policy, decision, exit code, outcome, check name, rate limit, MCP schema, or audit record.

## 1. What changed in behaviour, and what did not

Messages changed. Decisions did not. To check that, I ran the same 23 hook commands and 18 MCP calls on `main` and on this branch, with a fresh state directory for each case. I compared exit codes, outcomes, `isError`, check names, and JSON-RPC error codes. All 41 records match (section 6.2).

## 2. Previous messages (before)

| Surface | Message |
|---|---|
| Hook name (Kiro shows it as `Hook: <name>`) | `SlopSeal: block agent install commands` |
| Hook description | "Before the agent runs a shell command, runs the slopseal.hooks.on_install module ... BLOCK exits 2 ..." (long, mechanism-first) |
| Hook, block header | `BLOCKED by SlopSeal: this install is not allowed. Fix the problem below, or verify the package with the slopseal MCP tool first.` |
| Hook, ALLOW | `slopseal: ALLOW tinyfmt-kit==0.4.0: all checks passed` and `slopseal: WARN <check>: <reason>` (package name and reason written as prose) |
| Hook, fail-closed (unreadable payload, timeout, crash) | `BLOCKED by SlopSeal: Direct installs are disabled. You must use the slopseal MCP tool to verify the package first.` (wrong for a crash) |
| Hook, rate-limited package, fix text | `Do not install this package. Choose a different package, or ask the user to review it.` (wrong: the package was fine) |
| Hook, SlopSeal not installed for the interpreter | `BLOCKED: SlopSeal is not installed for "python3". Install it ...` |
| MCP tool text, every outcome | `BLOCK flsk==1.0.0: 'flsk' is 1 edit(s) from ...` (one line: outcome, package, reason as prose) |
| MCP tool text, setup failure | `no verdict was issued: <reason>. Do not install.` |
| MCP registration at server start | `SlopSeal MCP: Auto-registered security hook in workspace.` |
| PATH shim, ALLOW | `slopseal: ALLOW <pkg>==<ver>: <reason>` and `slopseal: WARN ...` |
| PATH shim, QUARANTINE | `slopseal: QUARANTINE <pkg>==<ver>: <reason>` (stdout keeps the JSON payload) |

## 3. Updated messages (after)

Fixed wording lives in one module, `src/slopseal/messages.py`. The hook, the MCP server and the PATH shim all read it. Metadata (package names, reasons, advisory identifiers) appears only as JSON values, never as prose (R-G-10).

### 3.1 Fixed wording

| Category | Headline |
|---|---|
| Progress (hook, install commands only) | `SlopSeal: Checking dependencies before installation.` then `SlopSeal: Analyzing package security and integrity.` |
| ALLOW | `SlopSeal: Package verified. Installation is permitted.` |
| BLOCK | `SlopSeal: Installation prevented. Security risks detected.` |
| QUARANTINE | `SlopSeal: Package held for review. Verification is incomplete.` |
| RATE_LIMITED | `SlopSeal: Verification temporarily paused. Request limit reached.` |
| ERROR | `SlopSeal: Unable to verify package. Installation is not permitted.` |
| Unverifiable form (hook only) | `SlopSeal: Installation prevented. This install form cannot be verified.` |

The unverifiable form has its own headline. Without it, an unpinned install such as `pip install csv-parser` would say "Security risks detected", which is not true. The package is not known to be risky. It is only written in a form SlopSeal cannot check.

### 3.2 Hook output (stderr, exit codes unchanged)

Block, typosquat (`pip install flsk==1.0.0`), exit 2:

```
SlopSeal: Checking dependencies before installation.
SlopSeal: Analyzing package security and integrity.
SlopSeal: Installation prevented. Security risks detected.
Next: do not install this version. Choose a different package or version, or ask the user to review it.
{"check": "typosquat", "fix": "Did you mean flask?", "package": "flsk", "reason": "'flsk' is 1 edit(s) from popular package 'flask' and was published 11.0 days ago", "version": "1.0.0"}
```

Rate limited (11th attempt), exit 2:

```
SlopSeal: Checking dependencies before installation.
SlopSeal: Analyzing package security and integrity.
SlopSeal: Verification temporarily paused. Request limit reached.
Next: stop installing for up to 60 seconds. Retries in that time are counted and extend the wait. Do not change the package.
{"check": "rate_limit", "fix": "Wait up to 60 seconds before the next attempt. Retries in that time are counted and extend the wait. Do not change the package.", "package": "csv-parser", "reason": "rate limit of 10 installs per minute exceeded", "version": "1.2.0"}
```

CVE block (`npm install urlnorm@0.9.0`), exit 2: headline `Installation prevented. Security risks detected.`; the JSON reason is `blocking advisories for this version: GHSA-fixture-urlnorm-0001`.

Approved (`pip install csv-parser==1.2.0`), exit 0:

```
SlopSeal: Checking dependencies before installation.
SlopSeal: Analyzing package security and integrity.
SlopSeal: Package verified. Installation is permitted.
{"outcome": "ALLOW", "package": "csv-parser", "reason": "all checks passed", "version": "1.2.0", "warnings": []}
```

Setup error (broken policy), exit 2: headline `Unable to verify package. Installation is not permitted.`; the JSON check is `policy_error`.

Unreadable payload or hook crash, exit 2: `SlopSeal: Unable to verify package. Installation is not permitted. Verify the package with the slopseal MCP tool, then run the install again.`

### 3.3 MCP tool text (structured result unchanged)

Approved:

```
SlopSeal: Package verified. Installation is permitted.
package: "csv-parser"
ecosystem: "pypi"
version: "1.2.0"
reason: "all checks passed"
Next: install the package at this exact version.
```

Blocked (`flsk==1.0.0`, `isError: true`):

```
SlopSeal: Installation prevented. Security risks detected.
package: "flsk"
ecosystem: "pypi"
version: "1.0.0"
check: "typosquat"
reason: "'flsk' is 1 edit(s) from popular package 'flask' and was published 11.0 days ago"
Next: do not install this version. Choose a different package or version, or ask the user to review it.
```

Quarantined (`colorkit` 2.0.1 with `expected_api`, `isError: true`): headline `Package held for review. Verification is incomplete.`, then `quarantine_id: "qs_..."` and a next step that names `slopseal escalate`.

Rate limited: headline `Verification temporarily paused. Request limit reached.`, `check: "rate_limit"`, next step `wait up to 60 seconds ... Do not change the package.`

Verification error (no verdict): `SlopSeal: Unable to verify package. Installation is not permitted.`, then `status: "no verdict was issued"`, the reason, and the next step.

When an advisory applies, the text also has `advisory_ids: ["GHSA-..."]`, taken from the evidence the check already records. No severity is shown, because the verdict does not carry one (section 7).

### 3.4 Other SlopSeal messages

| Message | Now |
|---|---|
| Wrapper, SlopSeal not installed | `SlopSeal: Unable to verify package. Installation is not permitted. SlopSeal is not installed for "python3". Install it into that Python with: ...` (exit 2, same as before) |
| Registration at server start | `SlopSeal: Install verification hook registered in this workspace.` |
| PATH shim ALLOW | headline, then one JSON object per package with outcome, package, version, reason, warnings |
| PATH shim BLOCK / QUARANTINE | headline and next step, then the existing JSON object. Stdout still carries only the QUARANTINE payload. |

### 3.5 Hook name and description

- Name: `SlopSeal: Verify dependency security before installation`
- Description: says what the hook checks, that pinned pip and npm installs are verified, which outcomes stop the command (BLOCK, QUARANTINE, RATE_LIMITED, ERROR), that unverifiable forms are stopped with a fix, that commands installing nothing are unaffected, and that the hook counts against the rate limit. R-G-9 requires the description to state the verdict behaviour, so it was written to match the code.

The filename `block-agent-installs.json` is unchanged, because the bootstrap and the tests refer to it.

## 4. Files changed

| File | Change |
|---|---|
| `src/slopseal/messages.py` | New. Fixed wording, `verdict_category`, `data_line`. |
| `src/slopseal/hooks/gate.py` | Headline and next step by category (`_category`, `_headline_category`). Progress lines. ALLOW written as JSON. Rate-limit fix text. The `HEADER` constant is removed. Problems, checks, exit codes and the decision are unchanged. |
| `src/slopseal/hooks/on_install.py` | `BLOCK_MESSAGE` wording. Same exit path. |
| `src/slopseal/mcp/server.py` | `verdict_text` and `no_verdict_result` wording. `REGISTERED_MESSAGE`. Wrapper echo text in `install_hook_command`. `structuredContent`, `isError` and the schema are unchanged. |
| `src/slopseal/intercept/path_shim.py` | `_emit_decision` and the ALLOW output use shared wording. Stdout is unchanged. |
| `.kiro/hooks/block-agent-installs.json` | Name, description, and wrapper text. Regenerated with the server's renderer. |
| `src/slopseal/hooks/block-agent-installs.json` | Same content (R-1.9). `cmp` confirms the two copies are identical. |
| `.kiro/specs/seal-v2/requirements.md` | R-U-1 added. |
| `src/tests/unit/test_hook_gate.py` | Assertions on the header and the ALLOW line updated to the new wording. Same checks. |
| `src/tests/integration/test_hooks.py` | Prefix and parser updated (prose lines are skipped, JSON lines are parsed). ALLOW expectations and the wrapper text updated. Exit-code assertions unchanged. |
| `src/tests/integration/test_path_shim.py` | ALLOW expectations updated. |
| `src/tests/unit/test_mcp_protocol.py` | Exact-text ALLOW assertion updated to the new fields. |
| `src/tests/unit/test_mcp_bootstrap.py` | Registration string updated. |
| `src/tests/properties/test_p_g_3_broken_pipeline.py` | "no ALLOW line on failure" now checks the new ALLOW headline. Same property. Not executed (section 6.3). |
| `src/tests/integration/test_messaging_ux.py` | New. 14 scenario tests (section 6.1). |
| `reports/SlopSeal_UX_MESSAGING_UPDATE.md` | This report. |

No assertion about an exit code, outcome, check name, or structured field was weakened. Every test that changed asserts the same decision with new words.

## 5. Messages Kiro generates (not customizable from SlopSeal)

| Message | Source | Can SlopSeal change it? |
|---|---|---|
| `Hook: <name>` label in the UI | Kiro | Only the name we set. The label format is Kiro's. |
| `Tool "execute_bash" was intercepted by PreToolUse hooks before execution.` | Kiro | No. |
| `The tool was NOT executed. Address each hook instruction ...` | Kiro | No. |
| `MCP tool error:` prefix on a result with `isError: true` | Kiro client | No. The text after the prefix is ours. |
| Hook timeout and how it is reported (30 s) | Kiro | No. The documentation does not say what happens on timeout. |
| Whether stderr from an exit-0 hook is shown to the user | Kiro | Not confirmed. See section 7. |
| Status indicators, progress spinners, and tool-call cards | Kiro | No. |

## 6. Test results

### 6.1 Scenario tests (new)

`src/tests/integration/test_messaging_ux.py`: 14 tests, all passing. They run the real hook (`evaluate`) and the real `slopseal-mcp` process over stdio, offline, against the bundled snapshot. They install nothing.

| Scenario | Test | Result |
|---|---|---|
| 1. Approved | `test_approved_package_says_permitted_and_keeps_allow` | pass |
| 2. Blocked (typosquat) | `test_blocked_package_names_the_check_and_the_next_step` | pass |
| 2b. Blocked (CVE) with advisory ID, no invented severity | `test_advisory_identifiers_are_shown_and_no_severity_is_invented` | pass |
| 3. Quarantined | `test_quarantined_package_is_held_with_its_id` | pass |
| 4. Rate-limited (MCP) | `test_rate_limited_mcp_request_says_paused_and_does_not_blame_the_package` | pass |
| 4. Rate-limited (hook) | `test_rate_limited_hook_command_says_paused_and_does_not_blame_the_package` | pass |
| 5. Verification error (MCP, broken policy) | `test_verification_error_on_mcp_says_not_permitted` | pass |
| 5. Unreadable payload | `test_unreadable_hook_payload_says_not_permitted` | pass |
| 5. Setup error in the hook | `test_setup_error_in_the_hook_says_not_permitted` | pass |
| Unverifiable form is not called a risk | `test_unverifiable_form_is_not_called_a_security_risk` | pass |
| Prose lines are fixed wording (4 cases) | `test_every_prose_line_is_fixed_wording` | pass |

### 6.2 Decisions unchanged (before and after)

Scratch probe `audit_probes/decision_probe.py`, run once on a `git archive` export of `main` and once on this branch. Each case has its own state directory.

- 23 hook cases: exit code, allowed flag, and check names. Covers approved, typosquat, existence, CVE, malware, unverifiable forms, rate limit, non-install commands, and a raw non-JSON payload.
- 18 MCP calls: outcome, `isError`, check, exit code, and JSON-RPC error. Covers ALLOW, typosquat BLOCK, existence BLOCK, CVE BLOCK, QUARANTINE (exit 75), and the rate limit on the 11th call.

Result: `diff before.json after.json` is empty. This check was run again after the last wording change.

### 6.3 Full suite

Commands (run with the toolchain interpreter, because the sandbox Python has no pytest):

```
ruff check .                                   -> All checks passed!
ruff format --check .                          -> 129 files already formatted
mypy src/slopseal                              -> Success: no issues found in 62 source files
PYTHONPATH=src python3 -m pytest --noconftest -q src/tests/unit src/tests/integration
                                               -> 708 passed
```

708 = 694 existing tests plus the 14 new scenario tests. The 694 figure is the count from the first run after the code change, before any test was added to the branch. The code change did not add or remove tests.

Not run:
- The property suite `src/tests/properties`. It needs Hypothesis, which is not installed in this sandbox. This includes P-G-1 (hook exit codes under failures) and P-G-3, where I changed one assertion. That assertion is unexecuted. It needs a run in CI or on a machine with Hypothesis.
- `--noconftest` skips `src/tests/conftest.py` because that file imports Hypothesis. The Hypothesis profile is not applied.

### 6.4 Expected-failure test F-07

`test_f07_rate_limited_hook_message_is_not_a_package_rejection` now passes. It lives in `src/tests/integration/test_phase4_security_audit.py`, which is only on `docs/phase4-security-audit` (PR #30). This branch was made from `main`, so the file is not here. The strict xfail marker must be removed when PR #30 is merged, because this change makes the test pass. I did not copy the audit file onto this branch, so the two PRs stay separate. The F-07 counting question (D4) is still open.

## 7. Limitations

1. **The live workspace hook still shows the old wording.** `/projects/sandbox/.kiro/hooks/block-agent-installs.json` is a copy made by the bootstrap on first start. The bootstrap never overwrites it, and it runs `/root/.cache/uv/.../bin/python`, which has its own installed copy of slopseal. That copy matches `main`, not this branch. The new messages will reach Kiro after (a) the workspace hook file is regenerated, and (b) the interpreter's slopseal is reinstalled from this branch. Both steps change the environment, so I did not do them.
2. **"Verification started" and "in progress" lines depend on how Kiro shows hook stderr.** Kiro shows stderr when the hook exits 2 (confirmed earlier in this audit). For exit 0, the documentation does not say whether stderr is shown. So the two progress lines and the ALLOW block may not be visible to the developer. They are always written, so they will appear in the output on a block. I could not test the Kiro UI from here.
3. **Severity is never shown.** The verdict does not carry a severity field for a CVE. The text shows advisory identifiers from the evidence, and it never guesses a severity. Showing severity needs a data change, which this task excluded.
4. **Shim setup and execution messages are unchanged.** Lines such as `slopseal: cannot find the real pip on PATH` are not verdicts. They are left as they were.
5. **MCP `instructions` text is unchanged.** It still says a BLOCK or QUARANTINE must not run. It does not mention rate limits, so an agent that reads only that text may retry too early. This is a candidate for a follow-up.
6. **The rate-limit wait is a bound, not a promise.** "Up to 60 seconds" is the length of the counting window. Retries in that time are counted (F-07), so the message tells the agent not to retry early.

## 8. Recommended next steps

1. Merge PR #30 first, then remove the F-07 strict xfail in the same change as this branch.
2. Run the property suite (Hypothesis installed) on this branch.
3. After merge, regenerate the workspace hook file and reinstall slopseal from `main`, then check one blocked install in Kiro. Record what Kiro shows for stderr on exit 0, which decides whether the progress and ALLOW lines are visible.
4. Decide whether `instructions` should mention the rate-limit behaviour.
