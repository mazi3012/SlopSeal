# SlopSeal: Install Verification Requirements

**Source:** `PRD.md`, Acceptance Criteria and Architecture sections.
**Format:** EARS (Easy Approach to Requirements Syntax).
**Requirement IDs:** `R-` plus the feature or check ID. Commit messages cite them, for example `feat(core): existence check [R-2.1]`.

---

## 1. Verdicts and exit codes

**R-V-1 (exit codes).** The system shall return exactly one of these exit codes per install check: 0 for ALLOW, 1 for HARD_BLOCK, 75 for QUARANTINE, 78 for policy or configuration failure.

**R-V-2 (verdict order).** The system shall evaluate verdict rules in this order and stop at the first decisive result: (1) HARD_BLOCK checks, (2) unknown or unreadable state, (3) deterministic API-surface mismatch, (4) L2 confidence below threshold, (5) ALLOW.

**R-V-3 (no intent).** When no intent is supplied, the system shall skip rules (3) and (4) and return ALLOW if no earlier rule applies.

**R-V-4 (warnings).** When an ALLOW verdict has one or more WARN-level checks fired, the system shall attach the warnings to the ALLOW result.

**R-4.1 (HARD_BLOCK).** When any hard-block check fails, the system shall return BLOCK, exit with code 1, and write a typed `DependencyViolation` object to stderr.

**R-4.4 (QUARANTINE).** When the verdict is QUARANTINE, the system shall pause the install, exit with code 75, and apply the quarantine rules R-Q-1 to R-Q-7.

## 2. Deterministic core (L1)

**R-2.1 (existence).** When a package name does not exist in the registry snapshot, the system shall return HARD_BLOCK with check `existence`.

**R-2.2 (typosquat).** When a package's Levenshtein distance to a top-N package is ≤ 2 AND the package is younger than 30 days, the system shall return HARD_BLOCK with check `typosquat`.

**R-2.2a (typosquat is an intersection).** The system shall not return HARD_BLOCK for the typosquat check on distance alone, or on age alone. Both conditions must hold.

**R-2.3 (slopsquat signature).** When a package name matches a compound hallucination signature in the signature list, the system shall return HARD_BLOCK with check `slopsquat`.

**R-2.4 (new package).** When a package is younger than 7 days AND has fewer than 3 releases, the system shall return HARD_BLOCK with check `new_package`. The thresholds are configurable in `dependency-trust.md`.

**R-2.5 (install scripts).** When a package declares an install script that matches the install-script policy, the system shall return WARN or BLOCK as set by policy.

**R-2.6 (CVE).** When OSV reports a critical or high CVE for the exact version, the system shall return BLOCK.

**R-2.7 (malware feed).** When OSV malicious-package data lists the package or version, the system shall return HARD_BLOCK with check `malware`.

**R-2.8 (allow and deny lists).** When a package is on the deny list, the system shall return BLOCK. When a package is on the allow list, the system shall skip checks that the allow list exempts, and no other check.

**R-2.9 (license).** When a package's license violates the license policy, the system shall return WARN or BLOCK as set by policy.

**R-2.10 (maintainer).** When a package's maintainer reputation falls below the policy threshold, the system shall return WARN or BLOCK as set by policy. When live mode reports that the registry does not publish maintainer account age, the system shall return WARN and attach the reason to the verdict and the audit entry. Unknown maintainer data from any other source shall BLOCK.

**R-2.11 (near name).** When a package is within Levenshtein distance 3, Jaro-Winkler ≥ 0.92, or keyboard distance 1 of a top-N package, the system shall attach a WARN with check `near_name`, regardless of package age.

## 3. Quarantine

**R-Q-1 (API-surface trigger).** When the intent declares an `expected_api` absent from the snapshot's exported symbols, the system shall return QUARANTINE with `mismatch_type: api_absent`.

**R-Q-2 (unknown exports).** When the package's exported symbols are unknown, the system shall return BLOCK, never QUARANTINE.

**R-Q-3 (payload).** When the verdict is QUARANTINE, the system shall write the payload with these fields: `verdict`, `quarantine_id`, `package`, `declared_intent`, `declared_api`, `found_apis`, `mismatch_type`, `missing_evidence`, `suggested_alternatives`, `retry_budget_remaining`, and `escalation_command`. The payload shall not contain a confidence value.

**R-Q-4 (exit code).** When the verdict is QUARANTINE, the system shall exit 75.

**R-Q-5 (retry).** When an agent re-invokes with the same `quarantine_id` and a refined intent, the system shall re-run the API-surface check. The retry budget is 1. When the budget is 0, the system shall not offer a retry.

**R-Q-6 (escalation).** When the retry fails, the system shall write a pending approval artifact, set `retry_budget_remaining` to 0, and exit 75.

**R-Q-7 (bounded termination).** Every quarantine path shall end in a defined exit code within the time bound set in `dependency-trust.md`.

## 4. Policy and fail-closed behavior

**R-1.4 (policy missing or malformed).** If the policy file is missing, unreadable, or malformed, the system shall exit 78 without consulting any other check. Malformed includes: zero or more than one policy block, malformed TOML, an unknown key, a missing required key, a value of the wrong type, and a `schema_version` the loader does not support.

**R-1.5 (bypass with audit).** When `--allow-unsafe` is used, the system shall write an audit entry containing the stated reason before proceeding.

**R-P-1 (unknown registry state).** If the registry snapshot or live registry is unreachable or ambiguous, the system shall return BLOCK.

**R-3.7 (L2 is advisory).** The system shall not return HARD_BLOCK based on L2 output.

**R-P-2 (snapshot integrity).** The system shall verify the SHA-256 checksum of each offline snapshot file against `manifest.json` at load time. A snapshot that fails verification shall cause BLOCK.

**R-P-3 (live registry).** Live mode is selected only by `--live` or `SLOPSEAL_OFFLINE_SNAPSHOT=0`. In live mode, a registry or advisory answer that cannot be read, times out, returns a status other than 200 (or 404 for an existence lookup), is malformed or partial, or exceeds the size limit shall be an explicit unknown value. A check given an unknown value shall BLOCK. Live mode shall send only the ecosystem, package name, and version, with no credentials.

**R-4.7 (rate limit).** When an agent makes more than `max_installs_per_minute` install attempts in a rolling 60-second window, the system shall BLOCK each further attempt until the window clears. Every attempt counts, including blocked ones. `--allow-unsafe` does not bypass this check.

## 5. Interception and API

**R-1.1 (PATH shim).** The system shall intercept `pip`, `npm`, and `npx` invocations through a PATH shim. Other package managers are on the post-hackathon roadmap.

**R-1.6 (exec-style installs).** `npx`, `npm exec`, `npm x`, and `npm init <initializer>` / `npm create <initializer>` download and run a package, so they are installs. The system shall verify the named package at an exact version (`name@x.y.z`) before the command runs. The system shall refuse, without running anything, any such command that uses `-c`/`--call`, names no package, names an unpinned or non-registry package, or whose package it cannot parse.

**R-1.7 (resolve then pin).** In live mode only, when an install names a package without a version, the system shall resolve the latest version from the live registry, verify that exact version, rewrite the command to pin it, and run the rewritten command. The system shall write both the original and the rewritten command to the audit log. `--no-resolve`, or `SLOPSEAL_NO_RESOLVE=1`, keeps the refusal. Offline, and when the latest version cannot be resolved, the system shall refuse the install.

**R-1.3 (verify_install).** The system shall expose `verify_install(package, version, intent?)`, which returns the same verdict and exit code as the shim.

**R-1.8 (MCP server).** The system shall expose `verify_install` as the only tool of a stdio MCP server (`slopseal-mcp`). The tool shall require `ecosystem`, `package`, and an exact `version`, and shall accept optional `purpose`, `expected_api`, and `quarantine_id`. It shall not accept a bypass. A result is an error (`isError: true`) for BLOCK and QUARANTINE, and for any failure to produce a verdict. Stdout shall carry only JSON-RPC messages.

## 6. Audit

**R-5.7.1 (log).** The system shall append one JSON object per verdict to an immutable JSONL log.

**R-5.7.1a (chain verification).** The log shall begin with one genesis entry (`seq = 0`, all-zero `prev_hash`) and each later line shall carry the previous line's hash. The command `slopseal audit verify` shall exit 0 when the chain and seals verify, exit 1 on a chain break or seal failure, and exit 78 when the log or key cannot be read.

**R-5.7.2 (seals).** The system shall sign each verdict seal over {package, version, checks_run, verdict, timestamp, policy_hash}.

**R-5.7.3 (replay).** Post-hackathon roadmap, not in v1. The system shall re-run the checks for a historical install using the snapshot and policy recorded with it.

**R-5.7.4 (policy diff).** The system shall print the steering changes between two installs as CLI output.

## 7. Semantic layer (L2, gated)

Requirements in this section apply only if the Day 12 gate passes.

**R-3.1 (intent contract).** The system shall accept an intent object with `purpose`, `expected_api`, and `expected_domain`. When no intent is supplied, the system shall skip L2.

**R-3.5 (confidence).** When L2 confidence is below the threshold, the system shall return QUARANTINE with `mismatch_type: l2_low_confidence`.

**R-3.6 (backend).** The system shall select the L2 backend from `.kiro/steering/llm-backend.md`.

**R-3.8 (latency).** The system shall complete an L2 intent check in under 500 ms on device.

## 8. Property suite

**R-PBT-1 (case count).** The property suite shall generate at least 500 cases per run and fail the change if any fail-closed property is violated.

**R-PBT-2 (policy edits).** When `.kiro/steering/dependency-trust.md` changes, the git pre-commit hook shall run the property suite and reject the commit if any property fails.
