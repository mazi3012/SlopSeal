# SlopSeal PRD

**Product:** SlopSeal
**Product version (target):** 1.0.0
**Document version:** 1.6.0
**Status:** Final for spec writing. Gating decisions resolved. Schedule is phase-based. The day-level plan lives in `docs/PLAN.md`.
**License:** MIT
**Hackathon:** Kiroween 2026
**Category (single entry):** Frankenstein
**Tagline:** *Every install gets a seal. Every seal is a verdict. Every verdict is a receipt.*
**Created:** November 15, 2026
**Last updated:** November 15, 2026

---

## Resolved Decisions

| # | Decision | Resolution |
|---|----------|------------|
| 1 | Typosquat rule (2.2) | HARD_BLOCK uses AND. A separate WARN-level check (2.11) uses OR across three signals. The OR-only version blocked every package under 30 days old regardless of name, which is a blanket ban, not fail-closed. |
| 2 | v1 scope cuts | Cut from v1: dashboard (5.7.6), registry proxy (1.2), SARIF output (5.7.5). These move to the roadmap. Policy diff (CLI output only), JSONL log, signed seals, PATH shim, and `verify_install` stay in v1. Replay (5.7.3) moved to the post-hackathon roadmap at feature freeze. |
| 3 | Semantic gate and quarantine trigger | The Needle 3 gate is numeric and evaluated at Milestone M1 (Nov 26). The deterministic quarantine trigger is an API-surface mismatch, and the exit 75 payload is revised (see Quarantine). If the gate fails, v1 ships deterministic-only. |
| 4 | Fixture corpus | 20 packages in Phase 1 (5 slopsquat, 5 typosquat, 5 legit-new, 5 legit-old). The corpus expands in Phase 5 and freezes at M3. The write-up states the final count. |
| 5 | Platforms | Linux and macOS only. Confirmed. |
| 6 | Schedule | Phase-based, with four dated milestones (M1–M4). Spec work began Nov 15, so that is the start date. Submission is Dec 3. Dec 4 is the emergency buffer. See Schedule. |
| — | Top-N source and snapshot date (Open Decision 4) | Top 5,000 packages per ecosystem, ranked by public download counts. The snapshot date is the date the checksummed snapshot is first built, in Phase 1 (Nov 18, 2026). The date and the ranking source are written into snapshot metadata. |
| — | Kiroween write-up format (Open Decision 11) | A detailed write-up explaining Kiro use is mandatory (see Decision Source below). The demo video must be hosted at a URL from YouTube, Facebook, Vimeo, or Youku. |

**Decision source for Kiroween write-up:** The official rules page on Devpost returned HTTP 403, so it could not be read directly. A third-party guide that quotes the rules states the write-up is mandatory. Devpost's help center states the video hosting rule. Monitor the submission page from Phase 0. Verify the form by M3 (Nov 30) at the latest. If the form opens late or has fields the write-up does not cover, M3 is the last point to adapt.

**Resolved during implementation:** Open Decisions 1, 2, 3, 6, 7, 8, 9, 10, and 13 (see the table below). Open Decision 11 stays a pre-submission check. None of them gate spec writing.

---

## Executive Summary

### Thesis
SlopSeal is a Kiro-native dependency trust firewall. It stops AI coding agents from installing slopsquatted, malicious, or semantically mismatched packages. It issues a signed verdict for every install, and it property-tests its own policy so the calling agent cannot weaken it.

### One-Sentence Pitch
AI agents install packages they hallucinated. SlopSeal makes every install a signed, auditable verdict, and it property-tests the rulebook so the agent it governs cannot weaken it.

### Theme
The wax seal is the narrative theme: a centuries-old mark of authenticity, applied as a trust primitive to agent installs. The theme is not the category. The category is Frankenstein, because SlopSeal stitches together deterministic checks, a deterministic quarantine state machine, an optional on-device model, Kiro's spec and steering runtime, and property-based testing.

### Core Principle
The arsonist does not inspect the fire. SlopSeal never uses the calling agent's LLM. The semantic check, when it is enabled, runs on Needle 3 on device. If a Kiro sub-agent is used, it runs as a separate process with separate context. Open Decision 1 decides whether the sub-agent path is feasible by the end of Phase 1 (Nov 22).

---

## Scope (v1)

| Area | v1 |
|------|----|
| Ecosystems | pip, npm, yarn, pnpm, cargo, gem, go get |
| Platforms | Linux, macOS |
| Interception | PATH shim (1.1), `verify_install` API (1.3) |
| L1 deterministic checks | 2.1–2.11 |
| Quarantine | Deterministic API-surface trigger, state machine, exit 75 payload, one retry, escalation artifact |
| L2 semantic verifier | **Not in v1.** M1 gate failed (`docs/needle_spike.csv`). Roadmap. |
| Audit | JSONL log, signed verdict seals, policy diff (CLI output). Replay is on the post-hackathon roadmap. |
| Offline mode | `SLOPSEAL_OFFLINE_SNAPSHOT=1` with checksummed snapshot |
| Kiro layer | Steering, specs, hooks, pre-commit guard, property suite |

### Roadmap (not in v1)

- Registry proxy mode (original 1.2)
- SARIF output (original 5.7.5)
- Minimal local dashboard (original 5.7.6)
- MCP server for use outside Kiro
- Windows support

### Ecosystem risk

Seven ecosystems are named in the original scope. Only pip and npm are in v1. The demo uses pip and npm only. Other ecosystems are on the post-hackathon roadmap (Open Decision 13, resolved). See Risks.

---

## Problem

### Context
AI coding agents (Kiro, Cursor, Claude Code, Codex) autonomously execute `pip install` and `npm install` based on LLM-generated suggestions.

### Failure Classes

| ID | Name | Description |
|----|------|-------------|
| P1 | Slopsquatting | LLMs hallucinate plausible package names (blending jscodeshift and react-codemod into react-codeshift). Attackers register those names with malware. |
| P2 | Silent semantic mismatch | An agent installs a real, reputable, CVE-free package that is wrong for the task (httpx when requests was required). The install succeeds, and the task fails silently in production. No CVE scanner catches this. |
| P3 | Silent policy erosion | Dependency policies live in wikis and tribal knowledge. When a policy is weakened, often by an agent editing a config file, there is no audit trail and no way to prove what the rule was at the time of a bad install. |

### Market Gap
Existing tools answer "does this package exist?" (ghostpkg, depverify) and "does it look malicious?" (slopgate, AgentShield, PhantomGuard, depthfirst). No existing tool verifies whether a package's actual purpose matches the agent's declared intent. No existing tool property-tests its own policy for fail-closed integrity.

---

## Architecture

### Layers

#### L1: Deterministic Core
LLM required: no. Latency target: 100 ms against the offline snapshot. Live mode is not latency-bounded.

Top-N means the top 5,000 packages per ecosystem, ranked by public download counts at the snapshot date.

| ID | Check | Verdict |
|----|-------|---------|
| 2.1 | Registry existence | HARD_BLOCK if missing |
| 2.2 | Typosquat: Levenshtein distance ≤ 2 to a top-N package AND package age < 30 days | HARD_BLOCK |
| 2.3 | Slopsquat signature match (compound hallucination patterns) | HARD_BLOCK |
| 2.4 | Package age < 7 days AND release count < 3 | HARD_BLOCK (configurable) |
| 2.5 | Install-script detection (postinstall, setup.py with exec) | WARN / BLOCK per policy |
| 2.6 | OSV.dev CVE lookup for exact version | BLOCK on critical or high |
| 2.7 | Malware feed lookup (OSV malicious-package data) | HARD_BLOCK |
| 2.8 | Allow-list / deny-list from `.kiro/steering/` | BLOCK / ALLOW |
| 2.9 | License policy | WARN / BLOCK per policy |
| 2.10 | Maintainer reputation | WARN / BLOCK per policy |
| 2.11 | Near-name similarity to a top-N package, no age condition. Any one of: Levenshtein distance ≤ 3, Jaro-Winkler ≥ 0.92, or keyboard distance ≤ 1 (one substitution by an adjacent QWERTY key) | WARN |

Check 2.11 is WARN, not HARD_BLOCK. It flags well-known names that resemble a top-N package without requiring a new package. Its purpose is to surface near-misses to the agent and the audit log without blocking established packages.

#### L2: Semantic Intent Verifier (gated)
Engine: Needle 3 via needle-rs. Needle 3 is a tool-calling model. Using it to score an intent declaration against package metadata is a new application. The M1 gate decides whether it ships in v1.

**Gate (evaluated at M1, Nov 26, numeric, no subjective review):**

- **Test set:** Fixture corpus intents, labeled before the spike runs. Matching intents n ≥ 5. Mismatched intents n ≥ 5. Each mismatched intent must declare an API that exists in the package's exports, so the deterministic check cannot catch it. Only purpose or domain mismatches qualify.
- **Threshold:** Set once in `.kiro/steering/dependency-trust.md` before the run. It is not tuned against the results.
- **Match-allow rate** = matching intents that L2 ALLOWs ÷ matching intents. **Required: ≥ 0.8.**
- **Mismatch-allow rate** = mismatched intents that L2 ALLOWs ÷ mismatched intents. **Required: ≤ 0.2.**
- These are specificity and false-negative rate, respectively, in standard classification terms, with the positive class being "mismatch."
- **Output:** `docs/needle_spike.csv`, committed at M1. Columns: `case_id, label, package, declared_intent, l2_confidence, threshold, l2_verdict, correct`.
- **Pass:** Both criteria met. **Fail:** v1 ships deterministic-only, and L2 becomes a roadmap item.

With n = 5 per class, each rate moves in steps of 0.2. Match-allow ≥ 0.8 allows at most one match that L2 rejects. Mismatch-allow ≤ 0.2 allows at most one mismatch that L2 accepts. A pass is evidence of separation on this corpus, not general accuracy. The write-up states n.

| ID | Check | Note |
|----|-------|------|
| 3.1 | Intent declaration contract: {purpose, expected_api, expected_domain} | Skipped if no intent is supplied |
| 3.2 | Purpose-vs-description match | Catches a safe package used for the wrong task |
| 3.3 | API-surface match against exported symbols | Also covered deterministically (see Quarantine). L2 adds purpose-level scoring. |
| 3.4 | Domain mismatch detection | Catches data exfiltration by misinstall |
| 3.5 | Confidence head → ALLOW / QUARANTINE | Threshold set in `dependency-trust.md` |
| 3.6 | Configurable backend (needle, ollama, openai, anthropic) | Set via `.kiro/steering/llm-backend.md` |
| 3.7 | Advisory only; never hard-blocks | Stops prompt injection from becoming an attack path |

### Verdict Resolution

Evaluate in this order and stop at the first decisive result:

1. Any HARD_BLOCK check fails → **HARD_BLOCK** (exit 1). L2 does not run.
2. Policy or registry state is unknown, unreadable, or ambiguous → **BLOCK** (exit 78 for policy, exit 1 for registry).
3. Intent supplied and the declared API is not in the package's exported symbols (from the snapshot) → **QUARANTINE** (exit 75, `mismatch_type: api_absent`).
4. L2 enabled, intent supplied, confidence below threshold → **QUARANTINE** (exit 75, `mismatch_type: l2_low_confidence`).
5. Otherwise → **ALLOW**. Any WARN-level check (2.5, 2.9, 2.10, 2.11) attaches a warning to the ALLOW.

If no intent is supplied, steps 3 and 4 are skipped. The verdict is ALLOW when no block or quarantine applies.

### Fail-Closed Invariant

**Statement:** For all inputs, if policy or registry state is unknown, unreadable, or ambiguous, the verdict MUST be BLOCK.

**Carve-out:** QUARANTINE (exit 75) is produced only by intent checks: the deterministic API-surface check (step 3) and the advisory L2 confidence check (step 4, which never hard-blocks, per 3.7). Neither applies when policy or registry state is unknown. The property tests encode this carve-out, and the "unknown state" test must assert BLOCK (exit 1 or 78), never 75.

**Enforcement:** Property-tested on every change to `.kiro/steering/dependency-trust.md`. Kiro hooks cannot block a save, so rejection happens in a git pre-commit hook. The `on-steering-change.json` hook reports the results.

**Generator strategy:**
- Synthetic package names: Unicode confusables, near-miss plurals, compound hallucinations
- Levenshtein distances 0–4
- Keyboard-adjacent substitutions
- Malformed intent payloads
- Registry timeout simulations
- Partial-policy states

---

## Kiro Integration

### Principle
`.kiro/` is not documentation. It is the product. SlopSeal reads behavior from specs and steering, and it does not hard-code policy.

### Components

| Path | Role | Defines |
|------|------|---------|
| `.kiro/steering/dependency-trust.md` | Trust policy (the policy engine) | Top-N definition, allow/deny lists, severity thresholds, confidence gate, install-script policy, license policy, quarantine retry budget, invariants section |
| `.kiro/specs/seal/requirements.md` | Requirements | EARS requirements for install verification |
| `.kiro/specs/seal/design.md` | Seal design | Verdict resolution, quarantine state machine, and the sub-agent path if Open Decision 1 allows it |
| `.kiro/specs/seal/properties.md` | PBT formal contract | Fail-closed invariant and generator strategy |
| `.kiro/hooks/block-agent-installs.json` | Install trigger | A PreToolUse hook on the shell tool (matcher `execute_bash`). Blocks agent install commands with exit 2, the block Kiro documents. Verification is in the PATH shim. |
| `.kiro/hooks/on-steering-change.json` | Policy-change reporter | Runs the unit and property suite when trust policy changes. The git pre-commit hook rejects a failing edit. |
| `.kiro/steering/product.md` | Product context | Product summary and non-negotiables that agents read |
| `.kiro/steering/tech.md` | Tech and conventions | Stack, commands, dependency rules, commit conventions |
| `.kiro/steering/structure.md` | Repository rules | Layout, import direction, spec-first order, files agents must not change |
| `.kiro/steering/llm-backend.md` | LLM backend config | Engine for the semantic layer (needle by default, if the gate passes) |
| `.kiro/steering/demo-fixtures.md` | Offline fixture config | Which checksummed snapshot the demo and benchmarks use |

### Narrative
SlopSeal is not built with Kiro. SlopSeal is constituted by Kiro. Its trust policy is a steering file. Its sub-agent is a spec. Its enforcement is a hook. Its fail-closed guarantee is a property.

---

## Features

### Interception

| ID | Capability | Detail |
|----|------------|--------|
| 1.1 | Shell-level interception | PATH shim wrapping pip and npm. Other package managers are on the roadmap. |
| 1.3 | Programmatic API | `verify_install(package, version, intent?)` |
| 1.4 | Fail-closed default | Unknown policy or unreachable registry → BLOCK |
| 1.5 | Bypass with audit | `--allow-unsafe` logs the bypass and the stated reason |

### Verdict Actions

| ID | Action | When | Behavior |
|----|--------|------|----------|
| 4.1 | HARD_BLOCK | Any hard-block check fails | Exit 1, typed error on stderr |
| 4.2 | ALLOW | Verdict resolution step 5 | Install proceeds; seal written to audit log |
| 4.3 | WARN | ALLOW with a WARN-level check | Install proceeds; warning logged and surfaced to agent |
| 4.4 | QUARANTINE | Verdict resolution steps 3 or 4 | Install paused; state machine below applies |
| 4.5 | Typed error to agent | Any block or quarantine | `DependencyViolation {check, package, reason, remedy}` |
| 4.6 | Remedy suggestions | Typosquat or slopsquat | Propose the real package the slopsquat mimicked |
| 4.7 | Rate limiting | Agent exceeds N installs per minute | Block further installs until the window resets. N = 10 per minute (`max_installs_per_minute`, Open Decision 7, resolved). |

### Quarantine State Machine

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | ALLOW: install may proceed |
| 1 | HARD_BLOCK: a deterministic check failed |
| 75 | QUARANTINE: retryable with refined intent, or escalate (EX_TEMPFAIL) |
| 78 | Policy missing or malformed, fail-closed (EX_CONFIG) |

**Deterministic trigger (v1, always on):** Exit 75 when the intent declares an `expected_api` that is not among the package's exported symbols in the snapshot. If the package's exports are unknown, the verdict is BLOCK, not QUARANTINE.

**Exit 75 payload:**
```json
{
  "verdict": "QUARANTINE",
  "quarantine_id": "qs_01J...",
  "package": "csv-parser",
  "declared_intent": {"purpose": "parse CSV", "expected_api": "csv.reader"},
  "declared_api": "csv.reader",
  "found_apis": ["parse", "parse_file"],
  "mismatch_type": "api_absent",
  "missing_evidence": ["api_surface_mismatch"],
  "suggested_alternatives": [
    {"package": "csv", "reason": "stdlib; exports csv.reader directly"},
    {"package": "pandas", "reason": "exports read_csv; heavier but matches purpose"}
  ],
  "retry_budget_remaining": 1,
  "escalation_command": "slopseal escalate qs_01J..."
}
```

`mismatch_type` is one of `api_absent` (deterministic trigger) or `l2_low_confidence` (Needle gate passed). The confidence number is not in the payload. L2 confidence is recorded in the audit log only.

**Resolution paths:**

1. **Automated retry.** Budget 1. The agent re-invokes with the same `quarantine_id` and a refined intent. The deterministic check runs again. If the declared API is now in the exported symbols, the verdict is ALLOW (or the L2 check runs, if enabled).
2. **Human escalation.** When the retry fails, SlopSeal writes a pending approval artifact and exits 75 with `retry_budget_remaining: 0`. Exit 75 is non-zero, so CI jobs fail unless configured to accept it. Whether escalation keeps exit 75 or uses a separate code is Open Decision 3.
3. **Abandon.** The agent proceeds with an alternative. The audit log records the abandonment with the original intent.

**Guarantee:** Every path terminates in a defined exit code within a bounded time. The bound is 900 seconds (`max_seconds`, Open Decision 7, resolved). The property suite tests this guarantee.

**Known limitation:** The deterministic trigger checks that the declared API exists, not that it fits the purpose. A retry that declares a real exported API passes even if the package is wrong for the task. P2 (silent semantic mismatch) is covered fully only if L2 ships. The write-up states this limit.

### Offline Fixture Mode

| Setting | Value |
|---------|-------|
| Environment variable | `SLOPSEAL_OFFLINE_SNAPSHOT=1` |

**Contents:**
- Checksummed registry metadata snapshot
- Checksummed OSV advisories snapshot
- Signed top-N list (top 5,000 per ecosystem, with ranking source and date in metadata)
- Fixture corpus, 20 packages in Phase 1: 5 slopsquat, 5 typosquat, 5 legit-new, 5 legit-old. Includes `csv-parser-pro` (absent from the registry snapshot) and `csv-parser` (exports `parse` and `parse_file`, not `csv.reader`).
- Expanded to 100 packages in Phase 5. The count frozen at M3 is final.

**Guarantees:**
- Checksums verified at load time against `manifest.json`. A tampered snapshot fails closed.
- Deterministic benchmark runs under 100 ms against the snapshot, reproducible on any machine.
- QUARANTINE demo outcome identical across takes.
- Snapshot path referenced from `.kiro/steering/demo-fixtures.md`.

### Audit and Observability

| ID | Capability | Purpose |
|----|------------|---------|
| 5.7.1 | Immutable install log (JSONL) | Forensics, compliance. Includes L2 confidence values when L2 is enabled. |
| 5.7.2 | Signed verdict seals | HMAC-SHA256 over {package, version, checks_run, verdict, timestamp, policy_hash} (symmetric, integrity-only in v1). Public verifiability via Ed25519 is a roadmap item. |
| 5.7.3 | Replay (post-hackathon roadmap, not in v1) | Re-run checks against a historical install |
| 5.7.4 | Policy diff (CLI output) | Print the steering changes between two installs |

### Roadmap items (not v1)
- 1.2 Registry proxy mode
- 5.7.5 SARIF and JSON output for CI
- 5.7.6 Minimal local dashboard

### Non-Goals

- Does not scan package source for vulnerabilities (Socket and Snyk cover that).
- Does not enforce runtime behavior after install.
- Does not use the calling agent's LLM.
- Does not require an LLM. Deterministic checks produce a complete verdict without one.
- Does not phone home beyond the checks. Live mode sends package names and versions to OSV.dev and registries. The exact data sent is Open Decision 9.

---

## Acceptance Criteria (EARS)

Requirement IDs follow one rule: `R-` plus the feature or check ID. For example, check 2.1 is requirement R-2.1. Commit messages reference the requirement, for example `feat(core): existence check [R-2.1]`. These move to `.kiro/specs/seal/requirements.md`.

| ID | Requirement |
|----|-------------|
| R-2.1 | When a package name does not exist in the registry snapshot, the system shall return HARD_BLOCK with check `existence`. |
| R-2.2 | When a package's Levenshtein distance to a top-N package is ≤ 2 AND the package is younger than 30 days, the system shall return HARD_BLOCK with check `typosquat`. |
| R-2.6 | When OSV reports a critical or high CVE for the exact version, the system shall return BLOCK. |
| R-2.11 | When a package is within Levenshtein distance 3, Jaro-Winkler ≥ 0.92, or keyboard distance 1 of a top-N package, the system shall attach a WARN with check `near_name`, regardless of package age. |
| R-3.7 | The system shall not return HARD_BLOCK based on L2 output. |
| R-4.1 | When any hard-block check fails, the system shall exit 1 and write a `DependencyViolation` object to stderr. |
| R-4.4 | When the verdict is QUARANTINE, the system shall exit 75 with the payload schema above. |
| R-Q-1 | When the intent declares an `expected_api` absent from the snapshot's exported symbols, the system shall return QUARANTINE with `mismatch_type: api_absent`. |
| R-Q-2 | When the package's exported symbols are unknown, the system shall return BLOCK, never QUARANTINE. |
| R-1.4 | If the policy file is missing, unreadable, or malformed, the system shall exit 78 without consulting any other check. Malformed includes zero or multiple policy blocks, malformed TOML, unknown or missing keys, and an unsupported `schema_version`. |
| R-1.5 | When `--allow-unsafe` is used, the system shall write an audit entry containing the stated reason before proceeding. |
| R-5.7.2 | The system shall sign each verdict seal over {package, version, checks_run, verdict, timestamp, policy_hash}. |
| R-PBT-1 | The property suite shall generate at least 500 cases per run and fail the change if any fail-closed property is violated. |

---

## Open Decisions

These are the only decisions that gate spec writing. All are resolved above.

| # | Decision | Status |
|---|----------|--------|
| 4 | Top-N source and snapshot date | Resolved. Top 5,000 per ecosystem by download count, snapshot date recorded in metadata. |
| 5 | Platforms | Resolved. Linux and macOS. |
| 12 | Schedule | Resolved. Phase-based plan with milestones M1–M4 (see Schedule). |

Every entry in this table is resolved or moved to the roadmap.

| # | Decision | Status |
|---|----------|--------|
| 1 | Headless invocation of a Kiro sub-agent. | **Resolved: moved to roadmap.** L2 is not in v1, so no sub-agent path is used. The design keeps the wording "separate process with separate context." |
| 2 | Intent trust: how L2 resists an agent that rewrites its intent on retry. | **Resolved: moved to roadmap.** It applies only to L2, which is not in v1. |
| 3 | Exit 75 for QUARANTINE. | **Resolved.** Exit 75 is kept (THREAT_MODEL section 5a). |
| 6 | Seal key scheme and snapshot integrity. | **Resolved.** HMAC-SHA256 seals. Snapshot checksum manifest (THREAT_MODEL sections 5a and 6). |
| 7 | Rate limit N (4.7) and the quarantine time bound. | **Resolved (Phase 5).** N = 10 installs per minute (`max_installs_per_minute`). Quarantine window 900 seconds (`max_seconds`). |
| 8 | Git pre-commit hook rejects failing policy edits. | **Resolved.** `.pre-commit-config.yaml` runs `scripts/policy_checks.sh` when the policy, loader, floors, or property suite change. The hook uses the venv's tools, so commit with the venv active. Verified with `pre-commit run policy-checks --all-files`. |
| 9 | Exact data sent to OSV.dev and registries in live mode. | **Resolved.** Documented in `docs/THREAT_MODEL.md`. Offline mode sends nothing. |
| 10 | Needle 3 gate. | **Resolved: gate failed.** L2 is not in v1 and is on the roadmap. Evidence: `docs/needle_spike.csv`. |
| 11 | Kiroween write-up format. | **Resolved with a caveat.** The write-up is `docs/WRITEUP.md`. The live Devpost form still needs a check before submission (`docs/SUBMISSION_CHECKLIST.md`). |
| 13 | Ecosystems beyond pip and npm. | **Resolved: moved to roadmap.** v1 ships pip and npm only. |

---

## Category Alignment

Kiroween 2026 allows one main category per project. SlopSeal enters **Frankenstein**, because it stitches together parts that do not usually work as one system:

| Part | Source technology |
|------|-------------------|
| Deterministic checks (L1) and quarantine | Registry, OSV.dev, snapshot data, and a state machine |
| Semantic intent check (L2, roadmap: M1 gate failed) | Needle 3 on-device model via needle-rs (not in v1) |
| Policy engine and orchestration | Kiro steering, specs, and hooks |
| Verification of the policy itself | Property-based testing on every policy change |

The wax seal is the narrative theme. Resurrection is not the category because SlopSeal does not bring back an obsolete technology.

The demo and the B2B compliance angle appear in the write-up and video. They are not separate submissions.

---

## Schedule

The schedule has eight phases and four dated milestones. Phases have exit criteria. Work within a phase can move freely. Milestone dates are fixed, and changing one requires a decision from the owner. The day-by-day plan is in `docs/PLAN.md`, which can change without a PRD version bump.

### Milestones

| ID | Date | What must be true |
|----|------|-------------------|
| M1 | Nov 26 | Needle gate result committed in `docs/needle_spike.csv`. Pass or fail is recorded. |
| M2 | Nov 27 | Submission-ready fallback checkpoint. End-to-end deterministic demo runs against the offline snapshot. Tag `v0.1.0-deterministic`. |
| M3 | Nov 30 | Feature freeze. Corpus frozen, count recorded. Hardening only after this point. |
| M4 | Dec 3 | Submitted before 2:00 PM PT. Dec 4 is the emergency buffer. |

### Phases

| Phase | Dates | Exit criterion |
|-------|-------|----------------|
| 0. Specs and setup | Nov 15–17 | `requirements.md`, `properties.md`, `design.md`, and `docs/DEMO_SCRIPT.md` committed. First commit made. Devpost monitoring started. |
| 1. Corpus and deterministic core | Nov 18–22 | 20-package corpus and snapshot v0 built. L1 checks 2.1–2.11 and the PBT suite pass on it. Open Decision 1 resolved. |
| 2. Kiro layer | Nov 23–24 | `dependency-trust.md`, both hooks, and the pre-commit guard in place. A policy edit that weakens fail-closed is rejected. Open Decisions 3, 6, and 8 resolved. |
| 3. Quarantine and Needle spike | Nov 25–26 | Deterministic quarantine passes its tests. Needle spike run on the labeled set and gate result committed at M1. |
| 4. Fallback checkpoint | Nov 27 | M2 met. Fallback scope is shippable. |
| 5. Primary path | Nov 28–29 | Interception (PATH shim, `verify_install`) and policy diff done. L2 not wired, because the gate failed. Corpus kept at 23 fixture records for v1. |
| 6. Freeze and release | Nov 30–Dec 2 | M3 met at the start of the phase. Demo recorded, README and Kiro write-up drafted, Devpost form drafted, candidate tag `v1.0.0-kiroween`. Bug fixes only. |
| 7. Submission | Dec 3 | M4 met. Dec 4 held as buffer. |

### Slip rules

- A phase that misses its exit criterion reports it before the next phase starts.
- Dec 4 is the only buffer. A slip that moves M4 past Dec 3 uses it.
- A slip that threatens M2 triggers the fallback scope described below.

### Fallback checkpoint (M2)

M2 is the fallback checkpoint. At this point the deterministic scope is shippable: L1 core (2.1–2.11), the property suite, deterministic quarantine, the JSONL log, signed seals, and `verify_install`. If the end-to-end demo runs cleanly against the offline snapshot, everything after M2 is polish on the primary path.

If the M2 demo fails, the phase 5 work goes to fixing it. The following move to the roadmap, in this order, until the checkpoint passes: policy diff, replay, PATH shim. `verify_install` stays, because the demo needs an entry point. Needle 3 is already out of v1 in this case.

### Compression note

The original plan had 20 days and ended on Dec 4, with no room for submission mechanics. Two changes made room: interception, replay, and policy diff are one phase, and M2 is a shippable checkpoint. The plan now submits on Dec 3, with Dec 4 as buffer. Any slip of more than one day cannot be absorbed by this plan.

---

## Demo Scripts

Both scripts are maintained in `docs/DEMO_SCRIPT.md`. The primary script runs when the Needle gate passes. The fallback script runs when it does not. The quarantine beat is the same in both.

### Primary (Needle gate passed)

| Time | Beat |
|------|------|
| 0:00–0:25 | Kiro agent runs `pip install csv-parser-pro`. SlopSeal blocks at the existence check. Typed error: `DependencyViolation {check: 'existence', remedy: 'Did you mean csv-parser?'}` |
| 0:25–0:55 | Agent runs `csv-parser` with intent `{purpose: 'parse CSV', expected_api: 'csv.reader'}`. The deterministic check finds that `csv.reader` is not among the exported symbols (`parse`, `parse_file`). Exit 75 with `mismatch_type: api_absent`, `found_apis`, `suggested_alternatives`, and `retry_budget_remaining: 1`. |
| 0:55–1:25 | Agent retries with refined intent, declaring the expected API as `parse` and the package as `csv-parser`. The API check passes. L2 scores the purpose and clears the threshold. ALLOW. Seal written to the audit log with a signed receipt. |
| 1:15 (narration over the retry) | Voiceover: "The deterministic check confirms the API exists; purpose-level verification is what Needle adds, and that's what we're testing this week." |
| 1:25–2:15 | Developer tries to weaken the fail-closed rule in `.kiro/steering/dependency-trust.md`. The on-steering-change hook runs the property suite with hundreds of synthetic cases. The weakened rule fails a property. The pre-commit guard rejects the edit. |
| 2:15–2:45 | Audit log, signed seals, policy diff (CLI output), and the `.kiro/` tree on screen. |
| 2:45–3:00 | Final slide: "The seal is not built with Kiro. The seal IS Kiro." |

### Fallback (deterministic only)

Same as primary, with these changes:
- 0:55–1:25: The retry passes the deterministic API check. The verdict is ALLOW with no L2 step. The write-up states that purpose is not verified in this mode (see the known limitation).
- The audit and seal beats show the same content.

**Fixture requirement:** `csv-parser-pro` must be absent from the offline registry snapshot. The real registry may contain it, so the demo depends on the snapshot, not live data.

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Needle 3 does not meet the numeric gate | Gate at M1. If it fails, v1 ships deterministic-only. Fallback scope applies if M2 fails. |
| Deterministic quarantine does not catch purpose mismatch (P2) | Stated as a known limitation. Full P2 coverage requires L2. |
| Seven ecosystems in v1, but the corpus starts with pip and npm | Decision 13. The demo uses pip and npm only. Other ecosystems ship if covered by M2. |
| Schedule has one buffer day (Dec 4) | Freeze at M3. Submit at M4. Any slip past Dec 3 uses the buffer. |
| Interception, replay, and policy diff share Phase 5 | If Phase 5 slips, policy diff and replay move to the roadmap, then the PATH shim. |
| Hardening compressed into Phase 5 | Phase 5 is L2 integration or hardening, and it also expands the corpus. Freeze at M3. Cut scope before freeze, not after. |
| Devpost form changes late or adds fields | Monitor the submission page from Phase 0. Verify by M3 at the latest. |
| Live registry or OSV latency ruins a take | `SLOPSEAL_OFFLINE_SNAPSHOT=1` with checksummed fixtures. Benchmarks and demo are reproducible. |
| Agent hangs in QUARANTINE | Explicit state machine: exit 75, one retry, escalation artifact, bounded time. Property-tested. |
| Policy edit silently breaks fail-closed | Property suite runs on every policy change. Failing edits are rejected by the pre-commit guard. |
| Kiro spec or hook format changes | `.kiro/` files are plain Markdown and JSON. Kiro version pinned in README. |
| Demo exceeds 3 minutes | Script is 3 minutes. Cut to fit. |
| Name or trademark collision | Availability search found no direct functional conflict. Confirm before any commercial launch. |

---

## Success Metrics

### Technical
- Blocks 100% of slopsquat and typosquat packages in the fixture corpus. The write-up states the final corpus size.
- Deterministic checks complete in under 100 ms against the checksummed snapshot.
- L2 intent check completes in under 500 ms on device, if L2 ships.
- PBT suite: at least 500 generated cases per run, zero fail-closed violations.
- QUARANTINE state machine: every generated path terminates in a defined exit code within the 900-second bound in the policy (Open Decision 7, resolved).

### Submission Requirements
- Public repository with MIT license.
- `.kiro/` at the root with working specs, steering, and hooks, including `on-steering-change.json` running the PBT suite.
- 3-minute demo video in offline fixture mode, hosted on YouTube or Vimeo.
- Detailed write-up explaining how Kiro was used: specs, steering, hooks, and PBT. It also states the known limitations.
- README documenting how specs, steering, and hooks constitute the trust policy, and how PBT guarantees the fail-closed invariant.

### Post-Hackathon Roadmap
- Registry proxy, SARIF output, and dashboard (moved from v1).
- Windows support and an MCP server for use outside Kiro.

---

## Repository Structure

**Principle:** A judge should open the repo and see `.kiro/` before they see `src/`.

```
.kiro/specs/seal/requirements.md
.kiro/specs/seal/design.md
.kiro/specs/seal/properties.md
.kiro/steering/product.md
.kiro/steering/tech.md
.kiro/steering/structure.md
.kiro/steering/dependency-trust.md
.kiro/steering/llm-backend.md
.kiro/steering/demo-fixtures.md
.kiro/hooks/block-agent-installs.json
.kiro/hooks/on-steering-change.json

src/slopseal/
  cli.py
  verdict.py
  intercept/ (path_shim, api)
  core/ (existence, typosquat, slopsquat, age, install_script, osv, allowlist, license, maintainer, near_name, failclosed)
  semantic/ (needle_backend, intent, confidence)      # only if M1 gate passes
  quarantine/ (state_machine, payload, escalation, api_surface)
  audit/ (log, seal)
  policy/ (loader, diff)
  fixtures/ (registry_snapshot.json, osv_snapshot.json, topn_snapshot.json, manifest.json)

src/tests/
  unit/
  properties/ (strategies.py, test_failclosed.py, test_state_machine.py)
  integration/

scripts/ (build_snapshot.py, run_pbt.sh, record_demo.sh, install_shims.sh)

docs/ (ARCHITECTURE.md, THREAT_MODEL.md, FAILURE_TAXONOMY.md, DEMO_SCRIPT.md, PLAN.md, adr/, needle_spike.csv)

.github/ (workflows/ci.yml, workflows/pbt.yml, pull_request_template.md, CODEOWNERS)

AGENTS.md
.editorconfig
.gitignore
.pre-commit-config.yaml

pyproject.toml
LICENSE (MIT)
README.md
CONTRIBUTING.md
SECURITY.md
CHANGELOG.md
.env.example
```

---

## Git Commit Strategy

**Principle:** `.kiro/` must appear in history before source code, to show that spec-driven development happened first.

| When | Contents |
|------|----------|
| Phase 0, first commit | `.kiro/specs/seal/requirements.md`, `properties.md`, LICENSE, stub README |
| Phase 2 | `.kiro/steering/dependency-trust.md`, both hooks, pre-commit guard, before wiring to implementation |
| Every source commit | Reference requirement ID, for example `feat(core): existence check [R-2.1]` |
| M1 | Commit `docs/needle_spike.csv` with the gate result |
| M2 | Tag `v0.1.0-deterministic` (fallback checkpoint) |
| Phase 6 | Candidate tag `v1.0.0-kiroween` |
| M4 | Final tag `v1.0.0-kiroween` at submission |

---

## Final Word for Judges

> Every other dependency firewall is a blocklist with a dashboard. SlopSeal is a seal: a signed, replayable verdict whose rulebook is a Kiro spec, whose integrity is a property test, and whose uncertainty is a bounded state machine. We did not build a feature. We made accountability checkable, and we proved the agent it governs cannot weaken it.

---

**Document version:** 1.6.0
**Created:** November 15, 2026
**Status:** Final for spec writing. The day-level plan is in `docs/PLAN.md`.
