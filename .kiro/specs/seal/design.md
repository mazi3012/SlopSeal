# SlopSeal: Design

**Source of truth for behavior:** `requirements.md` (what) and `properties.md` (what must always hold).
**Product context:** `PRD.md`.
**This file:** how the system is built. If this file and `requirements.md` disagree, `requirements.md` wins and this file is fixed.

---

## 1. System overview

SlopSeal turns one question into one signed answer: *may this package be installed, given this policy and this evidence?*

```
 install command ──► intercept ──► verify_install() ──► Decision ──► exit code + stderr/stdout payload
 (pip, npm, ...)    (PATH shim)        │                   │
                                       │                   ├──► audit log (JSONL) ──► signed seal
                                       ▼                   └──► quarantine state (if exit 75)
                         ┌─────────────┴──────────────┐
                         │ policy loader  snapshot     │
                         │ (steering md)  (signed)     │
                         └─────────────┬──────────────┘
                                       ▼
                        L1 checks ──► intent checks ──► L2 (optional, gated)
```

One entry point, `verify_install(package, version, intent?)`, produces a `Decision`. The PATH shim, the CLI, and Kiro hooks are thin callers of it. No check logic lives in a caller.

## 2. Design rules

These rules are what keep the codebase predictable for people and agents.

1. **Pure core, impure edges.** Check functions take data and return a `CheckResult`. They do no I/O. Network, filesystem, clock, and randomness enter only through the interfaces in section 4, so offline mode and property tests can substitute them.
2. **Fail closed by construction.** The only code that may return ALLOW is the last step of the pipeline. Every other path, including every unexpected exception, ends in BLOCK. See section 5.
3. **Policy is data, not code.** Thresholds, lists, and gates come from `.kiro/steering/dependency-trust.md`. No threshold appears as a literal in `src/slopseal/core/`.
4. **Deterministic.** Same package, snapshot, policy, and clock produce byte-identical decisions (P-SN-2). Time comes from an injected `Clock`.
5. **L2 is advisory.** L2 can only move a decision from ALLOW to QUARANTINE. It cannot produce a block (R-3.7).
6. **Zero mandatory runtime dependencies.** The default install pulls in nothing else. Needle sits behind the `slopseal[needle]` extra, and live-mode HTTP uses `urllib.request`. A dependency firewall exists to shrink the supply chain, and every runtime dependency would be code that SlopSeal trusts without checking, installed before SlopSeal is able to check anything. Any new dependency, mandatory or in an extra, needs an ADR (see `docs/adr/0002-stdlib-first.md`).

## 3. Module map

Each module has one responsibility and a requirement list. Dependency direction is downward only: a module may import from modules listed below it in this table, never above.

| Layer | Module | Responsibility | Requirements |
|-------|--------|----------------|--------------|
| 5 | `cli`, `intercept/` | Parse commands, call `verify_install`, map `Decision` to exit code and output | R-1.1, R-1.3, R-1.5 |
| 4 | `verdict` | Orchestrate the pipeline; produce `Decision`; failclosed wrapper | R-V-1..4 |
| 3 | `quarantine/` | State machine, payload, escalation artifact, API-surface check | R-Q-1..7 |
| 3 | `semantic/` | L2 backend interface and Needle adapter (gated at M1) | R-3.1..3.8 |
| 3 | `audit/` | JSONL log, seals. Replay is on the roadmap. | R-5.7.1, R-5.7.2 |
| 2 | `core/` | L1 checks 2.1–2.11, one file per check | R-2.1..2.11 |
| 2 | `policy/` | Load and validate policy, diff two policies | R-1.4, R-5.7.4 |
| 1 | `fixtures/` | Snapshot loader and checksum verification | R-P-2 |
| 0 | `types` (in `verdict.py` until it grows) | Frozen dataclasses and enums shared by all layers | none |

`core/` never imports `semantic/`. `semantic/` never imports `core/`. Both are composed by `verdict`.

**Note on `semantic/`.** The Python binding for Needle 3 is unresolved as of Phase 0. Phase 5 begins with a half-day binding spike. Fallback: install `needle-rs` from source. The choice is recorded in an ADR. Until then the package holds only the `SemanticBackend` interface and a stub.

## 4. Interfaces

These are the seams. Tests and offline mode replace implementations behind them.

```python
class Clock(Protocol):
    def now(self) -> datetime: ...                      # UTC, timezone-aware

class RegistryClient(Protocol):
    def lookup(self, ecosystem: Ecosystem, name: str, version: str | None) -> RegistryRecord | RegistryUnknown: ...

class AdvisoryClient(Protocol):                         # OSV
    def advisories(self, ecosystem: Ecosystem, name: str, version: str) -> Advisories | AdvisoryUnknown: ...

class SemanticBackend(Protocol):                        # L2
    def score(self, intent: Intent, record: RegistryRecord) -> SemanticScore: ...

class SealKey(Protocol):                                # HMAC-SHA256, Open Decision 6 (resolved)
    def seal(self, payload: bytes) -> str: ...          # hex digest
    def verify(self, payload: bytes, digest: str) -> bool: ...   # constant-time compare
```

`RegistryUnknown` and `AdvisoryUnknown` are explicit values, not exceptions and not `None`. A function that receives one must return BLOCK (P-FC-2). This makes "unknown" a case the type checker forces every caller to handle.

Implementations:

| Interface | Live | Offline (`SLOPSEAL_OFFLINE_SNAPSHOT=1`) | Test |
|-----------|------|------------------------------------------|------|
| `RegistryClient` | PyPI and npm over `urllib.request` | Checksummed snapshot | In-memory fake |
| `AdvisoryClient` | OSV.dev over `urllib.request` | Checksummed OSV snapshot | In-memory fake |
| `Clock` | System clock | Pinned to snapshot date | Fixed clock |
| `SemanticBackend` | Needle via needle-rs | Same (local) | Stub with fixed scores |

## 5. Core types

All types are frozen dataclasses or enums. Names are stable; fields may grow.

```python
class Ecosystem(Enum):  PYPI; NPM; CARGO; RUBYGEMS; GO

class Level(IntEnum):   PASS = 0; WARN = 1; BLOCK = 2; HARD_BLOCK = 3

@dataclass(frozen=True)
class CheckResult:
    check: str              # stable id: "existence", "typosquat", "near_name", ...
    level: Level
    reason: str             # human-readable, no secrets
    remedy: str | None      # for example "Did you mean csv-parser?"
    evidence: Mapping[str, JSON]

class Outcome(Enum):    ALLOW; BLOCK; QUARANTINE; POLICY_ERROR

@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    package: str
    version: str | None
    results: tuple[CheckResult, ...]     # every check that ran, in order
    warnings: tuple[CheckResult, ...]
    quarantine: QuarantinePayload | None
    policy_hash: str
    snapshot_id: str | None

    @property
    def exit_code(self) -> int:          # ALLOW 0, BLOCK 1, QUARANTINE 75, POLICY_ERROR 78
```

`Level.HARD_BLOCK` and `Level.BLOCK` both yield `Outcome.BLOCK` and exit 1. They differ in one way: a HARD_BLOCK stops the pipeline immediately and L2 never runs. A BLOCK-level result from policy (for example a CVE) is recorded and the pipeline still short-circuits to BLOCK, but the difference is kept so the audit log and `DependencyViolation` can say which kind fired.

## 6. Verdict pipeline

`verdict.verify_install` runs these steps in order and returns at the first decisive step. The order is the contract in PRD "Verdict Resolution".

```
0. load policy            fail  → POLICY_ERROR (exit 78), nothing else runs      [R-1.4]
1. load snapshot / live   fail  → BLOCK (exit 1)                                 [R-P-1, R-P-2]
2. L1 checks 2.1..2.11    any HARD_BLOCK/BLOCK → BLOCK (exit 1); WARNs collected [R-2.*]
3. intent supplied?       no  → skip to 6
4. API-surface check      exports unknown → BLOCK  [R-Q-2]
                          declared API absent → QUARANTINE api_absent [R-Q-1]
5. L2 (if enabled)        score < threshold → QUARANTINE l2_low_confidence [R-3.5]
6. ALLOW                  attach collected WARNs                                  [R-V-4]
```

**Failclosed wrapper.** `verify_install` is a thin function around `_verify`, which does the work. The wrapper catches every exception from `_verify` and returns `BLOCK` with `check="internal_error"`. Exception text is logged, not returned to the caller. A policy error raised during step 0 is not an "internal error": it is caught earlier and mapped to `POLICY_ERROR`.

**Check order within L1.** Checks that need only the name run first (2.3, 2.8), then those that need registry data (2.1, 2.2, 2.4, 2.5, 2.9, 2.10, 2.11), then those that need advisories (2.6, 2.7). All checks run even after a BLOCK so the audit log shows complete evidence, except HARD_BLOCK on `existence`, because without a record the later checks have no input.

## 7. Policy

**File:** `.kiro/steering/dependency-trust.md`. It is both human-readable steering and machine-readable policy.

**Format:** Markdown prose for people, plus exactly one fenced code block that holds the policy. The loader parses that block with `tomllib` (standard library) and ignores the prose.

**Fence-extraction rule.** One function, `policy.loader.extract_policy_block(text)`, is the only implementation. The pre-commit guard does not copy the rule. It runs `slopseal policy check <file>`, which calls the same function, so the loader and the guard cannot disagree about what the policy is. The rule:

- A block opens at a line matching the regular expression `^\x60{3}toml slopseal-policy[ \t]*$`. (`\x60` is a backtick, so the rule can be written here without opening a fence.) The match is anchored at column 0, so indented or quoted examples in prose never count.
- A block closes at the next line matching `^\x60{3}[ \t]*$`.
- Exactly one block must exist. Zero blocks, two or more blocks, or an opening line with no closing line is a policy error.
- Only backtick fences are recognized. Tilde fences and other info strings are ignored.

```toml slopseal-policy
schema_version = 1

[thresholds]
typosquat_max_distance = 2
typosquat_max_age_days = 30
new_package_max_age_days = 7
new_package_max_releases = 3

[near_name]
levenshtein_max = 3
jaro_winkler_min = 0.92
keyboard_distance_max = 1

[lists]
allow = []
deny = []

[quarantine]
retry_budget = 1
max_seconds = 900         # Open Decision 7, resolved in Phase 5

[semantic]
enabled = false
confidence_threshold = 0.0   # set before the M1 spike, never tuned after
```

**Policy hash.** `sha256` over the canonical JSON form of the parsed block (sorted keys, no whitespace). Prose edits do not change the hash. The hash is in every `Decision`, audit line, and seal.

**Schema version.** `schema_version` is a required key and must equal a version the loader supports. Today that is `1` only. Any other value, including a higher one, is rejected with exit 78 and a message that names the supported versions. A policy written for a newer schema is refused, not read with keys ignored.

**Everything that is not a valid policy exits 78 (R-1.4).** That covers a missing file, an unreadable file, a wrong block count, malformed TOML, an unknown key at any level, a missing required key, a value of the wrong type, and an unsupported `schema_version`. There is no fallback to a default, and no other check runs. Rejecting unknown keys stops a typo such as `typosquat_max_distnace` from silently falling back to a default.

**Diff.** `policy.diff(a, b)` compares two parsed policies key by key and prints added, removed, and changed values. It is CLI output only (R-5.7.4).

## 8. Snapshot

A snapshot is a directory under `src/slopseal/fixtures/`:

| File | Content |
|------|---------|
| `registry_snapshot.json` | Registry records keyed by ecosystem and name, including exported symbols |
| `osv_snapshot.json` | Advisories keyed by ecosystem, name, and version |
| `topn_snapshot.json` | Top 5,000 names per ecosystem, with ranking source and date |
| `manifest.json` | File list, sha256 of each file, snapshot id, `as_of` date (the pinned clock in offline mode) |

**Resolved (Open Decision 6): snapshot integrity is a static SHA-256 checksum manifest committed to the repo for v1.** Loading recomputes the sha256 of every file listed in `manifest.json` and compares it. Any mismatch, missing file, or unlisted file is an error, and the pipeline returns BLOCK (P-SN-1). The manifest detects corruption and accidental edits. It does not stop a person who can write to the repo, who can edit a data file and the manifest together. That limit is in `THREAT_MODEL.md`. `csv-parser-pro` must be absent from `registry_snapshot.json`, and `csv-parser` must list exports `parse` and `parse_file` and not `csv.reader`. `scripts/build_snapshot.py` is the only supported way to produce a snapshot.

`scripts/build_snapshot.py` regenerates `manifest.json` from the data files. It never edits the data files.

## 9. Quarantine state machine

State is stored as one JSON file per quarantine id under the SlopSeal state directory (see `.env.example`).

```
            first intent check fails
 (none) ───────────────────────────────► OPEN(budget=1)
                                              │
              retry with same id              │
         ┌────────────────────────────────────┤
         │ check passes                       │ check fails
         ▼                                    ▼
      ALLOWED (exit 0)                  ESCALATED(budget=0) ─► exit 75, artifact written
                                              │
                                              │ any further retry
                                              ▼
                                       ESCALATED (unchanged, exit 75)

 OPEN or ESCALATED ── abandon ──► ABANDONED (audit entry, no exit code from SlopSeal)
```

- **Terminal states:** ALLOWED, ESCALATED, ABANDONED. The machine has no state with no outgoing path to a terminal state (P-SM-1).
- **Time bound:** every state file carries an `expires_at`. After expiry the state is treated as ESCALATED. The bound is 900 seconds (`max_seconds`, Open Decision 7, resolved).
- **Retry re-checks:** a retry runs the API-surface check again on the new intent (P-SM-3). It never reuses a stored result.
- **Package pinning:** a retry for a different package or version than the quarantined one is a new quarantine, not a retry.
- **CI behavior (resolved, Open Decision 3).** Exit 75 is kept for QUARANTINE and is not remapped. Pipelines fail on 75 unless the job is configured to pause for approval (see `THREAT_MODEL.md`, section 5a).
- **Escalation artifact:** `pending_approval/<quarantine_id>.json`, containing the payload, the original and retry intents, and the policy hash. A human approves it with `slopseal escalate <id>` (command surface defined in Phase 3).
- **Corrupt or missing state file:** treated as a new quarantine, never as ALLOWED.

**Intent rewriting (Open Decision 2).** The calling agent writes the intent, so a retry can be tuned to pass. Design response in v1: the audit log stores the original intent and every retry intent, and the escalation artifact shows the diff. The deterministic check compares the declared API to the package's own exports, so changing the intent can only move the declared API to one that exists. It cannot make a missing API appear.

## 10. Audit

**Log:** `audit.jsonl` under the state directory. One JSON object per line, appended with `O_APPEND`. Fields:

```
seq, event, ts, package, version, ecosystem, outcome, exit_code,
checks_run[], warnings[], policy_hash, snapshot_id,
quarantine_id?, intents[]?, l2?{confidence, threshold, verdict}?,
bypass?{reason}, prev_hash, line_hash
```

`event` is `genesis` or `verdict`. A bypass is a `verdict` line with a `bypass` field.

**Genesis entry.** Every log starts with exactly one genesis line, written when the log file is created:

- `seq = 0`, `event = "genesis"`, `ts`, `slopseal_version`.
- `prev_hash = "0" * 64` (64 zero characters).
- No package fields.
- `line_hash` computed by the same rule as every other line.

Verification requires line 1 to be a genesis entry with `seq = 0` and the all-zero `prev_hash`. A log with no genesis, a second genesis, or a genesis in any other position is a chain break. The writer creates the file with `O_CREAT | O_EXCL` and the genesis in one step, so two processes cannot start two chains. Every later append takes an exclusive `flock` while it reads the last line and writes the next, so parallel installs cannot fork the chain.

**Hash chain.** `line_hash = sha256(prev_hash || canonical_json(line_without_line_hash))`, where `prev_hash` is the previous line's `line_hash`. The chain detects an edited line, a deleted or inserted line in the middle, and a reorder. It cannot detect removal of the last lines, because nothing after them refers back. `audit verify` prints the head `seq` and `line_hash` so a release can record them outside the log. The chain is a design choice beyond the PRD's "immutable" wording. It costs about ten lines and makes "immutable" checkable.

**Key lifecycle (resolved, Open Decision 6).** The CLI generates the seal key on first use: 32 bytes from `os.urandom`, written to `.slopseal/secret.key` with mode `0600`, created with `O_CREAT | O_EXCL` so two processes cannot race to write different keys. `.slopseal/` is git-ignored. The key is never printed, logged, or put in a payload. If the key file is missing and cannot be created, the command exits 78 and does not issue any seal. A verdict that cannot be sealed or logged is not returned as ALLOW.

**Seals.** A seal is an HMAC-SHA256 over `canonical_json({package, version, checks_run, verdict, timestamp, policy_hash})` (R-5.7.2), stored next to the log line it covers. A seal shows that a holder of the key produced the verdict and that the sealed fields are unchanged. It says nothing about line order. v1 seals are HMAC-SHA256 (symmetric, integrity-only); public verifiability via Ed25519 is a roadmap item (ADR 0002).

**Hash chain = ordering integrity, seals = provenance, both ship in Phase 4, neither substitutes for the other.** A chain without seals can be rebuilt end to end by anyone who can write the file. Seals without a chain can be dropped, duplicated, or reordered without detection.

**Verification command.** `slopseal audit verify [--log PATH]` checks, in order: the genesis entry, contiguous `seq` from 0, each `prev_hash` against the previous `line_hash`, each `line_hash` recomputed, and each seal against its line. It reports the first failure by `seq` and by which check failed.

| Exit code | Meaning |
|-----------|---------|
| 0 | Chain and seals verified. Head `seq` and `line_hash` printed |
| 1 | Chain break or seal failure (tampering detected) |
| 78 | Log file or verification key is missing or unreadable, so verification could not run. This is never reported as verified |

**L2 confidence** is written to the log only. It never appears in the quarantine payload (P-SM-5).

**Replay (post-hackathon roadmap, not in v1):** `replay(seq)` loads the log line, the recorded snapshot id and policy hash, re-runs the pipeline against them, and reports whether the outcome matches (P-AU-3). If the snapshot or policy is no longer available, replay reports that and does not guess.

**`--allow-unsafe`:** writes a log line with `bypass.reason` before the install proceeds. An empty reason is rejected (R-1.5).

## 11. Interception

- **PATH shim** (`intercept/path_shim.py`): a small executable installed ahead of the real tool on PATH. It parses the install subcommand and package specs for pip and npm in v1, calls `verify_install` for each, and execs the real tool only if every decision is ALLOW. Unsupported subcommands pass through unchanged. For a command it cannot parse, it blocks, not passes (fail closed).
- **API** (`intercept/api.py`): `verify_install(package, version=None, intent=None) -> Decision`. Same code path as the shim.
- **Kiro hook** (`.kiro/hooks/block-agent-installs.json`, matcher `execute_bash`): a PreToolUse hook. `scripts/hooks/on_install.py` reads `tool_input.command` and blocks agent shell commands which install packages (exit 2). It does not verify packages. The PATH shim does.
- **Recursion guard:** the shim sets `SLOPSEAL_ACTIVE=1` when it execs the real tool, so a tool that calls back into the shim does not loop.

## 12. L2 and the sub-agent question

`semantic/` holds the spike (`spike.py`) and the outcome. **Outcome: the M1 gate failed** (match-allow 0.40 against a minimum of 0.80; `docs/needle_spike.csv`). L2 is not integrated, so `SemanticBackend` has no implementation in v1. Re-opening L2 needs a new pre-registration with a different decision rule, not a re-tuning of this one.

Open Decision 1 asks whether a headless CLI can invoke a Kiro sub-agent. The design does not depend on the answer: the interface is the same whether the backend is a local model, a Kiro sub-agent, or a remote API. If no sub-agent path exists, the PRD wording becomes "separate process with separate context", which is already true for the Needle backend.

Prompt-injection posture: package descriptions and README text are untrusted. They are passed to the backend as data fields, never concatenated into instructions, and a backend output can only lower a decision from ALLOW to QUARANTINE.

## 13. Error handling and output

| Situation | Outcome | Exit | Where it goes |
|-----------|---------|------|---------------|
| Check returns BLOCK or HARD_BLOCK | BLOCK | 1 | `DependencyViolation` JSON on stderr |
| Registry or advisories unknown | BLOCK | 1 | `DependencyViolation` with `check="registry_unknown"` |
| Snapshot checksum fails | BLOCK | 1 | `DependencyViolation` with `check="snapshot_integrity"` |
| Unexpected exception | BLOCK | 1 | `DependencyViolation` with `check="internal_error"`; detail in log only |
| Policy missing or invalid | POLICY_ERROR | 78 | Plain message on stderr naming the file and the first error |
| Quarantine | QUARANTINE | 75 | Payload JSON on stdout (so agents can parse it), summary on stderr |
| Allow | ALLOW | 0 | One-line summary and any warnings on stderr |

`DependencyViolation` fields: `check`, `package`, `reason`, `remedy` (R-4.1). Output is JSON, one object, no color codes, stable key order.

## 14. Testing approach

- **Unit tests** (`src/tests/unit/`): one file per check, using in-memory fakes from section 4.
- **Property tests** (`src/tests/properties/`): one test per property ID in `properties.md`, named after it (`test_p_fc_1_...`). Strategies live in `strategies.py`.
- **Integration tests** (`src/tests/integration/`): run the CLI and shim as subprocesses against the offline snapshot. The demo path is one of them.
- **Traceability:** each test names the requirement or property it covers. A requirement with no test is a gap to close before M2.

## 15. Open items that affect this design

| Item | Affects | Status |
|------|---------|-----------|
| Key scheme (Open Decision 6) | Section 8, section 10 | Resolved (Phase 3): HMAC-SHA256 |
| Quarantine time bound and rate limit (Open Decision 7) | Section 7, section 9 | Resolved (Phase 5): 900 s window, N = 10 per minute |
| Exit 75 vs separate code in CI (Open Decision 3) | Section 9, section 13 | Resolved (Phase 3): exit 75 kept |
| Sub-agent invocation (Open Decision 1) | Section 12 | Resolved: no sub-agent path in v1; roadmap |
| Ecosystems beyond pip and npm (Open Decision 13) | Section 11, `core/` | Resolved: pip and npm only in v1; roadmap |
