# SlopSeal v2: Design

**Source of truth for behavior:** `requirements.md` (what) and `properties.md` (what must always hold).
**v1 design:** `.kiro/specs/seal/design.md` stays in force. This file adds to it and names each v1 statement it supersedes.
If this file and `requirements.md` disagree, `requirements.md` wins and this file is fixed.

---

## 1. Phase 1: verdict-aware install hook

### 1.1 Flow

```
 Kiro PreToolUse payload (stdin)
        │
        ▼
 on_install.evaluate(raw)
   read payload ─ unreadable ─────────────────────────────► exit 2   [R-G-6]
        │
   scan tool_input.command ── no install found ───────────► exit 0   [R-G-7]
        │ list[Detected]
        ▼
 gate.decide(detected)
   for each Detected:
     unverifiable? ─────────────────────────────► problem            [R-G-5]
     tool is pip / npm / npx ─ parse() ─ Install ─► (package, exact version)
                                         other ──► problem           [R-G-5]
        │
   any package to verify? ─ build_context() ─ error ──► exit 2       [R-G-6]
        │
   verify_install(package, version) for each distinct package        [R-G-1]
        │
   no problem and every decision ALLOW ───────────────► exit 0       [R-G-2]
   anything else ─────────────────────────────────────► exit 2       [R-G-3, R-G-4, R-G-5]
```

### 1.2 Modules

| Module | Layer | Change |
|--------|-------|--------|
| `hooks/gate.py` (new) | 5 | `decide()` and message building. Holds the mapping from decisions to the exit code |
| `hooks/on_install.py` | 5 | Defines `Detected` and `Evaluation`. Detection now collects each install as a `Detected` instead of returning a bool. Reads the payload, runs the deadline, calls `gate.decide` |
| `intercept/parse.py` | 5 | Unchanged. The hook reuses it |

`on_install` imports `gate` only when it has found an install, so an ordinary command does not load the pipeline. `gate` imports `Detected` and `Evaluation` from `on_install`, so the dependency runs from `gate` to `on_install` at import time and the other way only at call time.

`hooks/` is layer 5, the same layer as `intercept/` and `cli`. The import rule in `structure.md` says a module imports only from layers below it. The hook breaks that rule in one place: it imports `intercept.parse`. The exception is deliberate. `parse` is pure (no I/O), and sharing it means the shim and the hook cannot disagree about what a pinned install is. This is the same reasoning as the single policy-fence function (v1 design section 7). No other layer-5 to layer-5 import is added.

### 1.3 Detection and extraction

The v1 detection logic stays. It splits the command into simple commands, strips wrappers (`sudo`, `env`, `VAR=val`, `nohup`, `xargs`, and others), and recurses into `bash -c` strings. What changes is the result. Each function that returned `True` now also appends a `Detected(tool, args, unverifiable)` record, where `tool` is the base name of the installing command and `args` are its arguments after wrappers were removed.

Rules that keep extraction from verifying a different command than the one that runs:

- Every code path that returns `True` appends at least one record. A path that cannot read the text appends a record with `unverifiable` set. The evaluation never treats "detected but no record" as ALLOW.
- A `VAR=val` assignment, an `env` assignment, or an `export`, `declare`, `typeset`, `readonly`, or `local` before the install makes the install unverifiable. The reason: `PIP_INDEX_URL=... pip install name==1.0.0` verifies `name` against the snapshot but installs from another index. The mark is sticky for the rest of the command, so `export PIP_INDEX_URL=...; pip install name==1.0.0` is covered too. It also marks installs after an unrelated assignment, which is stricter than needed and fails closed.
- `xargs` is sticky in the same way, because the package names arrive on stdin.
- A `Passthrough` result from `parse` for a detected install (for example `pip install` with no package, or `pip download`) is a problem, not an ALLOW.
- When `tool_input.command` is missing or not a string, the evaluation scans every string in the payload as in v1, and every install it finds is unverifiable (R-G-6).
- Detection uses `shlex` over the command text. It does not run a shell. Expansion forms (`$VAR`, `$(...)`, globs) fail the strict version pattern in `parse`, so they become unverifiable.

Known limits, kept from v1: a script file or `python -c` that runs an install is not inspected, and neither is `curl | sh`. A package index set outside the command, such as `npm config set registry ...` in an earlier command, `.npmrc`, or `pip.conf`, is not inspected either. The PATH shim has the same limit (THREAT_MODEL T11). A redirect such as `2>&1` after the package list leaves a stray `2` word, which `parse` rejects. The command is then refused with a fix that says to remove the redirect.

### 1.4 Rate limit

Each `verify_install` call from the hook counts as an attempt (R-4.7: every attempt counts, including blocked ones). Before this change, an allowed install was also counted by the PATH shim, so one install counted twice, and the effective limit for allowed installs was half of `max_installs_per_minute`. That was a bug, and R-G-11 fixes it. The fix is one shared rate-limit record, `ratelimit.json`, in the state directory, with two lists:

- `attempts`: one timestamp per counted attempt, as before.
- `hook_allows`: per install key, one timestamp for each package the hook allowed. Each entry is a credit.

The install key is `ecosystem:normalized-name==version`. Normalization uses `core/names.py`, so the hook and the shim produce the same key for the same package.

| Caller | Attempt is counted? | Effect on `hook_allows` |
|--------|---------------------|-------------------------|
| Hook, any verdict | Yes, always | On ALLOW, adds one credit for the key |
| Shim, no live credit for the key | Yes | None |
| Shim, a live credit for the key (under 60 s old) | No. The shim is still verified | Consumes the oldest credit |
| Any caller with no version (API) | Yes | None |

Fail closed: the credit is written after the verdict. If the write fails, the verdict becomes BLOCK, as for any other error in `verify_install`. An ALLOW never returns without its credit saved, so a shim cannot skip a count for an install whose credit was lost.

Counting only in the shim would let an agent probe blocked packages through the hook without limit, so the hook always counts. A call is not counted only when a live hook credit matches it. The shim cannot see the hook's command ID, because the hook payload has no ID that reaches the shim. The install key is used instead. A credit that expires unused (no shim run within 60 seconds) leaves the install counted once, by the hook.

### 1.5 Exit codes

The hook uses its own two exit codes, as in v1. They are not the verdict exit codes.

| Hook exit | Meaning | Reached by |
|-----------|---------|------------|
| 0 | Run the command | No install (R-G-7), or all packages ALLOW (R-G-2) |
| 2 | Block the command (the Kiro PreToolUse block) | Every other path |

| Verdict | Verdict exit (shim, CLI) | Hook exit |
|---------|--------------------------|-----------|
| ALLOW | 0 | 0 |
| BLOCK | 1 | 2 |
| QUARANTINE | 75 | 2 |
| Policy, key, or snapshot error | 78 or 1 | 2 |

No new exit code is added.

### 1.6 Output

Stdout stays empty (R-G-8). On exit 2, stderr has one fixed first line, then one JSON object per problem, in the order the problems were found:

```
BLOCKED by SlopSeal: this install is not allowed. Fix the problem below, or verify the package with the slopseal MCP tool first.
{"check": "existence", "fix": "...", "package": "csv-parser-pro", "reason": "...", "version": "0.1.0"}
```

Keys are sorted. A BLOCK carries `check`, `package`, `version`, `reason`, `fix`. A QUARANTINE carries `check` (the `mismatch_type`), `package`, `version`, `quarantine_id`, `reason`, `next_step`. An unverifiable install carries `check` (`unverifiable_install`), `reason`, `fix`. A reason is capped at 300 characters (R-G-10).

Paths that fail before a command is known (unreadable payload, stalled stdin, deadline) keep the v1 `BLOCK_MESSAGE` text unchanged.

On exit 0 after a verified install, stderr has one `slopseal: ALLOW name==version: reason` line per package and one `slopseal: WARN check: reason` line per warning, as the shim prints. On exit 0 with no install, stderr is empty.

### 1.7 Errors and the deadline

`decide` handles the errors that building the context is known to raise: `PolicyError`, `SealKeyError`, `SnapshotIntegrityError`, and `OSError`. Each becomes exit 2 with a JSON problem that names the check. `verify_install` never raises (its own failclosed wrapper).

`tech.md` forbids catching a bare `Exception` outside that wrapper, so the hook does not. Instead `on_install` runs the whole evaluation in a worker thread and waits for it with a deadline. A worker that raises ends without a result, and the main thread treats "no result" as a block with the v1 `BLOCK_MESSAGE` and exit 2. The interpreter's own exit 1 is never reached. The `sh -c` wrapper in the hook config, which maps exit 1 to exit 2 (v1 design section 11), stays as the last line of defense (R-G-9).

The deadline is 25 seconds. The hook config's `timeout` is 30 seconds, so the deadline leaves time to write the block message. If the worker has not finished, the main thread writes the v1 block message and exits 2 at once with `os._exit`, the same pattern as the stdin stall.

### 1.8 Hook config

The `description` in both copies of `block-agent-installs.json` changes to describe R-G-2 to R-G-5. The `command`, `matcher`, `trigger`, and `timeout` stay. The test that checks the two copies are identical stays.

### 1.9 Documents out of date after Phase 1

The v1 requirements are not changed. Each place that described the hook as non-verifying is now corrected, as listed below. The v1 design keeps its original sentence under a dated note.

- `.kiro/specs/seal/design.md` section 11: dated note, "Superseded by seal-v2 for the hook (2026-11-16)". The original sentence stays.
- `docs/THREAT_MODEL.md` T11 and section 6: corrected to the verdict behavior.
- `README.md`, "What the hook does": corrected.
- `docs/WRITEUP.md`, hooks paragraph: corrected.
- `.kiro/steering/structure.md`: `hooks/` added to the layout, and the one same-layer import (section 1.2) written down.
- `docs/REFERENCE.md`: corrected in the hook commit.

## 2. Phase 2: Contract Check (not implemented)

Requirements: R-C-1 to R-C-9 (`requirements.md`, section 2). Properties: P-C-1 to P-C-7. Threats: T17, T18, T23, and a note on T5.

### 2.1 Flow

```
 verify_install(request with intent.expected_api)            [verdict.py, step 4]
        │
        ▼
 source.contract(eco, name, version)                          [RegistrySource, new method]
        │
        ├─ OfflineSource ── snapshot ──► Complete(exports) | Unknown(network)       [R-C-8]
        │
        └─ LiveSource
              1. pick artifact from registry metadata (already fetched)
                    PyPI: a wheel, else Unknown(sdist_only)                          [R-C-2]
                    npm:  dist.tarball
              2. read the published digest ── unusable ──► Unknown(parse_error)      [R-C-1]
              3. cache lookup by verified digest ── hit ──► Complete(exports)        [R-C-6]
              4. download to a temp dir (50 MB cap, host allowlist)
                    fail ──► Unknown(network | limit)
              5. hash the file, compare ── mismatch ──► DigestMismatch               [R-C-1, T23]
              6. run the worker subprocess (limits, no code from the artifact)       [R-C-4]
                    status complete ──► Complete(exports), stored in the cache
                    status unknown  ──► Unknown(reason)
              7. delete the temp dir
        │
        ▼
 check_contract(result, declared_api)
        │
        ├─ DigestMismatch  ──► CheckResult(contract_digest, HARD_BLOCK) ──► BLOCK exit 1
        ├─ Unknown(reason) ──► CheckResult(api_surface, BLOCK, reason)   ──► BLOCK exit 1
        ├─ Complete, symbol absent ──► QUARANTINE exit 75 (api_absent) with the contract diff
        └─ Complete, symbol present ──► continue to ALLOW
```

### 2.2 Modules

| Module | Layer | Role |
|--------|-------|------|
| `contract/model.py` (new) | adapter | `ContractComplete`, `ContractUnknown`, `ContractDigestMismatch`, `UnknownReason` |
| `contract/digest.py` (new) | adapter | Parse the published digest (PyPI hex, npm SRI). Hash a file. Constant-time compare |
| `contract/fetch.py` (new) | adapter | Download an artifact to a temp dir with the size cap, timeout, and host allowlist |
| `contract/cache.py` (new) | adapter | Read and write `contracts/<algorithm>-<hex>.json` |
| `contract/worker.py` (new) | adapter | The subprocess program. One file, standard library only, imports nothing from `slopseal` |
| `contract/runner.py` (new) | adapter | Start the worker, enforce the wall time, parse its JSON output |
| `registry/live.py` | adapter | `contract()` calls the runner. `exports()` is derived from it |
| `registry/source.py` | adapter | The `RegistrySource` protocol gains `contract()`. `OfflineSource.contract()` reads the snapshot |
| `quarantine/api_surface.py` | 3 | `check_contract()` maps a result to PRESENT, ABSENT, or UNKNOWN. `check_api_surface()` stays as it is |
| `quarantine/contract_diff.py` (new) | 3 | Nearest real symbol, using `core.distance.levenshtein` (layer 2, below) |
| `quarantine/payload.py` | 3 | Adds the diff entries to `missing_evidence` and caps `found_apis` |
| `verdict.py` | 4 | Step 4 and `_escalated_again` call `contract()` |

`contract/` sits beside `registry/` and follows the same import rule: it may import `core.types`, and `registry/live.py` imports it. `worker.py` is the one exception, because it runs as a separate program and must not import anything it does not need. `core/` and `semantic/` do not import `contract/`. `structure.md` lists `contract/` when the code lands.

**Wiring status (R-C-8).** `LiveSource.contract()` runs the registry metadata request, the artifact choice, the digest read, the cache lookup, the download, digest verification, the archive check, the cache write (complete contracts only), and then the extraction step. The extraction step is a stub until R-C-2 and R-C-3 land. It returns `ContractUnknown(PARSE_ERROR, "extractor not implemented")`. `LiveSource.exports()` returns the tuple for a complete contract and `None` otherwise, so it is derived from `contract()`. With the stub, `exports()` still returns `None` for every live package, so no live answer changes before the extractor lands. The stub is removed in the same commit as the extractor for each ecosystem, and `grep "extractor not implemented"` returns nothing before any pull request.

### 2.3 Types and the interface

```python
class UnknownReason(Enum):
    SDIST_ONLY = "sdist_only"
    DYNAMIC_EXPORTS = "dynamic_exports"
    LIMIT = "limit"
    PARSE_ERROR = "parse_error"
    NETWORK = "network"
    NO_DIGEST = "no_digest"
    NOT_IN_SNAPSHOT = "not_in_snapshot"

@dataclass(frozen=True)
class ContractComplete:   exports: tuple[str, ...]          # sorted, unique, both name forms
@dataclass(frozen=True)
class ContractUnknown:    reason: UnknownReason; detail: str  # detail is short and holds no package text
@dataclass(frozen=True)
class ContractDigestMismatch: algorithm: str; detail: str

ContractResult = ContractComplete | ContractUnknown | ContractDigestMismatch
```

`RegistrySource.contract(eco, name, version) -> ContractResult` is new. `exports()` stays on the protocol and returns the tuple for a `ContractComplete` and `None` for anything else, so callers outside the verdict keep working. Unknown is an explicit value, not `None` and not an exception (`tech.md`).

`ApiSurfaceResult` gains `reason: UnknownReason | None = None` (default `None`, so existing constructors are unchanged). `check_contract(result, declared_api)` returns it. In `verdict.py` step 4, `ContractUnknown` becomes `CheckResult("api_surface", BLOCK, "exported symbols for this version are unknown: <reason>")`. The text before the colon is the v1 text. `ContractDigestMismatch` becomes `CheckResult("contract_digest", HARD_BLOCK, ...)`. No new exit code and no new outcome (`AGENTS.md`): both are BLOCK, exit 1.

Existing tests: no test double implements `exports()`, and every existing intent test uses `OfflineSource`. Expected verdicts of existing tests do not change. Where a test names the BLOCK reason, the v1 prefix is kept.

### 2.4 Artifact choice and digest

- **PyPI.** The version endpoint `/pypi/<name>/<version>/json` is already fetched for the install-script check. Its `urls[]` lists the files, each with `filename`, `url`, and `digests`. The system picks a wheel (R-C-2) and reads `digests.sha256`.
- **npm.** The packument entry `versions[<version>].dist` has `tarball`, `integrity`, and `shasum`. The system reads `integrity` only. A `shasum` without `integrity` is UNKNOWN (`no_digest`). SRI strings are `<algorithm>-<base64>`, space separated. The system picks the strongest of sha512, sha384, sha256 and decodes the base64 value.
- The comparison uses `hmac.compare_digest`. The download is hashed while it is written, then compared, then opened. A digest is checked before any parsing.
- The digest string comes from the registry, so it is untrusted until it has passed the format check in R-C-6. It is never used in a path before that.

### 2.5 The worker process

The parent starts `python -I <path to worker.py> <kind> <artifact path>`, where `kind` is `wheel` or `npm`, with an empty environment, `stdin` closed, the temp dir as the working directory, and a wall-time kill after 10 seconds. The worker sets its own limits first, before it opens the artifact: `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, and `RLIMIT_CORE` set to 0. It sets them itself and the parent does not use `preexec_fn`, because the install hook calls the Contract Check from a process that has threads. The hook does not run it today (R-C-8), but the code stays safe if that changes.

The worker never imports, executes, or compiles for execution anything from the artifact:

- It reads archive members into memory with `zipfile` or `tarfile`, one at a time. It does not extract them to disk. A symlink, hardlink, device, or fifo member is rejected before any member is read.
- It parses Python with `ast.parse`. This builds a syntax tree and runs nothing.
- It scans JavaScript and TypeScript declaration files as text.
- The artifact is not put on `sys.path`. A `.pth` file inside a wheel is data. `site` processing happens at interpreter start, from the worker's own interpreter, and not from the artifact.
- A tar archive is read as a stream through a byte counter that sits after decompression, so a decompression bomb hits the 200 MB cap whether or not its members are read.

The worker prints one JSON object on stdout, at most 8 MB: `{"status": "complete", "exports": [...]}` or `{"status": "unknown", "reason": "<typed reason>", "detail": "<short text>"}`. Any other output, a non-zero exit, a signal, or a timeout is UNKNOWN with reason `limit` for a timeout or signal and `parse_error` for malformed output. A worker killed by a signal (wall-time, CPU, or memory limit) gives `limit`. A non-zero exit that is not a limit kill gives `parse_error`. The parent re-validates the worker's `root` after the JSON parses (R-C-4): it must be relative, have no `..` segment, no backslash, and no NUL, and resolve under the artifact's private directory. A worker that returns `"../../etc"` is rejected with `parse_error`. Stderr is read for a short diagnostic only and never returned to the agent.

If `import resource` fails (not POSIX), the worker reports UNKNOWN with reason `limit`. Windows is out of scope.

### 2.6 Python extraction

Two passes, both over `ast.parse` output. No code from the artifact runs.

1. **Completeness pass.** `ast.walk` visits the whole tree, function bodies included. It returns UNKNOWN (`dynamic_exports`) for the first match of the R-C-2 list: any reference to `exec`, `eval`, `setattr`, `globals`, `vars`, `sys.modules`, or `__dict__`; a `global` statement; a `del` of a module name; a module-level `def __getattr__` or `def __dir__`; a module-level `for`, `with`, or `while` block; a module-level tuple target; a module-level augmented assignment; and a non-literal change to `__all__`. A reference inside a function is flagged the same way, because a function may run at import time.
2. **Set collection.** Set B comes from the module body and from every branch of module-level `if` and `try` blocks, nested blocks included. That covers the `if`, `elif`, and `else` bodies, and the `try`, `except`, `else`, and `finally` bodies. The forms are `def`, `async def`, `class`, simple name assignments (including annotated and chained forms with plain names), and import bindings. A branch that is never taken still adds its names, which can only give a wrong PRESENT. The completeness pass rejects module-level `for`, `with`, `while`, and tuple targets before set collection, so they never reach set B. Set A is the literal `__all__` with its literal additions. The export set of a module is the union of set A and set B.

Names. Each module's symbols are emitted as `<dotted module path>.<symbol>`, and each top-level symbol of a top-level module or package is also emitted as its bare name. Module paths are names too. The union is sorted, de-duplicated, and capped at 100,000 names. Over the cap is UNKNOWN with reason `limit`.

Star imports. `from .x import *` reads the exports of `x` once. If `x` has its own star import, a completeness flag, or exists only as a compiled extension (`.so`, `.pyd`), the result is UNKNOWN with reason `dynamic_exports`.

Cost. The rule flags every reference to `__dict__` and `sys`, including harmless ones such as `self.__dict__` inside a class. Those packages lose coverage. That is the price of Q1 and of never calling a real export absent.

### 2.7 npm extraction

The stdlib has no JavaScript parser. The extractor therefore tokenizes each file, removes comments and string contents, and then matches the forms of R-C-3 on the token stream. The matching is conservative. Every token `exports` or `module` that is not the head of an exact modelled form gives UNKNOWN (`dynamic_exports`). So does every token `__export`, `__exportStar`, `__reExport`, or `__createBinding`, and every `Object.defineProperty` or `Object.assign` whose target is `exports` or `module`. A form that is only partly recognised is an unmodelled form. The tokenizer cannot finish on an unterminated string or on a regular-expression literal it cannot classify, which gives `parse_error`. Template literals are scanned as text, and any `exports` or `module` token inside a `${...}` is a reference.

Entry resolution. `exports` is read first: every `import`, `require`, and `default` leaf that is a JavaScript file, and every `types` leaf that is a declaration file. Then `module`, `main`, and `types` or `typings`, when `exports` is absent. Then `index.js`, when neither `exports` nor `main` is present. Each resolved entry is checked on its own, and the multi-entry rule of R-C-3 combines the results.

Names. A subpath is an import specifier: the package name followed by the subpath without `./`. Qualified names are `<specifier>.<symbol>`, for example `semver.parse`. Bare names are the symbols of the root entry only. Scoped packages are not emitted in qualified form, because the specifier contains `/`. The union is capped as for Python.

Declarations (`.d.ts`). `export declare`, `export function`, `export const`, `export let`, `export var`, `export class`, `export interface`, `export type`, `export enum`, and `export namespace` are modelled, as are `export { a as b }`, `export default`, and `export * from` one hop. `export = <anything>` gives UNKNOWN (Q3). `export default` adds the reserved name `default` (Q4).

Cost. UMD wrappers, bundler helpers, and CommonJS built with `typeof module` checks are UNKNOWN. Many real packages are of those kinds. This lowers coverage, and the labels expect it for the hard cases.

### 2.8 Cache

`<state dir>/contracts/<algorithm>-<hex>.json`. The entry is written to a temp file and moved into place with `os.replace`, as `rate_limit.py` does. The write is the last step of a miss, after step 5 of section 2.1 (the digest check). A cache write before the digest check is a violation (R-C-6, mutant in P-C-6). Fields: `schema`, `key`, `extractor_version`, `exports`, and `entry_sha256`, which is the SHA-256 of the canonical JSON of the other fields. The reader recomputes the hash and discards (and deletes) any entry that fails any check in R-C-6. A hit reads one small file and does no network call, so it fits the 100 ms bound.

The hash detects corruption and accidental edits. It does not stop someone who can write the state directory, who can rewrite an entry and its hash together. That is the same limit as the snapshot manifest (T9), and it is recorded under T17 in the threat model. There is no eviction in Phase 2. The cache holds only complete contracts, one small file each.

### 2.9 Tests and the acceptance measurement

**Hermetic parity test.** For each of the 23 snapshot versions, the test builds a wheel (PyPI) or tarball (npm) from that version's snapshot exports, serves it through a fake fetch with a matching digest, and runs the whole live path, including the worker. It requires: the live contract contains every snapshot export, and live and offline give the same PRESENT or ABSENT answer for every probe, where the probes are each snapshot export, each export with `_x` added, and one name that exists nowhere. The live set is larger than the snapshot set, because live also emits the bare and the module-path names, so the test compares answers on the probes and not whole sets. The test is named `test_contract_plumbing_snapshot_parity`. It proves the plumbing from artifact to verdict. It does not measure accuracy on real packages.

**Real-package measurement.** Fifty packages, 25 PyPI and 25 npm, are labelled by hand before any extractor run, from each package's official documentation and public API. The labels file is `docs/contract_labels.json`. The exact metric definitions are `docs/CONTRACT_EVAL.md`. Both land in one commit before the first extractor run, and neither changes after it. The labels file pins, per package, the exact version and the artifact file and digest. It lists symbols labelled present and plausible hallucinations labelled absent. It records the expected extraction status (complete, or UNKNOWN with a reason) for the hard cases, and the sources used. The three reported numbers are named here and defined in `CONTRACT_EVAL.md`:

- **Coverage**: the share of packages with a decided answer (PRESENT or ABSENT).
- **Decided accuracy**: the share of decided answers that match the label. Target at least 95%.
- **Strict agreement**: the same count with UNKNOWN counted as a miss.

A present-labelled symbol that the extractor calls ABSENT (a false ABSENT) is a hard stop for the phase. A wrong PRESENT is reported and is not a stop. The hard cases include a literal `__all__`, a module `__getattr__` (expected UNKNOWN), re-export-heavy packages, a `.d.ts`-only npm package, CommonJS, and ESM `exports` maps.

### 2.10 Contract Diff in the payload

P-SM-4 pins the payload to the exact R-Q-3 field set, and this phase does not change that set. The diff therefore uses existing keys: `declared_api` is the claimed symbol, `found_apis` is the real exports, and the nearest real symbol is an extra entry in `missing_evidence`, for example `["api_surface_mismatch", "nearest_real_symbol:parse_csv=>parse"]`. A name that reaches the payload has passed the name check in R-C-2, so it holds no whitespace and no control character. `found_apis` is capped at 200 sorted names, and a cut adds `found_apis_truncated`. The nearest symbol is computed over the whole set before the cap. The PRD example shows `missing_evidence` with one entry. The PRD is not edited.

Owner ruling: the structured Contract Diff (the claimed symbol, the real exports, and the nearest symbol for each miss) goes into the receipt in Phase 3, which is not implemented here. The payload keys stay as above. R-Q-3 and P-SM-4 are not edited.

Alternative, not chosen: a new `contract_diff` key. That would need R-Q-3 and the pinned set in `test_p_sm_quarantine.py` to change, which this phase does not do without the owner's decision.

### 2.11 The escalated retry

`_escalated_again` saves the escalated state as before, with the retry budget consumed. Then it asks for the contract with `contract()`, before it writes any escalation artifact. When the contract is UNKNOWN or a digest mismatch, it writes no artifact, appends the audit entry with the typed reason and the check name, and returns the BLOCK of R-C-9 (exit 1). It does not build an `api_absent` payload. When the contract is complete, it writes the escalation artifact and builds the payload as before.

**Owner rulings.** Decision 1: option (a). The contract is added to the source protocol, the live path runs the download and the cache now, and the extraction step is a stub until the extractor lands. Decision 2: confirmed. On UNKNOWN in `_escalated_again`, no escalation artifact is written, the state change (budget consumed) is kept, the audit entry carries the typed reason and the check name, and the BLOCK message names the reason and the next step, and no artifact reference. P-SM-2 still holds: this call makes no new intent check. It reads the contract only to fill `found_apis`, and in live mode a cache hit makes that read cheap. A cache miss can download, so a retry against an escalated quarantine can use the network once. If an existing test pins the old exit 75 for an unknown contract, work stops and the owner is told. None does. The four test files that pass a `quarantine_id` (`test_p_sm_quarantine.py`, `test_r_4_7_rate_limit.py`, `test_p_g_1_hook.py`, `test_mcp_protocol.py`) use no live source, and an offline version that was quarantined always has known exports, so the unknown branch is not reached by any existing test.

### 2.12 Constants

| Constant | Value | Source |
|----------|-------|--------|
| Compressed size | 50 MB | R-C-4, owner |
| Expanded size | 200 MB | R-C-4, owner |
| Archive members | 5,000 | R-C-4, owner |
| Extractor wall time | 10 s | R-C-4, owner |
| Cache hit time | 100 ms | R-C-6, owner |
| Download wall time | 30 s | proposed here |
| Source file size read by `ast.parse` | 5 MB | proposed here |
| Names in a contract | 100,000 | proposed here |
| Worker output | 8 MB | proposed here |
| Address-space limit | 1 GiB | proposed here |
| `found_apis` in the payload | 200 | proposed here |

Owner ruling: these values are fixed safety ceilings of the extractor. They are resource limits, not trust thresholds. They live as named constants in `contract/limits.py`, like `MAX_BYTES` (10 MB) in `registry/live.py`. A later policy section may lower them. Policy may never raise them, and a floor in `policy/invariants.py` must enforce that when such a section is added. That section is not part of this phase, and `dependency-trust.md` is not changed. In the table, *owner* marks a value from the brief and *proposed* marks a value this design chose. The owner may change any *proposed* value before the code lands.

### 2.13 Documents this phase updates when the code lands

`docs/REFERENCE.md` "Full limitations" (live exports are available only for artifacts the extractor can complete, and UNKNOWN blocks), `docs/THREAT_MODEL.md` (T5 status, T17, T18, T23 from planned to implemented, the data-sent table for the artifact download, section 6), `CHANGELOG.md`, and `.kiro/steering/structure.md` (`contract/`). Text that says live exports are always `None` is removed.

### 2.14 Owner rulings

All open questions from the previous step are closed. The rulings are:

- **General rule.** Completeness is opt-in. An extraction is complete only when every statement that can define or change an export matches a modelled form (the completeness rule, in `requirements.md`, section 2). Any other statement that writes to exports gives UNKNOWN (`dynamic_exports`). Over-flagging costs coverage. Under-flagging causes a false ABSENT. This replaces the earlier list of dynamic patterns in R-C-2, R-C-3, and R-C-5.
- **Q1, Python module writes.** `sys.modules` aliasing, `setattr`, `globals()` writes, `vars()` and `__dict__` writes, `exec`, and `eval` give UNKNOWN (`dynamic_exports`). The scan covers function bodies as well.
- **Q2, reassigned `module.exports`.** `module.exports = <anything that is not a plain object literal>` gives UNKNOWN. Later member writes are not tracked. Lodash is labelled expected UNKNOWN.
- **Q3, unnamed exports.** A function, class, identifier, or call assigned to `module.exports`, and `export =` in a `.d.ts`, give UNKNOWN (`dynamic_exports`). No eighth reason is added.
- **Q4, default.** `default` is a reserved contract name, added by `export default` and `exports.default =`. A claim on `default` is PRESENT if listed. It is ABSENT only when the extraction is complete and it is not listed. Python has no default export. Replaces the earlier rule that `export default` counts under the bare name of its declaration.
- **Q5, bundler and compiler helpers.** `__export(`, `__exportStar(`, `__reExport(`, `__createBinding(`, `Object.defineProperty(exports, ...)` except `__esModule`, `Object.assign(module.exports, ...)`, and `Object.keys(...).forEach` writing to exports give UNKNOWN (`dynamic_exports`). Immer stays expected UNKNOWN.
- **Two entry points.** A symbol is PRESENT when it is in any complete entry point. It is ABSENT only when every resolved entry point is complete and none lists it. Otherwise UNKNOWN (`dynamic_exports`).
- **Limits.** Unchanged (section 2.12).
- **Typed reasons.** Seven, unchanged. No eighth reason.
- **Receipt.** The structured Contract Diff goes to the receipt in Phase 3 (section 2.10).

Expected statuses in the labels were predicted before this rule was written. Under the rule, some `complete` predictions for CommonJS, UMD, and bundled packages may be wrong. A wrong prediction lowers coverage and does not change the accuracy figures. The owner decides before the first run whether those predictions are re-made. The labels are not changed for this reason in this step.

## 3. Phase 3 and later

Not designed. Phase 3 is signing (R-S). Phase 4 ships R-G-12, the depth-1 transitive check, which is not implemented. T16 stays open until then (see `requirements.md`, glossary and R-G-12). Each later phase starts by adding its requirements, design section, and properties to this spec, and by stopping for the owner's review (see `tasks.md`).
