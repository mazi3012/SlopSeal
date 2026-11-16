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

## 2. Phase 2 and later

Not designed. Phase 4 ships R-G-12, the depth-1 transitive check, which is not implemented. T16 stays open until then (see `requirements.md`, glossary and R-G-12). Each later phase starts by adding its requirements, design section, and properties to this spec, and by stopping for the owner's review (see `tasks.md`).
