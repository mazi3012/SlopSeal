# SlopSeal v2: Property-Based Testing Contract

**Relation to v1:** `.kiro/specs/seal/properties.md` is unchanged and still applies. This file adds properties.
**Runner:** Hypothesis, at least 500 cases per property (R-PBT-1). Tests live in `src/tests/properties/` and are named after the property id.

---

## 1. Gate (Phase 1)

**P-G-1 (the hook exits 0 or 2, only ALLOW reaches 0, and setup failures block).** For any hook payload text, any outcome assignment for the packages that `verify_install` is asked about (each package independently ALLOW, BLOCK, or QUARANTINE), and any setup failure from the set below:

- `none`: no failure.
- `build_policy`, `build_seal_key`, `build_snapshot`, `build_os`: building the context raises a policy, seal key, snapshot, or OS error.
- `import_missing`: the gate module cannot be imported (a missing or broken module).
- `decision_error`: the decision raises an exception.
- `stdin_unreadable`: reading stdin raises.
- `stdin_stalled`: stdin does not close within the stdin timeout.
- `deadline`: the decision does not finish within the deadline.

The property requires:

1. The exit code is 0 or 2.
2. Stdout is empty.
3. Any install verified is one the command names. Nothing is verified after a setup failure.
4. The exit code is 0 only if (a) there is no failure, (b) every install in the command is verifiable, (c) at least one verdict was requested, and (d) every verdict returned ALLOW.
5. If any verdict returned BLOCK or QUARANTINE, the exit code is 2.
6. `stdin_unreadable`, `stdin_stalled`, and `deadline` exit 2 for every payload. The hook cannot know what the command is, or the decision did not finish, so these block whether or not the command has an install (R-G-6).
7. `build_*`, `import_missing`, and `decision_error` exit 2 when the command contains an install. A command with no install never builds the context or loads the gate (R-G-7), so the failure is not on its path and it exits 0.

Property 4 is the part that says "only ALLOW maps to 0". The rule for a command with no install stays as in v1 (R-G-7). Blocking every `ls` because the policy file is broken would make the hook unusable. Property 7 is the scope of "setup error": a setup failure blocks the installs it affects, and the hook blocks on any failure it cannot get past. A setup failure on a non-install command is not a verdict, so it does not change that command's exit code. Owner decision: if you want every setup failure to block every command, the gate must be imported before the command scan, and that changes R-G-7 for the broken-install case.

**P-G-1 oracle.** The generator builds each command from pieces whose class is known by construction (no install, verifiable install, unverifiable install), joined by `&&`, `;`, `|`, a newline, or wrapped in `sudo`, `nohup`, `env VAR=val` (which makes the install unverifiable), or `bash -c`. The expected class is computed from the pieces, not from the code under test. The failure is drawn from the set above and injected at the point where it occurs in the real hook: the context build, the gate import, the gate call, stdin, the stdin stall timer, and the deadline. A second strategy feeds arbitrary text and arbitrary JSON shapes as the payload, and it applies the same failure set, and checks properties 1, 2, 5, and 6, with a verifier that always returns ALLOW. That is the worst case for the exit code.

### Generators

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_hook_command` | Commands built from classified pieces, joiners, and wrappers | P-G-1 (3, 4, 5, 7) |
| `gen_hook_payload` | Valid Kiro payloads, JSON with missing or mistyped `tool_input`, arbitrary text | P-G-1 (1, 2, 6) |
| `gen_outcome_map` | An outcome (ALLOW, BLOCK, QUARANTINE) per package name | P-G-1 (4, 5) |
| `gen_setup_failure` | One failure from the set above, injected at its point in the hook | P-G-1 (1, 3, 4, 6, 7) |

**P-G-3 (a broken pipeline never allows an install).** For any command that contains an install, pinned or unpinned, and any failure that stops the pipeline from loading or running a verdict, the exit code is 2 and stdout is empty. The failures are: the gate module cannot be imported, the context build raises (policy, seal key, snapshot, or OS error), the decision raises, or a verdict call raises. No line reading `slopseal: ALLOW` is written to stderr. A command with no install is outside this property, because it never loads the pipeline (R-G-7).

This is the broken-install case that R-G-7 keeps visible. Blocking every command on a broken install would stop the agent from running `ls` or tests, so only commands that contain an install are blocked.

### Generators

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_install_command` | One or more installs, pinned or unpinned, for pip and npm, with wrappers and joiners | P-G-3 |
| `gen_pipeline_failure` | One failure from the set above, injected at its point in the hook | P-G-3 |

## 2. Rate limit across layers (Phase 1)

**P-G-2 (one install, one count).** For any sequence of installs, where each install is one of: a hook call then a shim call for the same package and version (both layers), a hook call alone, or a shim call alone, and where time moves forward by any amount, the number of counted attempts equals the number of counted installs predicted by this model:

- Every hook call counts once (R-G-11).
- A hook call that ALLOWs adds one credit for its install key.
- A shim call counts once when no credit exists for its key, and consumes one credit (without counting) when a credit younger than the 60-second window exists.

A pair of hook and shim calls for one install therefore counts once. The oracle is the model above, a plain counter, not the limiter's code. The sequence stays at or under the limit, so every call is ALLOW and the blocked path is tested by R-4.7.

### Generators

| Generator | Produces | Used by |
|-----------|----------|---------|
| `gen_install_events` | Sequences of up to 10 events: hook or shim call for a key from a small pool (allowed packages and one blocked package), or a time step of 0 to 90 seconds | P-G-2 |

## 3. Contract Check (Phase 2)

Tests for these properties build their artifacts in memory and serve them through a fake fetch. They use no network. Each property is checked with at least one mutant (a deliberate break of the code under test), and the result of each mutant goes in the pull request. A mutant that the property does not catch is reported, not hidden.

**P-C-1 (the extractor never runs package code).** For any wheel, sdist, or npm tarball, including ones whose `setup.py`, `__init__.py`, `.pth` file, `sitecustomize.py`, `package.json` lifecycle scripts, and `index.js` are written to create a marker file when run, the marker file never appears, whatever result the extractor returns. The canary code embeds the absolute path of the marker. The extractor still returns a result (complete or UNKNOWN), and does not crash. An sdist is never opened: it returns UNKNOWN with reason `sdist_only`, and the property checks that too.

*Generators:* `gen_canary_artifact` builds an archive where each of the places that could run code, chosen by Hypothesis, holds canary code, with random surrounding legitimate code.
*Mutants:* (a) the worker runs `runpy.run_path` on a `setup.py` it finds. (b) the worker imports the top-level module. (c) the worker adds the extracted directory to `sys.path` and imports `sitecustomize`. Each must make the property fail.

**P-C-2 (UNKNOWN never allows).** For any artifact the extractor cannot complete (each of the seven typed reasons: `sdist_only`, `dynamic_exports`, `limit`, `parse_error`, `network`, `no_digest`, `not_in_snapshot`), and for any declared API, `verify_install` with that intent returns BLOCK (exit 1). It never returns ALLOW and never returns QUARANTINE (exit 75). The BLOCK names the typed reason. A QUARANTINE with `mismatch_type: api_absent` occurs only when the contract is complete and the symbol is not in it (R-C-5, P-FC-4). The one exception: a declared API that a complete entry point of a contract with several entry points lists is PRESENT, and the intent check passes it (R-C-3, two entry points). That symbol is never reported ABSENT, and the contract stays UNKNOWN.

*Generators:* `gen_unknown_contract` (one result for each of the seven typed reasons in every run, with random detail text; the property fails if the generator omits a reason), `gen_declared_api` (any string, including a name that is in the incomplete contract).
*Mutants:* (a) UNKNOWN is mapped to PRESENT. (b) UNKNOWN is mapped to ABSENT, which gives QUARANTINE. (c) a symbol found in an incomplete contract returns PRESENT. Each must fail the property.

**P-C-3 (a digest mismatch always blocks).** For any artifact, and any single-byte change to the artifact bytes or to the published digest, for each accepted algorithm (sha256, sha384, sha512) and both PyPI hex form and npm SRI form, the result is BLOCK with check `contract_digest` and level HARD_BLOCK. It is never UNKNOWN, never ALLOW, and never a cache hit. The archive is not opened before the digest has matched.

*Generators:* `gen_artifact_bytes`, `gen_digest_mutation` (flip one byte of the artifact, flip one character of the digest, truncate, extend).
*Mutants:* (a) the comparison checks only the first 8 bytes. (b) a mismatch is returned as UNKNOWN. (c) the archive is opened before the comparison, checked by a marker in a spy opener. (d) the algorithm is fixed at sha256, so an npm sha512 value is read with the wrong algorithm.

**P-C-4 (ABSENT needs a complete contract).** For any generated Python module or npm entry file, built from a known list of symbols: (a) if the extractor returns ABSENT for a symbol, the extraction was complete and the symbol is not in the known list; (b) if the file contains any dynamic pattern in the lists of R-C-2 or R-C-3, the result is UNKNOWN for every symbol, never ABSENT and never PRESENT; (c) every symbol in the known list is PRESENT when the file has no dynamic pattern. The oracle is the generator's own symbol list, not the extractor.

*Generators:* `gen_python_module` and `gen_js_module`, with symbols, optional literal `__all__`, optional re-exports, and optional injected dynamic patterns. The known list for a Python module includes public names that are not in `__all__`, and names in `__all__` that start with an underscore. Each of them must be PRESENT when the file has no dynamic pattern, which tests the union.
*Mutants:* (a) a computed `__all__` is read as empty. (b) a module-level `__getattr__` is ignored. (c) `from .x import *` is dropped. (d) the JS scan stops at the first `module.exports` and misses `exports.y`. (e) the export set is `__all__` alone, so the union is dropped. (f) a name in `__all__` that starts with an underscore is dropped. Each must fail the property.

**P-C-5 (limits and hostile archives give UNKNOWN).** For any archive that breaks a limit of R-C-4 (size, expanded size, member count, wall time) or contains an unsafe member (absolute path, `..` segment, NUL byte, duplicate name, symlink, hardlink, device, fifo), the result is UNKNOWN with reason `limit` or `parse_error` (the typed reason matches the break), nothing is written outside the private temp dir, nothing is written for a member, and no member outside the archive is read.

*Generators:* `gen_hostile_archive` (a zip or tar with one hostile property chosen by Hypothesis), `gen_bomb` (a highly compressible member).
*Mutants:* (a) the `..` check is removed. (b) the expanded-size counter is placed before decompression. (c) symlink members are followed. Each must fail the property.

**P-C-6 (the cache never returns a bad entry).** For any cache entry, and any single-byte change to the entry file, or a changed key, extractor version, or hash, the lookup is a miss, the bad entry is deleted, and the result comes from a fresh extraction. A valid entry returns the same exports as a fresh extraction. A download whose digest does not match leaves no cache entry afterward (R-C-6). A key that is not `<known algorithm>-<lowercase hex>` never reaches the file system.

*Generators:* `gen_cache_entry`, `gen_entry_mutation`, `gen_hostile_key` (path separators, `..`, uppercase, overlong).
*Mutants:* (a) the stored hash is not checked. (b) the extractor version is not checked. (c) the key is used in a path without the format check. (d) the entry is written before the digest is verified, and the mismatch test finds a file in the cache directory afterward. Each must fail the property.

**P-C-7 (the contract diff is honest and has no number).** For any ABSENT result, the QUARANTINE payload has exactly the R-Q-3 field set. The nearest real symbol, when present, is a member of the real export set. It is a minimum-distance member, and ties go to the smallest by byte order, so two runs give identical bytes. No numeric value other than `retry_budget_remaining` appears in the payload. `found_apis` is sorted and has at most 200 entries, and a cut adds `found_apis_truncated`.

*Generators:* `gen_export_set` (empty, one, many, more than 200), `gen_claimed_symbol` (near and far from the set).
*Mutants:* (a) the nearest symbol is taken from outside the set. (b) the tie-break is removed. (c) the distance is added to the payload. Each must fail the property.

**P-C-8 (no synthetic artifact for the completeness rules gives ABSENT).** For a synthetic artifact built for each ruling below, the extraction result is never ABSENT for any probe. Where the artifact would make a probe ABSENT under a naive reading, the result is UNKNOWN with reason `dynamic_exports`. The cases are:

- Q1, Python module writes: `sys.modules[__name__]` aliasing, `setattr(module, name, value)`, `globals()[name] = value`, `globals().update({...})`, `vars()[name] = value`, `module.__dict__[name] = value`, `exec(...)`, and `eval(...)`. Each as a module-level statement, and once inside a function body.
- Q2, reassigned exports: `module.exports = someIdentifier`, `module.exports = function () {}`, and `module.exports = new Thing()`, followed by `module.exports.x = ...`. Every probe is UNKNOWN, not ABSENT.
- Q3, unnamed exports: `module.exports = function ...` and `export = name` in a `.d.ts`. Every probe is UNKNOWN.
- Q4, default: `export default function f() {}` and `exports.default = value`. The probe `default` is PRESENT, never ABSENT. A probe that is not exported is ABSENT only when the contract is complete.
- Q5, helpers: `__export(exports, {...})`, `__exportStar(require("./x"), exports)`, `__reExport(...)`, `__createBinding(...)`, `Object.defineProperty(exports, "x", { get: ... })`, `Object.assign(module.exports, {...})`, and `Object.keys(src).forEach((k) => { exports[k] = src[k]; })`. Every probe is UNKNOWN.
- Two entry points: an `import` entry that lists `a`, and a `require` entry that is unresolvable or uses an unmodelled form. `a` is PRESENT. A probe that neither complete entry lists is UNKNOWN, not ABSENT.

*Generators:* `gen_q1_python_write`, `gen_q2_reassigned_exports`, `gen_q3_unnamed_export`, `gen_q4_default`, `gen_q5_helper`, `gen_two_entries`. Each draws one form from its list, places it at a random position in a file of otherwise modelled statements, and gives the expected result, which the test computes from the generator's own list, not from the extractor.

*Mutants.* Each one removes one rule. Each mutant must fail P-C-8:

- M-Q1: the Python reference check is skipped.
- M-Q2: a non-literal `module.exports = x` is read as a complete empty set.
- M-Q3: an unnamed export is read as a complete empty set, and `export = x` in a `.d.ts` is ignored.
- M-Q4: the reserved name `default` is not added to the contract.
- M-Q5: the bundler helper and `Object.defineProperty` checks are skipped.
- M-DUAL: a symbol missing from one entry point is ABSENT, even when another entry point is UNKNOWN.

Results of the mutant runs go in the pull request. A mutant that the property does not catch is reported, not hidden.

**Typed-reason tests (one per reason; not P-properties).** Each reason in the glossary has one test in `src/tests/unit/test_contract_reasons.py`. Each test triggers the reason through the verdict path, with a real `verify_install` call and a synthetic source. It asserts the verdict is BLOCK (exit 1), the typed reason is named in the `api_surface` or `contract_digest` detail, and the result is neither ALLOW nor QUARANTINE.

| Reason | Trigger | Test |
|--------|---------|------|
| `sdist_only` | A PyPI version whose files are only an sdist | `test_reason_sdist_only` |
| `dynamic_exports` | A wheel with a Q1 `setattr` on the module | `test_reason_dynamic_exports` |
| `limit` | A wheel above 50 MB compressed | `test_reason_limit` |
| `parse_error` | A `.py` file with a syntax error | `test_reason_parse_error` |
| `network` | A download that raises, and a redirect to a host outside the allowlist | `test_reason_network` |
| `no_digest` | An npm version with only `shasum`, and a PyPI file with no `sha256` | `test_reason_no_digest` |
| `not_in_snapshot` | An offline lookup for a package the snapshot does not cover | `test_reason_not_in_snapshot` |

These tests need `ContractUnknown` and the verdict wiring (tasks 2.4 and 2.6 to 2.8). They are written with those tasks, not before. Until then the table is the specification of what they check.

## Mapping to requirements

| Property | Requirements |
|----------|--------------|
| P-G-1 | R-G-1, R-G-2, R-G-3, R-G-4, R-G-5, R-G-6, R-G-7, R-G-8 |
| P-G-2 | R-G-11, R-4.7 |
| P-G-3 | R-G-6, R-G-7 |
| P-C-1 | R-C-1, R-C-4 |
| P-C-2 | R-C-5, R-Q-2 |
| P-C-3 | R-C-1 |
| P-C-4 | R-C-2, R-C-3, R-C-5 |
| P-C-5 | R-C-4 |
| P-C-6 | R-C-6 |
| P-C-7 | R-C-7 |
| P-C-8 | R-C-2, R-C-3, R-C-5 (completeness rule, Q1 to Q5) |

## Pass criteria

- P-G-1 passes with 500 or more cases.
- P-C-1 to P-C-7 pass with 500 or more cases, and each has at least one mutant that fails it.
- No v1 property is changed, skipped, or given fewer examples.
