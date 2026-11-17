# Contract Check: labels and metric definitions

Status: labels are NOT frozen. They freeze at the first extractor run, and that run's commit records the final labels hash. Until then they may change, each change in its own commit with the hash updated here.

Labels file: `docs/contract_labels.json`. SHA-256 of that file: `d258bc486224aa07345e0c07a70378878d10d035ae8174c50e7b3d1e2e715885`.

## What is labelled

- 51 packages: 25 PyPI and 26 npm. Each package is pinned to one exact version and one artifact. For PyPI the artifact is the wheel the R-C-2 rule chooses (a `none-any` wheel when one exists, otherwise the first wheel in ascending filename order), with its SHA-256 from the registry. For npm the artifact is the tarball, with the `sha512` integrity from the registry. npm `shasum` (sha1) is recorded in the registry metadata and is not used.
- 259 probes: 161 names labelled PRESENT and 98 names labelled ABSENT. A probe is one name in the form the contract emits: a bare top-level name, or `<module>.<name>` (PyPI module path, npm import specifier). A few probes use the qualified form.
- Each package has an expected status: `complete`, or `unknown` with an expected typed reason.
- Every label cites at least one official documentation or public API URL. Labels are drafted from documentation and public API, never from extractor output. Exceptions are listed under "Known limitations of the labels".
- Absent names are plausible hallucinations an agent might write. They are reviewed by the owner before the run (absent_review = pending_owner until then).

## Hard cases

A `hard_case` field records which case each package exercises.

- Literal `__all__` (union rule): pypi:httpx, pypi:marshmallow, pypi:pluggy, pypi:pytest, pypi:python-dotenv, pypi:tabulate, pypi:tomli, pypi:tqdm, pypi:urllib3
- Lazy module `__getattr__` (expected UNKNOWN): pypi:numpy, pypi:pydantic
- Re-export-heavy packages, including second-hop star imports (expected UNKNOWN for pyyaml and zod): npm:lodash-es, npm:zod, pypi:click, pypi:flask, pypi:idna, pypi:pyyaml, pypi:sqlalchemy, pypi:tenacity, pypi:typer
- Declaration-only npm packages (`.d.ts` only): npm:@types/js-yaml, npm:@types/jsonwebtoken, npm:@types/ms, npm:@types/semver
- CommonJS (`module.exports` literal, `exports.x =`, chained, and TypeScript-compiled forms): npm:commander, npm:cookie, npm:dotenv, npm:ini, npm:js-yaml, npm:jsonwebtoken, npm:lru-cache, npm:mime-types, npm:qs, npm:semver, npm:xml2js
- A UMD wrapper (tslib, expected UNKNOWN under the completeness rule): npm:tslib
- ESM exports maps: npm:colorette, npm:marked, npm:nanoid, npm:node-fetch, npm:query-string, npm:uuid
- Reassigned `module.exports` (Q2, expected UNKNOWN): npm:lodash
- An esbuild CommonJS export helper (Q5, expected UNKNOWN): npm:immer

Expected UNKNOWN packages: pypi:pydantic, pypi:numpy, pypi:pyyaml, npm:zod, npm:tslib, npm:immer, npm:lodash.

Not covered by these labels: the `sdist_only`, `limit`, `network`, `no_digest`, and `not_in_snapshot` reasons. The parity test, the property tests (P-C-1 to P-C-8), and the typed-reason tests cover those. A 50-package label set cannot exercise them.

## Known limitations of the labels

- **PRESENT means exported, not that the call works.** `safeLoad` and `safeDump` in js-yaml 4.1.0 are labelled PRESENT. The pinned artifact exports them as stubs that throw when called (`renamed(...)` in `index.js`). The changelog says they were removed. Both facts are recorded in the package notes.
- **Absent names were checked by a plain text search of the pinned artifact.** A hit is a line of text, not an export. Most hits are comments, docstrings, or other modules' names. The search found the js-yaml stubs, and that finding is the reason for the first limitation.
- **Expected statuses are predictions** made from each package's structure, before the completeness rule was final. A wrong expected status lowers coverage. It does not change the accuracy figures.
- **Docs can omit real exports.** A present name that a documentation page does not name is dropped from the labels rather than kept without a source. A real export missing from the labels is not counted, and that is a gap in the labels, not in the extractor.

## Coverage limits of the first run

These are recorded before the measurement and are not narrowed before it (rulings of 2.6).

- **Compiled extensions (`.so`, `.pyd`) give UNKNOWN for the whole artifact.** A Python wheel that ships a compiled module has its names unread, so the whole package is UNKNOWN with reason `dynamic_exports`. Packages with compiled modules lose coverage. The labels expect this for the numeric and native hard cases.
- **Dynamic forms.** `sys.modules`, any `__dict__`, `from sys import modules`, walrus assignments, `match`, `global` statements in a module file, and any unmodelled module-level statement give UNKNOWN for the whole artifact. Over-flagging costs coverage only.
- **False-PRESENT risk: `from .x import y`.** The extractor binds `y` and does not read `x`. A name that `x` does not define at run time is reported PRESENT. This cannot cause a false ABSENT. It is reported as a wrong PRESENT, not a stop.
- **False-PRESENT risk: `try` and `if` branches.** Every branch is unioned. A name bound in a branch that never runs is reported PRESENT.

## npm coverage limits (R-C-3, first run)

- **Extensionless `main` and `module` resolve by probe; a directory does not.** See the probe order below. `ms@2.1.3` (not labelled) now resolves to its `index.js`, and it is still UNKNOWN, because that file is `module.exports = function ...`, an unnamed export (Q2, Q3). A `main` that names a directory gives `parse_error`.
- **A `./package.json` subpath gives UNKNOWN.** A JSON leaf is neither a JavaScript nor a declaration leaf. Six labelled packages list one (dotenv, colorette, js-yaml, marked, immer, @types/js-yaml). Recorded in Run 1 as a decision for the owner.
- **An empty `main`, `module`, `types`, or `typings` gives `parse_error`.** This is a bug, not a rule. Node treats an empty string as absent. Three labelled `@types` packages (`main: ""`) are affected. Recorded in Run 1; not fixed before the measurement.
- **Two entry points, one not complete.** The complete entry's names are PRESENT. Every other name is UNKNOWN. Example: `kleur@4.1.5` (not labelled). Its ESM entry lists `default`, `kleur`, and `kleur/colors`, and its CommonJS entry is not complete.
- **Conditions outside the list give UNKNOWN.** Only `import`, `require`, `node`, `default`, and `types` are resolved. A `browser`, `development`, or `worker` condition gives UNKNOWN.
- **Literal `default` keys in `module.exports` give UNKNOWN.** Only `export default` and `exports.default =` add `default`.
- **A top-level `this` gives UNKNOWN (conservative, added at 2.8).** A `this` in a top-level block that is not a function or a class is not caught. This is a false-ABSENT gap that the first run measures.
- **Relative `export * from` is one hop.** A second hop, a bare package, and an `export * as` give UNKNOWN.
- **Declaration files: `export =`, `declare module` blocks, and `export as namespace` give UNKNOWN.**

## npm entry resolution order (R-C-3, ruled at the 2.14 review)

A declared `main` or `module` path with no extension is probed in this order. The first file that exists in the tarball is the entry:

1. `<path>.js`
2. `<path>.cjs`
3. `<path>.mjs`

A declared `types` or `typings` path with no extension is probed as `<path>.d.ts` only, so a type path never resolves to a JavaScript file. The path as written is not probed. A directory is not probed. When no probe finds a file, the entry is missing and gives `parse_error` for that entry. Extensionless `exports` leaves are not resolved.

The owner's list was `.js`, `.cjs`, `.mjs`, `.d.ts`. The split by field (`.d.ts` only for `types` and `typings`) is this document's refinement, and it keeps a type path from resolving to a JavaScript file.

## Metric definitions

Notation. A probe `p` is one (package, name) pair. `L(p)` is its label, PRESENT or ABSENT. `A(p)` is the extractor's answer: PRESENT or ABSENT when the package contract is complete, and UNKNOWN with its typed reason when it is not. A probe is *decided* when `A(p)` is PRESENT or ABSENT. A package is *decided* when its contract is complete.

1. **Coverage (a).** The number of decided packages, divided by 51. Probe coverage (decided probes divided by 259) is also reported, for information.
2. **Decided accuracy (b).** Among decided probes, the share with `A(p) = L(p)`. Target: at least 95%.
3. **Strict agreement (c).** Over all 259 probes, the share with `A(p) = L(p)`. An UNKNOWN answer always counts as a miss.
4. **False ABSENT (hard stop).** A probe with `L(p) = PRESENT` and `A(p) = ABSENT`. Any count above 0 stops the phase. This is counted over every probe, including those of expected-UNKNOWN packages.
5. **Wrong PRESENT (reported, not a stop).** A probe with `L(p) = ABSENT` and `A(p) = PRESENT`. It is reported with its count.
6. **Expected-UNKNOWN agreement (reported).** For each package whose expected status is `unknown`, whether the extractor returns UNKNOWN with the expected typed reason. A package that returns a complete contract is a deviation, listed by name. Its probes are still counted in 2 to 5.

Every number is reported per ecosystem and in total, and per hard case.

## Procedure

1. The labels file and this document are committed together, before the first extractor run.
2. The run uses the live path, with the artifacts downloaded and digest-verified as R-C-1 requires. Nothing is downloaded outside that path.
3. The runner writes its per-probe answers to a file. The labels are not read or changed during the run.
4. The owner reviews each absent name before the run. Once the run starts, nothing in the labels changes.
5. A false ABSENT is a stop. The phase does not continue until the cause is fixed in the spec or the code, and the run is repeated.
6. **Post-run audit of expected status.** After the run, print predicted and actual status for all 51 packages. Audit every package where the actual contract is more complete than predicted (a complete contract where UNKNOWN was predicted). Report each one, and do not change its label to match the result.

## What the numbers do not show

- They show agreement with 51 hand-labelled packages, not accuracy on the registry. The parity test shows the plumbing, not accuracy.
- Labels can be wrong. A wrong label on an absent name shows up as a wrong PRESENT. A wrong label on a present name shows up as a wrong ABSENT, which is a stop.

## Run 1: the measured run (not frozen)

Run 1 was measured twice on the same labels. The **first run** was on commit `f272bfc`. The **current run** is after the owner's Run 1 review (rulings: empty declared strings are absent, and the root package's own name is not an export; decisions 1, 2, and 5 kept as they stand). The current run is on commit `545f393`, and its JSON is the source of every figure below.

- **Labels.** `docs/contract_labels.json`, unchanged since commit `4591bab`. SHA-256 `d258bc486224aa07345e0c07a70378878d10d035ae8174c50e7b3d1e2e715885`. **Not frozen.**
- **Absent review (procedure step 4).** **Not met.** All 51 labels still read `absent_review: pending_owner`. The 98 absent probes are provisional until the owner's review. The owner has left this pending on purpose.
- **Post-run audit (procedure step 6).** Complete where UNKNOWN was predicted: none. Predicted complete but actual UNKNOWN: 33 packages (listed in "Where the rules are conservative over the labels"). No label was changed.
- **Errors.** None. Every package returned a contract.

### History: first run and current run

| Metric | First run (`f272bfc`) | Current run (`545f393`) |
|---|---|---|
| Coverage, packages | 10 / 51 = 19.6% | 11 / 51 = 21.6% |
| Probe coverage | 54 / 259 = 20.8% | 59 / 259 = 22.8% |
| Decided accuracy | 53 / 54 = 98.1% | 59 / 59 = 100.0% |
| Strict agreement | 53 / 259 = 20.5% | 59 / 259 = 22.8% |
| False ABSENT | 0 | 0 |
| Wrong PRESENT | 1 (`npm:cookie`, probe `cookie`) | 0 |
| Expected-UNKNOWN agreement | 7 / 7 | 7 / 7 |
| Expected complete but UNKNOWN | 34 of 44 | 33 of 44 |
| Uncached median / max (ms) | 132.6 / 593.7 | 136.9 / 587.1 |
| Cached median, complete (ms) | 0.165 | 0.18 |

### What changed between the two runs

- **`npm:cookie` (fixed).** The bare probe `cookie` was PRESENT because the root package name was an export. It is ABSENT now, which is correct: `cookie` does not export that symbol. The wrong PRESENT is gone.
- **`npm:@types/jsonwebtoken` (fixed).** It gave `parse_error` ("unsafe entry path") from `"main": ""`. The empty string is now absent, so the `types` entry decides. The contract is complete, and all five probes agree.
- **`npm:@types/ms` (not complete, and the label conflicts).** It moved from `parse_error` to UNKNOWN `dynamic_exports`, because its declaration file has `export = ms;` (Q3). The label expects complete. The rules govern (ruling 5).
- **`npm:@types/semver` (not complete, and the label conflicts).** It moved from `parse_error` to UNKNOWN `dynamic_exports`. Its declaration file has `export import compareIdentifiers = identifiers.compareIdentifiers;` (line 97), which the declaration rules do not model. The label expects complete. The rules govern.
- **`npm:@types/js-yaml`.** Still UNKNOWN. Its `./package.json` subpath is a JSON leaf (decision 2, kept).

### Headline (current run)

| Metric | Result |
|---|---|
| Coverage, packages (decided / 51) | 11 / 51 = 21.6% |
| Probe coverage (decided / 259) | 59 / 259 = 22.8% |
| Decided accuracy (target at least 95%) | 59 / 59 = 100.0% |
| Strict agreement (over 259 probes) | 59 / 259 = 22.8% |
| False ABSENT (any count is a stop) | **0** |
| Wrong PRESENT (reported) | 0 |
| Expected-UNKNOWN agreement | 7 / 7 with the expected reason; 0 complete |
| Expected complete but UNKNOWN (coverage, not a stop) | 33 of 44 packages |
| RECORD mismatches (`parse_error` on RECORD) | 0 |
| Digest mismatches | 0 |
| Label checks (filename and digest against the registry) | 51 of 51 match |

### By ecosystem (current run)

| Ecosystem | Packages | Decided packages | Probes | Decided probes | Decided accuracy | Strict agreement | False ABSENT | Wrong PRESENT |
|---|---|---|---|---|---|---|---|---|
| pypi | 25 | 4 | 136 | 18 | 100.0% | 13.2% | 0 | 0 |
| npm | 26 | 7 | 123 | 41 | 100.0% | 33.3% | 0 | 0 |
| **total** | 51 | 11 | 259 | 59 | 100.0% | 22.8% | 0 | 0 |

### By hard case (current run)

| Hard case | Packages | Decided packages | Probes | Decided probes | Decided accuracy | Strict agreement |
|---|---|---|---|---|---|---|
| commonjs | 11 | 5 | 55 | 31 | 100.0% | 56.4% |
| literal___all__ | 9 | 3 | 49 | 13 | 100.0% | 26.5% |
| reexport_heavy | 9 | 1 | 50 | 5 | 100.0% | 10.0% |
| None | 7 | 0 | 37 | 0 | - | 0.0% |
| esm_exports_map | 6 | 1 | 29 | 5 | 100.0% | 17.2% |
| dts_only | 4 | 1 | 16 | 5 | 100.0% | 31.2% |
| lazy_getattr | 2 | 0 | 9 | 0 | - | 0.0% |
| cjs_reassigned_exports | 1 | 0 | 5 | 0 | - | 0.0% |
| commonjs_umd | 1 | 0 | 4 | 0 | - | 0.0% |
| esbuild_cjs_helper | 1 | 0 | 5 | 0 | - | 0.0% |

The `None` row is the seven packages with no hard case in the labels (requests, rich, attrs, jinja2, beautifulsoup4, colorama, certifi). All seven are expected complete, and none is decided.

### Latency (contract step, one artifact, live registries)

- Uncached: median 136.9 ms, maximum 587.1 ms (`pypi:numpy`, a large wheel). It covers the registry metadata, the download, the digest check, the archive check, and the extraction, each in the worker.
- Cached, complete contracts: median 0.18 ms, maximum 0.26 ms. An UNKNOWN contract is not cached (R-C-6), so its second call repeats the full path at about the uncached time.
- The CLI adds process start-up and policy checks: about 0.27 to 0.45 s per `slopseal check` in the smoke test.

### Q1 breadth and the coverage impact (decision 1, kept)

Python rules stay as they are. Function and class bodies are included, and nothing is widened before the freeze. The first-firing message for the 21 UNKNOWN Python packages (current run) is:

| First-firing rule | Packages |
|---|---|
| Reference to a module namespace (`__dict__`, `sys.modules`) | 6 |
| Reference to a builtin that changes names (`setattr`, `globals`, `vars`, `eval`, `exec`) | 4 |
| Module-level `__getattr__` or `__dir__` | 4 |
| Module-level statement not modelled | 4 |
| `global` statement in a module file | 2 |
| `__all__` annotated without a literal value | 1 |

The first-firing rule is the one the worker reports. A package can break more than one rule. The split between function-body and module-level references is **not measured**. Measuring it would mean changing the rule, which is not done before the freeze. The labelled numbers therefore show the cost of Q1 as written, not what a narrower Q1 would decide.

### Where the rules are conservative over the labels (decision 5)

The rules govern. The labels are predictions. This table lists every expected-complete package that the rules keep UNKNOWN in the current run, with the rule that fires first. Each one is a coverage cost, not a wrong answer: UNKNOWN blocks, and it never allows or claims ABSENT.

| Package | Label expects | Rule that keeps it UNKNOWN (first firing) |
|---|---|---|
| pypi:requests | complete | reference to a builtin that changes names at run time |
| pypi:pytest | complete | reference to a module namespace |
| pypi:httpx | complete | module-level statement is not modelled |
| pypi:flask | complete | module-level __getattr__ or __dir__ |
| pypi:click | complete | reference to a module namespace |
| pypi:rich | complete | global statement in a module file |
| pypi:attrs | complete | reference to a module namespace |
| pypi:typer | complete | reference to a module namespace |
| pypi:sqlalchemy | complete | module-level __getattr__ or __dir__ |
| pypi:tqdm | complete | module-level statement is not modelled |
| pypi:jinja2 | complete | reference to a builtin that changes names at run time |
| pypi:beautifulsoup4 | complete | reference to a module namespace |
| pypi:urllib3 | complete | module-level statement is not modelled |
| pypi:colorama | complete | reference to a builtin that changes names at run time |
| pypi:certifi | complete | global statement in a module file |
| pypi:tenacity | complete | reference to a module namespace |
| pypi:marshmallow | complete | module-level __getattr__ or __dir__ |
| pypi:pluggy | complete | reference to a builtin that changes names at run time |
| npm:nanoid | complete | a condition or pattern the model does not resolve |
| npm:@types/ms | complete | export = is not modelled (Q3) |
| npm:@types/semver | complete | an export form that is not modelled in a declaration file |
| npm:uuid | complete | a condition or pattern the model does not resolve |
| npm:commander | complete | one entry point is not complete |
| npm:dotenv | complete | an entry that is neither JavaScript nor a declaration file |
| npm:colorette | complete | an entry that is neither JavaScript nor a declaration file |
| npm:lru-cache | complete | one entry point is not complete |
| npm:query-string | complete | one entry point is not complete |
| npm:xml2js | complete | a top-level this is module.exports in CommonJS |
| npm:js-yaml | complete | an entry that is neither JavaScript nor a declaration file |
| npm:marked | complete | an entry that is neither JavaScript nor a declaration file |
| npm:lodash-es | complete | an export list that names default (Q4 is only export default) |
| npm:@types/js-yaml | complete | an entry that is neither JavaScript nor a declaration file |
| npm:mime-types | complete | exports or module read or changed in a form the model does not follow |

Three groups of these are the cases where the label predicts complete and the rule is stricter, and the owner should see them:

- `npm:@types/ms` and `npm:@types/semver`: a declaration form the rules do not model (`export =`, `export import`). The rules are Q3 and the declaration rules as written.
- `npm:@types/js-yaml`, `npm:marked`, `npm:colorette`, `npm:dotenv`, `npm:js-yaml`, `npm:immer`: a `./package.json` subpath (decision 2, kept UNKNOWN).
- `npm:nanoid`, `npm:uuid`: a `browser`, `react-native`, or `worker` condition (decision 2, kept UNKNOWN).

### Decisions (Run 1 review)

| # | Decision | Status |
|---|---|---|
| 1 | Q1 breadth and the Python rules | Kept as written. Coverage impact documented above. |
| 2 | Subpath leaves and non-standard conditions (`browser`, `react-native`, `worker`) | Kept UNKNOWN. Strict Node condition matching stays. |
| 3 | Empty `main` string | Fixed: an empty declared string is absent (R-C-3). |
| 4 | The root package name as a bare export (`cookie`) | Fixed: the root name is an export only when the package exports that symbol (R-C-2, R-C-3). |
| 5 | Labels and expected statuses | The rules govern. Conservative rules are listed above. Absent review left pending. |

### Parity test (R-C-8)

`test_contract_plumbing_snapshot_parity`: 23 of 23 snapshot versions pass, with the naming change in place.

### Per-package results (current run)

Expected and actual status for all 51 packages. The probe columns count the decided probes and the probes that agree with the label. Latency is per call, in milliseconds.

| Package | Expected | Actual | Reason | Probes decided / total | Probe agreement | Uncached ms | Cached ms |
|---|---|---|---|---|---|---|---|
| pypi:requests | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 124.7 | 121.89 |
| pypi:pytest | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 127.3 | 135.77 |
| pypi:pydantic | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 133.5 | 131.37 |
| pypi:numpy | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 587.1 | 666.19 |
| pypi:httpx | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 117.7 | 116.67 |
| pypi:flask | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 119.1 | 114.38 |
| pypi:click | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 164.9 | 165.41 |
| pypi:rich | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 129.5 | 124.34 |
| pypi:attrs | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 120.8 | 122.98 |
| pypi:typer | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 123.5 | 125.6 |
| pypi:sqlalchemy | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 165.9 | 172.03 |
| pypi:tqdm | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 119.8 | 116.07 |
| pypi:pyyaml | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 119.2 | 123.08 |
| pypi:jinja2 | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 138.9 | 138.65 |
| pypi:beautifulsoup4 | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 124.3 | 126.17 |
| pypi:python-dotenv | complete | complete | - | 5 / 5 | 5 / 5 | 127.6 | 0.26 |
| pypi:tomli | complete | complete | - | 5 / 5 | 5 / 5 | 131.5 | 0.2 |
| pypi:urllib3 | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 119.1 | 120.03 |
| pypi:colorama | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 117.4 | 119.22 |
| pypi:certifi | complete | unknown | dynamic_exports | 0 / 3 | 0 / 3 | 120.7 | 122.4 |
| pypi:tenacity | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 126.4 | 129.9 |
| pypi:marshmallow | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 123.2 | 119.67 |
| pypi:tabulate | complete | complete | - | 3 / 3 | 3 / 3 | 140.2 | 0.19 |
| pypi:pluggy | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 124.2 | 121.79 |
| pypi:idna | complete | complete | - | 5 / 5 | 5 / 5 | 234.7 | 0.24 |
| npm:semver | complete | complete | - | 6 / 6 | 6 / 6 | 138.6 | 0.18 |
| npm:nanoid | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 131.8 | 136.59 |
| npm:zod | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 139.2 | 139.28 |
| npm:@types/ms | complete | unknown | dynamic_exports | 0 / 3 | 0 / 3 | 135.1 | 141.67 |
| npm:@types/semver | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 164.6 | 262.99 |
| npm:uuid | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 140.8 | 133.54 |
| npm:commander | complete | unknown | dynamic_exports | 4 / 6 | 4 / 6 | 148.9 | 146.81 |
| npm:dotenv | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 131.7 | 139.46 |
| npm:colorette | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 133.9 | 133.63 |
| npm:jsonwebtoken | complete | complete | - | 6 / 6 | 6 / 6 | 137.0 | 0.12 |
| npm:tslib | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 138.1 | 130.37 |
| npm:lru-cache | complete | unknown | dynamic_exports | 1 / 3 | 1 / 3 | 275.9 | 268.04 |
| npm:immer | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 149.5 | 141.68 |
| npm:query-string | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 129.3 | 127.58 |
| npm:qs | complete | complete | - | 5 / 5 | 5 / 5 | 137.9 | 0.12 |
| npm:xml2js | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 196.8 | 206.39 |
| npm:ini | complete | complete | - | 6 / 6 | 6 / 6 | 137.2 | 0.11 |
| npm:js-yaml | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 147.2 | 148.0 |
| npm:marked | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 150.7 | 141.09 |
| npm:node-fetch | complete | complete | - | 5 / 5 | 5 / 5 | 146.9 | 0.14 |
| npm:lodash-es | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 197.9 | 200.58 |
| npm:@types/js-yaml | complete | unknown | dynamic_exports | 0 / 3 | 0 / 3 | 136.9 | 142.83 |
| npm:@types/jsonwebtoken | complete | complete | - | 5 / 5 | 5 / 5 | 139.4 | 0.19 |
| npm:mime-types | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 131.8 | 134.2 |
| npm:cookie | complete | complete | - | 3 / 3 | 3 / 3 | 143.4 | 0.11 |
| npm:lodash | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 353.7 | 362.91 |
