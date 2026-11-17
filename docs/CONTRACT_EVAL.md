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

This is the one measured run, recorded before the labels freeze. The owner reviews the numbers before the freeze.

- **Command.** `python scripts/contract_eval.py --out run1.json` (harness commit `f272bfc`). The run started 2026-11-17 10:01:20 UTC and took about 16 s of wall time.
- **Labels.** `docs/contract_labels.json`, unchanged since its last commit (`4591bab`). SHA-256 at the run: `d258bc486224aa07345e0c07a70378878d10d035ae8174c50e7b3d1e2e715885`. Not frozen. The freeze and its commit wait for the owner's review.
- **Procedure step 1 (labels and this document committed before the run).** Met.
- **Procedure step 4 (owner reviews each absent name before the run).** **Not met.** All 51 labels still read `absent_review: pending_owner`. Run 1 used the labels as drafted, so the 98 absent probes are provisional until that review is done.
- **Procedure step 6 (post-run audit).** Complete where UNKNOWN was predicted: none. Predicted complete but actual UNKNOWN: 34 packages (listed in the table below). No label was changed.
- **Errors.** None. Every package returned a contract.

### Headline

| Metric | Result |
|---|---|
| Coverage, packages (decided / 51) | 10 / 51 = 19.6% |
| Probe coverage (decided / 259) | 54 / 259 = 20.8% |
| Decided accuracy (target at least 95%) | 53 / 54 = 98.1% |
| Strict agreement (over 259 probes) | 53 / 259 = 20.5% |
| False ABSENT (any count is a stop) | **0** |
| Wrong PRESENT (reported) | 1: `npm:cookie`, probe `cookie` (see decision 5) |
| Expected-UNKNOWN agreement | 7 / 7 with the expected reason; 0 complete |
| Expected complete but UNKNOWN (coverage, not a stop) | 34 of 44 packages |
| RECORD mismatches (parse_error on RECORD) | 0 wheels (none) |
| Digest mismatches | 0 |
| Label checks (filename and digest against the registry) | 51 of 51 match |

The decided accuracy is 53 of 54 decided probes. The one miss is the wrong PRESENT for `cookie`. The strict agreement counts every UNKNOWN as a miss, so it is low by design.

### By ecosystem

| Ecosystem | Packages | Decided packages | Probes | Decided probes | Decided accuracy | Strict agreement | False ABSENT | Wrong PRESENT |
|---|---|---|---|---|---|---|---|---|
| pypi | 25 | 4 | 136 | 18 | 100.0% | 13.2% | 0 | 0 |
| npm | 26 | 6 | 123 | 36 | 97.2% | 28.5% | 0 | 1 |
| **total** | 51 | 10 | 259 | 54 | 98.1% | 20.5% | 0 | 1 |

### By hard case

| Hard case | Packages | Decided packages | Probes | Decided probes | Decided accuracy | Strict agreement |
|---|---|---|---|---|---|---|
| commonjs | 11 | 5 | 55 | 31 | 96.8% | 54.5% |
| literal___all__ | 9 | 3 | 49 | 13 | 100.0% | 26.5% |
| reexport_heavy | 9 | 1 | 50 | 5 | 100.0% | 10.0% |
| None | 7 | 0 | 37 | 0 | - | 0.0% |
| esm_exports_map | 6 | 1 | 29 | 5 | 100.0% | 17.2% |
| dts_only | 4 | 0 | 16 | 0 | - | 0.0% |
| lazy_getattr | 2 | 0 | 9 | 0 | - | 0.0% |
| cjs_reassigned_exports | 1 | 0 | 5 | 0 | - | 0.0% |
| commonjs_umd | 1 | 0 | 4 | 0 | - | 0.0% |
| esbuild_cjs_helper | 1 | 0 | 5 | 0 | - | 0.0% |

The `None` row is the seven packages with no hard case in the labels: the seven expected-UNKNOWN packages. Every hard-case group has a false ABSENT count of 0.

### Latency (contract step, one artifact, live registries)

- Uncached: median 132.6 ms, maximum 593.7 ms (`pypi:numpy`, a large wheel). The uncached time is the registry metadata, the download, the digest check, the archive check in the worker, and the extraction in the worker.
- Cached (complete contracts only): median 0.165 ms, maximum 0.24 ms. The cache holds complete contracts only (R-C-6), so an UNKNOWN package repeats the full path on its second call, at about the uncached time.
- These are contract-level times. The CLI adds process start-up and the policy checks: about 0.27 to 0.45 s per `slopseal check` in the smoke test.

### What drives the coverage gap

The probes that give UNKNOWN follow the rules as written. The reason is the first rule that fires, and a file can break more than one rule.

**Python (25 wheels; 4 decided).** Most expected-complete wheels fire the Q1 rule, which covers function and class bodies (ruled at the 2.6 review):

- `setattr(...)`, `globals()`, `vars()`, `eval`, or `exec` inside a function body. Examples: `requests/adapters.py:234` (`setattr(self, attr, value)`), `pydantic/__init__.py:408` (`globals()[attr_name]`), `jinja2/compiler.py:1948`, `pluggy/_hooks.py:157`.
- `__dict__` or `sys.modules` inside any body. Examples: `requests/cookies.py:417` (`self.__dict__.copy()`), `typer/_typing.py:375` (`sys.modules[module_name]`), `rich/__init__.py:50`.
- A module-level `__getattr__` or `__dir__`: `flask/__init__.py:46`, `sqlalchemy/__init__.py:286`, `marshmallow/__init__.py:23`.
- A `global` statement in a function: `certifi/core.py:27`, `click/termui.py:737`, `attrs/_config.py:19`.
- A module-level statement the model does not follow: `httpx`, `tqdm`, `urllib3`.

**npm (26 packages; 6 decided).**

- A `./package.json` subpath (a JSON leaf): dotenv, colorette, js-yaml, marked, immer, @types/js-yaml (6 packages). See decision 2.
- A condition outside the list (`browser`, `react-native`, `worker`): nanoid, uuid, tslib.
- Two entry points, one not complete: commander, lru-cache, query-string. The complete entry's names are PRESENT (R-C-3), and the rest are UNKNOWN.
- An empty `main` (`""`): `@types/ms`, `@types/semver`, `@types/jsonwebtoken` give `parse_error` with "unsafe entry path". This is a bug. See decision 4.
- A rule on a form: `export { default }` re-export (lodash-es), a top-level `this` (xml2js), a read of `module.exports` (mime-types), and the lodash forms.

### Decisions for the owner (not applied; a changed rule or fix needs a new run)

1. **Q1 breadth (Python).** Function and class bodies are included by ruling. Most of the coverage gap comes from this: harmless `setattr`, `__dict__`, and `global` in methods. Options: keep it; or narrow to module-level writes, with the function-body rule kept only for `global` and `sys.modules`. Narrowing it changes the Python numbers and needs a new run.
2. **`./package.json` subpaths (npm).** Keep as UNKNOWN (current), or treat a JSON leaf as a non-JavaScript entry with no names. Six packages depend on this.
3. **Conditions outside the list (npm).** Keep UNKNOWN (current), or ignore `browser`, `react-native`, and `worker` for a Node resolution. Three packages depend on this.
4. **Empty `main`, `module`, `types`, `typings` (npm).** The current code gives `parse_error` for an empty string. That is a bug: Node treats an empty string as absent. Recommended fix: an empty string is absent, which turns the three `@types` packages into complete contracts. The fix changes the npm numbers, so it needs a new run. Not made here, so that Run 1 describes the code as committed.
5. **Module path as a bare name (wrong PRESENT).** The spec counts the module path as an export name (R-C-2, R-C-3). For the root package, that makes its bare name PRESENT, so `cookie` is PRESENT for `npm:cookie`. Options: exclude the root package's own name from the bare names, or accept the wrong PRESENT as reported.
6. **Expected statuses.** 34 of the 44 expected-complete packages are UNKNOWN under the rules as written. The expected statuses were predictions. The owner decides whether the rules or the predictions govern the next run.
7. **Absent review.** The 98 absent labels are unreviewed (`pending_owner`). The freeze waits for that review.

No rule or code was changed to make the run look better. A second run is a new run: its numbers replace this one only after the owner decides items 1 to 5 and the labels are reviewed.

### Parity test (R-C-8)

`test_contract_plumbing_snapshot_parity`: 23 of 23 snapshot versions pass. For each version the live path builds an artifact from the snapshot exports, verifies its digest, and runs both worker steps. The live contract contains every snapshot export, and live and offline agree on every probe.

### Per-package results

Expected and actual status for all 51 packages. The probe columns count the decided probes and the probes that agree with the label. Latency is per call, in milliseconds.

| Package | Expected | Actual | Reason | Probes decided / total | Probe agreement | Uncached ms | Cached ms |
|---|---|---|---|---|---|---|---|
| pypi:requests | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 122.0 | 123.97 |
| pypi:pytest | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 130.0 | 125.27 |
| pypi:pydantic | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 132.3 | 129.56 |
| pypi:numpy | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 593.7 | 557.05 |
| pypi:httpx | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 122.3 | 117.52 |
| pypi:flask | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 120.2 | 116.17 |
| pypi:click | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 163.4 | 172.26 |
| pypi:rich | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 126.1 | 124.12 |
| pypi:attrs | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 122.3 | 133.53 |
| pypi:typer | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 126.2 | 128.17 |
| pypi:sqlalchemy | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 157.3 | 162.83 |
| pypi:tqdm | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 122.8 | 121.8 |
| pypi:pyyaml | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 119.0 | 121.44 |
| pypi:jinja2 | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 138.4 | 134.34 |
| pypi:beautifulsoup4 | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 126.8 | 124.1 |
| pypi:python-dotenv | complete | complete | - | 5 / 5 | 5 / 5 | 125.5 | 0.24 |
| pypi:tomli | complete | complete | - | 5 / 5 | 5 / 5 | 128.5 | 0.2 |
| pypi:urllib3 | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 116.2 | 121.65 |
| pypi:colorama | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 113.8 | 111.94 |
| pypi:certifi | complete | unknown | dynamic_exports | 0 / 3 | 0 / 3 | 114.3 | 117.62 |
| pypi:tenacity | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 131.8 | 127.97 |
| pypi:marshmallow | complete | unknown | dynamic_exports | 0 / 7 | 0 / 7 | 118.6 | 115.39 |
| pypi:tabulate | complete | complete | - | 3 / 3 | 3 / 3 | 140.3 | 0.2 |
| pypi:pluggy | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 122.1 | 124.76 |
| pypi:idna | complete | complete | - | 5 / 5 | 5 / 5 | 243.1 | 0.22 |
| npm:semver | complete | complete | - | 6 / 6 | 6 / 6 | 150.3 | 0.19 |
| npm:nanoid | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 144.3 | 133.2 |
| npm:zod | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 144.4 | 148.27 |
| npm:@types/ms | complete | unknown | parse_error | 0 / 3 | 0 / 3 | 132.6 | 144.6 |
| npm:@types/semver | complete | unknown | parse_error | 0 / 5 | 0 / 5 | 141.4 | 136.68 |
| npm:uuid | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 140.7 | 139.83 |
| npm:commander | complete | unknown | dynamic_exports | 4 / 6 | 4 / 6 | 143.4 | 149.11 |
| npm:dotenv | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 172.3 | 132.42 |
| npm:colorette | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 130.1 | 135.54 |
| npm:jsonwebtoken | complete | complete | - | 6 / 6 | 6 / 6 | 136.3 | 0.14 |
| npm:tslib | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 131.8 | 133.03 |
| npm:lru-cache | complete | unknown | dynamic_exports | 1 / 3 | 1 / 3 | 276.2 | 272.21 |
| npm:immer | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 143.2 | 137.64 |
| npm:query-string | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 125.9 | 131.16 |
| npm:qs | complete | complete | - | 5 / 5 | 5 / 5 | 140.3 | 0.13 |
| npm:xml2js | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 205.8 | 196.31 |
| npm:ini | complete | complete | - | 6 / 6 | 6 / 6 | 131.3 | 0.13 |
| npm:js-yaml | complete | unknown | dynamic_exports | 0 / 4 | 0 / 4 | 142.0 | 141.51 |
| npm:marked | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 138.4 | 169.54 |
| npm:node-fetch | complete | complete | - | 5 / 5 | 5 / 5 | 142.2 | 0.14 |
| npm:lodash-es | complete | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 187.6 | 196.41 |
| npm:@types/js-yaml | complete | unknown | dynamic_exports | 0 / 3 | 0 / 3 | 138.0 | 129.97 |
| npm:@types/jsonwebtoken | complete | unknown | parse_error | 0 / 5 | 0 / 5 | 132.6 | 134.02 |
| npm:mime-types | complete | unknown | dynamic_exports | 0 / 6 | 0 / 6 | 129.1 | 137.15 |
| npm:cookie | complete | complete | - | 3 / 3 | 2 / 3 | 138.7 | 0.11 |
| npm:lodash | unknown / dynamic_exports | unknown | dynamic_exports | 0 / 5 | 0 / 5 | 372.7 | 355.5 |
