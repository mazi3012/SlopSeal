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
