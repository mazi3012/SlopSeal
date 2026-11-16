# Contract Check: labels and metric definitions

Status: labels frozen before the first extractor run (R-C-5, P-C-2, P-C-4). The extractor has not been run on these labels. Changing a label or a definition after a result is seen is not allowed. A label found wrong after a run is reported as a label error in its own commit, and both sets of numbers are shown.

Labels file: `docs/contract_labels.json`. SHA-256 of that file: `0a316d83e39562f6d860f755675882938e4bbc2fcfe8419efd544c2ba2a0e054`.

## What is labelled

- 50 packages: 25 PyPI and 25 npm. Each package is pinned to one exact version and one artifact. For PyPI the artifact is the wheel the R-C-2 rule chooses (a `none-any` wheel when one exists, otherwise the first wheel in ascending filename order), with its SHA-256 from the registry. For npm the artifact is the tarball, with the `sha512` integrity from the registry. npm `shasum` (sha1) is recorded in the registry metadata and is not used.
- 256 probes: 158 names labelled PRESENT and 98 names labelled ABSENT. A probe is one name in the form the contract emits: a bare top-level name, or `<module>.<name>` (PyPI module path, npm import specifier). A few probes use the qualified form.
- Each package has an expected status: `complete`, or `unknown` with an expected typed reason.
- Every label cites at least one official documentation or public API URL. Labels are drafted from documentation and public API, never from extractor output.
- Absent names are plausible hallucinations an agent might write. They are reviewed by the owner before the run (absent_review = pending_owner until then).

## Hard cases

The labels cover the hard cases the spec names. A `hard_case` field records which one each package exercises.

- Literal `__all__` (union rule): pypi:httpx, pypi:marshmallow, pypi:pluggy, pypi:pytest, pypi:python-dotenv, pypi:tabulate, pypi:tomli, pypi:tqdm, pypi:urllib3
- Lazy module `__getattr__` (expected UNKNOWN): pypi:numpy, pypi:pydantic
- Re-export-heavy packages, including a second-hop star import (expected UNKNOWN for pyyaml and zod): npm:lodash-es, npm:zod, pypi:click, pypi:flask, pypi:idna, pypi:pyyaml, pypi:sqlalchemy, pypi:tenacity, pypi:typer
- Declaration-only npm packages (`.d.ts` only): npm:@types/js-yaml, npm:@types/jsonwebtoken, npm:@types/ms, npm:@types/semver
- CommonJS (`module.exports` literal, `exports.x =`, chained, and TypeScript-compiled forms): npm:commander, npm:cookie, npm:dotenv, npm:ini, npm:js-yaml, npm:jsonwebtoken, npm:lru-cache, npm:mime-types, npm:qs, npm:semver, npm:xml2js
- A UMD wrapper (tslib): npm:tslib
- ESM exports maps: npm:colorette, npm:marked, npm:nanoid, npm:node-fetch, npm:query-string, npm:uuid
- An esbuild CommonJS export helper (expected UNKNOWN, see the open question on this pattern in `.kiro/specs/seal-v2/design.md`): npm:immer

Expected UNKNOWN packages: pypi:pydantic, pypi:numpy, pypi:pyyaml, npm:zod, npm:immer.

Not covered by these labels: the `sdist_only`, `limit`, `network`, `no_digest`, and `not_in_snapshot` reasons. The parity test, the property tests (P-C-1 to P-C-7), and the fixtures test those. A 50-package label set cannot exercise them.

## Metric definitions

Notation. A probe `p` is one (package, name) pair. `L(p)` is its label, PRESENT or ABSENT. `A(p)` is the extractor's answer: PRESENT or ABSENT when the package contract is complete, and UNKNOWN with its typed reason when it is not. A probe is *decided* when `A(p)` is PRESENT or ABSENT. A package is *decided* when its contract is complete.

1. **Coverage (a).** The number of decided packages, divided by 50. Probe coverage (decided probes divided by 256) is also reported, for information.
2. **Decided accuracy (b).** Among decided probes, the share with `A(p) = L(p)`. Target: at least 95%.
3. **Strict agreement (c).** Over all 256 probes, the share with `A(p) = L(p)`. An UNKNOWN answer always counts as a miss. This is the number that a deployment should not read as more than it is.
4. **False ABSENT (hard stop).** A probe with `L(p) = PRESENT` and `A(p) = ABSENT`. Any count above 0 stops the phase. This is counted over every probe, including those of expected-UNKNOWN packages.
5. **Wrong PRESENT (reported, not a stop).** A probe with `L(p) = ABSENT` and `A(p) = PRESENT`. It is reported with its count, and it does not stop the phase.
6. **Expected-UNKNOWN agreement (reported).** For each package whose expected status is `unknown`, whether the extractor returns UNKNOWN with the expected typed reason. A package that returns a complete contract is a deviation. It is listed by name. Its probes are still counted in 2 to 5.

Every number is reported per ecosystem and in total, and per hard case.

## Procedure

1. The labels file and this document are committed together, before the first extractor run.
2. The run uses the live path, with the artifacts downloaded and digest-verified as R-C-1 requires. Nothing is downloaded outside that path.
3. The runner writes its per-probe answers to a file. The labels are not read or changed during the run.
4. The owner reviews each absent name before the run. Once the run starts, nothing in the labels changes.
5. A false ABSENT is a stop. The phase does not continue until the cause is fixed in the spec or the code, and the run is repeated.

## What the numbers do not show

- They show agreement with 50 hand-labelled packages, not accuracy on the registry. The parity test shows the plumbing, not accuracy.
- Expected statuses are predictions from the package structure, as the labels say. A wrong expected status lowers coverage. It does not change the accuracy figures.
- Labels can be wrong. A wrong label on an absent name shows up as a wrong PRESENT. A wrong label on a present name shows up as a wrong ABSENT, which is a stop.
