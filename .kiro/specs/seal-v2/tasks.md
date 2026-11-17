# SlopSeal v2: Tasks

Rules for every phase (from the session brief):

- One phase per branch, named `feat/v2-<phase>`. Commits cite requirement ids.
- The spec for a phase lands before its code.
- No new dependency without an ADR in `docs/adr/` and a reason in the PR. Stdlib first.
- No policy floor is loosened. No threshold is changed to make a test pass. No existing fixture label is changed.
- Every new invariant gets a property test.
- Before each commit: `ruff check . && ruff format --check . && mypy src/slopseal && pytest -q`, and `bash scripts/demo.sh` must end `demo: PASS`.
- Stop after each phase and wait for the owner's review.

## Phase 1: verdict-aware install hook (`feat/v2-hook`)

Requirements: R-G-1 to R-G-11. Properties: P-G-1 to P-G-3. Shipped in PR #28. R-G-12 is Phase 4.

- [x] 1.1 Write `.kiro/specs/seal-v2/` (requirements, design, properties, tasks) [R-G-1..R-G-10]
- [x] 1.2 `hooks/gate.py`: `decide`, messages [R-G-1..R-G-5, R-G-10]
- [x] 1.3 `hooks/on_install.py`: collect `Detected`, add `evaluate`, deadline, fail-closed paths [R-G-5..R-G-8]
- [x] 1.4 Property test P-G-1 in `src/tests/properties/test_p_g_1_hook.py`
- [x] 1.5 Update `src/tests/integration/test_hooks.py` for the verdict-aware behavior. Record each changed assertion and why in the PR
- [x] 1.6 Update the hook `description` in both copies of `block-agent-installs.json` [R-G-9]
- [x] 1.7 Update `docs/REFERENCE.md` [R-G-9]
- [x] 1.8 CHANGELOG entry
- [x] 1.9 Full checks and the offline demo. Open the PR. Stop for review

## Phase 2: Contract Check (`feat/v2-contract`)

Requirements: R-C-1 to R-C-9. Properties: P-C-1 to P-C-7. Threats: T17, T18, T23, T5 note. Design: section 2.

Rules specific to this phase (from the session brief):

- Branch from `main`. Standard library only: `zipfile`, `tarfile`, `ast`, `json`, `hashlib`, `resource`, `subprocess`. If a dependency seems needed, stop and ask.
- Static analysis only. Never import, exec, or run code from an artifact, and never run an install script.
- Never loosen a policy floor. Never change a threshold, a fixture label, or the expected verdict of an existing test. If an existing test pins old behavior, stop and report it.
- One commit per requirement. The message cites the ID, for example `feat(contract): wheel export extraction [R-C-2]`.
- Run each check on its own: `ruff check .`, `ruff format --check .`, `mypy src/slopseal`, `pytest -q`, `bash scripts/demo.sh` (must end `demo: PASS (all beats)`), `bash scripts/check_credentials.sh`.
- Do not push and do not open a PR until the owner says so. Stop after each step marked STOP.

Order of work:

- [x] 2.1 Spec: requirements R-C-1 to R-C-9, design section 2, properties P-C-1 to P-C-7, threats T17, T18, T23 and the T5 note. **STOP for review.**
- [ ] 2.2 Draft the labels, `docs/contract_labels.json`, and the metric definitions, `docs/CONTRACT_EVAL.md`. 25 PyPI and 25 npm packages. The labels come from each package's official docs and public API, and never from extractor output. Each package pins an exact version, the artifact file name, and the artifact digest from the registry metadata. Each absent name is a plausible hallucination an agent might write. The hard cases are included: a literal `__all__`, a module `__getattr__` (expected UNKNOWN), re-export-heavy packages, a `.d.ts`-only npm package, CommonJS, and ESM `exports` maps. The expected extraction status is recorded for each. **The extractor is not run in this step.** **STOP: the owner reviews every absent label.**
- [ ] 2.3 Commit the labels and the metric definitions together, in their own commit, before the first extractor run. They do not change after any result is seen.
- [~] 2.4 Types, `UnknownReason`, `check_contract`, and the verdict wiring for UNKNOWN and digest mismatch, with tests that use fake sources [R-C-5]. Includes the seven `test_reason_*` tests (properties.md, typed-reason table). Done: types, limits, `check_contract`, `unknown_block`, `mismatch_block`, offline contract, R-C-9. Not done: verdict wiring of the live contract (decision pending), `test_reason_sdist_only`, `test_reason_dynamic_exports`, `test_reason_parse_error`, `test_reason_not_in_snapshot` at verdict level
- [ ] 2.5 Digest parsing and verification (PyPI hex, npm SRI) [R-C-1]
- [ ] 2.6 Archive safety, limits, and the worker subprocess [R-C-4]
- [~] 2.7 Python export extraction [R-C-2]. Done: the worker's extract mode (`ast` only, never run), completeness rules Q1 and the R-C-2 list, set A and set B, star imports one hop, RECORD and layout checks, wheel choice (`none-any` first, else ascending), `sdist_only`, the canary (P-C-1), P-C-4, and P-C-8 Q1. Mutants (all caught): P-C-1 M1 executes each module; P-C-8 M-Q1 skips the reference check (both forms, and each form alone); P-C-4 (a) computed `__all__` read as empty, (b) module `__getattr__` ignored, (c) star import dropped, (e) set B dropped, (f) underscore `__all__` names dropped. Not done: P-C-8 M-Q4 (the `default` name) is a JavaScript rule with no Python form; it runs with 2.8. Not done: `test_reason_sdist_only` and `test_reason_dynamic_exports` at verdict level
- [ ] 2.8 npm export extraction [R-C-3]
- [ ] 2.9 Cache [R-C-6]
- [ ] 2.10 Contract Diff in the payload [R-C-7]
- [ ] 2.11 Live wiring, the artifact download, and `test_contract_plumbing_snapshot_parity` [R-C-8]. Decision 1 is option (a): `contract()` on the source, the live download and cache now, the extraction step is the R-C-2 extractor for PyPI and a stub for npm that returns `ContractUnknown(PARSE_ERROR, "extractor not implemented")`. **MERGE BLOCKER: remove the npm stub** in the commit that lands the R-C-3 extractor. `grep "extractor not implemented"` must return nothing before any pull request is opened.
- [ ] 2.12 Escalated retry returns BLOCK for UNKNOWN [R-C-9]
- [ ] 2.13 Property tests P-C-1 to P-C-8, and the mutant run for each. P-C-8 covers the completeness rule (Q1 to Q5); its six mutants are listed in properties.md. Record the result of every mutant
- Rulings recorded here. Decision 2 (escalated retry, R-C-9): confirmed. On UNKNOWN in `_escalated_again`, no escalation artifact, the state change (budget consumed) is kept, the audit entry carries the typed reason and the check name, and the BLOCK names the reason and a next step, with no artifact reference. Tests: UNKNOWN on retry gives exit 1, the typed reason, no artifact file, the consumed budget, and an audit entry with the reason.
- [ ] 2.14 Run the extractor once against the 50 labelled packages. Report coverage, decided accuracy, and strict agreement, per ecosystem and per hard case. List every false ABSENT. **A false ABSENT stops the phase.**
- [ ] 2.15 Docs: `docs/REFERENCE.md` "Full limitations", `docs/THREAT_MODEL.md` (T5, T17, T18, T23 from planned to implemented, the data-sent table, section 6), `CHANGELOG.md`, `.kiro/steering/structure.md`. Remove text that says live exports are always `None`
- [ ] 2.16 Full check list. Stop and report: the diff summary per requirement, the mutant results per property, the three accuracy numbers, and the output of the checks. No push.

## Phase 3: not scheduled (R-S-*, signing)

Starts with ADR-0004 (Ed25519 behind the `slopseal[sign]` extra). The extra stays empty until the ADR is accepted.

## Phase 4: depth-1 transitive check (R-G-12). Not implemented

Ships R-G-12 and closes T16 when it is done. Starts with the requirement wording, the design section, and a property. Nothing in this phase is built yet, and no document may say T16 is closed before this phase ships.
