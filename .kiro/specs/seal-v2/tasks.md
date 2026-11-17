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
- [x] 2.7 Python export extraction [R-C-2]. Done: the worker's extract mode (`ast` only, never run); the completeness rules and the R-C-2 list; set A and set B; star imports one hop; RECORD and layout checks; the wheel choice; `sdist_only`; the canary; P-C-4 (with the `__all__` load cases); P-C-8 Q1. 2.6 rulings applied: `__all__` is read only as a plain or annotated literal assignment, and any other load gives `dynamic_exports` (ruling 6); a `global` statement gives `dynamic_exports` (ruling 2, stricter than the ruled wording); a `del` of a function local is not dynamic (only a module-level `del` is, as the spec says); compiled extensions give `dynamic_exports` for the whole artifact (ruling 1, recorded in `docs/CONTRACT_EVAL.md`); `from .x import y` is a recorded false-PRESENT risk (ruling 5); a name bound only in an `except ImportError:` branch is PRESENT, never ABSENT (ruling 8, tested). RECORD mismatches give `parse_error` (ruling 3). Run report: no wheel in the smoke test gave a RECORD mismatch. The 2.14 run lists every wheel that does. Mutants (all caught earlier): P-C-1 M1, P-C-8 M-Q1 (both forms), P-C-4 (a), (b), (c), (e), (f). Mutant M-ALL (the `__all__` load rule removed) is caught: 10 failures, including P-C-4 (d). Not done: `test_reason_sdist_only` and `test_reason_dynamic_exports` at verdict level.
- [x] 2.8 npm export extraction [R-C-3]. Done: the tokenizer (comments, strings, templates with substitutions, regular expressions, the slash rules, TokError for unfinished tokens), the accounted-for rule, Q2 to Q5, the entry points and conditions, literal subpaths, the declaration rules, one-hop star re-exports, the two-entry rule (as ruled, with the partial names of complete entry points). The stub is removed. Q1 has no JavaScript form (it is the Python rule). Mutants, all caught: M-Q2 (a non-literal `module.exports` read as complete) 2 failures; M-Q3 (`export =` ignored) 1; M-Q4 (`default` not added, three sites) 4; M-Q5 (bundler helpers not flagged) 1, from the P-C-8 helper-only forms; M-ACC (accounted-for rule removed) 10; M-TWO ("ABSENT if any complete entry lacks it") 1; M-DIV (every slash read as division) 3, the unit test for the regex-then-exports case is the one that fails; M-ALL (2.7) 10. Two live npm packages not in the labels, run through `LiveSource.contract()`: `ms@2.1.3` gives `dynamic_exports` (an extensionless entry), and `kleur@4.1.5` gives PARTIAL names from its complete ESM entry. Not done: the top-level this gap inside a block, recorded in `docs/CONTRACT_EVAL.md`.
- [ ] 2.9 Cache [R-C-6]
- [ ] 2.10 Contract Diff in the payload [R-C-7]
- [x] 2.11 Live wiring, the artifact download, and the contract cache [R-C-8]. Done: `contract()` on the source, the live download, digest verification, the archive check, the cache (wired in `runtime.py`, commit 3a285e8), and the extraction step. The extraction stub is removed: PyPI uses the R-C-2 extractor and npm the R-C-3 extractor. A grep for the stub's error text returns nothing in the repository. The two-entry partial and the escalated retry are in 2.12. Not done: `test_contract_plumbing_snapshot_parity` (2.9 hermetic parity).
- [ ] 2.12 Escalated retry returns BLOCK for UNKNOWN [R-C-9]
- [ ] 2.13 Property tests P-C-1 to P-C-8, and the mutant run for each. P-C-8 covers the completeness rule (Q1 to Q5); its six mutants are listed in properties.md. Record the result of every mutant
- Rulings recorded here. Decision 2 (escalated retry, R-C-9): confirmed. On UNKNOWN in `_escalated_again`, no escalation artifact, the state change (budget consumed) is kept, the audit entry carries the typed reason and the check name, and the BLOCK names the reason and a next step, with no artifact reference. Tests: UNKNOWN on retry gives exit 1, the typed reason, no artifact file, the consumed budget, and an audit entry with the reason.
- Rulings of the 2.6 report, status at 2.8: (1) compiled extensions give `dynamic_exports` for the whole artifact, recorded in `docs/CONTRACT_EVAL.md`, not narrowed. (2) The dynamic forms are confirmed, and the `global` rule is added to the spec (this build flags every `global`, which is stricter). Add to 2.14: a `global` rule and the dynamic forms are part of the 2.14 coverage count. (3) RECORD mismatches give `parse_error`. The 2.14 run lists every wheel that hits it. (5) `from .x import y` is a false-PRESENT risk, recorded. (6) `__all__` is read only as a literal assignment, and any other load is `dynamic_exports`. P-C-4 has the cases and mutant M-ALL. (7) The 10 s wall limit covers the archive check and the extraction together. Uncached latency measured: about 120 ms per artifact for the complete PyPI packages, with the cache hit under 1 ms. (8) `except ImportError` is PRESENT, never ABSENT, and tested. (9) Commit 81cb280 spans R-C-8, R-C-9, and R-C-5. It is accepted and noted. (4) Ecosystem enum: **not decided, asked.** The enum has five values, so the ruled condition does not hold.
- [ ] 2.14 Run the extractor once against the 50 labelled packages. Report coverage, decided accuracy, and strict agreement, per ecosystem and per hard case. List every false ABSENT. **A false ABSENT stops the phase.**
- [ ] 2.15 Docs: `docs/REFERENCE.md` "Full limitations", `docs/THREAT_MODEL.md` (T5, T17, T18, T23 from planned to implemented, the data-sent table, section 6), `CHANGELOG.md`, `.kiro/steering/structure.md`. Remove text that says live exports are always `None`
- [ ] 2.16 Full check list. Stop and report: the diff summary per requirement, the mutant results per property, the three accuracy numbers, and the output of the checks. No push.

## Phase 3: not scheduled (R-S-*, signing)

Starts with ADR-0004 (Ed25519 behind the `slopseal[sign]` extra). The extra stays empty until the ADR is accepted.

## Phase 4: depth-1 transitive check (R-G-12). Not implemented

Ships R-G-12 and closes T16 when it is done. Starts with the requirement wording, the design section, and a property. Nothing in this phase is built yet, and no document may say T16 is closed before this phase ships.
