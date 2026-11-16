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

Requirements: R-G-1 to R-G-10. Property: P-G-1.

- [x] 1.1 Write `.kiro/specs/seal-v2/` (requirements, design, properties, tasks) [R-G-1..R-G-10]
- [x] 1.2 `hooks/gate.py`: `decide`, messages [R-G-1..R-G-5, R-G-10]
- [x] 1.3 `hooks/on_install.py`: collect `Detected`, add `evaluate`, deadline, fail-closed paths [R-G-5..R-G-8]
- [x] 1.4 Property test P-G-1 in `src/tests/properties/test_p_g_1_hook.py`
- [x] 1.5 Update `src/tests/integration/test_hooks.py` for the verdict-aware behavior. Record each changed assertion and why in the PR
- [ ] 1.6 Update the hook `description` in both copies of `block-agent-installs.json` [R-G-9]
- [ ] 1.7 Update `docs/REFERENCE.md` [R-G-9]
- [ ] 1.8 CHANGELOG entry
- [ ] 1.9 Full checks and the offline demo. Open the PR. Stop for review

## Phase 2: Contract Check (R-C-*)

Requirements, design, and properties are written at the start of the phase, after the owner confirms the scope.

## Phase 3: not scheduled (R-S-*, signing)

Starts with ADR-0004 (Ed25519 behind the `slopseal[sign]` extra). The extra stays empty until the ADR is accepted.

## Phase 4: depth-1 transitive check (R-G-12). Not implemented

Ships R-G-12 and closes T16 when it is done. Starts with the requirement wording, the design section, and a property. Nothing in this phase is built yet, and no document may say T16 is closed before this phase ships.
