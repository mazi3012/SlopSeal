# SlopSeal v2-complete: Tasks

Goal: see `requirements.md`. Observation and ADR: `reports/SlopSeal_V2_COMPLETE_OBSERVATION.md`, `docs/adr/0006-mcp-lifecycle-binding-and-two-tiers.md`.

Rules for every task (from `CONTRIBUTING.md`, `AGENTS.md`, and the Phase 6 plan):

- One task per branch, from `main`, named `feat/v2c-<name>` (or `fix/` or `docs/`). Commits cite requirement ids.
- The spec for a task lands before its code. A new requirement id is added to `requirements.md` first.
- Before each commit: `ruff check . && ruff format --check . && mypy src/slopseal && pytest -q`, `bash scripts/demo.sh` must end `demo: PASS (all beats)`, and `bash scripts/check_credentials.sh` passes.
- A fix removes the strict-xfail marker for its finding in the same commit. No marker is removed early. No test is deleted, skipped, or loosened.
- No policy floor is loosened and no threshold is changed to pass a test. No new dependency without an ADR. Stdlib first.
- A task marked **STOP** waits for the owner's review before the next one starts.
- Never claim a status above what the preflight reports (R-ST-2).

Status marks: `[ ]` not started, `[~]` in progress, `[x]` done. Size: S under half a day, M about a day, L several days.

## Acceptance scenarios (the v2-complete exit)

| ID | Scenario | Tier | Needs |
|---|---|---|---|
| S1 | Fresh workspace. Add one entry and connect. The managed hook appears. The first result starts with the status line and the setup sentence. | 0 | V2C-1, V2C-3 |
| S2 | `pip install flsk==1.0.0` is blocked with a reason and a next step. `pip install requests==<pinned>` is allowed (live default). | 0 | V2C-1 |
| S3 | Skip setup. Balanced applies with no further input, and no offer repeats. | 0 | V2C-3 |
| S4 | Choose Strict. A package that warned under Balanced now blocks. | 0 | V2C-3 |
| S5 | The agent asks to loosen a setting. It is refused with the human route named, and the refusal is in the audit log. | 0 | V2C-3 |
| S6 | Delete the entry. The next shell command runs with no SlopSeal output, and the managed hook file is gone. | 0 | V2C-1 |
| S7 | Add the entry back. The hook returns. | 0 | V2C-1 |
| S8 | With the service entry and the platform egress rule: `curl` to PyPI and npm from the agent shell fails. `pip install` of an ALLOW package works through the gateway. A BLOCK package gets no bytes. The status says ENFORCED only after the probes pass. | 1 | V2C-4 |

S1 to S7 run as an integration test on a fake workspace tree and as one manual run on Kiro Web. S8 runs on a real Web workspace with the platform rule set by the owner.

## Phase V2C-0: decisions and probes

Docs and measurements only. No product code.

- [ ] 0.1 Merge this spec (PR). **STOP.** Owner reviews the spec and ADR 0006.
- [ ] 0.2 Owner decides D-V2C-1 to D-V2C-8 and D1 to D3, and records each in this file under "Rulings". **STOP.** (S)
- [ ] 0.3 Probes on real surfaces, recorded in `reports/SlopSeal_V2C_PROBE_RESULTS.md` as PASS, FAIL, or NOT RUN (observation section 6). Web probes run in a session. IDE and CLI probes need the owner and follow protocol H1 to M3 of the native investigation. (M)
- [ ] 0.4 Decide the fate of PR #32: rebase onto `main`, or close and re-cut the gateway in V2C-4. (S)

Exit: rulings recorded, probe table filled, no NOT RUN left for Web probes 1 to 5.

## Phase V2C-1: auto-plug (R-AP, R-LV)

Closes issues #50, #55, #56, #57. Scenarios S1 (partly), S2, S6, S7.

- [ ] 1.1 Managed hook marker and atomic refresh (R-AP-2). Property P-V2C-2. Remove the duplicated hook copy rule of issue #56. (M)
- [ ] 1.2 Launcher: `plugged_state` and the exit rules (R-AP-3 to R-AP-6). Property P-V2C-1 with its four mutants. Stdlib only. (M)
- [ ] 1.3 Wire the launcher into the packaged hook and `bootstrap_install_hook`. Decide inline or sibling file (D-V2C-8) by a test that runs a 3 KB command through the hook runner. Integration test for S6 and S7 on a fake workspace. Property P-V2C-5. (M)
- [ ] 1.4 Live mode as the default, fixture guard, and `as_of` rule (R-LV-1 to R-LV-4). Property P-V2C-8. Regenerating the fixtures needs the owner's approval. **STOP.** (L)
- [ ] 1.5 Pinned entry, release checklist "gate pin", README "one entry" install section, privacy line (R-AP-1, R-LV-1). (S)
- [ ] 1.6 First status line in the first result for Tier 0 (R-AP-9, R-ST-1). (S)

Exit: S2, S6, S7 pass in the integration test. All checks and the demo pass. **STOP.**

## Phase V2C-2: hardening (Phase 6 gate A)

Required before any claim stronger than "advisory" (R-HD-1). Details and finding mapping are in `reports/SlopSeal_PHASE6_SECURITY_PLAN.md`, section 3. Each item is its own task, spec first.

- [ ] 2.1 A1, F-01: deny-by-default hook. Adds `R-G-13`. Starts after 1.3, because both touch the hook entry. (L)
- [ ] 2.2 A2, F-02 part A: the hook honors an open quarantine. Adds `R-G-14`. (M)
- [ ] 2.3 A3, F-11: `enforce_floors` called in `runtime.build_context`, plus floors for `levels.install_scripts`, `levels.license`, and the rate-limit ceiling (decision D6). (M)
- [ ] 2.4 A4 and A5, F-03 and F-04: sealed full record, head checkpoint. (M)
- [ ] 2.5 A6 and A7, F-05 and F-06: MCP server survives deep JSON and state errors. (S)
- [ ] 2.6 A8 to A11, F-10, F-09, F-08, F-12: audit and config fixes. F-12 is largely closed by the entry in 1.5. (M)
- [ ] 2.7 A13, F-19 and F-20: version-exists check and normalized names. (S)

Exit: eleven strict-xfail markers gone (F-01 to F-06, F-08 to F-12), gate A items merged, status line may drop "advisory" for the forms the hook now reads. F-13 (package.json installs), F-14 (index redirection and transitive dependencies), and F-16 (key and state readable) are not fixed in Tier 0. Tier 1 closes F-13, F-14 at the index level, and F-16 (V2C-4.3, 4.6). Depth-1 transitive checks are listed under "Later". **STOP.**

## Phase V2C-3: settings (R-SET)

Scenarios S1 (completes), S3, S4, S5. Starts after 1.6. Can run beside V2C-2.

- [ ] 3.1 Settings model, overlay, sealed store, floors integration (R-SET-5, R-SET-10, R-SET-11). Property P-V2C-3 parts (c) and (d). (M)
- [ ] 3.2 `slopseal_settings` tool, channel rule, no-off rule, audit (R-SET-1, R-SET-6 to R-SET-8). Properties P-V2C-3 and P-V2C-7 with mutants. (L)
- [ ] 3.3 MCP prompt `slopseal-setup`, read the client's `elicitation` capability, form with chat fallback (R-SET-2, R-SET-3). Declare `prompts` capability. Test against a fake client with and without the capability. (L)
- [ ] 3.4 First-run offer and skip (R-SET-3, R-SET-4). Property P-V2C-4. (M)
- [ ] 3.5 Human channel: `slopseal settings` and `slopseal purge` commands (R-SET-6, R-AP-8). (M)
- [ ] 3.6 Docs: setup text, `autoApprove` guidance (R-SET-9), what the agent can still edit in Tier 0. (S)

Exit: S3, S4, S5 pass. Status line names the setup state. **STOP.**

## Phase V2C-4: Tier 1 boundary (R-NB)

Needs the rulings on D1 to D3 and D-V2C-1, and Phase V2C-2 merged. Scenario S8. Builds on the D2 design and ADR 0004.

- [ ] 4.1 ADR 0004 accepted after review. Gateway code re-based or re-cut per 0.4. (M)
- [ ] 4.2 Live upstream adapter: artifact URL and published digest for PyPI and npm. (M)
- [ ] 4.3 Index protocol: pip simple API and npm registry JSON (R-NB-4, closes R-GW-6). (L)
- [ ] 4.4 Sessions and one-use grants (R-NB-3), property P-V2C-9, AC-32 to AC-34. (L)
- [ ] 4.5 Remote MCP transport and service packaging, health check (R-NB-1, R-NB-7). ADR if a dependency is needed. (L)
- [ ] 4.6 State in the service only (R-NB-2). The workspace holds no secret. (L)
- [ ] 4.7 Signed approvals with the Ed25519 verifier (R-NB-6). (M)
- [ ] 4.8 Probe harness (issue #39), preflight wiring, status from probes (R-NB-5, R-NB-8). Property P-V2C-6. (L)
- [ ] 4.9 Platform step and its guided setup text. **STOP:** the owner sets the egress allow-list, then S8 runs on a real Web workspace and the results go in `reports/`. (M)

Exit: S8 passes on a real workspace. ENFORCED appears only with fresh PASS probes. **STOP.**

## Phase V2C-5: release and assurance

- [ ] 5.1 Wording test for the status lines and docs at each tier (R-ST-2). (S)
- [ ] 5.2 Docs sweep: README, `docs/REFERENCE.md`, `docs/THREAT_MODEL.md` (T11, T16 note, new rows from design section 6), `power-upload/POWER.md`, CHANGELOG. (M)
- [ ] 5.3 Red-team corpus: each F-01 form as a regression test. (M)
- [ ] 5.4 Full check list, demo, and one manual run of S1 to S7 on Kiro Web. Tag `v2.0.0` after review. **STOP.** (M)

Later, not in v2-complete: depth-1 transitive check (R-G-12, T16), lockfile and `--require-hashes` through the gateway, external append-only audit store, Windows, other ecosystems, L2.

## Rulings

None yet. Record each owner decision here with its date.
