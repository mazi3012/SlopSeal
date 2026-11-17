# SlopSeal Phase 6 (proposed): Enforced Installation Boundary

- Status: proposal. Nothing in this plan is approved for implementation yet, except the items you explicitly approve.
- Numbering: `docs/PLAN.md` already uses "Phase 5" for the hardening path, so this phase is labelled 6 here. Confirm the number before it enters `docs/PLAN.md`. Per `CONTRIBUTING.md`, a change to milestone dates goes to `PRD.md` first.
- Inputs: `reports/SlopSeal_PHASE4_SECURITY_AUDIT.md` (finding IDs F-01 to F-14, F-16 to F-21; there is no F-15), `reports/SlopSeal_PHASE4_REMEDIATION_PLAN.md` (decisions D1 to D6), and the gateway recommendation in this session.

## 1. Goal and the honest claim

Goal: a developer or agent cannot install a package that SlopSeal has not verified, whatever command form it uses.

Claim we may make after each exit gate:
- After gate A: "SlopSeal stops installs written in the recognised forms, and fails closed on forms it cannot read." This is not a complete control.
- After gate B: "Packages reach the agent sandbox only through the SlopSeal gateway, and the verifier's keys and state are outside the agent's reach." This is the first claim of enforcement.
- After gate C: "Transitive dependencies are verified too." Until then, T16 in `docs/THREAT_MODEL.md` stays open.

No document may use "complete protection" before gate B passes.

## 2. Rules for every item (repo rules)

1. Spec first: add or find the `R-` ID in `.kiro/specs/seal-v2/requirements.md`. Add the property in `properties.md` when an invariant changes.
2. One finding per branch, branched from `main` (`fix/<short-name>`). One finding per commit where possible. Conventional commit with the requirement ID.
3. Each fix removes the strict xfail marker for its finding in the same commit. No marker is removed before its fix lands, and no test is deleted, skipped, or loosened.
4. No policy value is weakened. Policy floors are checked, not changed, unless the owner approves a change.
5. `ruff check .`, `ruff format --check .`, `mypy src/slopseal`, and `pytest` pass before a PR. The property suite runs in CI with Hypothesis installed.
6. Any change that turns an unknown or error state into ALLOW is rejected (fail closed).

## 3. Gate A: hardening inside the repo

No infrastructure needed. Each item is independently reviewable.

| Order | Finding | Work | Requirement (to add) | Expected-failure tests converted |
|---|---|---|---|---|
| A1 | F-01 | Deny by default in `hooks/on_install.py`: installer names anywhere in argv, `eval`, substitutions in command position, `sh <file>`, `python -c`, `node -e`, registry URLs in `curl`/`wget`. Keep a short list of non-install forms (`pip list`, `pip --version`, `npm run`, `npm test`). | R-G-13 | 12 `test_f01_*` cases |
| A2 | F-02 Part A | The hook loads the quarantine store and refuses an OPEN or ESCALATED quarantine for the same ecosystem, name and version. Allows APPROVED or ALLOWED for that exact version. | R-G-14 | `test_f02_hook_respects_open_quarantine` |
| A3 | F-11 | Call `enforce_floors` in `runtime.build_context`. Raise `PolicyError` on any violation. Add floors for `levels.install_scripts` and `levels.license` (must stay `block`) and a rate-limit ceiling (decision D6). | R-1.4 (floors) | `test_f11_*` (2 cases) |
| A4 | F-03 | Seal the full canonical record (including `seq`, `prev_hash`, and every content field). Version the format. Old logs read as "legacy, unsealed". | R-5.7.2 | `test_f03_*` (2 cases) |
| A5 | F-04 | Write a head checkpoint after each append. Verify it. Document that an agent with write access can delete both (gate B fixes this). | R-5.7.1 | `test_f04_truncation_is_detected` |
| A6 | F-05 | Catch `RecursionError` in `mcp/server.Server.handle` and return −32700. | R-1.8 | `test_f05_*` |
| A7 | F-06 | Map `OSError` in `verify_with_runtime` to `NoVerdict`. Decide and document what an unexpected error in `serve` does (end the process, or answer that message with an error). | R-1.8 | `test_f06_*` |
| A8 | F-10 | Save the hook credit before recording ALLOW. If the save fails, record BLOCK. | R-G-11 | `test_f10_*` |
| A9 | F-09 | Append an `error` audit event on the `internal_error` path, and log MCP no-verdict results. | R-5.7.1 | `test_f09_*` |
| A10 | F-08 | Record wall-clock time in `ts` and in the seal. Keep the snapshot clock for checks, and store `snapshot_as_of` separately. | R-P-2 | `test_f08_*` |
| A11 | F-12 | Remove `SLOPSEAL_POLICY_PATH` and `SLOPSEAL_SNAPSHOT_DIR` from `power-upload/mcp.json`. Keep `test_policy_drift.py` green. | R-1.9 | `test_f12_*` |
| A12 | F-07 | Counting rule (decision D4). The message part is done in the messaging branch (`feat/hook-messaging`). | R-4.7, R-G-11 | `test_f07_*` (after PR #30 merges) |
| A13 | F-19, F-20 | Add a `version_exists` check. Log the normalized package name too. | R-2.1, R-5.7.1 | new tests |

Exit gate A: all A items merged. The 25 expected-failure instances that map to A1 to A12 are converted. The threat model says the hook is not a complete control, in plain words.

## 4. Gate B: the real boundary (needs decisions D1 to D3)

This gate needs infrastructure outside this repository, and an ADR before code (`docs/adr/0004-verifying-package-gateway.md`).

| Step | Work | Closes |
|---|---|---|
| B1 | ADR 0004: gateway design, threat model, dependency choices (stdlib first; each dependency needs its own ADR). | design record |
| B2 | Gateway service: proxies the PyPI simple index and the npm registry. Calls the existing `verify_install`. Serves a package only on ALLOW for that exact name, version, and artifact hash. Refuses BLOCK, QUARANTINE, and RATE_LIMITED. Rate limit counts per session token. | F-01 (completeness), F-14 (index redirection), F-13 (package.json installs) |
| B3 | Egress allow-list for the agent sandbox: only the gateway host. Confirm with `pip download` and `npm view` that direct registry access fails. (Kiro documentation says Web sandboxes support a custom allow-list. The enforcement strength is unconfirmed, so test it.) | direct registry bypass |
| B4 | Move `secret.key`, `audit.jsonl`, `ratelimit.json`, quarantine store, and the policy pin out of the workspace (D2). The agent sandbox cannot read them. The gateway holds them. | F-16, F-11 pin, F-03/F-04 trust |
| B5 | Approvals signed with Ed25519 by a key only humans hold (D3). The gateway verifies the signature. Replaces unauthenticated `slopseal escalate`. | F-02 Part B |

Exit gate B: from the agent sandbox, a direct `pip install` and a direct `npm install` of a package that verifies as ALLOW both fail at the network layer. Only gateway-served packages install. The gateway, not the agent, holds the key. Tests: the gateway has integration tests with a mocked registry, and an egress test that runs in the sandbox.

Cost to plan for: the gateway is critical infrastructure. If it goes down, nobody can install. It needs its own threat model and an availability target.

## 5. Gate C: verification depth

| Step | Work | Closes |
|---|---|---|
| C1 | Lockfile and hash pinning: `npm ci` and `pip --require-hashes` through the gateway. | F-13 (completeness) |
| C2 | Index and registry configuration refused or pinned by the gateway (`PIP_INDEX_URL`, `npm_config_registry`, `.npmrc`, `pip.conf`). | F-14 (config part) |
| C3 | R-G-12: depth-1 transitive verification at the gateway, with the same L1 checks. Then decide on deeper resolution. | F-14 (transitive), T16 |
| C4 | Live advisory parsing from CVSS vectors. | F-18 |

Exit gate C: T16 in the threat model is closed for depth 1, and the claim is updated to say what depth is covered.

## 6. Gate D: assurance

- External append-only audit store, so truncation and deletion of the whole log are detectable (completes F-04).
- Property suite (Hypothesis) runs in CI on every PR that touches policy, hook, or audit code.
- Red-team corpus: a list of bypass attempts kept as regression tests. Each new bypass found in review is added before its fix.
- Threat model review by a second person (CODEOWNERS for `src/slopseal/hooks`, `src/slopseal/audit`, `src/slopseal/policy`, and `src/slopseal/fixtures`).

## 7. Decisions needed before gate B

| ID | Decision | Recommendation |
|---|---|---|
| D1 | Allow direct registry access from the agent sandbox? | No. Gateway host only. |
| D2 | Where do the key and the state live? | In the gateway. The workspace holds no secret. |
| D3 | Who approves a quarantine, and how? | Ed25519 signature by a human-held key. |
| D4 | Count an MCP verify plus the following install once or twice? | Once, per package and version, keyed to the session. This is a security trade-off, so the owner decides. |
| D5 | npm with `package.json` in scope? | Handled by the gateway (it sees the whole tree). The hook-side rule (refuse) is only a stopgap. |
| D6 | Policy floors for `levels.*` and the rate-limit ceiling | Install scripts, malware, and critical/high CVEs stay fixed at block. Rate limit ceiling 30 per minute. |

## 8. Order and dependencies

```
Gate A (A1..A13)  ── no infrastructure ── start now after approval
   A3 and A4 are needed before any claim in gate B about the audit
Gate B ── needs D1, D2, D3 and ADR 0004
   B4 ── needed for B5 and for the F-03/F-04 trust claim
Gate C ── needs B2 (the gateway) for C1 and C2
Gate D ── after C
```

## 9. What this phase does not do

- It does not make the Kiro hook the enforcement point. The hook stays an early warning.
- It does not claim protection against a user with root on the machine or with the signing key.
- It does not rely on Kiro "Approve for me", which is a model judgement, not a deterministic check.
- It does not change any policy value without owner approval.

## 10. What I need from you

1. Confirm the phase number (6, or another).
2. Approve gate A, or name the items to start with. A1 (F-01) and A2 (F-02 Part A) are the first two I would start.
3. Decide D1 to D3 before gate B.
