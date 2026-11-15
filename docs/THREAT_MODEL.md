# SlopSeal Threat Model

Status: v1 draft. Update it when a new external call, dependency, or trust boundary is added (see `.kiro/steering/structure.md`).

## 1. What is protected

| Asset | Why it matters |
|-------|----------------|
| The decision (ALLOW, BLOCK, QUARANTINE) | If it can be forced to ALLOW, the tool has failed at its one job |
| The policy (`dependency-trust.md`) | Defines what is blocked. Weakening it silently is failure class P3 |
| The snapshot | Source of truth in offline mode and for the demo |
| The audit log and seals | Evidence of what was decided and under which policy |
| The signing key | Lets an attacker forge seals and snapshots |
| The developer's machine | The thing an installed malicious package would attack |

## 2. Actors

| Actor | Capability assumed |
|-------|--------------------|
| **Package attacker** | Registers names on PyPI or npm, writes metadata and README text, publishes versions. No access to the developer's machine |
| **Compromised or careless agent** | Runs shell commands, edits repository files including the policy, writes intent declarations. Not trusted |
| **Network attacker** | Can alter or block traffic to registries and OSV (live mode only) |
| **Local tamperer** | Can edit files on disk: policy, snapshot, log, state. Does not hold the signing key |
| **Maintainer** | Trusted. Holds the signing key |

Out of scope: an attacker who already has the signing key, root on the machine, or control of the user's shell startup files.

## 3. Trust boundaries

1. Registry and OSV responses are **untrusted input**. In offline mode they are replaced by the signed snapshot.
2. Package metadata (name, description, README, install scripts) is **untrusted input**, including anything passed to L2.
3. The intent declaration is **untrusted input** written by the agent.
4. The policy file is **trusted only after the property suite passes** on it.
5. The snapshot is **trusted only after signature and hash verification**.

## 4. Threats and mitigations

| ID | Threat | Mitigation | Requirement or property |
|----|--------|------------|-------------------------|
| T1 | Slopsquatted package name is installed | Existence, typosquat, slopsquat signature, and age checks | R-2.1..2.4 |
| T2 | Near-miss name of a popular package | Near-name WARN, typosquat HARD_BLOCK on new packages | R-2.2, R-2.11 |
| T3 | Known-vulnerable or known-malicious version | OSV advisory and malware lookups | R-2.6, R-2.7 |
| T4 | Registry or OSV is down, slow, or returns partial data | Unknown is an explicit value; unknown means BLOCK | R-P-1, P-FC-2 |
| T5 | Network attacker alters registry responses | Offline signed snapshot; live mode is documented as lower assurance | R-P-2 |
| T6 | Agent weakens the policy to let an install through | Property suite on every policy change; pre-commit rejects failure; policy hash in every seal | R-PBT-2, P-FC-8 |
| T7 | Agent tunes its intent to pass the API check | Check compares to the package's own exports; every retry intent is logged; escalation shows the diff | R-Q-1, design section 9 |
| T8 | Prompt injection through package description or README into L2 | L2 gets data fields only, is advisory, can only move ALLOW to QUARANTINE | R-3.7, P-FC-5 |
| T9 | Snapshot is tampered with | Signature over manifest and per-file hashes | R-P-2, P-SN-1 |
| T10 | Audit log is edited or truncated | Hash chain across lines; seals signed | R-5.7.1, R-5.7.2, P-AU-1, P-AU-2 |
| T11 | Install bypasses the shim | Shim is advisory by design; the Kiro hook and agent steering add a second trigger. Documented limit | R-1.1 |
| T12 | Quarantine retry used to probe the check repeatedly | Retry budget 1, then escalation; rate limit on installs per minute | R-Q-5, R-Q-6, R-4.7 |
| T13 | Unexpected crash returns success | Failclosed wrapper turns any exception into BLOCK | design section 6 |
| T14 | `--allow-unsafe` used silently | Requires a non-empty reason and writes an audit line before proceeding | R-1.5 |
| T15 | Secrets leak through logs or output | No env dumps; exception detail goes to the log only; stdout is the payload only | tech.md conventions |

## 5. Data that leaves the machine (live mode)

This answers Open Decision 9. Offline mode sends nothing.

| Destination | What is sent | What is not sent |
|-------------|--------------|------------------|
| PyPI, npm (registry metadata) | Ecosystem, package name, version | Intent, project path, environment, other packages |
| OSV.dev | Ecosystem, package name, version | Intent, project path, environment, other packages |
| L2 backend `needle` (default) | Nothing leaves the machine | |
| L2 backend `ollama` | Intent and package metadata to the local Ollama host | |
| L2 backend `openai` or `anthropic` | Intent and package metadata to that provider | Off by default. Choosing it is an explicit policy edit |

Each request reveals that the developer is considering a given package. That is inherent to checking it.

## 6. Accepted limits for v1

- **Seals and snapshot signatures are symmetric (HMAC-SHA256).** Anyone who can verify a seal or snapshot can also forge one. A verifier must therefore be a trusted holder of the key. Third parties cannot independently verify a SlopSeal verdict in v1. Public verifiability (Ed25519) is a roadmap item. This weakens the "signed receipt" claim for outside auditors and is stated in the write-up. Key compromise lets an attacker rewrite history undetected, which is why key storage is part of Open Decision 6.

- The shim can be bypassed by calling the real binary by absolute path. It protects agents and developers who go through PATH, and the Kiro hook covers agent shell calls. It does not stop a determined local user.
- Live mode trusts TLS to the registry and OSV. Only offline mode gives signed inputs.
- The deterministic intent check proves the declared API exists. It does not prove the package fits the task. Only L2 addresses purpose, and it is gated.
- A new malicious package with a unique name, no typosquat distance, and clean metadata can pass L1. Age and install-script checks reduce this risk and do not remove it.
- Seven ecosystems are named in scope. Only pip and npm are covered by the fixture corpus and the demo.

## 7. Open items

| Item | Owner decision | Due |
|------|----------------|-----|
| Signing algorithm, key location, and who signs | Open Decision 6 | End of Phase 2 |
| Quarantine time bound and install rate limit | Open Decision 7 | M2 |
