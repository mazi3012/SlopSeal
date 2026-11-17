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

1. Registry and OSV responses are **untrusted input**. In offline mode they are replaced by the checksummed snapshot.
2. Package metadata (name, description, README, install scripts) is **untrusted input**, including anything passed to L2.
3. The intent declaration is **untrusted input** written by the agent.
4. The policy file is **trusted only after the property suite passes** on it.
5. The snapshot is **trusted only after its checksums match `manifest.json`**.

## 4. Threats and mitigations

| ID | Threat | Mitigation | Requirement or property |
|----|--------|------------|-------------------------|
| T1 | Slopsquatted package name is installed | Existence, typosquat, slopsquat signature, and age checks | R-2.1..2.4 |
| T2 | Near-miss name of a popular package | Near-name WARN, typosquat HARD_BLOCK on new packages | R-2.2, R-2.11 |
| T3 | Known-vulnerable or known-malicious version | OSV advisory and malware lookups | R-2.6, R-2.7 |
| T4 | Registry or OSV is down, slow, or returns partial data | Unknown is an explicit value; unknown means BLOCK | R-P-1, P-FC-2 |
| T5 | Network attacker alters registry responses | Offline checksummed snapshot is the default. Live mode (R-P-3) treats every failed, malformed, or partial response as unknown, and a check given unknown blocks. Live mode is lower assurance: responses are not verified. In live mode only, PyPI and npm do not publish maintainer account age, so the maintainer check returns WARN, not BLOCK. Existence, typosquat, slopsquat, CVE/OSV, malware, and install-script checks stay fail-closed. Offline mode is unchanged: unknown maintainer data still blocks. Planned (Phase 2, not implemented): the Contract Check verifies an artifact against the digest the registry published. That digest arrives in the same TLS response as the rest of the metadata, so it catches a corrupted download or an artifact swapped after the metadata was published. It does not defend against an attacker who controls the response, because that attacker can supply a matching digest and artifact (see T23). | R-P-2, R-P-3, R-2.10, R-C-1 |
| T6 | Agent weakens the policy to let an install through | Property suite on every policy change; pre-commit rejects failure; policy hash in every seal | R-PBT-2, P-FC-8 |
| T7 | Agent tunes its intent to pass the API check | Check compares to the package's own exports; every retry intent is logged; escalation shows the diff | R-Q-1, design section 9 |
| T8 | Prompt injection through package description or README into L2 | L2 gets data fields only, is advisory, can only move ALLOW to QUARANTINE | R-3.7, P-FC-5 |
| T9 | Snapshot is tampered with | Static SHA-256 checksum manifest checked at load. Detects corruption and accidental edits only; a repo writer can change data and manifest together (see section 6) | R-P-2, P-SN-1 |
| T10 | Audit log is edited or truncated | Hash chain across lines; seals signed | R-5.7.1, R-5.7.2, P-AU-1, P-AU-2 |
| T11 | Install bypasses the shim | The shim covers `pip`, `npm`, and `npx`. `npx`, `npm exec`, `npm x`, and `npm init <initializer>` must name an exact `name@x.y.z`, or they are refused (R-1.6). The shim is advisory: a call to the real binary by absolute path, or to a tool not shimmed, bypasses it. The Kiro hook (`block-agent-installs.json`) is a second trigger. It detects agent install commands for pip, pipx, uv, uvx, poetry, pdm, conda, mamba, easy_install, npm, npx, pnpm, yarn, cargo, gem, and `go get`/`go install`, including after `sudo`, `env`, `VAR=val`, `bash -c`, and command chains. It verifies pinned pip and npm installs with the same pipeline as the shim (R-G-1), and it blocks every other install with a fix (R-G-5). Out of scope: a script file or `python -c` that runs an install, and `curl \| sh`. Documented limit | R-1.1, R-1.6 |
| T12 | Quarantine retry used to probe the check repeatedly | Retry budget 1, then escalation; rate limit on installs per minute | R-Q-5, R-Q-6, R-4.7 |
| T13 | Unexpected crash returns success | Failclosed wrapper turns any exception into BLOCK | design section 6 |
| T14 | `--allow-unsafe` used silently | Requires a non-empty reason and writes an audit line before proceeding | R-1.5 |
| T15 | Secrets leak through logs or output | No env dumps; exception detail goes to the log only; stdout is the payload only | tech.md conventions |
| T16 | A dependency pulled in by an allowed package is installed unverified | Not mitigated in v1. The shim verifies only the packages named on the command line, not their transitive dependencies, and their install-time code is not checked. The hook does the same. A one-level-deep dependency check is planned as R-G-12 in seal-v2 Phase 4. It is not implemented, and T16 stays open until it ships | R-G-12 (not implemented, Phase 4) |
| T17 | Hostile artifact: an archive bomb, a path-traversal or link member, or code that runs while the artifact is read | Implemented (Phase 2, R-C-4). The artifact is read statically in a subprocess with limits on CPU time, memory, file size, and wall time. The size caps are 50 MB compressed, 200 MB expanded, and 5,000 members. Members are read in memory and never written to disk. A member with an absolute path, a `..` segment, a NUL byte, a repeated name, or a link, device, or fifo type rejects the artifact. No code from the artifact is imported, run, or compiled, and no install script runs. The contract cache hash detects corruption, not someone who can write the state directory (same limit as T9) | R-C-1, R-C-4, P-C-1, P-C-5, P-C-6 |
| T18 | An artifact that builds its exports at run time (a module `__getattr__`, `exec`, a computed `__all__`, a computed `module.exports`) so that a static check cannot read them | Implemented (Phase 2, R-C-2 and R-C-3). The contract is incomplete, so the result is UNKNOWN with reason `dynamic_exports`, and UNKNOWN gives BLOCK. A symbol found in an incomplete contract is not PRESENT. The cost is that a legitimate package that does this is also blocked for intent checks, which lowers coverage | R-C-2, R-C-3, R-C-5, P-C-2, P-C-4 |
| T23 | An artifact that does not match the digest the registry published (a corrupted download, or a file swapped on a mirror or CDN) | Planned (Phase 2, not implemented). The digest is checked before the archive is opened. A mismatch is BLOCK (check `contract_digest`, HARD_BLOCK), never UNKNOWN. An npm version with only a sha1 `shasum` is UNKNOWN with reason `no_digest`, because sha1 is not trusted. This does not defend against an attacker who controls the registry response (see T5) | R-C-1, P-C-3 |

T19 to T22 are reserved for later phases. Phase 2 does not use them.

## 5. Data that leaves the machine (live mode)

This answers Open Decision 9. Offline mode sends nothing.

| Destination | What is sent | What is not sent |
|-------------|--------------|------------------|
| PyPI, npm (registry metadata) | Ecosystem, package name, version | Intent, project path, environment, other packages |
| OSV.dev | Ecosystem, package name, version | Intent, project path, environment, other packages |
| `files.pythonhosted.org`, `registry.npmjs.org` (artifact download). **Planned (Phase 2). Nothing is sent today** | A GET for one wheel or one tarball. The URL holds the file name and its path. Live mode only, and only when an intent names an `expected_api` | Intent, project path, environment, other packages, credentials. The download is up to 50 MB of untrusted data, and it is read, not run |
| L2 backend `needle` (default) | Nothing leaves the machine | |
| L2 backend `ollama` | Intent and package metadata to the local Ollama host | |
| L2 backend `openai` or `anthropic` | Intent and package metadata to that provider | Off by default. Choosing it is an explicit policy edit |

Each request reveals that the developer is considering a given package. That is inherent to checking it.

Live mode uses `urllib` with a 10-second timeout per request, a 10 MB response cap, and no retries. It sends a `slopseal` User-Agent and no credentials, cookies, or tokens. urllib follows HTTP redirects. Offline mode is the default: an unset `SLOPSEAL_OFFLINE_SNAPSHOT` means offline. Live mode runs only with `SLOPSEAL_OFFLINE_SNAPSHOT=0` or `--live`.

## 6. Accepted limits for v1

- **Tools outside the shim.** `yarn`, `pnpm` (including `pnpm dlx`), `cargo`, `gem`, and `go get` are not shimmed in v1. A command that runs them is not verified.
- **Transitive dependencies are not verified (T16).** A package that passes can pull in dependencies that SlopSeal never checks, and their install-time code runs. This is the largest gap after the shim boundary (T11).
- **Resolve-then-pin trusts the registry's latest pointer (R-1.7).** In live mode an unpinned `pip install x` or `npm install x` resolves to the registry's latest version, verifies that version, and installs it. A wrong registry or OSV answer can change which version is verified. The rewrite pins the verified version, so pip or npm cannot pick a different one. Offline, unpinned installs are refused. `--no-resolve` or `SLOPSEAL_NO_RESOLVE=1` keeps the refusal.
- **Live maintainer check is WARN (R-2.10, R-P-3).** In live mode only, PyPI and npm do not publish maintainer account age, so the maintainer check returns WARN, not BLOCK. Existence, typosquat, slopsquat, CVE/OSV, malware, and install-script checks stay fail-closed. Offline mode is unchanged: unknown maintainer data still blocks. Live mode also has no exported symbols, so intent checks always block. Its top-N list comes from the checksummed snapshot. It rules out install-time code only for a version with a universal wheel on PyPI. It does not follow OSV pagination.
- **Snapshot integrity is a checksum manifest, not a signature (Open Decision 6, resolved).** HMAC was rejected because the seal key is per machine, so a committed snapshot could not be checked by anyone else. Ed25519 would need a dependency. Snapshot files are checked against `manifest.json`. Anyone with write access to the repo can change a snapshot file and its manifest together, and verification will pass. The manifest protects against corruption and accidental edits, not against a malicious committer. A reviewer must treat any change to `src/slopseal/fixtures/` as a security-relevant change, which is why `CODEOWNERS` covers it.
- **Seals are symmetric (HMAC-SHA256, key in `.slopseal/secret.key`).** Anyone who can verify a seal or snapshot can also forge one. A verifier must therefore be a trusted holder of the key. Third parties cannot independently verify a SlopSeal verdict in v1. Public verifiability (Ed25519) is a roadmap item. This weakens the "signed receipt" claim for outside auditors and is stated in the write-up. Key compromise lets an attacker rewrite history undetected, which is why key storage is part of Open Decision 6.

- The shim can be bypassed by calling the real binary by absolute path. It protects agents and developers who go through PATH, and the Kiro hook checks install commands in agent shell calls. It verifies pinned pip and npm installs and blocks the rest (R-G-5). Neither stops a determined local user.
- The install hook depends on the Kiro IDE version. It is verified on Kiro IDE 1.4.178, the minimum supported version (v1 JSON hook format, stdin payload, exit 2 blocks). It does not load on Kiro IDE 0.12.x, so an agent on that version is not covered by the hook.
- The hook does not inspect a script file or a `python -c` program that runs an install, and it does not cover `curl | sh`.
- Live mode trusts TLS to the registry and OSV. Only offline mode gives signed inputs.
- The deterministic intent check proves the declared API exists. It does not prove the package fits the task. Only L2 addresses purpose, and it is gated.
- A new malicious package with a unique name, no typosquat distance, and clean metadata can pass L1. Age and install-script checks reduce this risk and do not remove it.
- Only pip and npm are in v1. The other package managers named in the original scope are on the post-hackathon roadmap (Open Decision 13). The fixture corpus and the demo cover pip and npm.

## 7. Open items

| Item | Owner decision | Due |
|------|----------------|-----|
| Signing algorithm, key location, and who signs | Open Decision 6 | **Resolved** (section 5a and section 6) |
| Quarantine time bound and install rate limit | Open Decision 7 | **Resolved** (Phase 5): 900-second window, N = 10 installs per minute |

## 5a. CI behavior for QUARANTINE (Open Decision 3, resolved)

Exit 75 means QUARANTINE: retryable with a refined intent, or waiting for a human. It is not a pass. CI runners treat any non-zero exit as a failure, so a pipeline that installs a quarantined package fails by default. That is the intended result. A pipeline that should pause for manual approval must opt in explicitly, by mapping exit 75 to a pause step in its own configuration. No default in SlopSeal turns 75 into success.
