# SlopSeal reference

Details that used to sit in the README. For the short version, start with the [README](../README.md).

## Verdict order

For each install, `verify_install(package, version, intent?)` runs in order:

1. **Rate limit.** More than 10 install attempts per minute block. Denied attempts still count.
2. **Policy and snapshot checks.** A missing or malformed policy exits 78. A snapshot that fails its checksums blocks.
3. **Deterministic checks (L1).** Registry existence, typosquat, slopsquat signatures, package age, install scripts, OSV advisories and malware feed, allow and deny lists, license, maintainer, near-name similarity.
4. **Intent check.** If the agent declares the API it expects, SlopSeal compares it with the package's real exports. A mismatch returns QUARANTINE with one bounded retry, then escalation to a person.
5. **Seal.** The decision goes to an append-only, hash-chained audit log with an HMAC-SHA256 seal on each line.

SlopSeal never uses the calling agent's LLM. In offline mode (the default), the verdict depends only on the policy and the checksummed snapshot. Live mode also depends on the registries' responses.

| Exit code | Meaning |
|-----------|---------|
| 0 | ALLOW |
| 1 | BLOCK (DependencyViolation JSON on stderr) |
| 75 | QUARANTINE (payload JSON on stdout). CI fails on 75 unless the job opts in to a pause |
| 78 | Policy, key, or state directory is unusable. No verdict is issued |

## PATH shim

`python -m slopseal.intercept.shims <dir>` writes `pip`, `npm`, and `npx` wrappers. The wrappers verify each pinned install before the real tool runs. `npx`, `npm exec`, and `npm x` must name an exact `name@x.y.z`. Other forms are refused. The shim is advisory: a command that calls the real binary by absolute path skips it (see `THREAT_MODEL.md`, T11).

## Zero-config hook registration

Adding the `slopseal-mcp` server to a workspace is enough to register the install hook. When the server starts, it writes `.kiro/hooks/block-agent-installs.json` into the current working directory if that file is missing. The hook command runs slopseal with the Python that started the server, so it works under uvx, pipx, or a local venv, and it does not depend on what `python3` is on PATH. The hook is the same in Kiro Web, Kiro IDE, and Kiro CLI. An existing file is never overwritten. If the workspace is read-only, the server keeps running and prints `SlopSeal MCP: could not register security hook` to stderr. It does not block the MCP tool. Without the hook, the agent can still run raw install commands, so check stderr on first start.

Kiro loads hook files when a session starts. A hook registered during a running session can take effect only in the next session. Start a new session after the first MCP start in a workspace (R-1.9).

The hook is fail closed. Its command is a `sh -c` wrapper. If the interpreter cannot run the module (exit code other than 0 or 2, such as a missing `slopseal` package), the wrapper prints `BLOCKED: SlopSeal is not installed` with an install command and exits 2. Without the wrapper, Kiro would treat that exit 1 as a pass.

The hook covers pip, pip3, `python -m pip`, pipx, uv, uvx, poetry, pdm, conda, mamba, easy_install, npm, npx, pnpm, yarn, cargo, gem, and `go get`/`go install`, including after `sudo`, `env`, `VAR=val`, `bash -c`, and `&&`, `||`, `;`, `|`. It does not verify packages. The PATH shim and the MCP tool do. It does not inspect a script file or `python -c` that runs an install, and `curl | sh` is out of scope (THREAT_MODEL T11).

## Install with Kiro Powers

SlopSeal ships as a Kiro power. The `power-upload/` folder holds `POWER.md` (the description Kiro shows), `plugin.json` (the manifest Kiro requires), and `mcp.json` (how Kiro starts the server). The power adds one tool, `verify_install`, which runs the deterministic checks on an exact package version.

Requirements: a Kiro IDE that supports Powers, and `uv` for the `uvx` launch command. Install `uv` first if `uvx --version` fails. The Kiro docs do not state a minimum IDE version for Powers, so check the Powers panel in your version.

1. Get the SlopSeal folder on disk: `git clone https://github.com/mazi3012/SlopSeal.git`
2. In Kiro, open the Powers panel and choose **Add Custom Power**.
3. Choose **Import power from a folder**, then select the `power-upload/` folder inside the SlopSeal repo. It contains `plugin.json`.
4. Confirm that the power lists the `verify_install` tool. A power named `slopseal` appears under installed powers.
5. Test it. In a chat, mention a package install, for example "install tinyfmt-kit 0.4.0". The power activates, and the agent calls `verify_install` before it installs.

Notes:

- The server starts with the SlopSeal folder as its working directory. It reads the trust policy from `.kiro/steering/dependency-trust.md` in that folder, or falls back to the bundled default policy, and runs offline against the checksummed snapshot.
- The power does not install packages. The install still goes through the shell, and the install hook and PATH shim still apply.
- To run the server from a different folder, set `SLOPSEAL_POLICY_PATH` and `SLOPSEAL_STATE_DIR` in `mcp.json` to absolute paths.
- Without Kiro, the same server runs from a shell: `uvx --from . slopseal-mcp`, from the SlopSeal folder. It reads JSON-RPC on stdin and writes it to stdout.

The Kiro GUI import step is written from Kiro's Powers documentation and has not been tested in the IDE. The `uvx` launch command was tested over stdio.

## CLI examples

After activating the venv:

```bash
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check csv-parser-pro --version 0.1.0     # exit 1
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check csv-parser --version 1.2.0 --expected-api csv.reader   # exit 75
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check tinyfmt-kit --version 0.4.0        # exit 0
slopseal audit verify
slopseal audit html --out receipt.html   # one-file HTML receipt of the audit log
slopseal policy check
slopseal policy diff .kiro/steering/dependency-trust.md .kiro/steering/dependency-trust.md
SLOPSEAL_OFFLINE_SNAPSHOT=0 slopseal check requests --version 2.33.0   # live registries
```

## Full limitations

- The intent check confirms that a declared API exists in the package's exports. It does not confirm that the package fits the purpose. The semantic layer that would address purpose is not in v1.
- Measured on the 23-package fixture corpus, 9 of 10 attack packages were blocked, and 1 of 13 legitimate packages was flagged. Details: `L1_THRESHOLD_REVIEW.md`.
- In live mode, `pip install x` and `npm install x` without a version resolve to the latest version. That version is verified and the command is rewritten to pin it. The original and rewritten commands are audited. `--no-resolve` or `SLOPSEAL_NO_RESOLVE=1` keeps the refusal. Offline, unpinned installs are refused (R-1.7).
- Transitive dependencies are not verified in v1. A package that passes can pull in dependencies that SlopSeal does not check, and their install-time code runs (THREAT_MODEL T16).
- Live mode (`--live` or `SLOPSEAL_OFFLINE_SNAPSHOT=0`) queries PyPI, npm, and OSV over HTTPS, and treats every failure as unknown. PyPI and npm do not publish maintainer account age, so in live mode the maintainer check returns WARN, not BLOCK. Existence, typosquat, slopsquat, CVE/OSV, malware, and install-script checks stay fail-closed. Offline mode is unchanged: unknown maintainer data still blocks. Offline mode cannot read exported symbols, so intent checks block, and its top-N list comes from the offline snapshot. It is lower assurance (THREAT_MODEL T5).
- The PATH shim is advisory. A call to the real binary by absolute path skips it.
- The hook is verified on Kiro IDE 1.4.178. It uses the v1 JSON hook format, reads the stdin payload, and blocks on exit 2. It does not load on Kiro IDE 0.12.x. The minimum supported Kiro IDE version is 1.4.178.
- The policy-save hook runs in Kiro IDE and CLI sessions, not Kiro Web.
- The hook command is a `sh -c` wrapper, so Windows is untested.
- The generated hook file names the interpreter that started the server. It is written once and never rewritten. Do not commit a generated hook file to a shared repo.
- SlopSeal does not scan package source for vulnerabilities and does not police runtime behavior after install.

## Post-hackathon roadmap

A one-level-deep check of transitive dependencies (T16), replay (R-5.7.3), live registry proxy, SARIF output, local dashboard, Windows support, other package managers beyond the hook's coverage, and a semantic layer if a new pre-registered experiment passes.

## Repository map

| Path | Purpose |
|------|---------|
| `PRD.md` | Product requirements, scope, milestones |
| `docs/WRITEUP.md` | Kiro write-up: how Kiro was used and the architecture |
| `docs/DEMO_SCRIPT.md` | Demo runbook |
| `docs/` | Plan, threat model, failure taxonomy, architecture, L1 review, ADRs |
| `.kiro/specs/seal/` | Requirements, design, properties |
| `.kiro/steering/` | Product, tech, and structure rules; the trust policy |
| `src/slopseal/` | Implementation |
| `src/tests/` | Unit, property, and integration tests |
| `AGENTS.md`, `CONTRIBUTING.md` | Rules for coding agents and contributors |
