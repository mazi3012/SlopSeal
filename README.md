# SlopSeal

**Every install gets a seal. Every seal is a verdict. Every verdict is a receipt.**

SlopSeal is a dependency trust firewall that checks each `pip` and `npm` install an AI coding agent makes and returns a signed ALLOW, BLOCK, or QUARANTINE verdict.

Built for Kiroween 2026, Frankenstein category. License: MIT.

Product requirements: [PRD.md](PRD.md). Kiro write-up: [docs/WRITEUP.md](docs/WRITEUP.md). Demo runbook: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

> **Status:** v1 is feature-complete for the deterministic path. The deterministic checks, the PATH shim, the quarantine state machine, the rate limit, the signed audit log, and the CLI are built and tested. The semantic layer (L2) tested against Needle 3 and failed its pre-registered gate, so it is not in v1. Live mode queries PyPI, npm, and OSV. The registries do not publish maintainer account age, so in live mode the maintainer check warns instead of blocking. Use the offline snapshot for demos. Nothing here is ready for production use.

## The problem

AI coding agents run `pip install` and `npm install` from LLM suggestions.

- **Slopsquatting.** The model invents a plausible package name. An attacker registers it with malware.
- **Semantic mismatch.** The package is real and safe, but it does not provide the API the agent needs. No CVE scanner flags it.
- **Policy erosion.** Dependency rules live in wikis. When one is weakened, nothing records it.

## How it works

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

The PATH shim (`python -m slopseal.intercept.shims <dir>`) writes `pip`, `npm`, and `npx` wrappers. The wrappers verify each pinned install before the real tool runs. `npx`, `npm exec`, and `npm x` must name an exact `name@x.y.z`. Other forms are refused. The shim is advisory: a command that calls the real binary by absolute path skips it (see `docs/THREAT_MODEL.md`, T11).

## How Kiro constitutes the policy

`.kiro/` is part of the product, not documentation.

| Kiro feature | What it is here |
|--------------|-----------------|
| Steering | `dependency-trust.md` holds the trust policy that the code loads at run time |
| Specs | `.kiro/specs/seal/` holds requirements (EARS), design, and the property contract |
| Hooks | `block-agent-installs.json` (matcher `execute_bash`) runs `scripts/hooks/on_install.py`, which blocks agent shell commands that install packages (exit 2). `on-steering-change.json` runs the property suite when the policy is saved (Kiro IDE and CLI only) |
| Properties | Hypothesis tests assert that unknown state always blocks. A pre-commit guard rejects a policy edit that fails them |

## Install with Kiro Powers

SlopSeal ships as a Kiro power. The repo root holds `POWER.md` (the description Kiro shows),
`plugin.json` (the manifest Kiro requires), and `mcp.json` (how Kiro starts the server). The
power adds one tool, `verify_install`, which runs the deterministic checks on an exact package
version.

Requirements: a Kiro IDE that supports Powers, and `uv` for the `uvx` launch command. Install
`uv` first if `uvx --version` fails. The Kiro docs do not state a minimum IDE version for
Powers, so check the Powers panel in your version.

1. Get the SlopSeal folder on disk. Clone it, or download and unpack the repo:
   `git clone https://github.com/mazi3012/SlopSeal.git`
2. In Kiro, open the Powers panel and choose **Add Custom Power**.
3. Choose **Import power from a folder**, then select the SlopSeal folder, the one that
   contains `plugin.json`.
4. Confirm that the power lists the `verify_install` tool. A power named `slopseal` appears
   under installed powers.
5. Test it. In a chat, mention a package install, for example "install tinyfmt-kit 0.4.0".
   The power activates, and the agent calls `verify_install` before it installs.

Notes:

- The server starts with the SlopSeal folder as its working directory. It reads the trust
  policy from `.kiro/steering/dependency-trust.md` in that folder and runs offline against the
  checksummed snapshot. If the policy is missing, the tool reports no verdict, and the install
  must not run.
- The power does not install packages. The install still goes through the shell, and the
  install hook and PATH shim still apply.
- To run the server from a different folder, set `SLOPSEAL_POLICY_PATH` and
  `SLOPSEAL_STATE_DIR` in `mcp.json` to absolute paths.
- Without Kiro, the same server runs from a shell: `uvx --from . slopseal-mcp`, from the
  SlopSeal folder. It reads JSON-RPC on stdin and writes it to stdout.

I could not run the Kiro GUI, so the import step above is written from Kiro's Powers
documentation and has not been tested in the IDE. The `uvx` launch command was tested over stdio.

## Demo

The demo runs the deterministic path against the checksummed offline snapshot in a temporary state directory. It needs Python 3.11 or newer.

```bash
git clone https://github.com/mazi3012/SlopSeal.git
cd SlopSeal
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
bash scripts/demo.sh
```

The script ends with `demo: PASS (all beats)`. It runs seven beats: a slopsquat name is blocked, an API mismatch is quarantined, a retry is allowed, pip and npm run through the PATH shim, the audit log verifies, a tampered log fails, and a weakened policy fails the floor check.

Single commands, after activating the venv:

```bash
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check csv-parser-pro --version 0.1.0     # exit 1
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check csv-parser --version 1.2.0 --expected-api csv.reader   # exit 75
SLOPSEAL_OFFLINE_SNAPSHOT=1 slopseal check tinyfmt-kit --version 0.4.0        # exit 0
slopseal audit verify
slopseal audit html --out receipt.html   # one-file HTML receipt of the audit log
slopseal policy check
slopseal policy diff .kiro/steering/dependency-trust.md .kiro/steering/dependency-trust.md
SLOPSEAL_OFFLINE_SNAPSHOT=0 slopseal check requests --version 2.33.0   # live registries; see Limitations
```

## Repository map

| Path | Purpose |
|------|---------|
| `PRD.md` | Product requirements, scope, milestones |
| `docs/WRITEUP.md` | Kiro write-up: how Kiro was used, the architecture, and the v1 limitation |
| `docs/DEMO_SCRIPT.md` | Demo runbook |
| `.kiro/specs/seal/` | Requirements, design, properties |
| `.kiro/steering/` | Agent-facing product, tech, and structure rules; the trust policy |
| `src/slopseal/` | Implementation |
| `src/tests/` | Unit, property, and integration tests |
| `docs/` | Plan, threat model, failure taxonomy, architecture, L1 review, ADRs |
| `AGENTS.md` | Rules for coding agents |

## Development

Requires Python 3.11 or newer.

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy src/slopseal
pytest
```

Contributors and agents: read `CONTRIBUTING.md` and `AGENTS.md` first.

## Post-Hackathon Roadmap

In v1: pip and npm checks, PATH shim, `verify_install`, quarantine, rate limit, audit log with signed seals, policy diff, offline snapshot. Post-hackathon roadmap: a one-level-deep check of transitive dependencies (T16), replay (R-5.7.3), live registry proxy, SARIF output, local dashboard, MCP server, Windows support, other package managers (yarn, pnpm, cargo, gem, go get), and a semantic layer if a new pre-registered experiment passes.

## Limitations

- The intent check confirms that a declared API exists in the package's exports. It does not confirm that the package fits the purpose. The semantic layer that would address purpose is not in v1.
- Measured on the 23-package fixture corpus, 9 of 10 attack packages were blocked, and 1 of 13 legitimate packages was flagged. The details are in `docs/L1_THRESHOLD_REVIEW.md`.
- In live mode, `pip install x` and `npm install x` without a version resolve to the latest version. That version is verified and the command is rewritten to pin it. The original and rewritten commands are audited. `--no-resolve` or `SLOPSEAL_NO_RESOLVE=1` keeps the refusal. Offline, unpinned installs are refused (R-1.7).
- Transitive dependencies are not verified in v1. A package that passes can pull in dependencies that SlopSeal does not check, and their install-time code runs (THREAT_MODEL T16).
- Live mode (`--live` or `SLOPSEAL_OFFLINE_SNAPSHOT=0`) queries PyPI, npm, and OSV over HTTPS, and treats every failure as unknown. PyPI and npm do not publish maintainer account age, so in live mode the maintainer check returns WARN, not BLOCK. Existence, typosquat, slopsquat, CVE/OSV, malware, and install-script checks stay fail-closed. Offline mode is unchanged: unknown maintainer data still blocks. It cannot read exported symbols, so intent checks block, and its top-N list comes from the offline snapshot. It is lower assurance (THREAT_MODEL T5).
- The PATH shim is advisory. A call to the real binary by absolute path skips it.
- The install hook (`block-agent-installs.json`) blocks agent install commands with exit 2. It covers pip, pip3, `python -m pip`, pipx, uv, uvx, poetry, pdm, conda, mamba, easy_install, npm, npx, pnpm, yarn, cargo, gem, and `go get`/`go install`, including after `sudo`, `env`, `VAR=val`, `bash -c`, and `&&`, `||`, `;`, `|`. It does not verify packages. The PATH shim does. It does not inspect a script file or `python -c` that runs an install, and `curl | sh` is out of scope (THREAT_MODEL T11).
- The hook is verified on Kiro IDE 1.4.178. It uses the v1 JSON hook format, reads the stdin payload, and blocks on exit 2. It does not load on Kiro IDE 0.12.x. The minimum supported Kiro IDE version is 1.4.178.
- The policy-save hook runs in Kiro IDE and CLI sessions, not Kiro Web.
- SlopSeal does not scan package source for vulnerabilities and does not police runtime behavior after install.

## Security

Report vulnerabilities as described in `SECURITY.md`.

## License

MIT. See `LICENSE`.
