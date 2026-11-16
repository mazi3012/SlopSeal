# SlopSeal

**A seatbelt for AI coding agents. Every package install gets checked, and every decision gets a signed receipt.**

Built for Kiroween 2026, Frankenstein category. MIT license.

## The problem

AI agents install packages on their own. They sometimes invent a package name that sounds real, and attackers register those names with malware first. This attack is called slopsquatting. A normal vulnerability scanner will not catch it, because the package is new and has no known CVE.

## What SlopSeal does

Before an install runs, SlopSeal checks the package and answers with one of three verdicts:

| Verdict | Meaning | Example |
|---------|---------|---------|
| ✅ **ALLOW** | Looks safe. Go ahead. | `tinyfmt-kit 0.4.0` |
| 🛑 **BLOCK** | Looks malicious or fake. Do not install. | `csv-parser-pro`, a made-up lookalike name |
| ⏸️ **QUARANTINE** | Real package, but it does not offer the API the agent expects. A person decides. | `csv-parser`, when the agent expects `csv.reader` |

Each verdict goes into a tamper-evident, signed audit log, so you can prove later what was decided and why. The checks are fixed rules (package exists, name is not a lookalike, package is not brand new, and more). SlopSeal does not ask an AI to judge another AI.

## See it in 60 seconds

Needs Python 3.11 or newer. The demo runs offline and installs nothing.

```bash
git clone https://github.com/mazi3012/SlopSeal.git
cd SlopSeal
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
bash scripts/demo.sh
```

It walks through seven steps and ends with `demo: PASS (all beats)`: a fake package is blocked, an API mismatch is quarantined, a retry is allowed, pip and npm are intercepted, the audit log verifies, a tampered log is caught, and a weakened policy is rejected.

## 🚀 Quick Start: Kiro Web & IDE

Add SlopSeal to Kiro as an MCP server. It sets up its own security hook on first start, so there is nothing else to configure.

```json
{
  "mcpServers": {
    "slopseal": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/mazi3012/SlopSeal.git",
        "slopseal-mcp"
      ],
      "env": {
        "SLOPSEAL_OFFLINE_SNAPSHOT": "0"
      }
    }
  }
}
```

- **Kiro IDE:** paste this into your `.mcp.json` config.
- **Kiro Web:** go to **Agent Config > Powers & MCP > + Add server**, choose **Paste JSON**, and paste the block.

Then **start a new Kiro session**. Kiro reads hook files only at session start, so the hook protects you from the second session on.

`SLOPSEAL_OFFLINE_SNAPSHOT=0` turns on Live Mode, which checks real PyPI and OSV data. Remove it to use the bundled offline snapshot, which is better for demos.

### What the hook does

Without it, an agent can skip SlopSeal and run `npm install` in the terminal. The hook blocks agent install commands and tells the agent to verify the package with the SlopSeal tool first. If SlopSeal cannot run, the hook blocks the command rather than letting it through.

## How we used Kiro

The `.kiro/` folder is part of the product.

| Kiro feature | What it does here |
|--------------|-------------------|
| **Steering** | `dependency-trust.md` is the trust policy. The code reads it at run time. |
| **Specs** | Requirements, design, and the rules the tests must hold are in `.kiro/specs/seal/`. |
| **Hooks** | One hook blocks agent installs that skip SlopSeal. Another runs the tests when the policy changes. |
| **MCP** | The `verify_install` tool lets the agent check a package before installing. |
| **Property tests** | Tests assert that an unknown or error state always blocks and never allows. |

The full story is in [docs/WRITEUP.md](docs/WRITEUP.md).

## Honest limits

SlopSeal is a hackathon project and is not ready for production.

- On our 23-package test set, it blocked 9 of 10 attack packages and wrongly flagged 1 of 13 safe ones.
- It checks that a package exists and behaves like a real one. It does not check that the package fits the agent's purpose. We tried an AI layer for that, and it failed our own accuracy test, so it is not in v1.
- Dependencies of a package are not checked yet.
- The hook is tested on Kiro IDE 1.4.178 and up. The shell wrapper is untested on Windows.
- A user who calls the real `pip` by its full path can skip the shell shim. The hook still catches agent commands.

The complete list is in [docs/REFERENCE.md](docs/REFERENCE.md#full-limitations).

## Learn more

| Want to know | Read |
|--------------|------|
| How checks run, exit codes, CLI commands, Kiro Powers install | [docs/REFERENCE.md](docs/REFERENCE.md) |
| How Kiro was used | [docs/WRITEUP.md](docs/WRITEUP.md) |
| Demo walkthrough | [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) |
| What can go wrong | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Product goals | [PRD.md](PRD.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md) |

## License

MIT. See [LICENSE](LICENSE).
