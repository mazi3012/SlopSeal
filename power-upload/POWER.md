# SlopSeal

SlopSeal checks a package before the agent installs it. Use it whenever the agent is about to
run `pip install`, `npm install`, `npx`, or another command that adds a package.

## What it checks

AI coding agents sometimes invent package names. Attackers register those names with malicious
code (slopsquatting). SlopSeal checks each exact package version against deterministic rules:

- The package exists in the registry.
- The name is not a typo or near-copy of a popular package (typosquatting), and not a known
  slopsquat.
- The version has no known malware record and no unexpected install scripts.
- The license and maintainer data meet the trust policy.
- The package is not a brand-new package with almost no releases.
- The declared API (`expected_api`) is an export of that exact version.

## The tool

`verify_install` takes:

| Argument | Required | Meaning |
|----------|----------|---------|
| `ecosystem` | yes | `pypi` for pip, `npm` for npm |
| `package` | yes | the package name, as the install command gives it |
| `version` | yes | the exact version to install, such as `1.2.3` |
| `purpose` | no | why the package is needed |
| `expected_api` | no | a symbol the code will import from the package |
| `quarantine_id` | no | the id from an earlier QUARANTINE, when retrying |

It returns one of three outcomes:

- **ALLOW**: the checks passed. The agent may install that exact version.
- **BLOCK**: the install must not run. The result includes the failed check and a remedy.
- **QUARANTINE**: the package needs a human decision. Do not retry without a changed request.

The tool does not install anything. Any result other than ALLOW is an error, and the install must
not run.

## How the agent should use it

1. Before any install, call `verify_install` with the exact version.
2. Install only if the outcome is ALLOW.
3. If the outcome is BLOCK or QUARANTINE, tell the user what failed. Do not try another package
   name or an unpinned version to get around the result.

## Limits

- Deterministic checks only. The offline snapshot is the default, so no package name leaves the
  machine. The semantic layer is not in v1.
- Transitive dependencies are not checked (threat T16 in `docs/THREAT_MODEL.md`).
- Only pip and npm are covered in v1.
- The PATH shim and the install hook are separate parts of SlopSeal. This power provides only the
  verification tool.

## Setup

The server runs with `uvx`, so `uv` must be installed. The server reads `.kiro/steering/
dependency-trust.md` from its working directory and fails closed when that file is missing.
See the README, "Install with Kiro Powers", for the setup steps and the trust policy.
