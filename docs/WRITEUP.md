# SlopSeal: a dependency trust firewall built with Kiro

Category: Frankenstein. Repository: https://github.com/mazi3012/SlopSeal. License: MIT.

## What it does

AI coding agents install packages that a language model suggested. Some of those names do not
exist, and an attacker has registered them with malware (slopsquatting). Others exist and are
safe, but they do not provide the API the agent needs. No vulnerability scanner flags either case.

SlopSeal sits between the agent and `pip` or `npm`. For each install it returns one verdict:
ALLOW, BLOCK, or QUARANTINE. It writes the verdict to an append-only audit log and signs each
entry. The rules live in a Kiro steering file, and a property test suite guards that file.

The verdict is returned on the command line with the exit codes 0, 1, 75, and 78. The PATH shim
puts that check in front of `pip` and `npm`. In the offline demo, a slopsquat name is blocked
before the real tool runs, a pinned allowed package runs, and a tampered audit log fails
verification.

## How Kiro was used

Kiro was the development environment for the whole project. The repository shows four ways it
was used.

**Specs.** `.kiro/specs/seal/` has three documents. `requirements.md` states each requirement
in EARS form with an ID such as R-2.4 or R-4.7. `design.md` describes the verdict pipeline and
the quarantine state machine. `properties.md` lists the invariants the tests must check. Commit
messages and tests cite the requirement IDs, so a reviewer can trace a line of code back to the
requirement it serves.

**Steering.** `.kiro/steering/dependency-trust.md` is the trust policy: thresholds, allow and
deny lists, license and maintainer rules, and the rate limit. The code loads this file at run
time. The product, tech, and structure steering files tell the agent what the project is and
how to work in it. One rule matters most here: the agent may tighten a policy value, but it
cannot loosen a value past a floor set in code (`src/slopseal/policy/invariants.py`). Changing a
threshold is therefore a reviewed decision, not a side effect of an agent edit.

**Hooks.** Two hooks are configured in `.kiro/hooks/`, in the Kiro v1 JSON format. The first
is a PreToolUse hook on the agent's shell tool. It blocks any shell command that installs
packages, using exit code 2, which Kiro documents as the block for this event. It does not
verify packages. Verification happens in the PATH shim. The second hook runs
`scripts/policy_checks.sh` when the policy file is saved. That trigger works in the Kiro IDE
and CLI. It does not run in a Kiro Web session, where the git pre-commit hook and CI run the
same check. A policy edit that breaks a property is rejected.

**Property-based tests.** The test suite uses Hypothesis. There are 114 `@given` properties
across 18 files, and each runs 500 generated examples in CI. The properties assert things such
as: unknown or error state never produces ALLOW, a corrupt state file blocks, a denied rate-limit
attempt still counts, and each audit line carries a hash link and an HMAC seal. Mutation checks confirmed
that the rate-limit tests catch an off-by-one error and a denied attempt that goes uncounted.
Both were restored afterward.

## Architecture: the arsonist does not inspect the fire

The agent that wants a package is the party with an interest in installing it. It should not
judge its own request. SlopSeal therefore never calls the agent's LLM. Every check is
deterministic code that reads a checksummed, offline registry snapshot. The verdict depends only on
the policy, the snapshot, and the inputs. Given the same inputs, it returns the same verdict.

The layers are:

1. Policy and snapshot integrity. A bad policy or a snapshot whose checksums fail exits 78 or
   blocks. Nothing runs on unknown state.
2. Rate limit. More than 10 install attempts per minute block. This check runs first, and it is
   not bypassed by `--allow-unsafe`.
3. Deterministic checks, 2.1 to 2.11: existence, typosquat, slopsquat signatures, package age,
   install scripts, known CVEs, malware advisories, allow and deny lists, license, maintainer,
   and near-name similarity.
4. Intent check. If the agent declares the API it expects, SlopSeal compares that with the
   package's real exports. A mismatch returns QUARANTINE with one retry. A retry that still
   fails escalates to a person.
5. Seal. Each decision is appended to a hash-chained log and signed with HMAC-SHA256.

A QUARANTINE payload contains no confidence number. It lists the exports the package really
has, so the agent can correct its request without guessing.

An honest caveat about the shim: it is advisory. A command that calls the real `pip` by its
absolute path skips it. This is documented as threat T11 in `docs/THREAT_MODEL.md`.

## The limitation: v1 is deterministic only

The original plan included an on-device semantic check, the L2 layer, to judge whether a package
fits the agent's stated purpose. That layer used the Needle 3 model. It was tested against a
pre-registered gate before any code used it:

- Match-allow had to reach at least 0.80. It reached 0.40 (2 of 5).
- Mismatch-allow had to stay at or below 0.20. It was 0.00 (0 of 5).

The gate failed. On three of the five matching cases, the model declined to call a tool and
reported high confidence (0.77 to 0.89), so its confidence signal did not measure fit. On one
matching case, the model chose `parse_file` over `parse`, and the label was ambiguous. On every
mismatch, it declined to answer.

The result is recorded in `docs/adr/0003-needle-runtime.md` and in `docs/needle_spike.csv`.
Because the gate failed, L2 is not wired into the verdict pipeline. I did not tune the threshold
or the labels to pass. One probe ran on one case after the labels were committed. It was disclosed
and did not change any label or threshold.

Two consequences follow for anyone who uses SlopSeal:

- A package can pass every deterministic check and still not fit the task. The intent check only
  confirms that the declared API exists.
- Two L1 results are measured and documented, not hidden. On the 23-package fixture corpus,
  9 of 10 attack packages were blocked. The miss sat exactly on the 7-day new-package boundary.
  One of 13 legitimate packages was flagged, because the fixture advisory data marks that version as
  critical. See `docs/L1_THRESHOLD_REVIEW.md`. The corpus is 23 hand-written fixture records, not the
  5,000-package list the PRD mentions for later.

## Why cactus-needle was rejected and needle-rs was chosen

Both packages offer Needle 3 to Python. They differ in what they do when they run.

`cactus-needle` 3.2.9 sends usage events to a third-party Supabase endpoint on first use and by
default. Telemetry can be turned off with `NEEDLE_TELEMETRY=0`, but it is on by default. It also
downloads its model weights and engine binaries from Hugging Face at run time. Both behaviors
conflict with SlopSeal's rule that it does not phone home and that unknown state never produces
an ALLOW.

`needle-rs` 0.3.1 is a compiled extension. We found no URLs in its binary and no telemetry. It
loads `needle3.cact` from a local path, and that file is checked against a pinned SHA-256 before
use. The checksum matches Hugging Face's published LFS object ID.

`needle-rs` has a risk we have not closed. A third party maintains it, not Cactus Compute. Its
README says its output matches the upstream JAX reference exactly, and we did not reproduce that
comparison. It sits in an optional `needle` extra, so the default install adds no dependency.

## Transitive dependencies

SlopSeal checks the packages named on the command line. It does not check the packages those
packages depend on, and their install-time code runs. A package that passes every check can
still bring in an unverified dependency. The threat is recorded as T16 in `docs/THREAT_MODEL.md`.
A one-level-deep check is on the post-hackathon roadmap.

## Live mode

`--live` queries PyPI, npm, and OSV with the standard library. Every failed, malformed, or partial response becomes an explicit unknown, and unknown blocks. The public registries do not publish maintainer account age, so live mode blocks every package at the maintainer check. I chose to keep that block rather than weaken the check. Live mode is lower assurance than the offline snapshot, and `docs/THREAT_MODEL.md` T5 says so.

## What I would do next

- Compare `needle-rs` output with the upstream reference, and pin the wheel hash.
- Write a new pre-registered L2 experiment with a different decision rule. Retuning this one
  would not count.
- Replace the deterministic advisory-only shim with a check at the lockfile or the registry
  boundary, so absolute-path calls cannot skip it.
- Check one level of transitive dependencies, so a dependency pulled in by an allowed package is verified too (T16).
- Let the install hook call the verdict pipeline, so a verified agent install can run. Today it blocks every install command the agent issues.
