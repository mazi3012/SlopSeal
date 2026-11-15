# 0001. Policy as a fenced TOML block in the steering file

Status: Accepted
Date: 2026-11-15

## Context

The trust policy must be a Kiro steering file (that is the product thesis) and must also be machine-readable by the code. Steering files are Markdown. A policy with no schema invites silent defaults, and silent defaults weaken a fail-closed tool.

## Decision

`.kiro/steering/dependency-trust.md` contains prose for people and exactly one fenced code block with the info string `toml slopseal-policy`. The loader parses that block with `tomllib` and ignores the prose. A missing block, a second block, malformed TOML, an unknown key, a missing required key, or an unsupported `schema_version` is a policy error (exit 78). One function in the loader extracts the block, and the pre-commit guard calls it through `slopseal policy check` instead of reimplementing the rule (see `design.md` section 7).

## Consequences

- No parsing dependency: `tomllib` is in the standard library from Python 3.11.
- The steering file stays readable and diffable in review.
- The policy hash covers the parsed block only, so a prose edit does not change it.
- Rejecting unknown keys catches typos, at the cost of a policy error when a newer file meets an older loader. Mitigated by the required `schema_version` key: an unsupported version is refused with exit 78, not read with keys ignored.
- Rejected: YAML front matter (needs a YAML dependency), JSON in a separate file (loses the steering-file thesis), free-form Markdown parsing (ambiguous).
