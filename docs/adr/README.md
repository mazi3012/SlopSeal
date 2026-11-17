# Architecture Decision Records

An ADR records one decision that is expensive to reverse: what was chosen, why, and what was given up.

## When to write one

- A new runtime dependency (required by `.kiro/steering/tech.md`).
- A new external service call or trust boundary.
- A change to an exit code, the policy format, or the audit format.
- Reversing an earlier ADR (add a new one that supersedes it).

## Format

File name: `NNNN-short-title.md`, numbered in order.

```markdown
# NNNN. Title

Status: Proposed | Accepted | Superseded by NNNN
Date: YYYY-MM-DD

## Context
What forced a decision.

## Decision
What was chosen.

## Consequences
What gets easier, what gets harder, what was rejected.
```

## Index

| ID | Title | Status |
|----|-------|--------|
| 0001 | Policy as a fenced TOML block in the steering file | Accepted |
| 0002 | Zero mandatory runtime dependencies | Accepted |
| 0005 | Ed25519 signatures for anchor receipts and approvals | Accepted |
