# Security Policy

SlopSeal is a security tool, so reports about its own weaknesses matter most.

## Supported versions

SlopSeal is pre-1.0. Only the latest commit on `main` is supported.

## Reporting a vulnerability

Do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting for this repository: **Security tab → Report a vulnerability**. If that is unavailable, contact the repository owner through the email on their GitHub profile.

Include:

- What you found and where.
- Steps or an input that reproduces it.
- The effect: for example, "an unknown registry state returns ALLOW."
- Your suggested fix, if you have one.

You can expect an acknowledgement within 5 business days. This is a hackathon-stage project maintained by a small team, so fix times are best effort.

## What counts as a vulnerability

Highest priority:

- Any input that makes SlopSeal return ALLOW when policy, registry, advisory, or snapshot state is unknown, unreadable, or ambiguous (breaks the fail-closed invariant).
- A way to pass a tampered snapshot, policy, audit log, or seal without detection.
- A way for L2 output or package metadata to cause code execution or to override a deterministic block.
- A way to bypass the PATH shim or the install hook without an audit entry.
- Leakage of secrets or environment data to logs, stdout, or the network.

Also in scope: crashes that produce an exit code other than 0, 1, 75, or 78, and quarantine states that never terminate.

## Out of scope

- Vulnerabilities inside packages SlopSeal evaluates.
- Attacks that require the attacker to already control the machine's signing key or the user's shell.
- Windows behavior (not supported in v1).

## Design assumptions

The threat model, trust boundaries, and known limits are in `docs/THREAT_MODEL.md`. Read it before reporting a bypass; some limits are documented and accepted for v1.
