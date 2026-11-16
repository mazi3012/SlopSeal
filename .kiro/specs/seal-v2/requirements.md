
# SlopSeal v2: Requirements

**Relation to v1:** `.kiro/specs/seal/` is the v1 contract and stays unchanged. v2 adds requirements. Where a v2 requirement changes a v1 statement, the v2 requirement names the v1 statement it supersedes. v1 files are not edited.
**Format:** EARS (Easy Approach to Requirements Syntax).
**Requirement IDs:** `R-<area>-<n>`. Commit messages cite them, for example `feat(hooks): verdict-aware hook [R-G-1]`.

| Prefix | Area | Phase | Status |
|--------|------|-------|--------|
| `R-G-*` | Gate: the Kiro install hook | 1 (`feat/v2-hook`) | Specified below |
| `R-C-*` | Closure: dependencies of an installed package | Not scheduled | Reserved. Requirements are written at the start of that phase |
| `R-S-*` | Signing: Ed25519 seals behind an optional extra | Not scheduled | Reserved. Needs ADR-0004 before any code |

The meaning of `R-C` and `R-S` comes from the v1 roadmap (THREAT_MODEL T16 and `docs/adr/0002-stdlib-first.md`). It is an assumption until the owner confirms it.

Terms used below:

- **Install** (for the hook): a simple command in the hook payload's `tool_input.command` that the v1 hook detects as an install. Detection is unchanged from v1.
- **Verifiable install**: an install that `slopseal.intercept.parse` turns into one or more registry packages, each at an exact version. That covers `pip install name==x.y.z`, `npm install name@x.y.z`, and `npx`, `npm exec`, `npm x` with `name@x.y.z`.
- **Unverifiable install**: any other install.

---

## 1. Gate: the verdict-aware install hook

**R-G-1 (verdict per package).** When the hook payload's `tool_input.command` contains a verifiable install, the system shall call `verify_install` once for each distinct package and exact version that the command names, without an intent. Each call is an install attempt for the rate limit (R-4.7).

**R-G-2 (ALLOW).** When every call under R-G-1 returns ALLOW and the command contains no unverifiable install, the system shall exit 0, so the command runs. The system shall write one summary line per package, and any warnings, to stderr.

**R-G-3 (BLOCK).** When any call under R-G-1 returns BLOCK, the system shall exit 2. For each blocked package the system shall write to stderr the package, the version, the failed check, the reason, and a suggested fix. The suggested fix is the check's remedy when it has one, and a fixed fallback text otherwise.

**R-G-4 (QUARANTINE).** When any call under R-G-1 returns QUARANTINE, the system shall exit 2. For each quarantined package the system shall write to stderr the package, the version, the check name (`mismatch_type`), the `quarantine_id`, and the next step.

**R-G-5 (unverifiable installs).** When the command contains an unverifiable install, the system shall exit 2 and write the reason and a suggested fix to stderr. Unverifiable includes: an unpinned name or a version range, a URL or local path, `-r` or another option that changes the source, a tool other than pip, npm, and npx, an install that names no package, packages supplied through `xargs`, an environment assignment before the install (it can redirect the index), and text the hook cannot parse. The system shall not resolve versions and shall not rewrite the command, because the hook can only allow or block the command it was given. R-1.7 does not apply to the hook.

**R-G-6 (fail closed).** If the hook cannot reach a decision, the system shall exit 2. That includes: an unreadable payload, a payload that does not close within the stdin timeout, a command that cannot be parsed, a policy, seal key, or snapshot error, an audit log that cannot be written, and a decision that does not finish within the hook deadline. When `tool_input.command` is missing or not a string, the system shall exit 2 for any install found in the payload, because it cannot know what will run.

**R-G-7 (non-install).** When the command contains no install, the system shall exit 0, shall call no verdict, shall write nothing to the audit log, and shall write nothing to stdout or stderr. This is the v1 behavior and it is unchanged.

**R-G-8 (exit codes and streams).** The hook shall exit with 0 or 2 only. Exit 0 is reached only through R-G-2 or R-G-7. The hook shall write nothing to stdout.

**R-G-9 (hook config).** The hook description in `.kiro/hooks/block-agent-installs.json` shall state the verdict behavior of R-G-2 to R-G-5. The packaged copy at `src/slopseal/hooks/block-agent-installs.json` shall stay identical to it (R-1.9). The `sh -c` wrapper that maps an exit code other than 0 or 2 to exit 2 shall stay.

**R-G-10 (untrusted metadata).** The system shall treat the text of a verdict reason as data. The hook shall write it as a JSON string value, never as prose that the agent could read as an instruction, and shall cap its length.

### Supersedes

- v1 `design.md` section 11: "It does not verify packages." This no longer holds for verifiable installs.
- v1 `THREAT_MODEL.md` T11: "The hook does not verify packages." Same.

Both v1 statements stay as written until the owner decides to edit v1. The Phase 1 pull request lists every place that is now out of date.
