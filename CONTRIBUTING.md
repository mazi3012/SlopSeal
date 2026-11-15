# Contributing to SlopSeal

This guide applies to people and to AI agents. Agents should also read `AGENTS.md`.

## Before you start

1. Read `PRD.md` for scope and `.kiro/specs/seal/` for behavior.
2. Check `docs/PLAN.md` for what is in progress. Work outside the current phase needs a conversation first.
3. Features listed under the roadmap in `PRD.md` are out of scope for v1.

## Setup

Requires Python 3.11 or newer.

```bash
git clone https://github.com/mazi3012/SlopSeal.git
cd SlopSeal
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Workflow

SlopSeal is spec-first. Order of work:

1. **Requirement.** Find or add the `R-...` id in `.kiro/specs/seal/requirements.md`.
2. **Property.** If an invariant is affected, update `.kiro/specs/seal/properties.md`.
3. **Design.** If structure changes, update `.kiro/specs/seal/design.md`.
4. **Test.** Write a test that names the requirement or property id.
5. **Code.** Make the change.

Spec and steering changes land before the code that depends on them.

## Branches and commits

- Branch from `main`: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`.
- Never commit to `main` directly.
- Conventional commits with a requirement id:

  ```
  feat(core): existence check [R-2.1]
  fix(quarantine): reject retry for a different package [R-Q-5]
  docs(design): clarify snapshot loading
  ```

  Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `ci`.
- One logical change per commit.

## Checks

A change is ready when all of these pass:

```bash
ruff check . && ruff format --check .
mypy src/slopseal
pytest
```

Changes to `.kiro/steering/dependency-trust.md` must also pass `pytest src/tests/properties`.

## Pull requests

Use the template in `.github/pull_request_template.md`. A PR needs:

- The requirement ids it covers.
- Test evidence (command output).
- A note on any spec, steering, or dependency change.

Keep PRs small. A reviewer should be able to check one in under 15 minutes.

## Rules that are not negotiable

- **Fail closed.** No change may turn an unknown or error state into ALLOW.
- **Property tests are not loosened to pass a change.** If one fails, fix the code or the spec and say which.
- **No policy literals in code.** Thresholds and lists come from the policy file.
- **No secrets** in code, tests, fixtures, logs, or commit messages.
- **New dependencies** need a stated reason and an entry in `docs/adr/`.

## Credential checks

Credential checks must be value-level, not keyword-level. This is a security product; its docs discuss credentials as prose. Run `scripts/check_credentials.sh` before pushing. Its keyword output is informational only.

## Code style

Enforced by ruff and mypy. Details in `.kiro/steering/tech.md`.

## Reporting security issues

Do not open a public issue. See `SECURITY.md`.

## License

By contributing you agree that your contributions are licensed under the MIT License.
