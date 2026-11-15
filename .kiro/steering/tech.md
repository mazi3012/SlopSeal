---
inclusion: always
---

# SlopSeal: Tech Stack and Commands

## Stack

| Concern | Choice |
|---------|--------|
| Language | Python 3.11 or newer |
| Layout | `src/` layout, package `slopseal` |
| Build | `pyproject.toml`, setuptools backend |
| Runtime dependencies | Zero mandatory (ADR 0002). Optional extra: `slopseal[needle]` for L2. |
| Live-mode HTTP | `urllib.request` from the standard library |
| Tests | pytest, Hypothesis |
| Lint and format | ruff (`ruff check`, `ruff format`) |
| Types | mypy, strict mode on `src/slopseal` |
| Policy parsing | `tomllib` (standard library) |

## Commands

Run from the repo root.

```bash
pip install -e ".[dev]"           # install with dev tools
ruff check . && ruff format --check .
mypy src/slopseal
pytest                             # all tests
pytest src/tests/unit              # fast loop
pytest src/tests/properties        # property suite (500+ cases per property)
```

A change is ready when lint, mypy, and pytest all pass. Run them before reporting work as done.

## Dependency rules

- Use the standard library when it does the job. Examples: `tomllib`, `hashlib`, `json`, `difflib`, `argparse`.
- The default install has zero mandatory runtime dependencies. This is deliberate: SlopSeal is a dependency firewall, so it must not add to the supply chain it guards.
- A new dependency of any kind, mandatory or in an extra, needs a stated reason in the PR and a short ADR in `docs/adr/`. Already anticipated: Needle bindings in the `needle` extra (only if the M1 gate passes), and a signing library if Open Decision 6 cannot be met with the standard library.
- Anything needed to verify a snapshot or a seal must work in the default install, so it cannot live in an optional extra.
- Dev dependencies go in `[project.optional-dependencies].dev`.
- Never add a dependency to avoid writing about 20 lines.

## Coding conventions

- Type-annotate every function. No `Any` in public signatures.
- Use frozen `dataclass` for data and `Enum` for closed sets. Do not pass raw dicts between modules.
- Check functions are pure: they take data and return `CheckResult`. I/O goes through the Protocols in `design.md` section 4.
- Represent "unknown" as an explicit value (`RegistryUnknown`), not `None` and not an exception.
- Do not catch bare `Exception` except in the failclosed wrapper in `verdict.py`.
- No threshold, list, or limit as a literal in `core/`. Read it from the policy object.
- Log with the `logging` module. Never log secrets, tokens, or full environment dumps.
- Output to stdout is machine-readable JSON only. Human text goes to stderr.

## Commit and PR conventions

- Conventional commits with a requirement id: `feat(core): existence check [R-2.1]`.
- Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `ci`.
- One logical change per commit. Spec and steering changes land before the code that depends on them.
- Never commit to `main` directly. Use a branch and a pull request.
- A change to `.kiro/steering/dependency-trust.md` must pass the property suite.

## Environment

Variables are documented in `.env.example`. `SLOPSEAL_OFFLINE_SNAPSHOT=1` makes all checks run against the signed snapshot with no network.
