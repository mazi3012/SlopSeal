## What and why

<!-- One or two sentences. -->

## Requirements covered

<!-- Ids from .kiro/specs/seal/requirements.md, for example R-2.1, R-Q-1. -->

## Checks

```
ruff check . && ruff format --check .
mypy src/slopseal
pytest
```

<!-- Paste results, or state which were not run and why. -->

## Checklist

- [ ] Spec or steering changes are in this PR or already merged
- [ ] Tests name the requirement or property they cover
- [ ] No property test was loosened, skipped, or deleted
- [ ] No policy threshold or list added as a literal in code
- [ ] No unknown or error state can now reach ALLOW
- [ ] New dependency? Reason stated and ADR added in `docs/adr/`
- [ ] No secrets in code, fixtures, logs, or commit messages
