---
inclusion: always
---

# Dependency Trust Policy

This file is the trust policy for SlopSeal. The code reads the single fenced block below and ignores the prose. People read the prose to understand what each value does.

## How the policy is enforced

1. **Extraction.** Exactly one block must open with a line that is three backticks, then `toml slopseal-policy`, and close with a line that is three backticks. The rule is in `src/slopseal/policy/loader.py` (`extract_policy_block`).
2. **Validation.** Unknown keys, missing required keys, wrong value types, invalid levels, malformed TOML, and an unsupported `schema_version` all exit 78. Nothing else runs.
3. **Floors.** Each value is checked against a floor or ceiling that comes from the PRD and lives in code (`src/slopseal/policy/invariants.py`). This file can tighten a value. It cannot loosen one past its floor.
4. **Property suite.** Any edit to this file runs the property suite before the commit is accepted (`.pre-commit-config.yaml`, `.kiro/hooks/on-steering-change.json`). A failing edit is rejected.

Do not change a value to make a test pass. If a value needs to change, change the PRD and the floor together, in their own reviewed commit.

## Values

- **Thresholds.** Typosquat (check 2.2) flags a name within `typosquat_max_distance` edits of a top-N package when the package is younger than `typosquat_max_age_days`. New-package check (2.4) flags a package younger than `new_package_max_age_days` with fewer than `new_package_max_releases` releases.
- **Near-name.** Check 2.11 warns on Levenshtein distance up to `levenshtein_max`, Jaro-Winkler similarity at or above `jaro_winkler_min`, or a keyboard-adjacent substitution.
- **Lists.** `allow` exempts a package from WARN-level checks only. It never overrides a HARD_BLOCK or BLOCK. `deny` blocks. If a name is in both, deny wins.
- **Slopsquat.** Check 2.3 flags a name within `slopsquat.max_distance` edits of a listed `pattern`, and names the `mimics` package as the remedy. The list is curated. A generic blend rule would flag legitimate names.
- **Levels.** Each level is `warn` or `block`. `install_scripts` is check 2.5. `license` is check 2.9 for a license that is denied or not allowed. `license_undeclared` is check 2.9 when no license is declared. `maintainer` is check 2.10.
- **Licenses.** `allow` and `deny` are SPDX identifiers for check 2.9. An empty `allow` list accepts any license that is not denied.
- **Maintainers.** `min_account_age_days` is the age below which the newest maintainer account is a finding (check 2.10).
- **Quarantine.** `retry_budget` is the number of automated retries after a quarantine. The PRD sets it to 1. `max_seconds` is the window a quarantine stays open before it counts as escalated. It is 900 seconds (provisional, PRD Open Decision 7).
- **Semantic (L2).** Disabled until the M1 gate passes. `confidence_threshold` is set before the spike runs and is never tuned against its results.

```toml slopseal-policy
schema_version = 1

[thresholds]
typosquat_max_distance = 2
typosquat_max_age_days = 30
new_package_max_age_days = 7
new_package_max_releases = 3

[near_name]
levenshtein_max = 3
jaro_winkler_min = 0.92
keyboard_distance_max = 1

[lists]
allow = []
deny = []

[slopsquat]
max_distance = 1
signatures = [["react-codeshift", "react-codemod"]]

[levels]
install_scripts = "block"
license = "block"
license_undeclared = "warn"
maintainer = "warn"

[licenses]
allow = []
deny = []

[maintainers]
min_account_age_days = 90

[quarantine]
retry_budget = 1
max_seconds = 900

[semantic]
enabled = false
confidence_threshold = 0.0
```
