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
- **Limits.** `max_installs_per_minute` is the rate limit (PRD 4.7). Install attempts beyond it in a rolling 60-second window are BLOCKED before any check runs. Every attempt counts, including blocked ones, so a blocked agent cannot reset the window by retrying. The value 10 is the v1 setting (PRD Open Decision 7, resolved).
- **Quarantine.** `retry_budget` is the number of automated retries after a quarantine. The PRD sets it to 1. `max_seconds` is the window a quarantine stays open before it counts as escalated. It is 900 seconds (PRD Open Decision 7, resolved).
- **Compiled wheels.** A version with no universal wheel can run install-time code, so check 2.5 blocks it. `[compiled_wheels]` is a reviewed exception for one exact version of one package. It applies only when the release names the reviewed publisher, the host platform has a reviewed wheel, and that wheel's sha256 equals the pin. An sdist alone is refused. The live OSV check still runs. The allowlist is in code (`src/slopseal/policy/invariants.py`), and the policy cannot widen it. A `known_exports` record names one symbol that a reviewed version exports, and clears only a `dynamic_exports` api_surface block for that symbol (R-CW-2). Reviewed by owner on 2026-11-17, ADR 0005. Install with `--only-binary` and `--require-hashes` from `requirements/sign.lock`.
- **Semantic (L2).** Not in v1: the M1 gate failed (`docs/needle_spike.csv`). It stays disabled. `confidence_threshold` is 0.5, pre-registered before the spike runs. It is the midpoint between the model card's figures for a wrong call (0.26) and a correct one (0.93). It is never tuned against the spike results.

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

[limits]
max_installs_per_minute = 10

[quarantine]
retry_budget = 1
max_seconds = 900

[semantic]
enabled = false
confidence_threshold = 0.5

[compiled_wheels.cryptography]
version = "50.0.2"
publisher = "github.com/pyca/cryptography"
reviewed_by = "owner"
reviewed_on = "2026-11-17"
adr = "0005"

[compiled_wheels.cryptography.platforms.linux-x86_64]
wheel = "cryptography-50.0.2-cp39-abi3-manylinux_2_28_x86_64.whl"
sha256 = "f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5"

[compiled_wheels.cryptography.platforms.macos-arm64]
wheel = "cryptography-50.0.2-cp39-abi3-macosx_11_0_arm64.whl"
sha256 = "0ec5f09541743261e66e291b4a0cbf0fb2997aeaab6d9e9c740b9dba1b58d1c2"

[[compiled_wheels.cryptography.known_exports]]
package = "cryptography"
version = "50.0.2"
symbol = "ed25519.Ed25519PublicKey"
reviewer = "owner"
date = "2026-11-17"
```
