# L1 threshold review (Phase 5)

Scope: the deterministic checks (2.1–2.11) run over the 23 fixture packages in
`src/slopseal/fixtures/`, using the policy in `.kiro/steering/dependency-trust.md` and the
offline snapshot (`as_of` 2026-11-18). The review changed no threshold and no label.

Reproduce: `python scripts/l1_review.py`. Labels: `docs/l1_review_labels.json`, committed
before the run (commit `eb5bf1b`).

## Method

- Labels were fixed before the run. Classes come from fixture metadata: typosquat is a
  misspelling of a popular package, legit-old was first published in 2016 or earlier, and the
  new packages split into slopsquat and legit-new by publish age and maintainer history.
  Counts: 5 slopsquat, 5 typosquat, 5 legit-new, 8 legit-old (the PRD corpus shape).
- Expected: slopsquat and typosquat BLOCK (PRD success metric: 100%). legit-new and legit-old
  ALLOW. Any BLOCK or QUARANTINE on a legit package counts as a false positive.
- Each package was checked at its latest version. The rate limit was off, because it is not an
  L1 check.

## Results

| Class | Packages | Expected | Result |
|---|---|---|---|
| typosquat | 5 | BLOCK | 5 BLOCK (`typosquat`) |
| slopsquat | 5 | BLOCK | 4 BLOCK (`install_script`, `new_package`, `malware`), 1 ALLOW (`pandas-numpy-utils`) |
| legit-new | 5 | ALLOW | 5 ALLOW |
| legit-old | 8 | ALLOW | 7 ALLOW, 1 BLOCK (`urlnorm` 0.9.0, `cve`) |

- Detection: 9 of 10 attack packages blocked (90%). The PRD target is 100%.
- False positives: 1 of 13 legit packages flagged (7.7%).

## Findings

### 1. False negative: `pandas-numpy-utils` 0.2.0 (pypi)

The package was first published 2026-11-11. At the snapshot date (2026-11-18) it is exactly
7.0 days old. Check 2.4 flags a package younger than `new_package_max_age_days = 7`, and 7.0 is
not younger than 7. The check did what the rule says. My label assumed newness from the
maintainer account age (3 days), which check 2.4 does not read.

Options, not applied:
- Keep the rule and record the boundary as a known limit (a package at exactly the age
  threshold passes). This is the default.
- Move the threshold. That would be tuning after seeing the result. It needs a new,
  pre-registered reason and the policy floor (`new_package_max_age_days >= 7`) would still apply.
- Add a maintainer-age signal. That is a new check and out of scope for Phase 5.

### 2. False positive: `urlnorm` 0.9.0 (npm)

The fixture OSV snapshot lists `GHSA-fixture-urlnorm-0001` (critical, prototype pollution) for
exactly this version, and check 2.6 (`cve`) blocks it. The block is correct behavior. My
`legit-old` label assumed the package was clean, and the snapshot says the pinned version is
not. Under the pre-registered label this is a false positive. If the label were
"legit-old with critical advisory", this would be a correct block.

I did not change the label. Relabeling after a run would be tuning. The decision belongs to
you.

## Verdict on the gate

The gate needs an acceptable false-positive rate on the 23 fixtures. Under the pre-registered
labels the rate is 1 of 13 (7.7%), and the one flagged package has a critical advisory in the
snapshot. Detection is 9 of 10, below the PRD's 100% target because of the boundary case in
finding 1.

Decision needed: accept both results as documented limits, or approve a labeled change to
either the threshold or the label, recorded as a separate reviewed commit.
