# Devpost submission checklist (Kiroween 2026)

Deadline from `docs/PLAN.md`: Dec 3, 2026, before 2:00 PM PT. Submit earlier if the form allows.

The rules page on Devpost returned HTTP 403 when the PRD was written. Confirm each field against
the live form before pasting. If the form asks for something not listed here, check `PRD.md`
(Open Decision 11) and add it to this file.

## 1. Project fields

| Devpost field | Paste |
|---------------|-------|
| Project name | SlopSeal |
| Tagline | Every install gets a seal. Every seal is a verdict. Every verdict is a receipt. |
| Category | Frankenstein (single entry; one main category per project) |
| Built with | Kiro (specs, steering, hooks), Python 3.11+, Hypothesis, ruff, mypy, GitHub Actions. Optional extra: needle-rs (Needle 3 runtime, not in v1) |
| License | MIT |

## 2. Pitch (one sentence)

> SlopSeal is a dependency trust firewall that checks each pip and npm install an AI coding agent makes and returns a signed ALLOW, BLOCK, or QUARANTINE verdict.

## 3. Links

| Field | Value |
|-------|-------|
| Repository | https://github.com/mazi3012/SlopSeal |
| Release tag | https://github.com/mazi3012/SlopSeal/tree/v1.0.0-kiroween (exists, pushed Nov 15, 2026, points at 030b773) |
| Demo video | `VIDEO_URL_PLACEHOLDER` (replace with the YouTube, Vimeo, Facebook, or Youku URL) |
| Kiro write-up | https://github.com/mazi3012/SlopSeal/blob/main/docs/WRITEUP.md |
| Product requirements | https://github.com/mazi3012/SlopSeal/blob/main/PRD.md |

## 4. Description (paste)

Paste the body of `docs/WRITEUP.md` into the long description field. Keep the heading, or
remove it if the form already shows the project name.

Confirm before pasting:

- The text says v1 is deterministic only. The Needle L2 gate failed.
- The 23-package corpus figures match `docs/L1_THRESHOLD_REVIEW.md`: 9 of 10 attacks blocked,
  1 of 13 legitimate packages flagged.

## 5. Demo instructions for judges (paste)

```bash
git clone https://github.com/mazi3012/SlopSeal.git
cd SlopSeal
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
bash scripts/demo.sh
```

The demo runs offline against a signed fixture snapshot. The last line should read
`demo: PASS (all beats)`.

## 6. Pre-submit steps

- [ ] `docs/DEMO_SCRIPT.md` take recorded and uploaded. Check that the exit codes on screen match the table in that file.
- [ ] `VIDEO_URL_PLACEHOLDER` replaced with the real URL in this file and in the Devpost form.
- [ ] Video is 3 minutes or less, and the host is YouTube, Facebook, Vimeo, or Youku.
- [ ] `docs/WRITEUP.md`, `README.md`, and this file are merged to `main`.
- [ ] CI is green on `main` (`lint, types, tests` and `properties`).
- [ ] `bash scripts/demo.sh` passes on a fresh clone of `main`.
- [ ] `scripts/check_credentials.sh origin/main..HEAD` passes on the release branch.
- [x] Tag `v1.0.0-kiroween` exists on origin (030b773, Nov 15, 2026). The docs cleanup merges after it. Re-point the tag only with your approval, and only before submission.
- [ ] Form fields checked against the live Devpost page, not only this file.

## 7. Known limits to state in the form (already in the write-up)

- v1 is deterministic only. The semantic layer (Needle 3) failed its pre-registered gate.
- The intent check confirms that a declared API exists. It does not confirm that the package
  fits the purpose.
- The PATH shim is advisory. A call to the real binary by absolute path skips it.
- Measured on 23 fixture packages, not on a live registry.
