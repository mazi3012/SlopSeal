# SlopSeal Demo Runbook (3-minute video)

Source: `PRD.md`, Demo Scripts. Every command here was run against the repository and matches
the exit codes shown. Record in the offline fixture mode, so the output is reproducible.

## Before you record

1. Use a clean checkout of the tagged release, not a working copy with local edits.
2. Use a terminal with at least 100 columns and a large font. Hide shell history and personal
   prompts.
3. Set up the environment once, off camera:

   ```bash
   git clone https://github.com/mazi3012/SlopSeal.git
   cd SlopSeal
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

4. Before every take, set a fresh state directory and the offline snapshot. The rate limit is
   10 install attempts per minute, and state carries over between runs, so a stale state
   directory can block the take.

   ```bash
   export SLOPSEAL_OFFLINE_SNAPSHOT=1
   export SLOPSEAL_STATE_DIR="$(mktemp -d)"
   ```

5. Do not run a real `pip install` or `npm install` on camera. The fixture names are not
   real packages, and a live install would fetch whatever PyPI or npm serves for that name. The
   shim beat uses stub tools, which `scripts/demo.sh` sets up.

## Shot list

Total runtime is about 3 minutes. The times are targets.

| Time | Beat | Command | Expected on screen |
|------|------|---------|--------------------|
| 0:00 | Intro | none, title card | "Every install gets a seal." |
| 0:15 | 1. Slopsquat name | `slopseal check csv-parser-pro --version 0.1.0` | exit 1. Violation JSON with `"check": "existence"` and the remedy `Did you mean csv-parser?` |
| 0:45 | 2. API mismatch | `slopseal check csv-parser --version 1.2.0 --expected-api csv.reader --purpose "parse CSV"` | exit 75. Payload JSON with `api_absent`, `found_apis` (`parse`, `parse_file`), `retry_budget_remaining: 1`, and no confidence field |
| 1:15 | 3. Retry | `slopseal check csv-parser --version 1.2.0 --expected-api parse --purpose "parse CSV" --quarantine-id <id>` | exit 0. Summary line `ALLOW csv-parser==1.2.0` |
| 1:35 | 4. PATH shim | `bash scripts/demo.sh`, screen-captured from the beat 4 header onward | pip and npm through the shim: two blocks, one allowed pin that runs the stub, one unpinned install refused |
| 2:05 | 5. Audit intact | `slopseal audit verify` | exit 0 |
| 2:20 | 6. Tampering | the demo's beat 6 flips one verdict in a copy and verifies it | exit 1. The chain or seal check fails |
| 2:40 | 7. Weakened policy | the demo's beat 7 runs `slopseal policy check` on a copy with a lower floor | exit 1. Floor violated |
| 2:55 | Close | `ls docs/WRITEUP.md` and the repo URL on screen | Repository URL and the Kiro write-up path |

### Beat-by-beat commands for a manual take

Run these in order after the environment is set and the state directory is fresh:

```bash
slopseal check csv-parser-pro --version 0.1.0
slopseal check csv-parser --version 1.2.0 --expected-api csv.reader --purpose "parse CSV"
# copy the quarantine_id from the payload above into QID, then:
QID=<quarantine_id>
slopseal check csv-parser --version 1.2.0 --expected-api parse --purpose "parse CSV" --quarantine-id "$QID"
slopseal audit verify
slopseal policy check
```

Beat 4 (the shim) and beats 6 and 7 (the tampered log and the weakened policy) run inside
`scripts/demo.sh`. Use that script for those segments so the stub tools and the temporary copies
are set up correctly. A manual take of those steps would need the same setup by hand.

### Full automated run (use for the proof shot)

```bash
bash scripts/demo.sh
```

It prints one `PASS` or `FAIL` line per assertion and ends with `demo: PASS (all beats)`.
Show the final line on camera. The script uses its own temporary state directory and needs no
manual setup beyond the venv.

## Voiceover

Keep each line under the time shown. Speak in the present tense.

- 0:15, beat 1: "The agent asks for a package that does not exist. SlopSeal blocks it and suggests the real name."
- 0:45, beat 2: "The package exists, but it does not export the API the agent expects. SlopSeal does not guess. It quarantines the install and lists the real exports."
- 1:15, beat 3: "The agent retries with an API that exists. SlopSeal allows it, once."
- 1:35, beat 4: "pip and npm go through the same check. Blocked packages never reach the real tool."
- 2:05, beat 5: "Every decision is in a hash-chained, signed log. The log verifies."
- 2:20 and 2:40: "A tampered log fails. A weakened policy fails the floor check, so the agent cannot loosen its own rules."
- 2:55, close: "SlopSeal is deterministic in v1. The semantic layer did not pass its gate, and the write-up says so."

## Known limitation to say on camera

The deterministic intent check confirms that the declared API exists. It does not confirm that
the package fits the purpose. A retry that declares a real API passes even if the package is wrong
for the task. The write-up in `docs/WRITEUP.md` covers this.

## After the take

- Check the exit codes match the table above. If one does not, the take is wrong. Do not edit
  the output. Record again with a fresh state directory.
- Upload to YouTube, Vimeo, Facebook, or Youku. Devpost requires one of these hosts.
- Put the video URL in `docs/SUBMISSION_CHECKLIST.md` in place of the placeholder.
