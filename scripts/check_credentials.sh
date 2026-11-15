#!/usr/bin/env bash
# Pre-push credential check for commits this branch adds to origin/main.
#
# Value-level scan (blocking): looks for credential formats in added lines.
# Keyword scan (informational only): prints prose matches for review. It never
# fails the run, because this is a security product and its docs discuss
# credentials as prose.
#
# Usage: scripts/check_credentials.sh [range]    (default: origin/main..HEAD)
# Exit: 0 = no credential values found, 1 = at least one value-level match.

set -euo pipefail

range="${1:-origin/main..HEAD}"

# Value patterns. Each is a credential format, not a keyword.
value_patterns=(
    'AKIA[0-9A-Z]{16}'                       # AWS access key ID
    'ghp_[A-Za-z0-9]{36}'                    # GitHub personal access token
    'sk-[A-Za-z0-9]{48}'                     # OpenAI-style secret key
    'xox[baprs]-[A-Za-z0-9-]{10,}'           # Slack token
    '-----BEGIN [A-Z ]*PRIVATE KEY-----'     # PEM private key header
)

added_lines() {
    git log -p "$range" | grep '^+' | grep -v '^+++'
}

status=0

echo "== value-level scan (blocking), range: $range"
for pattern in "${value_patterns[@]}"; do
    if added_lines | grep -qE -- "$pattern"; then
        echo "FAIL: credential format matched: $pattern"
        added_lines | grep -nE -- "$pattern" | sed 's/^/  line /' | cut -c1-120
        status=1
    fi
done
if [ "$status" -eq 0 ]; then
    echo "PASS: no credential values in added lines"
fi

echo "== keyword scan (informational only, prose will match; does not affect exit code)"
keyword_hits=$(added_lines | grep -iE 'api[_-]?key|token|secret|bearer' | grep -viE 'example|placeholder|your-|xxx' | wc -l | tr -d ' ')
echo "informational: $keyword_hits keyword line(s). Review by hand only if a value-level match appears above."

exit "$status"
