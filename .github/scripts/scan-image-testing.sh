#!/usr/bin/env bash
# The permanent vulnerability gate, then (only if it fails) the TEMPORARY Testing-only D-SSL check.
#
#   scan-image-testing.sh <image ref> <name> <output dir> <environment>
#
# 1. verify-permanent-gate.py proves the permanent gate is unchanged (no ignore rule, --fail-on high).
# 2. scan-image.sh, the permanent gate, runs exactly as everywhere else. If it passes: done.
# 3. If it fails, scan-exception.py reads that scan's own Grype JSON and accepts it ONLY when every
#    HIGH/CRITICAL finding is one of the exact OpenSSL 3.5.9-r1 findings in
#    .github/security/dssl-testing-exception.json, for an image listed there, in environment
#    "testing", from a listed workflow, before 2026-12-01T00:00:00Z. Anything else: the failure stands.
# Remove this file, scan-exception.py and the exception file on 1 Dec (removal procedure in
# docs/security/dssl-temporary-exception.md); the calls then go back to scan-image.sh.
set -euo pipefail

REF="${1:?usage: scan-image-testing.sh <image ref> <name> <output dir> <environment>}"
NAME="${2:?usage: scan-image-testing.sh <image ref> <name> <output dir> <environment>}"
OUT="${3:?usage: scan-image-testing.sh <image ref> <name> <output dir> <environment>}"
ENVIRONMENT="${4:?usage: scan-image-testing.sh <image ref> <name> <output dir> <environment>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
EXCEPTION=".github/security/dssl-testing-exception.json"

python3 -I "$HERE/verify-permanent-gate.py" .

mkdir -p "$OUT"
rm -f "$OUT/$NAME.grype.json" "$OUT/$NAME.dssl-exception.json"
status=0
"$HERE/scan-image.sh" "$REF" "$NAME" "$OUT" || status=$?
[ "$status" -eq 0 ] && exit 0

if [ ! -f "$EXCEPTION" ] || [ ! -s "$OUT/$NAME.grype.json" ]; then
  echo "::error::$REF: the permanent gate failed and no temporary exception can be evaluated; the failure stands"
  exit "$status"
fi
echo "--- $REF ($NAME): the permanent gate FAILED; checking the temporary Testing-only D-SSL exception"
python3 -I "$HERE/scan-exception.py" --grype-json "$OUT/$NAME.grype.json" --image "$NAME" \
  --environment "$ENVIRONMENT" --exception "$EXCEPTION" --evidence "$OUT/$NAME.dssl-exception.json"
