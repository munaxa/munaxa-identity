#!/usr/bin/env bash
# Vulnerability scan of a built image, with an SBOM kept as evidence. Runs in CI on every pull
# request and in the publish workflow BEFORE anything is pushed, so an image with a known HIGH or
# CRITICAL finding is never published.
#
#   scan-image.sh <image ref> <name> [output dir]
#
#   1. Syft writes the image's SBOM (SPDX JSON and Syft JSON) to <output dir>/<name>.*.json.
#   2. Grype matches that SBOM against its current vulnerability database (OS packages AND the
#      npm packages in the image) and fails on any finding of severity HIGH or above, fixed or not.
#      The full table is printed; JSON goes to <output dir>/<name>.grype.json.
#
# Exceptions: none by default. An accepted risk is an `ignore` rule in .grype.yaml at the
# repository root, and every rule must carry, on the comment line directly above it,
#   # exception: <CVE> owner=<who approved> expires=<YYYY-MM-DD> reason=<why>
# A rule without one, or past its expiry date, fails this script: an exception cannot silently
# outlive its approval. Nothing is ignored by severity, fix state or package type.
#
# The scanners are pinned by digest (multi-arch index), not by tag. They read the image through the
# local Docker daemon; nothing is pushed and no credential is used.
set -euo pipefail

REF="${1:?usage: scan-image.sh <image ref> <name> [output dir]}"
NAME="${2:?usage: scan-image.sh <image ref> <name> [output dir]}"
OUT="${3:-image-reports}"
SYFT_IMAGE="anchore/syft:v1.57.0@sha256:3c70e6d5979364cefdc22b51617a78fd264574d3bd6b4f84a351204147025e2a"
GRYPE_IMAGE="anchore/grype:v0.121.2@sha256:6a36234da13f9faa327306ac0b3dab3405cfa2b4eb20c8f904125a8707863913"
FAIL_ON="high"
CONFIG=".grype.yaml"

fail() { echo "::error::$REF: $*" >&2; exit 1; }

mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"
DB_CACHE="${RUNNER_TEMP:-/tmp}/grype-db"
mkdir -p "$DB_CACHE"

# Every exception names its approval and expires.
config_args=()
grype_args=()
if [ -f "$CONFIG" ]; then
  today="$(date -u +%F)"
  prev=""
  while IFS= read -r line; do
    if printf '%s\n' "$line" | grep -qE '^[[:space:]]*-[[:space:]]*vulnerability:'; then
      printf '%s\n' "$prev" | grep -qE '^[[:space:]]*# exception: [A-Z]+-[0-9]+-[0-9A-Za-z-]+ owner=[^ ]+ expires=[0-9]{4}-[0-9]{2}-[0-9]{2} reason=.+' \
        || fail "$CONFIG: '$line' has no '# exception: <id> owner= expires= reason=' line above it"
      if printf '%s\n' "$prev" | grep -qiE ' owner=(pending|tbd|none)( |$)'; then
        fail "$CONFIG: exception has no owner approval yet: $prev"
      fi
      expires="$(printf '%s\n' "$prev" | sed -nE 's/.* expires=([0-9]{4}-[0-9]{2}-[0-9]{2}) .*/\1/p')"
      [[ "$expires" > "$today" || "$expires" == "$today" ]] || fail "$CONFIG: exception expired on $expires: $prev"
    fi
    [ -n "$(printf '%s' "$line" | tr -d '[:space:]')" ] && prev="$line"
  done < "$CONFIG"
  if grep -qE '^[[:space:]]*(-[[:space:]]*)?(fix-state|namespace|vex-status|match-type):|^(only-fixed|only-notfixed|fail-on-severity|exclude|ignore-wontfix):' "$CONFIG"; then
    fail "$CONFIG: an exception may name a vulnerability (and package), never a class of findings"
  fi
  config_args=(-v "$PWD/$CONFIG:/grype.yaml:ro")
  grype_args=(-c /grype.yaml)
fi

echo "--- SBOM of $REF ($NAME)"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$OUT_ABS:/out" \
  "$SYFT_IMAGE" "docker:$REF" -q \
  -o "spdx-json=/out/$NAME.spdx.json" -o "syft-json=/out/$NAME.syft.json"
[ -s "$OUT/$NAME.syft.json" ] || fail "syft wrote no SBOM"

echo "--- Vulnerabilities in $REF ($NAME), failing on $FAIL_ON or above"
status=0
docker run --rm \
  -v "$OUT_ABS:/out" -v "$DB_CACHE:/db" \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_DB_AUTO_UPDATE=true -e GRYPE_DB_VALIDATE_AGE=true \
  "${config_args[@]}" \
  "$GRYPE_IMAGE" "sbom:/out/$NAME.syft.json" \
  "${grype_args[@]}" -o table -o "json=/out/$NAME.grype.json" --fail-on "$FAIL_ON" || status=$?

[ -s "$OUT/$NAME.grype.json" ] || fail "grype wrote no report (exit $status)"
# The database the result came from, so the evidence says when it was true.
docker run --rm -v "$DB_CACHE:/db" -e GRYPE_DB_CACHE_DIR=/db "$GRYPE_IMAGE" db status 2>/dev/null \
  | sed 's/^/grype db: /' || true

case "$status" in
  0) echo "$REF ($NAME): no finding of severity $FAIL_ON or above" ;;
  *) fail "findings of severity $FAIL_ON or above (grype exit $status); see the table above and $OUT/$NAME.grype.json" ;;
esac
