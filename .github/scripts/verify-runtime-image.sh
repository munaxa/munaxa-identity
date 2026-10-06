#!/usr/bin/env sh
# Verify a built Identity runtime image before anything deploys it.
#
#   .github/scripts/verify-runtime-image.sh <image reference, ideally by digest>
#
# One image serves two jobs in AWS: the Identity ECS service (`node dist/main.js`, the image's CMD)
# and the one-off ECS tasks that override the command — `node dist/migrate.js`, and the provisioning
# scripts. So this checks both, and the properties the Dockerfile exists to guarantee: x86_64, not
# root, no development toolchain, no credential in the layer history.
#
# It never starts the HTTP service and needs no database: the migration runner is invoked with
# `--help`, and once with no credential, which must fail fast with its own JSON error rather than
# hang or start anything.
set -eu

REF="${1:?usage: verify-runtime-image.sh <image reference>}"
fail() { echo "::error::$1" >&2; exit 1; }
run() { docker run --rm --network none --entrypoint sh "$REF" -c "$1"; }

# Architecture: Fargate tasks are declared X86_64; an arm64 image would not start there.
arch=$(docker image inspect --format '{{.Architecture}}' "$REF")
[ "$arch" = "amd64" ] || fail "image architecture is $arch, expected amd64"
echo "architecture: $arch"

# The service's contract with ECS: the command, the directory it runs from, the port.
cmd=$(docker image inspect --format '{{json .Config.Cmd}}' "$REF")
[ "$cmd" = '["node","dist/main.js"]' ] || fail "CMD changed: $cmd"
workdir=$(docker image inspect --format '{{.Config.WorkingDir}}' "$REF")
[ "$workdir" = "/app/apps/api" ] || fail "working directory changed: $workdir"
entrypoint=$(docker image inspect --format '{{json .Config.Entrypoint}}' "$REF")
# The official node image's own entrypoint, which only execs the command it is given — inherited, as
# it always has been. Anything else would sit between ECS's command override and the process.
case "$entrypoint" in null | '[]' | '["docker-entrypoint.sh"]') ;; *) fail "unexpected ENTRYPOINT: $entrypoint" ;; esac
echo "service command: $cmd in $workdir"

user=$(run 'id -un')
[ "$user" != "root" ] || fail "image runs as root"
echo "runs as: $user"

# `pnpm install --prod` relinks but does not garbage-collect pnpm's store, so this is a real check:
# it caught vitest, eslint, turbo and the Nest CLI shipping in a "production" image once already.
# (`typescript` and the `prisma` CLI are deliberately absent from this list: the lockfile resolves them
# as optional peers of `@prisma/client`, a production dependency, so every image so far carries them.
# Removing them is a dependency change, not a publishing one.)
for pkg in vitest eslint turbo '@nestjs+cli'; do
  if run "ls -d /app/node_modules/.pnpm/${pkg}@* 2>/dev/null" | grep -q .; then
    fail "development dependency $pkg present in the runtime image"
  fi
done
echo "no development toolchain"

# No credential in any layer's history: GitHub tokens, npm auth, AWS access keys.
if docker history --no-trunc --format '{{.CreatedBy}}' "$REF" |
  grep -qE 'ghp_|github_pat_|gh[osu]_[A-Za-z0-9]{20,}|_authToken=[A-Za-z0-9]|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'; then
  fail "a credential appears in image history"
fi
if run 'find / -name ".npmrc" -not -path "/proc/*" 2>/dev/null | xargs -r grep -l "_authToken=" 2>/dev/null' | grep -q .; then
  fail "an npmrc carrying a token is present in the image"
fi
echo "no credentials in history or filesystem"

# Identity generates its client into node_modules/.prisma/identity-client, so the bare
# `@prisma/client` entry point is not what proves it survived the production install.
run 'node -e "require(\"/app/node_modules/.prisma/identity-client\"); console.log(\"prisma client loads\")"'

# The one-off task entrypoints, present in the same image.
for file in dist/migrate.js dist/database/direct-connection.js scripts/owner-connection.mjs \
  scripts/bootstrap-account.mjs scripts/seed-work-roles.mjs \
  /app/prisma/migrations/20260901120000_identity_baseline/migration.sql \
  /app/artifacts/work-permissions.json; do
  run "test -f $file" || fail "missing from the image: $file"
done
echo "one-off task files present"

run 'node dist/migrate.js --help' | grep -q 'Usage: node dist/migrate.js' || fail "migrate --help failed"

# Without a credential the runner must refuse at once, in its own words, and exit 1 — proof the
# command runs the runner and not the service. `timeout` turns a hang into a failure.
set +e
out=$(docker run --rm --network none "$REF" timeout 30 node dist/migrate.js 2>&1)
code=$?
set -e
[ "$code" -eq 1 ] || fail "migrate without a credential exited $code, expected 1: $out"
echo "$out" | grep -q '"event":"migrate.failed"' || fail "migrate did not report migrate.failed: $out"
echo "$out" | grep -qi 'listening' && fail "migrate started a server: $out"
echo "migration runner refuses without a credential, starts nothing"

echo "runtime image verified: $REF"
