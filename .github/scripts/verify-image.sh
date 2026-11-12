#!/usr/bin/env bash
# Checks a built Identity image before anyone relies on it: in CI on every pull request, and in
# publish-images-ecr.yml on the exact digest that was pushed.
#
#   verify-image.sh <image ref> <runtime|migrate>
#
# It fails on the first problem and prints what it found. It reads the image only; it needs no
# credential and sends nothing anywhere.
#
#   1. linux/amd64, the platform ECS Fargate runs (X86_64 in munaxa-platform infra/aws).
#   2. Not root, by name and by uid.
#   3. zlib at or above 1.4-r0, the Alpine release that fixes CVE-2026-4738, and the loaded library
#      is that version (libz.so.1 -> libz.so.1.4*), not a stale copy beside the package record.
#   4. Exactly the operating-system packages of the pinned base image: the zlib fix may change a
#      version, never add or remove a package.
#   5. No registry credential in the image history or in any .npmrc inside the image.
#   6. runtime only: no development toolchain in node_modules.
set -euo pipefail

REF="${1:?usage: verify-image.sh <image ref> <runtime|migrate>}"
TARGET="${2:?usage: verify-image.sh <image ref> <runtime|migrate>}"
ZLIB_FIXED="1.4-r0"
DOCKERFILE="$(dirname "$0")/../../apps/api/Dockerfile"

fail() { echo "::error::$REF: $*" >&2; exit 1; }
in_image() { docker run --rm --entrypoint sh "$REF" -c "$1"; }

case "$TARGET" in runtime|migrate) ;; *) fail "unknown target '$TARGET'";; esac

platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$REF")"
[ "$platform" = "linux/amd64" ] || fail "platform is $platform, expected linux/amd64"

user="$(in_image 'id -un')"
uid="$(in_image 'id -u')"
{ [ "$user" != "root" ] && [ "$uid" != "0" ]; } || fail "runs as root ($user, uid $uid)"

zlib="$(in_image "apk info -v 2>/dev/null | sed -n 's/^zlib-\([0-9][^ ]*\)\$/\1/p'")"
[ -n "$zlib" ] || fail "zlib is not installed as a package (cannot verify CVE-2026-4738)"
cmp="$(in_image "apk version -t '$zlib' '$ZLIB_FIXED'")"
[ "$cmp" != "<" ] || fail "zlib $zlib is older than $ZLIB_FIXED (CVE-2026-4738)"
lib="$(in_image 'readlink /usr/lib/libz.so.1')"
case "$lib" in libz.so.1.4*) ;; *) fail "libz.so.1 resolves to $lib, not zlib 1.4";; esac

# The base the Dockerfile pins; every FROM must be either it or an earlier stage.
base="$(sed -n 's/^FROM \(node:[^ ]*@sha256:[0-9a-f]\{64\}\) AS base$/\1/p' "$DOCKERFILE")"
[ -n "$base" ] || fail "the Dockerfile's base stage is not pinned by digest"
docker image inspect "$base" >/dev/null 2>&1 || docker pull -q "$base" >/dev/null
want="$(docker run --rm --entrypoint sh "$base" -c "apk info 2>/dev/null | sort")"
have="$(in_image "apk info 2>/dev/null | sort")"
[ "$want" = "$have" ] || fail "OS packages differ from the base: $(diff <(echo "$want") <(echo "$have") | grep '^[<>]' | tr '\n' ' ')"

if docker history --no-trunc --format '{{.CreatedBy}}' "$REF" | grep -qE 'ghp_|ghs_|github_pat_|_authToken=[A-Za-z0-9]'; then
  fail "a credential appears in the image history"
fi
if in_image 'find / -name ".npmrc" 2>/dev/null | xargs grep -l "_authToken=[A-Za-z0-9]" 2>/dev/null' | grep -q .; then
  fail "an .npmrc carrying a token is present in the image"
fi

if [ "$TARGET" = runtime ]; then
  for pkg in vitest eslint turbo '@nestjs+cli'; do
    if in_image "ls -d /app/node_modules/.pnpm/${pkg}@* 2>/dev/null" | grep -q .; then
      fail "development dependency $pkg present in the runtime image"
    fi
  done
fi

echo "$REF ($TARGET): $platform, user $user (uid $uid), zlib $zlib ($lib), OS packages = base, no credential"
