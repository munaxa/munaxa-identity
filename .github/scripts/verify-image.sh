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
#   3. zlib at or above 1.4-r0, the Alpine release that fixes CVE-2026-4738; the libz the loader
#      maps is that package's libz.so.1.4*, and no libz file exists that the package does not own.
#   4. Exactly the operating-system packages of the pinned base image: the zlib fix may change a
#      version, never add or remove a package.
#   5. No registry credential in the image history or in any .npmrc, and no build-proxy CA.
#   6. runtime only: no development toolchain in node_modules.
#   7. The libraries a running Node process maps after loading the Prisma engine: the musl loader,
#      no glibc, every shared object outside node_modules owned by an Alpine package (so the
#      scanner, scan-image.sh, sees every one of them).
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
cmp="$(in_image "apk version -t '$zlib' '$ZLIB_FIXED'" || true)"
case "$cmp" in
  '='|'>') ;;
  '<') fail "zlib $zlib is older than $ZLIB_FIXED (CVE-2026-4738)" ;;
  *) fail "cannot compare zlib '$zlib' with $ZLIB_FIXED" ;;
esac
# The library the dynamic loader actually maps (musl searches /lib before /usr/lib), resolved to
# its file, must belong to that zlib package; and no other libz may exist outside the package.
lib="$(in_image "ldd /sbin/apk | sed -n 's/^[[:space:]]*libz\.so\.1 => \([^ ]*\) .*/\1/p'")"
[ -n "$lib" ] || fail "cannot find the libz the loader maps"
lib="$(in_image "readlink -f '$lib'")"
case "$lib" in */libz.so.1.4*) ;; *) fail "the loader maps $lib, not zlib 1.4";; esac
# As root for this read only, so a libz in a directory the image user cannot read is still found.
stray="$(docker run --rm --user 0 --entrypoint sh "$REF" -c "find / -xdev -name 'libz.so*' 2>/dev/null | while read -r f; do apk info -W \"\$f\" 2>/dev/null | grep -q ' is owned by zlib-$zlib\$' || echo \"\$f\"; done")"
[ -z "$stray" ] || fail "libz files not owned by zlib-$zlib: $(echo "$stray" | tr '\n' ' ')"

# The base the Dockerfile pins; every FROM must be either it or an earlier stage.
base="$(sed -n 's/^FROM \(node:[^ ]*@sha256:[0-9a-f]\{64\}\) AS base$/\1/p' "$DOCKERFILE")"
[ -n "$base" ] || fail "the Dockerfile's base stage is not pinned by digest"
docker image inspect "$base" >/dev/null 2>&1 || docker pull -q "$base" >/dev/null
want="$(docker run --rm --entrypoint sh "$base" -c "apk info 2>/dev/null | sort")"
have="$(in_image "apk info 2>/dev/null | sort")"
[ "$want" = "$have" ] || fail "OS packages differ from the base: $(diff <(echo "$want") <(echo "$have") | grep '^[<>]' | tr '\n' ' ')"

# What the loader really maps, not what the package database says.
maps_js='const e=process.argv[1]; if (e) process.dlopen({ exports: {} }, e);
const seen=new Set(); for (const l of require("fs").readFileSync("/proc/self/maps","utf8").split("\n")) {
  const f=l.split(/\s+/)[5]; if (f && f.startsWith("/") && /\.so(\.|$)|\.node$/.test(f)) seen.add(f); }
console.log([...seen].join("\n"));'
engine=""
if true; then
  engine="$(in_image "find / -xdev -name 'libquery_engine-linux-musl-openssl-3.0.x.so.node' 2>/dev/null | head -n1")"
  [ -n "$engine" ] || fail "no linux-musl-openssl-3.0.x Prisma engine in the image"
fi
mapped="$(docker run --rm --entrypoint node "$REF" -e "$maps_js" "$engine")" || fail "node could not load $engine"
echo "$mapped" | grep -q '/ld-musl-x86_64\.so\.1$' || fail "node is not running on the musl loader"
if echo "$mapped" | grep -qE '(ld-linux|libc\.so\.6|/x86_64-linux-gnu/)'; then
  fail "a glibc library is mapped: $(echo "$mapped" | grep -E '(ld-linux|libc\.so\.6|/x86_64-linux-gnu/)' | tr '\n' ' ')"
fi
unowned=""
for f in $(echo "$mapped" | grep -v '/node_modules/'); do
  real="$(in_image "readlink -f '$f'")"
  in_image "apk info -W '$real' >/dev/null 2>&1" || unowned="$unowned $real"
done
[ -z "$unowned" ] || fail "mapped libraries no Alpine package owns:$unowned"
loaded="$(echo "$mapped" | sed 's#.*/##' | sort -u | tr '\n' ' ')"

if docker history --no-trunc --format '{{.CreatedBy}}' "$REF" | grep -qE 'ghp_|ghs_|github_pat_|_authToken=[A-Za-z0-9]'; then
  fail "a credential appears in the image history"
fi
if in_image 'find / -name ".npmrc" 2>/dev/null | xargs grep -l "_authToken=[A-Za-z0-9]" 2>/dev/null' | grep -q .; then
  fail "an .npmrc carrying a token is present in the image"
fi

# The build stage can append a proxy CA for local builds (Dockerfile); a published image must not
# carry it, and migrate is cut from that stage.
if in_image 'test -e /etc/ssl/certs/build-proxy.pem'; then
  fail "the build-proxy CA is present in the image"
fi

if [ "$TARGET" = runtime ]; then
  for pkg in vitest eslint turbo '@nestjs+cli'; do
    if in_image "ls -d /app/node_modules/.pnpm/${pkg}@* 2>/dev/null" | grep -q .; then
      fail "development dependency $pkg present in the runtime image"
    fi
  done
fi

echo "$REF ($TARGET): $platform, user $user (uid $uid), zlib $zlib ($lib), OS packages = base, mapped: $loaded, no credential"
