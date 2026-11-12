# Munaxa Identity — the authentication service.
#
# Multi-stage so the runtime image carries no compiler, no source and no dev dependency: the
# smaller the image, the smaller the set of things that can be exploited inside it.
#
# The GitHub Packages credential arrives as a build secret rather than a build argument. An ARG is
# recorded in the image history, so a token passed that way is readable by anybody who can pull the
# image — which for a private registry is a wider set than the people who were given the token.

# One base for every stage, so the runtime image and the migrate image (cut from `build`) carry the
# same operating system, and pinned by digest so a rebuild of the same commit starts from the same
# bytes. The digest is node:22-alpine (Node 22.23.5, Alpine 3.24.4) as published on 11 Nov 2026,
# the image the 5a5994f release resolved the floating tag to.
#
# zlib is raised to 1.4-r0 on top of it because that image still ships zlib 1.3.2-r1, which carries
# CVE-2026-4738 (CRITICAL in the ECR scan of the 5a5994f images). Alpine's aports secfixes list the
# fix in 1.4-r0 (main/zlib/APKBUILD, 3.24-stable), and upstream zlib 1.4's ChangeLog names it. No
# official node:22-alpine digest carried the fix when this was written; when one does, move the pin
# to it and drop the upgrade. The version is exact, not `>=`, so the image is reproducible: if
# Alpine replaces 1.4-r0 the build fails here, loudly, instead of quietly shipping something else.
# apk verifies the package signature against the keys already in the pinned image; nothing else is
# added or upgraded. .github/scripts/verify-image.sh checks the result in CI and before publishing.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS base
# The split is the point: `apk list -I zlib` prints `zlib-<version> <arch> ...` and $1 is the first word.
# hadolint ignore=SC2046
RUN apk add --no-cache 'zlib=1.4-r0' && \
    set -- $(apk list -I zlib 2>/dev/null) && installed="${1#zlib-}" && \
    if [ "$installed" != "1.4-r0" ]; then \
      echo "zlib is '$installed', expected 1.4-r0 (CVE-2026-4738)" >&2; exit 1; \
    fi

FROM base AS build
WORKDIR /app

# An optional trust anchor for build environments whose egress proxy re-terminates TLS — most
# corporate networks, and the sandbox this was first built in. Without it the failure is
# `SELF_SIGNED_CERT_IN_CHAIN` from every registry fetch, which reads like a broken network rather
# than a missing certificate and costs an afternoon to place.
#
# A secret mount rather than a COPY: the certificate is not sensitive, but mounting it keeps it out
# of the image layers, and a build that does not supply one is unaffected. Nothing here disables
# verification — the CA is *appended* to the trust bundle, which is the difference between trusting
# one more issuer and trusting everybody.
#
# Appended directly rather than through `update-ca-certificates`, which alpine does not ship:
# installing it would need the network this certificate exists to unblock. Node is handled
# separately via NODE_EXTRA_CA_CERTS because it carries its own CA store and ignores the system
# one — which is why appending to the bundle alone still failed with SELF_SIGNED_CERT_IN_CHAIN.
RUN --mount=type=secret,id=ca_bundle \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
      cp /run/secrets/ca_bundle /etc/ssl/certs/build-proxy.pem; \
    fi && \
    NODE_EXTRA_CA_CERTS="$([ -f /etc/ssl/certs/build-proxy.pem ] && echo /etc/ssl/certs/build-proxy.pem || true)" \
    corepack enable && \
    NODE_EXTRA_CA_CERTS="$([ -f /etc/ssl/certs/build-proxy.pem ] && echo /etc/ssl/certs/build-proxy.pem || true)" \
    corepack prepare pnpm@10.33.0 --activate

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc ./
COPY apps/api/package.json apps/api/
COPY packages/config/package.json packages/config/
COPY packages/testing/package.json packages/testing/
# `always-auth` is not optional and its absence is not obvious. GitHub Packages answers a tarball
# request with a 302 to a CDN, and without this pnpm drops the credential on the redirect — so
# metadata resolves, `npm view` works, and only the download fails, with a bare
# ERR_PNPM_FETCH_401 that looks like a bad token rather than a dropped header.
#
# The credential is written and removed inside one RUN, so it is absent from the committed layer.
RUN --mount=type=secret,id=npm_token --mount=type=secret,id=ca_bundle \
    NODE_EXTRA_CA_CERTS="$([ -f /etc/ssl/certs/build-proxy.pem ] && echo /etc/ssl/certs/build-proxy.pem || true)" \
    sh -c 'set -e; \
      T="$(cat /run/secrets/npm_token)"; \
      printf "//npm.pkg.github.com/:_authToken=%s\n//npm.pkg.github.com/:always-auth=true\n" "$T" > /root/.npmrc; \
      pnpm install --frozen-lockfile; \
      rm -f /root/.npmrc'

COPY . .
RUN pnpm --filter @identity/config build && \
    pnpm --filter @identity/api exec prisma generate --schema ../../prisma/schema.prisma && \
    pnpm --filter @identity/api build

# The release job for the shared AWS stack (munaxa-platform infra/aws): the full migration history,
# applied by the owner role from its own secret bundle (DATABASE_MIGRATION_URL), never by the
# runtime role. It needs the Prisma CLI, a development dependency, so it is cut from the build stage
# before the production install below removes it. The baseline grants identity_app its privileges
# table by table, so nothing runs after it.
FROM build AS migrate
ENV NODE_ENV=production
RUN addgroup -S identity && adduser -S -G identity migrate
USER migrate
CMD ["sh", "-c", "export DATABASE_URL=\"$DATABASE_MIGRATION_URL\" && exec /app/node_modules/.bin/prisma migrate deploy --schema=/app/prisma/schema.prisma"]

FROM build AS prune
# Dev dependencies are removed with a production install rather than with `pnpm prune --prod` or
# `pnpm deploy`, both of which were tried first and both of which are wrong here.
#
# `pnpm deploy` deadlocks on pnpm 10.33: `--legacy` (which v10 demands for a non-injected workspace)
# enters the copy from the content-addressable store and then waits forever on nothing. A build that
# never returns is worse than one that fails, because CI has no failure to report.
#
# `pnpm prune --prod` returns promptly and looks correct — it reports the root devDependencies it
# removed and nothing else — but it also empties every *workspace project's* node_modules and does
# not put them back. The image builds, starts, and dies on the first `require` of a dependency,
# which is the worst possible place to find out. `pnpm install --prod` re-links every project in the
# workspace with production dependencies only, which is what was wanted all along.
#
# CI=true is required, not cosmetic: the install rebuilds the modules directory and without a TTY to
# confirm that it refuses with ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY.
#
# The generated Prisma client is set aside across it: it lives under node_modules/.prisma but
# belongs to no package, so whether the install treats it as extraneous is not something to leave to
# chance in the one artifact that reaches staging.#
# `rm -rf node_modules` before the install, and that is the part that matters. `pnpm install --prod`
# re-links each project's node_modules but does not garbage-collect the virtual store underneath, so
# vitest, eslint, turbo and the Nest CLI all survived into the shipped image — the manifest said
# production and the filesystem said otherwise. Removing the tree first makes the prod install
# materialise only what production actually resolves. Packages come from the build stage's
# content-addressable store, so this costs seconds, not a re-download.
RUN --mount=type=secret,id=npm_token --mount=type=secret,id=ca_bundle \
    NODE_EXTRA_CA_CERTS="$([ -f /etc/ssl/certs/build-proxy.pem ] && echo /etc/ssl/certs/build-proxy.pem || true)" \
    CI=true \
    sh -c 'set -e; \
      T="$(cat /run/secrets/npm_token)"; \
      printf "//npm.pkg.github.com/:_authToken=%s\n//npm.pkg.github.com/:always-auth=true\n" "$T" > /root/.npmrc; \
      cp -r node_modules/.prisma /tmp/prisma-client; \
      rm -rf node_modules apps/*/node_modules packages/*/node_modules packages/modules/*/node_modules; \
      pnpm install --prod --frozen-lockfile; \
      rm -rf node_modules/.prisma; \
      cp -r /tmp/prisma-client node_modules/.prisma; \
      rm -rf /tmp/prisma-client; \
      rm -f /root/.npmrc'

FROM base AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Amazon RDS's eu-central-1 root CAs (deploy/aws/rds-ca-eu-central-1.crt, AWS's regional trust
# bundle), for the bootstrap scripts the shared stack's identity-bootstrap task runs from this
# image (scripts/bootstrap-account.mjs, seed-control-roles.mjs, seed-work-roles.mjs). They connect
# with node-postgres, which treats `sslmode=require` as `verify-full`; RDS certificates chain to
# these private roots and to nothing in Node's store, so without them every run fails with
# SELF_SIGNED_CERT_IN_CHAIN. Appending them keeps full verification (chain and host name) rather
# than turning it off. Public certificates, not signing material.
COPY deploy/aws/rds-ca-eu-central-1.crt /usr/local/share/ca-certificates/rds-ca-eu-central-1.crt
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/rds-ca-eu-central-1.crt

# Never root. A container that is compromised should not also be privileged inside itself.
RUN addgroup -S identity && adduser -S -G identity identity

# Copied at the paths the build used, not flattened into one directory. pnpm's node_modules is a
# tree of relative symlinks into node_modules/.pnpm; move a package and every link inside it dangles.
# So the workspace shape is preserved and only the parts a running service needs are carried over —
# no source, no test, no toolchain.
COPY --from=prune --chown=identity:identity /app/node_modules ./node_modules
COPY --from=prune --chown=identity:identity /app/package.json ./package.json
COPY --from=prune --chown=identity:identity /app/packages/config/package.json ./packages/config/package.json
COPY --from=prune --chown=identity:identity /app/packages/config/dist ./packages/config/dist
COPY --from=prune --chown=identity:identity /app/packages/config/node_modules ./packages/config/node_modules
COPY --from=prune --chown=identity:identity /app/apps/api/package.json ./apps/api/package.json
COPY --from=prune --chown=identity:identity /app/apps/api/dist ./apps/api/dist
COPY --from=prune --chown=identity:identity /app/apps/api/scripts ./apps/api/scripts
COPY --from=prune --chown=identity:identity /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=prune --chown=identity:identity /app/artifacts ./artifacts
COPY --from=prune --chown=identity:identity /app/prisma ./prisma

WORKDIR /app/apps/api

USER identity
EXPOSE 4001

# Readiness touches the database, because an authentication service that cannot reach its accounts
# is not ready however healthy the process is.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4001/api/auth/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/main.js"]
