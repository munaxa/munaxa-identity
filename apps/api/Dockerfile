# Munaxa Identity — the authentication service.
#
# Multi-stage so the runtime image carries no compiler, no source and no dev dependency: the
# smaller the image, the smaller the set of things that can be exploited inside it.
#
# The GitHub Packages credential arrives as a build secret rather than a build argument. An ARG is
# recorded in the image history, so a token passed that way is readable by anybody who can pull the
# image — which for a private registry is a wider set than the people who were given the token.

FROM node:22-alpine AS build
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
# chance in the one artifact that reaches staging.
RUN --mount=type=secret,id=npm_token --mount=type=secret,id=ca_bundle \
    NODE_EXTRA_CA_CERTS="$([ -f /etc/ssl/certs/build-proxy.pem ] && echo /etc/ssl/certs/build-proxy.pem || true)" \
    CI=true \
    sh -c 'set -e; \
      T="$(cat /run/secrets/npm_token)"; \
      printf "//npm.pkg.github.com/:_authToken=%s\n//npm.pkg.github.com/:always-auth=true\n" "$T" > /root/.npmrc; \
      cp -r node_modules/.prisma /tmp/prisma-client; \
      pnpm install --prod --frozen-lockfile; \
      rm -rf node_modules/.prisma; \
      cp -r /tmp/prisma-client node_modules/.prisma; \
      rm -rf /tmp/prisma-client; \
      rm -f /root/.npmrc'

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Never root. A container that is compromised should not also be privileged inside itself.
RUN addgroup -S identity && adduser -S -G identity identity

# Copied at the paths the build used, not flattened into one directory. pnpm's node_modules is a
# tree of relative symlinks into node_modules/.pnpm; move a package and every link inside it dangles.
# So the workspace shape is preserved and only the parts a running service needs are carried over —
# no source, no test, no toolchain.
COPY --from=build --chown=identity:identity /app/node_modules ./node_modules
COPY --from=build --chown=identity:identity /app/package.json ./package.json
COPY --from=build --chown=identity:identity /app/packages/config/package.json ./packages/config/package.json
COPY --from=build --chown=identity:identity /app/packages/config/dist ./packages/config/dist
COPY --from=build --chown=identity:identity /app/packages/config/node_modules ./packages/config/node_modules
COPY --from=build --chown=identity:identity /app/apps/api/package.json ./apps/api/package.json
COPY --from=build --chown=identity:identity /app/apps/api/dist ./apps/api/dist
COPY --from=build --chown=identity:identity /app/apps/api/scripts ./apps/api/scripts
COPY --from=build --chown=identity:identity /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=build --chown=identity:identity /app/artifacts ./artifacts
COPY --from=build --chown=identity:identity /app/prisma ./prisma

WORKDIR /app/apps/api

USER identity
EXPOSE 4001

# Readiness touches the database, because an authentication service that cannot reach its accounts
# is not ready however healthy the process is.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4001/api/auth/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/main.js"]
