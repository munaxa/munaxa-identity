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
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc ./
COPY apps/api/package.json apps/api/
COPY packages/config/package.json packages/config/
COPY packages/testing/package.json packages/testing/
RUN --mount=type=secret,id=npm_token \
    NODE_AUTH_TOKEN="$(cat /run/secrets/npm_token)" \
    npm config set "//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}" --location=user && \
    pnpm install --frozen-lockfile && \
    npm config delete "//npm.pkg.github.com/:_authToken" --location=user

COPY . .
RUN pnpm --filter @identity/config build && \
    pnpm --filter @identity/api exec prisma generate --schema ../../prisma/schema.prisma && \
    pnpm --filter @identity/api build && \
    pnpm --filter @identity/api deploy --prod /runtime

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Never root. A container that is compromised should not also be privileged inside itself.
RUN addgroup -S identity && adduser -S -G identity identity

COPY --from=build --chown=identity:identity /runtime/node_modules ./node_modules
COPY --from=build --chown=identity:identity /app/apps/api/dist ./dist
COPY --from=build --chown=identity:identity /app/apps/api/scripts ./scripts
COPY --from=build --chown=identity:identity /app/artifacts ./artifacts
COPY --from=build --chown=identity:identity /app/prisma ./prisma
COPY --from=build --chown=identity:identity /app/node_modules/.prisma ./node_modules/.prisma

USER identity
EXPOSE 4001

# Readiness touches the database, because an authentication service that cannot reach its accounts
# is not ready however healthy the process is.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4001/api/auth/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/main.js"]
