# Munaxa staging on Render

The validated compose topology, mapped onto Render. `render.yaml` in this directory is the
blueprint; this file is the reasoning and the operator procedure.

## Topology

| Compose              | Render                       | Public?                |
| -------------------- | ---------------------------- | ---------------------- |
| `front-door` (Caddy) | Web Service, custom domain   | **yes — the only one** |
| `identity`           | Private Service, `:4001`     | no                     |
| `work-api`           | Private Service, `:3000`     | no                     |
| `work-admin`         | Private Service, `:3001`     | no                     |
| `cache` (Redis)      | Key Value, `ipAllowList: []` | no                     |
| `postgres`           | Supabase, over TLS           | no                     |

Routing is unchanged, because Caddy is unchanged: `/api/auth/*` → Identity, `/api/v1/*` → Work API,
everything else → Work Admin.

**Caddy is not replaceable here.** Render routes a custom domain to exactly one service and has no
path-based routing across services. The `__Host-` session cookie requires the portal and the issuer
to share an origin, so all three paths must answer on one hostname.

**Caddy does not hold the certificate.** Render provides and renews it for the custom domain and
terminates HTTPS at its edge, forwarding plain HTTP to `PORT`. So the baked `Caddyfile` listens on
`:{$PORT:10000}`, sets `auto_https off`, and performs no HTTP→HTTPS redirect — a request that
arrived over HTTPS reaches the container as HTTP, and an automatic upgrade would bounce a correct
request for ever. `Caddyfile.tls` is the same routing addressed by hostname, for the compose
topology where Caddy _is_ the TLS endpoint; both import `caddy-routes.caddyfile`, so the path split
is one definition.

## Images

Three are pulled by digest from GHCR; the front door is built by Render.

The application Dockerfiles take the GitHub Packages credential as a BuildKit secret
(`--mount=type=secret,id=npm_token`), which Render's builder does not implement. The alternative —
a build ARG — writes the token into image history, which is the defect removed in Phase 11. So they
are built in GitHub Actions, where BuildKit secrets work, and deployed here by digest.

A workflow in each repository builds and pushes `munaxa-identity-api`, `munaxa-work-api` and
`munaxa-work-admin` to GHCR on a named commit and prints the digests. All three are published, so
`render.yaml` carries real digests and no `REPLACE_WITH_PUBLISHED_DIGEST` placeholders remain.

Pinned commits: Identity `7e2eb6a`, Work API and Admin `869cceb`.

**The packages are private.** An anonymous pull of the published digest returns 401, so Render needs
a registry credential or it fetches nothing and says so only at pull time. Create one in Render
(Settings → Registry Credentials) named `ghcr-munaxa`, holding a GitHub token with `read:packages`
on the organisation — read-only is the whole requirement, since nothing in Render pushes.

Published so far:

| Image                 | Commit    | Digest                                                                    | Run           |
| --------------------- | --------- | ------------------------------------------------------------------------- | ------------- |
| `munaxa-identity-api` | `7e2eb6a` | `sha256:6f7b6fb7c03e99f9e50da250c95ce51ba2b1957579b168f9357f8bac7bc3e718` | `34323444447` |
| `munaxa-work-api`     | `869cceb` | `sha256:395b973b681f56a0c9d372ea018b29c3bc99ce0ed029f810b17798118ab80f36` | `33634221986` |
| `munaxa-work-admin`   | `869cceb` | `sha256:89330919fd1b888aab829066b7d4d61b03d3e9425c4b207bd22ce8f2e5250a2f` | `33634221986` |

`869cceb` is the merge commit of PR #20, and its tree is identical to `1d927ee` — the merge took a
base that had not moved, so `git diff 1d927ee 869cceb` is empty. The Work images therefore
correspond byte-for-byte to the commit CI is green on.

## Databases — two, never one

Identity and Work do **not** share a database. `docs/runbooks/staging-provisioning.md` is explicit:
"two databases, never one. No shared schema, no shared connection, no foreign key." They also
disagree at the mechanism level — Work isolates on `app.tenant_id`, Identity on
`identity.tenant_id` — so a shared database would need two isolation conventions in one `public`
schema.

Supabase gives one database per project, so Identity needs **its own Supabase project**. The free
plan's two-project ceiling is per organisation, and the two projects sit in different
organisations, so neither constrains the other.

| Product  | Project                                            | Organisation           | Region     |
| -------- | -------------------------------------------------- | ---------------------- | ---------- |
| Work     | `munaxa-work's Project` (`qyqhnkfhtuoywcjpfrqn`)   | `lhyuumvpbikycsiugrhl` | ap-south-1 |
| Identity | `munaxa-identity-staging` (`kuddkknzlxigxnqsdmza`) | `vhnsaozvjnghlfheeeai` | ap-south-1 |

Both are provisioned and validated — Work in Phase 18, Identity in Phase 21. Identity's roles,
privilege baseline and PostgREST closure are in `deploy/supabase/`, and the release-time migration
procedure is `docs/runbooks/supabase-identity-staging.md`. Its `public` schema is deliberately
empty: the first deployment applies the Prisma baseline to a clean database.

## Connections

| Purpose    | Role                        | Port        | Notes                                                   |
| ---------- | --------------------------- | ----------- | ------------------------------------------------------- |
| Migrations | `work_mig` / `identity_mig` | 5432 direct | Prisma DDL needs a session, not a transaction pool      |
| Runtime    | `work_app` / `identity_app` | 6543 pooler | `?pgbouncer=true` or Prisma's prepared statements break |

`max_connections` is 60 with ~14 already held by Supabase. Set `connection_limit` per service
deliberately; the default of `num_cpus * 2 + 1` per instance exhausts that quickly.

Never run migrations as `postgres`. Supabase's default privileges are keyed to the creating role and
grant `anon` full CRUD on everything `postgres` creates in `public`.

## Redis

Identity requires it — lockout counters, rate limits, resolved permission sets. Redis down must stay
a 503 on both readiness and sign-in, never a fallback that lets authentication proceed uncounted.

Work is given none. Its `REDIS_URL` is optional in the schema and its only consumer is a health
label; a connection it does not use is a credential to leak for nothing. Work's health will report
`cache: not-configured`, which is accurate.

`maxmemoryPolicy: noeviction` is deliberate. Under an eviction policy a lockout counter is a
suggestion.

## The two agreements nothing validates

`PLATFORM_AUTH_ISSUER` must equal Identity's `IDENTITY_BASE_URL` character for character, and
`IDENTITY_SIGNING_KID` must appear in `PLATFORM_AUTH_PUBLIC_KEYS` before Identity signs with it.
No service checks either. Both fail identically: every sign-in succeeds and every authenticated
request afterwards answers 401.

`PLATFORM_AUTH_PUBLIC_KEYS` is a single-line JSON array of `{kid, publicKey}` with `\n` escapes
inside the PEMs. Render stores values verbatim, so this is safer here than it was under
`docker compose --env-file`, whose parser breaks on a literal newline mid-value.

For Identity's PEM, prefer a Render **Secret File** and point `IDENTITY_SIGNING_PRIVATE_KEY_FILE` at
its path. `NAME_FILE` wins over an ambient `NAME`, and a multi-line secret in a file avoids the
whole class of newline-mangling problems.
