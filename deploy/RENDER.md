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

## Images

Three are pulled by digest from GHCR; the front door is built by Render.

The application Dockerfiles take the GitHub Packages credential as a BuildKit secret
(`--mount=type=secret,id=npm_token`), which Render's builder does not implement. The alternative —
a build ARG — writes the token into image history, which is the defect removed in Phase 11. So they
are built in GitHub Actions, where BuildKit secrets work, and deployed here by digest.

**This is the one repository change Render requires**: a workflow that builds and pushes
`munaxa-identity-api`, `munaxa-work-api` and `munaxa-work-admin` to GHCR on the validated commits,
and prints the digests. Until it exists, `render.yaml` cannot be applied — its four
`REPLACE_WITH_PUBLISHED_DIGEST` placeholders are deliberate, so a half-configured blueprint fails
loudly rather than deploying something unintended.

Pinned commits: Identity `ef3410d`, Work API and Admin `ea1bdeb`.

## Databases — two, never one

Identity and Work do **not** share a database. `docs/runbooks/staging-provisioning.md` is explicit:
"two databases, never one. No shared schema, no shared connection, no foreign key." They also
disagree at the mechanism level — Work isolates on `app.tenant_id`, Identity on
`identity.tenant_id` — so a shared database would need two isolation conventions in one `public`
schema.

Supabase gives one database per project, and its pooler only serves `postgres`. So Identity needs
**its own Supabase project**. The free plan allows two projects per organisation, which is exactly
enough and leaves no margin.

Work's project `qyqhnkfhtuoywcjpfrqn` is provisioned and validated (Phase 18). Identity's is not yet
created.

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
