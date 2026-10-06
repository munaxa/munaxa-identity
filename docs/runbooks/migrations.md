# Runbook — applying Identity's database migrations

Identity's schema is the SQL under `prisma/migrations/<name>/migration.sql`, applied exactly as
written, in name order, each exactly once. The runner is `node dist/migrate.js`, shipped in the
service image beside the service; it is not part of the service and the service never runs it.

## What the runner does

|                              |                                                                                                                                                                                                                                                                                   |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Applies**                  | each pending `migration.sql`, in directory-name order, each in one transaction together with its ledger row                                                                                                                                                                       |
| **Records**                  | `identity_migration.applied` — `name`, `checksum` (SHA-256 of the file), `mode` (`applied` / `adopted`), `applied_at`, `applied_by`, `execution_ms`                                                                                                                               |
| **Refuses, writing nothing** | the runtime role `identity_app`; any superuser or `BYPASSRLS` role; a recorded migration whose file changed; a recorded migration missing from the image (database ahead of code); a pending migration older than one already applied; an unverified TLS connection in production |
| **Serialises**               | concurrent runners, with a PostgreSQL advisory lock                                                                                                                                                                                                                               |
| **Exit code**                | `0` applied, or nothing to do · `1` refused or failed — nothing partial recorded · `2` bad arguments                                                                                                                                                                              |
| **Logs**                     | one JSON object per line on stdout/stderr: `migrate.start`, `migrate.role`, `migrate.applied`, `migrate.done`, `migrate.failed`. Never a password, a connection string or a certificate.                                                                                          |

The ledger lives in its own schema, not `public`: every `public` table except `identity_tenant` must
carry forced row-level security, and the runtime role is granted nothing on `identity_migration`.

## What it needs

| Name                      | Kind                                | Value                                                                                                                                                                                                                                 |
| ------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DIRECT_DATABASE_URL`     | **secret**                          | `postgresql://identity_mig:<password>@<rds-endpoint>:5432/identity` — the **migration owner**. No `sslmode` parameter when a CA is configured (the runner refuses the contradiction). `DIRECT_DATABASE_URL_FILE` is accepted instead. |
| `DATABASE_TLS_CA`         | configuration (public certificates) | The PEM bundle the database certificate chains to. For RDS: Amazon's **region bundle**, `https://truststore.pki.rds.amazonaws.com/<region>/<region>-bundle.pem`. `DATABASE_TLS_CA_FILE` is accepted instead.                          |
| `NODE_ENV`                | configuration                       | `production` — the image's default. In production the runner requires verified TLS.                                                                                                                                                   |
| `IDENTITY_MIGRATIONS_DIR` | optional                            | Overrides the migrations directory. Leave unset: the image's is `/app/prisma/migrations`.                                                                                                                                             |

It needs nothing else — no signing key, no Redis, no runtime `DATABASE_URL`.

**The role.** `identity_mig`: `LOGIN`, owner of the `identity` database, `NOSUPERUSER NOBYPASSRLS`
(`staging-provisioning.md` steps 3 and 6). `identity_app` must exist before the first run — the
baseline grants to it — and is created with `LOGIN` by step 4. Never the RDS master user: it is not a
superuser on RDS, but it is not the owner either, and tables are owned by whoever creates them.

**TLS.** With `DATABASE_TLS_CA` set, the runner verifies the certificate chain against that bundle
**and** the host name against the RDS endpoint — `verify-full`. Any TLS parameter in the URL is
removed first, because `pg` would otherwise let it override the CA (`sslmode=require` silently drops
it; `sslmode=no-verify` silently disables verification). Without a CA, production accepts only
`sslmode=verify-full` against the system trust store, which does not contain Amazon's RDS CAs — so on
RDS the CA is required. There is no way to configure encrypted-but-unverified.

**Name the host, never its address.** Verified TLS is refused for an IP-literal host. `pg` sends no
TLS server name for an address, and Node then checks the certificate against `localhost` instead of
the address — measured: a certificate issued only for `localhost` verified a connection to
`127.0.0.1`. Use the RDS instance endpoint (`<id>.<hash>.<region>.rds.amazonaws.com`).

**The same connection, everywhere.** `bootstrap-account.mjs` and `seed-work-roles.mjs` connect through
the same module (`src/database/direct-connection.ts`, loaded from `dist` by
`scripts/owner-connection.mjs`), with the same variables and the same refusals. Each prints one line
before it connects — `Database identity_mig@<host>:5432/identity — TLS verify-full (configured CA).` —
which is the line to check.

### The CA bundle, and where it can live

Use Amazon's **regional** bundle for the region the database is in. Measured on 2026-10-06:

| Bundle                                                                          | Size              | Certificates |
| ------------------------------------------------------------------------------- | ----------------- | ------------ |
| Regional (`eu-west-1`, `eu-central-1`, `us-east-1`, `ap-south-1`, `me-south-1`) | 4,576–4,600 bytes | 3            |
| Global (`global-bundle.pem`)                                                    | 169,984 bytes     | 111          |

Against the stores an ECS task can inject from:

| Store                                             | Maximum value | Regional bundle     | Global bundle |
| ------------------------------------------------- | ------------- | ------------------- | ------------- |
| **Secrets Manager** (plaintext secret)            | 64 KB         | **fits — use this** | does not fit  |
| SSM Parameter Store, **advanced** tier            | 8 KB          | fits                | does not fit  |
| SSM Parameter Store, standard tier                | 4 KB          | **does not fit**    | does not fit  |
| One environment variable (Linux limit per string) | 128 KiB       | fits                | does not fit  |

So: store the regional bundle's PEM text, unmodified, as a plaintext Secrets Manager secret (or an
advanced-tier parameter) and inject it as `DATABASE_TLS_CA`. The global bundle cannot be injected as
an environment variable at all; if it were ever needed it would have to be a file in the image and
`DATABASE_TLS_CA_FILE` — which is not done, because the regional bundle is the narrower trust and
fits. When Amazon rotates RDS certificate authorities, refresh the stored bundle from the same URL
before the instance switches CA.

## AWS staging: the one-off ECS task

Same task family as the Identity service — the same ECR image digest (`ecr-image.md`), the same
private subnets — with:

```text
command            ["node", "dist/migrate.js"]          (working directory is /app/apps/api)
secrets            DIRECT_DATABASE_URL  ← Secrets Manager: identity-mig database URL
                   DATABASE_TLS_CA      ← Secrets Manager (plaintext): the RDS regional bundle, PEM
execution role     may read exactly those two, pull the image, write logs — never the service's
                   signing key or runtime DATABASE_URL
security group     egress 5432 to the Identity RDS security group; nothing inbound
logs               awslogs, e.g. /ecs/<env>/identity-migrate
```

No port mapping, no load balancer and no health check: the process opens no socket and exits.

### The provisioning scripts, as one-off tasks

Same image, same task shape and the same two secrets as the migration task, plus the operator's
account details for the bootstrap. Run them after the migration task, in this order
(`staging-provisioning.md` steps 14–16):

```text
1  bootstrap   ["node", "scripts/bootstrap-account.mjs", "--organisation", "<slug>", "--organisation-name", "<Name>"]
               + IDENTITY_OWNER_EMAIL (configuration), IDENTITY_OWNER_PASSWORD (secret)
2  seed roles  ["node", "scripts/seed-work-roles.mjs", "--organisation", "<slug>"]
3  assign      ["node", "scripts/bootstrap-account.mjs", "--organisation", "<slug>", "--role", "work-staging-operator"]
               + IDENTITY_OWNER_EMAIL, IDENTITY_OWNER_PASSWORD
```

Both need `DIRECT_DATABASE_URL` (or `_FILE`) and, with `NODE_ENV=production` as the image sets it,
`DATABASE_TLS_CA` (or `_FILE`). Neither needs Redis, the signing key or the runtime `DATABASE_URL`,
and neither starts the HTTP service. Each exits non-zero on any refusal or failure. The bootstrap
prints the account's `sub` for Munaxa Work's `db:bootstrap`. Restart the Identity service after
seeding roles (`staging-provisioning.md`, "Changing a role's permissions requires a restart").

### Before deploying a new Identity version

1. Run the one-off task with the **new** image digest.
2. Wait for it to stop. Proceed only if the container's exit code is `0`.
3. Then update the Identity service to the same digest.

On a non-zero exit, do not deploy. Read the `migrate.failed` line: it names the migration and the
reason. Nothing was recorded — the failed migration's transaction rolled back — so fix the cause and
run the task again. A dropped connection (failover mid-migration) reports the same way.

### Verifying success

- The task's container exit code is `0`, and its last log line is
  `{"event":"migrate.done","applied":[…],"adopted":[],"alreadyApplied":N}`.
- `migrate.start` shows `"tls":"verify-full (configured CA)"` and the intended host and database.
- In the database, as `identity_mig`:

  ```sql
  select name, mode, applied_at, applied_by from identity_migration.applied order by name;
  ```

- `GET /api/auth/health/ready` answers 200 once the service is running — it checks the required
  tables are present.

### A database provisioned before the runner existed

Environments built with `psql -f` have the baseline's tables and no ledger. The runner refuses them
rather than re-running the baseline. After confirming the schema is the baseline, run the task once
with:

```text
command            ["node", "dist/migrate.js", "--adopt-baseline"]
```

It records the baseline as `adopted` — not executed — and only if every table the service requires is
present. It is refused on any database whose ledger already records something.

## Locally and in CI

```bash
pnpm build
DIRECT_DATABASE_URL=postgresql://identity_mig:…@localhost:5432/identity pnpm db:migrate
```

Outside production, a URL without TLS parameters connects in plain text. CI applies the schema this
way — twice, the second applying nothing — and `packages/testing/src/migration-runner.integration.test.ts`
proves the runner against a real PostgreSQL, using `TEST_SUPERUSER_URL` to create and drop its own
throwaway databases.

## Adding a migration

A new directory under `prisma/migrations/` named `<UTC yyyymmddhhmmss>_<snake_case>`, containing
`migration.sql`. It must sort after every applied migration. Never edit a migration once it has been
applied anywhere: the checksum check stops every later run until the file is restored.

`prisma migrate` is not the migration mechanism here — it knows nothing of row-level security, roles
or this ledger. Do not run `pnpm prisma:deploy` against an Identity database.
