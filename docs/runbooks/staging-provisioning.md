# Runbook — provisioning a staging environment

Seventeen steps, in order. The order is load-bearing in three places and each is called out where it
occurs. Every command is real; nothing here invents a credential, and no step is safe to skip
because a later one appears to work without it.

**Credentials.** Every password below comes from your secret store. `openssl rand -base64 32`
produces one if you need it. Do not reuse a development credential — not `work/work`, not
`identity/identity`, not the values in `.env.example`, which exist so a laptop can run the test
suite and nothing else.

---

## Before you start

| You need                                              | Why                                                                      |
| ----------------------------------------------------- | ------------------------------------------------------------------------ |
| A PostgreSQL server, or two                           | Two databases; they may share a server                                   |
| `PUBLIC_HOST` assigned, with DNS pointing at the host | The front door obtains a certificate for it, and the cookie is host-only |
| A secret store                                        | Four secrets, none of which may live in a file in Git                    |
| Munaxa Work images built and pushed                   | `WORK_API_IMAGE`, `WORK_ADMIN_IMAGE`                                     |

---

## Database roles and databases (1–6)

Both products use the same two-role model, and it is the model the tests assert rather than one
described only in prose: migrations run as an **owner**, the service connects as a **restricted**
role that is `NOBYPASSRLS`. `force row level security` applies to a table's owner too, so a service
that connected as the owner would read every tenant — which is why the split is not cosmetic.

```bash
# 1 — Work's migration role. CREATEROLE, because its 33rd migration creates
#     work_membership_resolver (Work's ADR-0077). Not BYPASSRLS: nothing in either deployment
#     holds that, and the whole of ADR-0077 exists to avoid needing it.
psql "$ADMIN_URL" -c "create role work_mig login password '$WORK_MIG_PASSWORD'
  nosuperuser nobypassrls createrole;"

# 2 — Work's runtime role.
psql "$ADMIN_URL" -c "create role work_app login password '$WORK_APP_PASSWORD'
  nosuperuser nobypassrls nocreatedb nocreaterole noreplication;"

# 3 — Identity's migration role. No CREATEROLE needed: its migration creates no role.
psql "$ADMIN_URL" -c "create role identity_mig login password '$IDENTITY_MIG_PASSWORD'
  nosuperuser nobypassrls;"

# 4 — Identity's runtime role.
psql "$ADMIN_URL" -c "create role identity_app login password '$IDENTITY_APP_PASSWORD'
  nosuperuser nobypassrls nocreatedb nocreaterole noreplication;"

# 5, 6 — two databases, never one. No shared schema, no shared connection, no foreign key
#        between them. The only thing that crosses is a signed token.
psql "$ADMIN_URL" -c "create database work     owner work_mig;"
psql "$ADMIN_URL" -c "create database identity owner identity_mig;"
```

## Migrations (7)

**Ordering point 1: migrations run before any service starts, as the owner, never as the runtime
role.** A service that starts first will fail its readiness probe, which is the correct outcome and
not a reason to start it anyway.

```bash
# Work — in a munaxa-work checkout
DATABASE_URL="postgresql://work_mig:…@…/work" pnpm db:migrate

# Identity — the migration runner, as the owner. On AWS this is a one-off ECS task from the
# service image (`node dist/migrate.js`); see docs/runbooks/migrations.md for the task, its
# secrets and TLS. From a checkout, after `pnpm build`:
DIRECT_DATABASE_URL="postgresql://identity_mig:…@…/identity" pnpm db:migrate

# Identity's runtime grants: what it uses, and nothing more. Note the audit table gets
# select and insert only — append-only is a privilege the application cannot talk its way
# out of, rather than a rule it is trusted to follow.
psql "postgresql://identity_mig:…@…/identity" -c "
  grant usage on schema public to identity_app;
  grant select on identity_tenant to identity_app;
  grant select, insert, update, delete on identity_account, identity_session,
    identity_refresh_token, identity_role, identity_role_assignment,
    identity_reset_token to identity_app;
  grant select, insert on identity_audit_event to identity_app;"

# Work's runtime grants
psql "postgresql://work_mig:…@…/work" -c "
  grant usage on schema public to work_app;
  grant select, insert, update, delete on all tables in schema public to work_app;
  grant usage, select on all sequences in schema public to work_app;"
```

If Work's migration stops with _"Cannot administer role work_membership_resolver"_, it is working
as designed: the role already exists in the cluster from another database, and the message names
the exact grant. Apply it and re-run.

## Verify the database before trusting it (8, 9)

```bash
# 8 — RLS is enabled AND forced on every tenant-bearing table. Enabled-without-forced looks
#     identical in a schema diff and exempts the owner, which is the trap.
psql "$IDENTITY_APP_URL" -c "
  select c.relname, c.relrowsecurity as enabled, c.relforcerowsecurity as forced
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname='public' and c.relkind='r' order by 1;"

# 9 — the runtime roles are what we think they are.
psql "$IDENTITY_APP_URL" -c "select current_user, rolsuper, rolbypassrls
  from pg_roles where rolname = current_user;"
psql "$WORK_APP_URL" -c "select * from app_isolation_diagnostics();"
```

Every `forced` must be `t` except `identity_tenant`, which has no RLS by design — it is what a
tenant context is resolved _from_, holds no personal data, and is not writable at runtime.
`rolsuper` and `rolbypassrls` must be `f` everywhere.

## The signing key and secrets (10, 11)

```bash
# 10 — Redis. Not published, not persisted; everything on it is reconstructible.
#      Started by compose in step 12; nothing to do here beyond confirming the compose file
#      is the one you intend to run.

# 11 — the key, generated by an operator and never by the service.
pnpm keys:generate --kid identity-staging-2026-09
```

The private half goes to `deploy/secrets/identity_signing_private_key.pem`. The public half goes to
`PLATFORM_AUTH_PUBLIC_KEYS` in `deploy/.env`. Then the other three secret files, per
`deploy/secrets/README.md`, and the placeholders in `.env.staging.example`.

A service that generated its own keypair would generate a new one on every restart, so every token
issued before the restart would stop verifying and Work's configured public key would silently
become wrong. That is why this is a step and not a startup behaviour.

## Start the services (12, 13)

**Ordering point 2: readiness, not `depends_on`.** The compose file gates each service on the
previous one's _health_ — `service_healthy`, not `service_started` — because started-but-not-ready
is the state that serves 502s to the first users through the door after every deploy.

```bash
cd deploy && docker compose -f docker-compose.staging.yml up -d
docker compose -f docker-compose.staging.yml ps          # every service healthy before proceeding
curl -sf https://$PUBLIC_HOST/api/auth/health/ready
```

Readiness reports the signing `kid`, whether the cache is Redis or in-process, and which mode the
session concurrency limit is in. Check the `kid` matches what Work was configured with: that single
line catches the most common misconfiguration in this whole runbook.

## The first account (14, 15, 16)

**Ordering point 3: the account exists in Identity before Work's tenant is bootstrapped**, because
Work's bootstrap takes the account's `sub` as its argument.

These scripts connect exactly as the migration runner does — `DIRECT_DATABASE_URL` for the owner,
and against RDS `DATABASE_TLS_CA` (the regional bundle) for verified TLS; a plain URL is refused in
production. On AWS they run as one-off ECS tasks; see `migrations.md`, "The provisioning scripts".

```bash
# 14 — the organisation and the account, as the migration owner: provisioning an organisation is
#      not something the application role may do, and this script does not ask it to.
DIRECT_DATABASE_URL="postgresql://identity_mig:…@…/identity" \
IDENTITY_OWNER_EMAIL=operator@example.invalid \
IDENTITY_OWNER_PASSWORD="$(read -rsp 'password: ' p; echo "$p")" \
  pnpm db:bootstrap-account --organisation acme --organisation-name "Acme"
```

Read from a prompt, not from a shell literal: a password on a command line is in the shell history
and in `ps` output. It is never echoed and never stored in plaintext, and it is validated against
the real policy — a bootstrap that accepted a weak password is how the weakest credential in a
deployment ends up on the account with the most reach.

```bash
# 15 — the Work roles, from Work's own generated catalogue. Refuses a wildcard, a scope, or any
#      grant Work does not declare.
DIRECT_DATABASE_URL="postgresql://identity_mig:…@…/identity" \
  pnpm db:seed-work-roles --organisation acme

# 16 — the assignment. Unscoped, always: a Platform scope suffixes every permission in the role,
#      producing strings Work drops as undeclared — a silent, total denial.
DIRECT_DATABASE_URL="postgresql://identity_mig:…@…/identity" \
IDENTITY_OWNER_EMAIL=operator@example.invalid IDENTITY_OWNER_PASSWORD=… \
  pnpm db:bootstrap-account --organisation acme --role work-staging-operator
```

Note the `sub` it prints. Then, in a Munaxa Work checkout, as Work's **unprivileged** role:

```bash
DATABASE_URL="postgresql://work_app:…@…/work" \
  node scripts/bootstrap-tenant.mjs --platform-user-id <sub>
```

Record the mapping in your own runbook — it is an operational fact and no code asserts it:

```
Identity organisation <id>   ↔   Work tenant <id>
```

## Verify the whole thing (17)

```bash
IDENTITY_URL=https://$PUBLIC_HOST WORK_URL=https://$PUBLIC_HOST ORIGIN=https://$PUBLIC_HOST \
ACCOUNT=operator@example.invalid PASSWORD=… \
IDENTITY_SIGNING_PRIVATE_KEY_FILE=./secrets/identity_signing_private_key.pem \
WORK_DATABASE_URL="postgresql://work_app:…@…/work" \
  node apps/api/scripts/cross-product-acceptance.mjs
```

Eighteen checks with a real token this deployment minted. The two optional credentials are what
make the wrong-issuer, wrong-audience and database-isolation checks meaningful; without them the
script prints `skip` rather than passing something it did not test.

Anything less than all of them passing is not a staging environment yet.

## Running the integration suite (never against a live database)

`@identity/testing` truncates every table it knows about in `beforeAll`. That is correct for a test
suite and catastrophic if it is pointed somewhere else — during Phase 11 it was aimed at the staging
Identity database to run against a real PostgreSQL, and it emptied it. Recovery took one
`pg_restore` and no data was lost that mattered, because staging data is synthetic and disposable by
policy; the lesson is the guard, not the outage.

`truncateAll` now refuses a database whose name does not identify it as a throwaway. Give it one:

```bash
# A throwaway with the same shape, ownership and grants as the real thing — the parity is the point,
# because RLS is a property of roles meeting policies and a hand-rolled schema does not reproduce it.
psql -U postgres -c 'create database identity_test owner identity_mig'
pg_dump -U postgres -d identity --schema-only | psql -U postgres -d identity_test
psql -U postgres -d identity_test -tAc \
  "select 'alter table public.'||tablename||' owner to identity_mig;' from pg_tables where schemaname='public'" \
  | psql -U postgres -d identity_test

TEST_DATABASE_URL=postgresql://identity_app:…@…/identity_test \
TEST_DIRECT_DATABASE_URL=postgresql://identity_mig:…@…/identity_test \
  pnpm --filter @identity/testing test:integration
```

The ownership reassignment is not optional: `pg_dump` restored as a superuser leaves the tables owned
by that superuser, `FORCE ROW LEVEL SECURITY` does not constrain a superuser, and the RLS suite then
proves nothing while passing.

## Changing a role's permissions requires a restart

Platform's `PermissionResolver` caches role _definitions_ in process. `RoleAdministration` owns the
invalidation, and `seed-work-roles.mjs` cannot use it — it connects over `pg`, deliberately, because
it runs during provisioning before any service exists. So a role written or edited by the seed is
not visible to a _running_ Identity until that process restarts.

Measured, not assumed: a role edited in the database kept resolving its previous grant set through a
Redis `FLUSHALL`, through the 60-second permission-cache TTL, and across repeated sign-ins. One
`docker compose restart identity` fixed it immediately.

```bash
pnpm --filter @identity/api db:seed-work-roles
docker compose -f deploy/docker-compose.staging.yml restart identity   # not optional
```

**This matters most when a grant is removed.** The stale definition is the permissive one, so a role
narrowed in the database goes on granting what it used to until the restart happens. Phase 9's
measured revocation window (≈16m30s) covers _assignment_ changes made through `RoleAdministration`;
it does not cover a role definition edited underneath a running process, which does not expire at
all.

Order roles before services, as the migration section already does, and treat any later role change
as a deployment step rather than a database edit.
