# Munaxa Identity staging — the Supabase database

Identity's database is **its own Supabase project**, separate from Munaxa Work's. That is an
architectural requirement, not a convenience: the two products isolate tenants through different
GUCs (`identity.tenant_id` and `app.tenant_id`), Supabase gives one database per project, and a
shared `public` schema would need two isolation conventions in it. There is no shared database, no
shared schema, no shared connection and no foreign key between them.

|              | Identity                                           | Work                                             |
| ------------ | -------------------------------------------------- | ------------------------------------------------ |
| Project      | `munaxa-identity-staging` (`kuddkknzlxigxnqsdmza`) | `munaxa-work's Project` (`qyqhnkfhtuoywcjpfrqn`) |
| Organisation | `vhnsaozvjnghlfheeeai`                             | `lhyuumvpbikycsiugrhl`                           |
| Region       | ap-south-1                                         | ap-south-1                                       |
| PostgreSQL   | 17.6                                               | 17.6                                             |
| Roles        | `identity_mig`, `identity_app`                     | `work_mig`, `work_app`                           |

The free plan's two-project ceiling is per organisation, and the two projects are in different
organisations, so neither constrains the other.

## What is provisioned

- `identity_mig` — owns the schema and every object in it. NOSUPERUSER, **NOBYPASSRLS**,
  NOCREATEDB, NOCREATEROLE. Holds USAGE and CREATE on `public`.
- `identity_app` — the application runtime. NOSUPERUSER, **NOBYPASSRLS**, NOCREATEDB, NOCREATEROLE.
  Holds USAGE on `public` and nothing else until the baseline migration grants per table.
- Neither role has a password. Set them in the Supabase dashboard and put the resulting URLs
  straight into Render's secret store — never into Git, an image, a log or a report.
- No extension is required. Identity's baseline uses `plpgsql` and nothing else; the project's
  installed extensions are Supabase's own defaults (`pgcrypto`, `uuid-ossp`, `pg_stat_statements`,
  `supabase_vault`), all outside `public`.
- `public` is **empty**: no table, no routine, no type, no `_prisma_migrations`. The first real
  deployment applies the Prisma baseline to a clean database.

`deploy/supabase/01-roles-and-privileges.sql` is what was applied, and is idempotent.

## Run migrations as identity_mig, never as postgres

Supabase presets default privileges keyed to the creating role: anything **`postgres`** creates in
`public` is granted `arwdDxtm` to `anon`, `authenticated` and `service_role`. Applied as `postgres`,
every Identity table would exist with an anon key holding full CRUD on it. Default privileges follow
the creator, not the object, so creating everything as `identity_mig` avoids them entirely — and
`identity_mig` being NOBYPASSRLS is what makes `FORCE ROW LEVEL SECURITY` mean something.

Identity's `prisma/schema.prisma` has no `directUrl`; Prisma resolves its datasource from
`DATABASE_URL` alone. So the migration step sets `DATABASE_URL` to the **identity_mig direct**
connection for the length of that command, and nothing else in the deployment ever sees it:

    DATABASE_URL=<identity_mig direct URL> pnpm prisma:deploy   # prisma migrate deploy

Then, in the same maintenance window, as `identity_mig`:

    psql "<identity_mig direct URL>" -f deploy/supabase/02-post-migration-hardening.sql

That second step is not optional. PostgreSQL grants EXECUTE on every new routine to PUBLIC and
USAGE on every new type to PUBLIC, and `ALTER DEFAULT PRIVILEGES ... REVOKE ... FROM PUBLIC` does
not prevent it — measured on this project, the revoke records nothing and a routine created
afterwards still carries `=X`. It has to be removed after the objects exist. Use **ALL ROUTINES**:
`REVOKE EXECUTE ON ALL FUNCTIONS ... FROM PUBLIC` was measured here to leave procedures untouched.

## Connections

`max_connections` is **60**, with about fourteen already held by Supabase's own services.

| Purpose    | Role           | Port                     | Notes                                                   |
| ---------- | -------------- | ------------------------ | ------------------------------------------------------- |
| Migrations | `identity_mig` | 5432, direct/session     | Prisma DDL needs a session, not a transaction pool      |
| Runtime    | `identity_app` | 6543, transaction pooler | `?pgbouncer=true` or Prisma's prepared statements break |

Direct host: `db.kuddkknzlxigxnqsdmza.supabase.co`. The pooler host and the exact
tenant-qualified username the pooler expects are **not** recorded here — read them from the
project's Connect dialog at release time rather than assuming a form that Supabase may change.

Shapes only, no credentials:

    DATABASE_URL   postgresql://identity_app:<pw>@<pooler-host>:6543/postgres?pgbouncer=true&sslmode=require&connection_limit=<n>
    (migration)    postgresql://identity_mig:<pw>@db.kuddkknzlxigxnqsdmza.supabase.co:5432/postgres?sslmode=require

Size `connection_limit` deliberately. Identity is the only Munaxa service on this project, but
Prisma's default of `num_cpus * 2 + 1` per instance still exhausts a 60-connection budget quickly
once there is more than one instance.

## PostgREST is closed

Supabase exposes `public` through PostgREST as `anon` and `authenticated`. Identity does not use
PostgREST at all, so the schema is taken away from those roles entirely: `anon`, `authenticated`,
`service_role` and `PUBLIC` hold no privilege on schema `public`. Schema USAGE is the gate — an
object nobody may name cannot be read, executed or called, whatever its own ACL says. That is what
makes the residual PUBLIC EXECUTE described above unreachable rather than merely undesirable, and
it is why the post-migration revoke is a second lock rather than the only one.

Re-run the verification block in `02-post-migration-hardening.sql` after **any** schema change.

## Deviations from local PostgreSQL

1. **`postgres` holds BYPASSRLS.** Supabase's admin role bypasses every policy and that cannot be
   changed. Locally the migration role does not. Mitigated by owning every object with
   `identity_mig` (NOBYPASSRLS), so FORCE RLS binds the owner exactly as it does locally — but an
   operator connected as `postgres` still sees across organisations. Treat `postgres` as
   break-glass, and never as a migration or runtime role.
2. **Supabase's `supabase_admin` default privileges still grant `anon`/`authenticated` full CRUD**
   on anything _that role_ creates in `public`. It cannot be altered from the project's admin
   connection, and Identity creates nothing as `supabase_admin`, so nothing acquires those grants.
   The schema-level revoke covers it regardless.
3. **Free plan.** Daily backups, no PITR, and projects auto-pause after about seven days idle. A
   shared staging environment that pauses itself needs either a paid plan or an accepted wake-up
   delay on the first request after a quiet week.
