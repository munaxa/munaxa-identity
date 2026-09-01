# Runbook — provisioning a staging environment

Every step below is a real command. Nothing here invents a credential, and no step is safe to skip
because a later one appears to work without it.

## 1 — The signing key

```bash
pnpm keys:generate --kid identity-staging-2026-09
```

Prints both halves and writes neither. Put the **private** half in the deployment's secret store
(`deploy/secrets/identity_signing_private_key.pem` under compose). Put the **public** half into
Munaxa Work's `PLATFORM_AUTH_PUBLIC_KEYS`. Platform publishes no JWKS endpoint, so a configured
public key is not a fallback — it is the only mechanism that exists.

## 2 — The databases

Two databases, two roles each. The migration owner creates and owns the tables; the runtime role is
non-superuser and `NOBYPASSRLS`. Both are checked by the test suite, because `force row level
security` does not apply to a superuser and a superuser connection makes every isolation test pass
while isolating nothing.

```bash
psql "$IDENTITY_OWNER_URL" -f prisma/migrations/20260901120000_identity_baseline/migration.sql
psql "$IDENTITY_OWNER_URL" -c "
  grant usage on schema public to identity_app;
  grant select on identity_tenant to identity_app;
  grant select, insert, update, delete on identity_account, identity_session,
    identity_refresh_token, identity_role, identity_role_assignment, identity_reset_token
    to identity_app;
  grant select, insert on identity_audit_event to identity_app;"   -- append-only, by grant
```

For Munaxa Work, its own migrations, run by a role holding `CREATEROLE` (its ADR-0077). If that
migration stops with _"Cannot administer role work_membership_resolver"_, it is working as designed
— the role exists in the cluster from another database and the message names the exact grant.

## 3 — The organisation and the first account

```bash
DIRECT_DATABASE_URL=$IDENTITY_OWNER_URL \
IDENTITY_OWNER_EMAIL=operator@example IDENTITY_OWNER_PASSWORD='…' \
  pnpm db:bootstrap-account --organisation acme --organisation-name Acme
```

As the owner, because provisioning an organisation is not something the application role may do —
`identity_app` holds `select` on `identity_tenant` and nothing more, so a compromised service cannot
invent an organisation to put accounts in. The password is validated against the real policy;
weakening it for a bootstrap is how the weakest credential ends up on the account with the most
reach. Idempotent: a second run reports and writes nothing.

## 4 — The Work roles

```bash
DIRECT_DATABASE_URL=$IDENTITY_OWNER_URL pnpm db:seed-work-roles --organisation acme
```

Reads `artifacts/work-permissions.json` — Munaxa Work's generated catalogue — and provisions
`work-staging-operator` with 45 grants. It refuses a wildcard, a scope, and any grant Work does not
declare, so a role that could not work is caught here rather than as a 403 nobody can explain.

## 5 — The assignment

```bash
DIRECT_DATABASE_URL=$IDENTITY_OWNER_URL \
IDENTITY_OWNER_EMAIL=operator@example IDENTITY_OWNER_PASSWORD='…' \
  pnpm db:bootstrap-account --organisation acme --role work-staging-operator
```

Unscoped, always. A Platform scope suffixes every permission in the role, producing strings Work
drops as undeclared — which reads to everyone involved as a permission that simply does not work.

Note the `sub` it prints.

## 6 — Work's side

```bash
DATABASE_URL=$WORK_APP_URL node scripts/bootstrap-tenant.mjs --platform-user-id <sub>
```

Run in a Munaxa Work checkout, as its unprivileged application role. Record the mapping:

```
Identity organisation <id>  ↔  Work tenant <id>
```

An operational fact, in this runbook. No code asserts the two are equal.

## 7 — Verify

```bash
IDENTITY_URL=… WORK_URL=… ACCOUNT=… PASSWORD=… \
  node apps/api/scripts/cross-product-acceptance.mjs
```

Fourteen checks, using a real token this deployment minted. It is the difference between "the
services started" and "the contract holds".
