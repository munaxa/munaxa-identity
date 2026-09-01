# Munaxa Identity

The Munaxa ecosystem's authentication and authorization authority. It owns accounts, credentials,
sessions, refresh lineages, roles and role assignments, and it is the only thing in the ecosystem
that issues an access token.

It implements no cryptography, no password comparison and no token format of its own. Every one of
those is `@munaxa/*` — the shared security platform — and this repository is the adapters, the
wiring and the data those libraries were designed to be given.

## The boundary, in three sentences

**Munaxa Work does not own credentials.** It holds no password, no session, no signing key and no
private key of any kind; it verifies tokens with a configured public key and could not mint one it
would accept.

**Munaxa Identity does not own Work tenant membership.** It knows organisations, accounts and
grants. Which Work tenant somebody may act in is answered by Work's own `tenant_membership`, and
the `tid` claim is deliberately not read there.

**Munaxa Platform owns security primitives, not durable product state.** No database driver appears
in any `@munaxa/*` package, by design. The tables live here because a product owns its data.

## Quick start

```bash
pnpm install                       # needs a token with read:packages on the munaxa org
pnpm keys:generate                 # prints the key pair; private half to your .env, public to Work
createdb identity && psql identity -f prisma/migrations/*/migration.sql
pnpm prisma:generate

IDENTITY_OWNER_EMAIL=you@example IDENTITY_OWNER_PASSWORD='…' \
  pnpm db:bootstrap-account --organisation acme --organisation-name Acme
pnpm db:seed-work-roles --organisation acme
IDENTITY_OWNER_EMAIL=you@example IDENTITY_OWNER_PASSWORD='…' \
  pnpm db:bootstrap-account --organisation acme --role work-staging-operator

pnpm --filter @identity/api dev
```

The last command prints the account's `sub`. That value is what Munaxa Work needs:
`pnpm db:bootstrap --platform-user-id <sub>`.

## The API

|                                     |                                                                  |
| ----------------------------------- | ---------------------------------------------------------------- |
| `GET /api/auth/login`               | The sign-in page. A plain form; works without JavaScript.        |
| `POST /api/auth/login`              | Credentials in, `__Host-mx_session` and `__Host-mx_refresh` out. |
| `POST /api/auth/refresh`            | Rotates both, re-resolves permissions, detects reuse.            |
| `POST /api/auth/logout`             | Revokes the session and the lineage. Works on an expired token.  |
| `GET /api/auth/session`             | Subject and expiry. Never a token, never a permission set.       |
| `GET /api/auth/health/{live,ready}` | Readiness touches the database.                                  |

## Documentation

- [**Architecture**](./ARCHITECTURE.md) — ownership, the flow, tenancy, and what is deliberately absent.
- [**Decisions**](./docs/adr) — the choices that would otherwise be re-litigated.
- [**Runbooks**](./docs/runbooks) — provisioning, key rotation, revocation, rollback.
- [**Artifacts**](./artifacts) — Munaxa Work's permission catalogue, and why it is a file.
- [**Secrets**](./docs/runbooks/secrets.md) — what is secret, what is only configuration, and why.

## Known limitations

Stated here rather than discovered later.

- **MFA is not implemented.** `@munaxa/auth` provides it; this service does not yet wire it. Staging
  is safe without it — lockout, rate limiting and password policy are all live — and it is a
  production requirement, not an optional extra. See `docs/adr/0003-mfa-deferred.md`.
- **Revocation reaches Munaxa Work only when the access token expires**, up to about 16½ minutes.
  This is a property of the architecture, not a defect, and it is measured rather than assumed:
  `docs/runbooks/revocation.md`.
- **Password reset has a store and a conformance-tested adapter but no endpoint.** The flow is a
  later slice; the store exists because that is what the conformance suite validates.
- **Federation is not wired.** The account model carries `identity_source` and `external_id` from
  the first migration so adopting an external provider later is not a backfill.
