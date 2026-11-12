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

|                                         |                                                                     |
| --------------------------------------- | ------------------------------------------------------------------- |
| `GET /api/auth/login`                   | The sign-in page. A plain form; works without JavaScript.           |
| `POST /api/auth/login`                  | Credentials in, `__Host-mx_session` and `__Secure-mx_refresh` out.  |
| `POST /api/auth/refresh`                | Rotates both, re-resolves permissions, detects reuse.               |
| `POST /api/auth/logout`                 | Revokes the session and the lineage. Works on an expired token.     |
| `GET /api/auth/session`                 | Subject and expiry. Never a token, never a permission set.          |
| `GET /api/auth/introspect`              | For products: is this bearer access token's session still live?     |
| `GET /api/auth/sessions`                | The caller's live sessions: times, network prefix, device label.    |
| `DELETE /api/auth/sessions/:id`         | Signs out one of the caller's own sessions, lineage included.       |
| `POST /api/auth/sessions/revoke-others` | Signs out every session except the one making the request.          |
| `POST /api/auth/mfa/verify`             | Redeems the `__Host-mx_mfa` challenge with a TOTP or recovery code. |
| `GET /api/auth/mfa/status`              | Whether a factor is active and how many recovery codes remain.      |
| `POST /api/auth/reauthenticate`         | Password, plus the factor when enrolled; opens the step-up window.  |
| `POST /api/auth/mfa/enrollment`         | Starts TOTP enrollment (session after step-up, or a challenge).     |
| `POST /api/auth/mfa/enrollment/confirm` | Confirms it; returns recovery codes once, ends other sessions.      |
| `POST /api/auth/mfa/recovery-codes`     | Replaces every recovery code. Requires a recent step-up.            |
| `DELETE /api/auth/mfa`                  | Removes the factor. Step-up required; refused when policy needs it. |
| `GET /api/auth/health/{live,ready}`     | Readiness touches the database.                                     |

## Documentation

- [**Architecture**](./ARCHITECTURE.md) — ownership, the flow, tenancy, and what is deliberately absent.
- [**Decisions**](./docs/adr) — the choices that would otherwise be re-litigated.
- [**Runbooks**](./docs/runbooks) — provisioning, key rotation, revocation, rollback.
- [**Production readiness**](./docs/production-readiness.md) — what must be true before an image built from `main` runs in production.
- [**Artifacts**](./artifacts) — Munaxa Work's permission catalogue, and why it is a file.
- [**Secrets**](./docs/runbooks/secrets.md) — what is secret, what is only configuration, and why.
- [**AWS**](./docs/runbooks/aws.md) — the shared AWS stack (draft): images, the migrate task and configuration.
- [**Dependency overrides**](./docs/dependency-overrides.md) — each override, the advisory behind it and when it goes.

## Known limitations

Stated here rather than discovered later.

- **MFA enforcement is off by default.** TOTP MFA is implemented (ADR-0005) and production requires
  its key ring, but who must use it is `MFA_POLICY`, which defaults to `off`. The production target
  is `privileged`: [production readiness](./docs/production-readiness.md).
- **Revocation reaches Munaxa Work only when the access token expires**, up to about 16½ minutes.
  This is a property of the architecture, not a defect, and it is measured rather than assumed:
  `docs/runbooks/revocation.md`.
- **Password reset is implemented but cannot be enabled in production yet.** There is no
  production email transport, so production requires `IDENTITY_PASSWORD_RESET=disabled`
  ([password recovery](./docs/runbooks/password-recovery.md)).
- **There is no administration API.** Operator recovery (lost MFA device, account disable,
  enforcement roll-out, key re-encryption) is one-off commands: ADR-0006.
- **Federation is not wired.** The account model carries `identity_source` and `external_id` from
  the first migration so adopting an external provider later is not a backfill.
