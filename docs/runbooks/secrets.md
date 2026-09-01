# Staging secret inventory

Three categories, and the reason for separating them is that they are protected differently.
Treating configuration as secret makes deployment painful enough that people work around it;
treating a secret as configuration is how it ends up in Git.

## Secrets — a leak means rotate, and possibly re-authenticate everybody

| Secret                         | Held by        | Delivered as                        | If it leaks                                                                                                                                                                                                  |
| ------------------------------ | -------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `IDENTITY_SIGNING_PRIVATE_KEY` | Identity       | mounted file → `*_FILE`             | **Worst case.** Mints a token for any account in any organisation. Rotate immediately and remove the old public key from Work at once, accepting that every session dies. `docs/runbooks/key-rotation.md`.   |
| `IDENTITY_SIGNING_SECRET`      | Identity       | mounted file → `*_FILE`             | Pepper for refresh-token hashes and CSRF signing. A stolen database becomes usable for refresh-token lookup. Rotate; existing refresh tokens stop resolving, so everybody signs in again.                    |
| Identity `DATABASE_URL`        | Identity       | mounted file → `*_FILE`             | Every account, session and role. The connection is `NOBYPASSRLS`, so RLS still applies — but the credential also reaches `identity_tenant`, which is readable without a context. Rotate the role's password. |
| Work `DATABASE_URL`            | Work           | environment, from your secret store | Every tenant's business data, subject to RLS. Rotate the role's password.                                                                                                                                    |
| `WORK_PII_MATCH_SECRET`        | Work           | environment, from your secret store | The keyed digest for national-identifier matching. Rotating it invalidates stored digests — treat as a data migration, not a password change.                                                                |
| `PLATFORM_PACKAGES_TOKEN`      | GitHub Actions | Actions secret                      | Read access to `@munaxa/*` packages. Revoke and reissue; no runtime impact.                                                                                                                                  |
| The first operator's password  | a person       | typed at a prompt                   | One account. Change it. It is never in Git, never echoed, and never in shell history if the runbook is followed.                                                                                             |

Identity's four are **files**, not environment variables, and that is the point of the `*_FILE`
convention: an environment variable is visible to `docker inspect`, to every process in the
container, and to any crash reporter that dumps the environment.

## Configuration — public, and wrong is an outage rather than a breach

| Setting                                                               | Why it is not a secret                                                                                                   |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `PUBLIC_HOST`, `PUBLIC_ORIGIN`                                        | A hostname. It is in DNS and in every certificate log.                                                                   |
| `PLATFORM_AUTH_ISSUER`                                                | Derived from `PUBLIC_ORIGIN`. Appears in every token.                                                                    |
| `PLATFORM_AUTH_AUDIENCE`                                              | `munaxa-work`. Appears in every token.                                                                                   |
| `PLATFORM_AUTH_ALGORITHM`                                             | `ES256`.                                                                                                                 |
| `PLATFORM_AUTH_PUBLIC_KEYS`                                           | The **public** half. It verifies; it cannot sign. Publishing it is what a JWKS endpoint would do, and Platform has none. |
| `IDENTITY_SIGNING_KID`                                                | A key's name, in every token header.                                                                                     |
| `WORK_API_URL`, `IDENTITY_DEFAULT_ORGANISATION`, image tags, versions | Deployment topology.                                                                                                     |

Getting one of these wrong produces a 401 on every request with nothing in the log to explain it —
which is why the readiness endpoint reports the signing `kid` and the provisioning runbook says to
compare it against what Work was configured with.

## Generated at runtime — not provisioned, not backed up as secrets

Session records, refresh-token lineages (hashed, peppered — the token itself is never stored), the
hash-chained audit trail, and the permission cache in Redis.

The audit trail is evidence and should be exported off-box; the platform ships exporters for that.
Redis holds nothing that cannot be rebuilt, which is why the compose file does not persist it — a
persisted cache is a file of session-shaped data nobody is watching.
