# Runbook — revoking access, and how long it takes

## The window, measured

| Layer                               | Value             | Where it comes from                      |
| ----------------------------------- | ----------------- | ---------------------------------------- |
| Permission cache                    | 60 s              | `PermissionResolver`, `cacheTtl` default |
| Access token                        | 15 min            | `ACCESS_TOKEN_TTL`                       |
| Clock skew                          | 30 s              | `PLATFORM_AUTH_CLOCK_SKEW_MS`            |
| **Worst case reaching Munaxa Work** | **≈ 16 min 30 s** | the three, in series                     |

Measured, not assumed: a role removed by direct SQL produced a token with zero grants 46 seconds
later — the resolver cache expiring — and Work honours an already-issued token until it expires.

## What takes effect immediately, and what does not

| Action                                | Identity                                            | Munaxa Work                |
| ------------------------------------- | --------------------------------------------------- | -------------------------- |
| `RoleAdministration.revoke`           | at once — the cache is invalidated in the same call | next token                 |
| A role change written directly in SQL | within 60 s, when the cache expires                 | next token                 |
| Session revoked                       | at once; refresh refuses                            | within 5 s (introspection) |
| Account disabled                      | at once; refresh refuses                            | within 5 s (introspection) |
| Refresh token replayed                | at once; the whole lineage is revoked               | within 5 s (introspection) |

## Sessions and lineages are revoked together

Every user-facing revocation goes through `CredentialRevocation`
(`apps/api/src/account/credential-revocation.ts`), which revokes the `identity_session` row **and**
every refresh token bound to it in one transaction, with the account id in the `WHERE` clause.

| Trigger                                                    | What is revoked                                     | Reason recorded    |
| ---------------------------------------------------------- | --------------------------------------------------- | ------------------ |
| `POST /api/auth/logout`                                    | the caller's session and its lineage                | `logout`           |
| `DELETE /api/auth/sessions/:id` (own session only)         | that session and its lineage                        | `logout`           |
| `POST /api/auth/sessions/revoke-others`                    | every other session of the caller, and lineages     | `logout-all`       |
| Password reset (`revokeAllForUser`)¹                       | every session and refresh token of the account      | `password-reset`   |
| Password change (`revokeAllForUser`)¹                      | the same; optionally keeping the changing session   | `password-changed` |
| MFA removal or replacement (`revokeAllForUser`, `except`)¹ | every other session                                 | `mfa-changed`      |
| Refresh token replayed                                     | the lineage (Platform) and its session (Identity)   | `token-reuse`      |
| `AccountLockdown.suspectedCompromise`                      | token version bumped, everything revoked            | `risk-detected`    |
| `AccountLockdown.disable`                                  | status disabled, version bumped, everything revoked | `account-disabled` |
| Refresh after a token-version bump                         | the lineage and its session                         | `password-changed` |

¹ The hook exists and is tested, but on main nothing calls it yet: the password-reset,
password-change and MFA flows that will call it are separate changes. Until they merge, these rows
describe the contract those flows must follow, not behaviour the service has today.

Every row a user or the system initiates through `AccountSessionsService` or `AccountLockdown`
also writes an audit record (`session.revoked`, or `auth.account.locked` for a disablement) after
the revocation commits, outside its transaction: counts, reason and session id, never a token, an
address or a user-agent. A failing audit sink is reported and does not undo the revocation.

Two properties hold whatever races what:

- **Revocation is one-way.** `PrismaSessionStore.update` only writes an unrevoked row, so the
  whole-record write `SessionManager.touch` makes on every refresh can no longer write
  `revoked_at = null` over a revocation that committed between its read and its write.
- **Refresh cannot restore a session.** Every rotation re-reads the account (status and current
  token version) and re-validates the session against that version; a failure revokes the lineage.
  A token rotated concurrently with a revocation is refused on its first use.

`AccountLockdown` has no HTTP route yet: there is no administration API. It is what one, an
operator script or a risk engine calls.

## What an already-issued access token can still do

The access token is a 15-minute ES256 JWT. After any revocation above:

- **Every Identity route refuses it at once.** `resolvePrincipal` (`apps/api/src/auth/principal.ts`)
  verifies the token, loads the account, requires the current token version, and validates the
  session row on every request.
- **Munaxa Work refuses it within its revocation window** (Work ADR-0080). After verifying the
  signature, Work asks `GET /api/auth/introspect` with the token as a Bearer credential. The route
  decides with the same `resolvePrincipal` and answers `{ active: true, sub, tid, sid, exp }` or
  `{ active: false }` (`no-store`), or 503 `AUTH_UNAVAILABLE` when a dependency fails, which Work
  treats as a refusal. Work reuses a positive answer for at most `PLATFORM_AUTH_REVOCATION_CACHE_MS`
  (default 5 s) from when it asked, so a revocation committed at R stops a token at every Work
  instance for requests received after R + 5 s. The route is under the edge's `api-per-ip` limit
  (300 per minute per caller address), which bounds Work's throughput per task; see Work ADR-0080.

## Cutting someone off now

Revoke the session **and** the refresh lineage. No further token is issued; Identity refuses the
access token at once, and Munaxa Work within its revocation window (5 s by default). A product that
verifies tokens without introspecting still honours one until it expires, at most 15½ minutes.

A role change is different: it is not a session revocation, so introspection still answers active.
It reaches Work with the next token (at most one access-token lifetime), as the first table says.

## Never

Do not mutate `identity_role_assignment` directly in production. `RoleAdministration` is the only
path that pairs the write with `PermissionResolver.invalidateUser`, and the pairing is why a
revocation takes effect in seconds rather than in a minute. Nothing else in the service is permitted
to import the role ports.
