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

| Action                                | Identity                                            | Munaxa Work                   |
| ------------------------------------- | --------------------------------------------------- | ----------------------------- |
| `RoleAdministration.revoke`           | at once — the cache is invalidated in the same call | next token                    |
| A role change written directly in SQL | within 60 s, when the cache expires                 | next token                    |
| Session revoked                       | at once; refresh refuses                            | when the access token expires |
| Account disabled                      | at once; refresh refuses                            | when the access token expires |
| Refresh token replayed                | at once; the whole lineage is revoked               | when the access token expires |

## Cutting someone off now

Revoke the session **and** the refresh lineage. No further token is issued, so the exposure is
bounded by the current access token's remaining life — at most 15½ minutes, usually much less.
Nothing shortens a token already in a browser: that is the cost of a stateless verifier, and it is
the trade the architecture makes deliberately.

If that window is ever judged unacceptable, the smallest additional contract is a
`permission_version` claim plus one briefly-cached introspection endpoint Work consults. Munaxa Docs
implements exactly that (`apps/api/src/core/auth/permission-version.ts`), and its comment records
what the unchecked version claim cost them: three documented revocation guarantees that were false.
It is not built here, because building it means a per-request call from Work to Identity and that is
a decision with its own cost.

## Never

Do not mutate `identity_role_assignment` directly in production. `RoleAdministration` is the only
path that pairs the write with `PermissionResolver.invalidateUser`, and the pairing is why a
revocation takes effect in seconds rather than in a minute. Nothing else in the service is permitted
to import the role ports.
