# Rate limits on Identity's credential routes

Every limit below is enforced in Redis (Valkey), shared by every Identity task that uses the same
store, and counted atomically (`INCRBY`). The edge matches the route Express actually serves, under
every spelling: `canonicalRoute(request.originalUrl)` removes an absolute-form scheme and host, the
query and the fragment, decodes once, resolves `.` and `..`, collapses repeated and trailing
slashes and lowercases. No request header takes part in it. The client address is `request.ip`,
which is the client's own only because `TRUST_PROXY_HOPS` names the one proxy in front (the ALB:
`1`); a client's `X-Forwarded-For` cannot choose its bucket.

## The policy

| Route (canonical), method                                                               | Rule                                                            | Counter identity                                                                             | Limit (default, env)                                              | Window                              | On refusal                                 | On store failure                         |
| --------------------------------------------------------------------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------- | ------------------------------------------ | ---------------------------------------- |
| `/api/auth/login` POST                                                                  | `login-per-identifier`                                          | digest of the typed identifier, trimmed and lowercased; any address, existing account or not | 20 (`EDGE_LOGIN_PER_IDENTIFIER_LIMIT`, 10–200)                    | 15 min                              | 429 `SECURITY_RATE_LIMITED`, `Retry-After` | 503 `AUTH_UNAVAILABLE`, `Retry-After: 5` |
| `/api/auth/login` POST                                                                  | `login-per-ip`                                                  | client address                                                                               | 300 (`EDGE_LOGIN_PER_IP_LIMIT`, 30–100,000)                       | 5 min                               | 429, `Retry-After`                         | 503                                      |
| `/api/auth/login` POST                                                                  | account lockout (Platform `LoginService`)                       | (organisation, trimmed lowercased identifier); counts failures only                          | 10 failures (`LOGIN_MAX_ATTEMPTS`)                                | locked for `LOGIN_LOCKOUT` (15 min) | 429 `AUTH_RATE_LIMITED`, `Retry-After`     | 503 (sign-in needs the store)            |
| `/api/auth/password/forgot`, `/api/auth/password/reset` POST                            | `password-reset-per-ip`                                         | client address                                                                               | 60 (`EDGE_PASSWORD_RESET_PER_IP_LIMIT`, 10–10,000)                | 1 h                                 | 429                                        | 503                                      |
| `/api/auth/password/forgot` POST (service)                                              | `password-forgot-per-identifier`, then `password-forgot-per-ip` | digest of (organisation, identifier); client address                                         | 3; 30 (`PASSWORD_RESET_REQUESTS_PER_IP`, 5–10,000)                | 1 h                                 | 429 `AUTH_RATE_LIMITED`                    | 503                                      |
| `/api/auth/mfa/verify` POST                                                             | `mfa-per-session`                                               | digest of the challenge cookie                                                               | 10 (`EDGE_MFA_PER_SESSION_LIMIT`, 5–100)                          | 15 min                              | 429                                        | 503                                      |
| `/api/auth/reauthenticate`, `/api/auth/mfa/recovery-codes` POST, `/api/auth/mfa` DELETE | `mfa-per-session`                                               | the session's `sid` (access-token cookie verified locally)                                   | 10                                                                | 15 min                              | 429                                        | 503                                      |
| `/api/auth/mfa/enrollment`, `/api/auth/mfa/enrollment/confirm` POST                     | `mfa-per-session`                                               | session `sid`, else digest of the enrolment challenge                                        | 10                                                                | 15 min                              | 429                                        | 503                                      |
| all six MFA routes above                                                                | `mfa-per-ip`                                                    | client address                                                                               | 300 (`EDGE_MFA_PER_IP_LIMIT`, 30–100,000)                         | 15 min                              | 429                                        | 503                                      |
| MFA (service)                                                                           | per challenge; per account                                      | challenge; account                                                                           | 5 (`MFA_CHALLENGE_MAX_ATTEMPTS`); 10 (`MFA_ACCOUNT_MAX_FAILURES`) | challenge TTL; `LOGIN_LOCKOUT`      | 401 / locked                               | 503                                      |
| `/api/auth/password/change` POST (service)                                              | `password-change-per-account`                                   | account                                                                                      | 5                                                                 | 15 min                              | 429 `AUTH_RATE_LIMITED`                    | 503                                      |
| `/api/auth/introspect` GET                                                              | `introspect-per-ip`; `introspect-per-user` (identity#15)        | client address; account                                                                      | 12,000/min; 600/min                                               | 1 min                               | 429 `RATE_LIMITED`                         | admits (general limit)                   |
| every other route                                                                       | `api-per-ip`                                                    | client address                                                                               | 300/min                                                           | 1 min                               | 429                                        | admits (general limit)                   |

Rules are evaluated in the order listed; the first refusal stops, and later rules are not charged.
Every rule is a plain sliding window: refused attempts count, and the count is one stable counter
per rule and subject. (Platform 2.4.1's adaptive rules restart their count after a refusal, so none
is used here; see munaxa-platform#107 for the fix in Platform.) Page views (`GET` of the sign-in,
reset and MFA pages) are not counted by the credential rules. A request with no identifier, no
challenge or no verifiable session is still counted by the address rule, and the route refuses it.

## Why these numbers (shared NAT)

A school or an office reaches Identity from one public address. The per-address limits are
therefore sized for a population, and the controls that stop guessing at one account do not depend
on the address:

- **One account** gets at most `LOGIN_MAX_ATTEMPTS` (10) wrong passwords per lockout period, and at
  most 20 sign-in posts per 15 minutes at the edge, from any number of addresses. Changing address,
  case or surrounding whitespace does not reset either.
- **One address** gets 300 sign-in posts per 5 minutes, about 900 in a 15-minute morning rush:
  enough for a site of several hundred people signing in at once with typos and retries (a refused
  post is told when to retry, and the rest of the day is far below the limit). A larger site, or
  one whose users all sign in in the same minute, should raise `EDGE_LOGIN_PER_IP_LIMIT` before it
  is onboarded.
- **One person hammering one account inside a school** is refused on the identifier rule first,
  which is evaluated before the address rule, so those refusals are not charged to the school.
- **Many accounts guessed from one address** (credential stuffing) are what the address limit is
  for; at 300 per 5 minutes that is at most 3,600 an hour, each still subject to its account's
  lockout. An attacker inside the school's network shares the school's address: that is the
  trade-off of any address limit, and why it is set high and the account limits low.
- **Lockout is temporary** (15 minutes) and cannot be made permanent by an unauthenticated caller.
  An attacker can keep one known account locked by sending 10 wrong passwords every 15 minutes;
  that is the accepted cost of account lockout, and an operator can see it in the audit log
  (`auth.account.locked`).
- **Password reset** cannot lock anybody out: requesting a link does not change the password or the
  account. Three requests per identifier per hour bound how often somebody else's outstanding link
  can be replaced; thirty per address per hour let a school's forgetful mornings through.
- **No limit reveals whether an account exists**: every identifier-keyed counter is keyed by what was
  typed, not by an account, and the answer is the same for both.

**These values are provisional.** No production traffic exists yet. Before a customer with more
than about 500 people per site is onboarded, and in any case after the first month of production
traffic, compare the `security.ratelimit.exceeded` audit events (rule, retry) and the ALB request
counts per client address against these limits, and adjust through the environment variables.
Nothing here needs an infrastructure change to adjust.

## Multiple tasks

All counters live in the one Redis the task uses. Several tasks share a limit exactly when they use
the **same** Redis. The current AWS stack runs Valkey as a sidecar of each Identity task
(`127.0.0.1:6379`), so with `desired_counts.identity` above 1 every limit, lockout and MFA challenge
would exist once per task: see the owner decision in the 2026-11-12 rate-limiting report. Run one
Identity task per Valkey until a shared store exists.

## Failure behaviour

- Store refuses or the connection is lost: the command fails; credential routes answer 503 with
  `Retry-After: 5`; sign-in, reset and MFA services also refuse (503).
- Store hangs: each command fails after `REDIS_COMMAND_TIMEOUT_MS` (2 s), then as above.
- Malformed values: Platform's cache reads an unparseable value as a miss; a counter is written only
  by `INCRBY`, so a value Redis cannot increment is an error, handled as a failure.
- General API limits (`api-per-ip`, introspection) admit on a store failure, so a cache outage does
  not take down every route; the credential routes are refused either way.
