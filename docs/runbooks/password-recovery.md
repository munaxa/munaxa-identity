# Password recovery and email delivery

What the reset flow does, how to turn it on, what fails and how, and what to do when a link or a
mailbox is compromised.

Code: `apps/api/src/password/` (service and routes), `apps/api/src/delivery/email.ts` (delivery
port and transports), `apps/api/src/ui/password-recovery.page.ts` (pages),
`packages/config/src/password-recovery.ts` (configuration and its fail-closed rules). Tests:
`packages/testing/src/password-recovery.integration.test.ts`,
`packages/config/src/password-recovery.test.ts`.

## Deployment prerequisites (blocking)

- **Production refuses to start unless recovery is disabled.** `IDENTITY_PASSWORD_RESET`
  defaults to `enabled` and `PRODUCTION_EMAIL_TRANSPORTS` is empty, so with `NODE_ENV=production`
  (which every AWS task definition sets) Identity exits at startup unless the task definition sets
  `IDENTITY_PASSWORD_RESET=disabled`. Add that variable before rolling out any image built from
  this code.
- **Password reset is unusable in production** until an SES task-role transport is implemented
  and added to `PRODUCTION_EMAIL_TRANSPORTS` (see "Email delivery on AWS").
- **Reset links carry the token in the query string.** The request log records only the path,
  but an ALB, CloudFront or other proxy access log on `/api/auth/password/reset` records the full
  URL, so those logs contain live bearer credentials for up to the link TTL. Before enabling
  recovery anywhere: either keep load-balancer and CDN access logging off for this path, or treat
  those logs as secret (restricted access, short retention). The token leaves the URL after the
  first request (it moves into a form field), so only the initial `GET` is exposed.

## The flow

| Route                                        | Does                                                                                                                                                                        | Never                                                                                          |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `GET /api/auth/password/forgot`              | Request form                                                                                                                                                                |                                                                                                |
| `POST /api/auth/password/forgot`             | Ask for a link. `202 {ok:true}` (form: `303` to the "sent" notice)                                                                                                          | Answers differently for a known, unknown or disabled account, or an unknown organisation       |
| `GET /api/auth/password/reset?org=…&token=…` | Inspect a link: renders the new-password form, or "invalid or expired". `Accept: application/json` gets `{valid}`                                                           | Consumes the link                                                                              |
| `POST /api/auth/password/reset`              | `{organisation, token, password}`. Sets the password and signs every device out. `200`, `400 AUTH_RESET_TOKEN_INVALID`, `422 AUTH_PASSWORD_POLICY / AUTH_PASSWORD_BREACHED` | Signs the user in. They sign in normally afterwards, so MFA, when enrolled, is still asked for |

Every route answers `404` when recovery is disabled and `503 AUTH_RESET_UNAVAILABLE` when it is
enabled but cannot deliver.

The rules themselves (token generation, 256-bit tokens hashed at rest with the deployment pepper,
single use by compare-and-swap, binding to the password in force at issue time, only the newest
link valid, policy and breach checks) are Platform's `PasswordResetService`, used unchanged.
Identity adds:

- **Atomic completion.** Platform performs completion as five port calls (claim, password write,
  token-version bump, revoke other links, `onReset`). Identity runs the whole call, plus the
  session and refresh-lineage revocation in `onReset`, inside one PostgreSQL transaction
  (`PrismaService.unitOfWork`): every adapter's `withTenant` joins it. The account row is locked
  `FOR UPDATE` first, so a concurrent password change cannot interleave. If any step fails, or the
  process or its connection dies, PostgreSQL rolls all of it back: the link is still usable and
  the old password and sessions are untouched. There is no state in which a link is spent but the
  password is unchanged, or the password is changed but old sessions still work. Tested by
  injecting a failure at each step and by terminating the transaction's backend mid-way.
- **No enumeration, including by timing.** The request is answered after only the input-shape
  check and the rate limits, both independent of any account. Looking up the organisation and
  account, writing the token and sending the email happen afterwards, off the request path.
- **Links from configuration only.** `IDENTITY_PASSWORD_RESET_URL` plus `?org=&token=`. The
  `Host` and `X-Forwarded-Host` headers are never read.
- **Mail scanners cannot burn links.** `GET` only inspects. The token moves from the URL into a
  hidden form field and is spent by the `POST`.
- **Delivery fails closed.** No transport: recovery is unavailable and writes nothing. A
  transport that refuses a message (after up to three attempts for retryable failures) has the
  token it carried revoked immediately, so no live, undelivered link is ever left behind.
- **Abuse limits, shared.** `POST /forgot`: 5 per hour per client address and 3 per hour per
  (organisation, identifier digest), in the shared Redis cache, keyed the same way whether or not
  the account exists. If Redis cannot be reached the request is refused with `503` (Platform's
  limiter allows on failure; recovery deliberately does not). The `GET`/`POST /reset` routes are
  covered by the edge's Platform baseline rule `password-reset-per-ip` (5 per hour per address).
- **Nothing sensitive is logged.** No token, password, address or link appears in any log line or
  audit payload. The request log records the path without the query string. Every response
  carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (the edge's API headers),
  and the reset pages add `<meta name="referrer" content="no-referrer">`.
- **The owner is told.** After a completed reset a "your password was changed" notice is sent,
  best effort.

Audit events (hash-chained trail): `auth.password.reset.requested` (success, or failure with
`reason: delivery-failed`), `auth.password.reset.completed` (success, or failure with
`reason: token-invalid`), `auth.password.policy.rejected`.

## Configuration

| Variable                      | Default   | Meaning                                                                                                                                                                  |
| ----------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `IDENTITY_PASSWORD_RESET`     | `enabled` | `disabled` removes every route (404).                                                                                                                                    |
| `IDENTITY_PASSWORD_RESET_URL` | empty     | Absolute URL of the reset page. Origin must be in `CSRF_TRUSTED_ORIGINS`; https in production; no query, fragment or credentials. Required once a transport is selected. |
| `IDENTITY_PASSWORD_RESET_TTL` | `30m`     | 1 minute to 1 hour.                                                                                                                                                      |
| `IDENTITY_EMAIL_TRANSPORT`    | `none`    | `none` or `outbox`.                                                                                                                                                      |
| `IDENTITY_EMAIL_FROM`         | empty     | Sender address; required for any transport other than `none`.                                                                                                            |
| `IDENTITY_EMAIL_OUTBOX_DIR`   | empty     | Directory for `outbox`.                                                                                                                                                  |

Startup refuses, in production (`NODE_ENV=production`, which the AWS task definitions set):

- `IDENTITY_PASSWORD_RESET=enabled` without a production-grade transport. **There is none yet**,
  so every production deployment must set `IDENTITY_PASSWORD_RESET=disabled` until the SES
  adapter below exists. This is deliberate: a reset flow that mails nothing is worse than none.
- `IDENTITY_EMAIL_TRANSPORT=outbox`, whatever the recovery setting: it writes live links to disk.

In development, `IDENTITY_EMAIL_TRANSPORT=outbox` with `IDENTITY_EMAIL_OUTBOX_DIR=./.outbox` and
`IDENTITY_PASSWORD_RESET_URL=http://localhost:4001/api/auth/password/reset` gives a working flow:
each message is a `0600` JSON file holding the link.

## Email delivery on AWS (not built yet)

The delivery port is Platform's `NotificationTransportPort` (`send(message) → {delivered,
retryable}`); a provider is one class implementing it, registered in `emailTransportFor` and added
to `PRODUCTION_EMAIL_TRANSPORTS`. The preferred AWS integration:

- **Amazon SES v2 `SendEmail` API over HTTPS, signed with the ECS task role.** No SMTP, and no IAM
  user: SES SMTP credentials are a long-lived IAM-user secret, which this project does not create.
- Task-role permission limited to `ses:SendEmail` on the verified sending identity, with the
  `ses:FromAddress` condition pinned to `IDENTITY_EMAIL_FROM`.
- A verified domain identity with DKIM, a configuration set with bounce and complaint
  notifications, and the account out of the SES sandbox.
- A VPC route to the SES endpoint (NAT or an interface endpoint) from the private subnets.
- Map SES throttling and 5xx to `retryable: true`; a rejected recipient to `retryable: false`.

None of this exists, and none of it was created by this change. Adding the adapter needs a new
dependency (`@aws-sdk/client-sesv2`, or a SigV4 signer), which needs a lockfile update by someone
with access to the package registry, plus the AWS resources above. Until then production runs
with recovery disabled.

`@munaxa/notifications` (Platform's `NotificationService`, with retries, deduplication and a
secret-leak guard) is not used yet for the same lockfile reason; `sendEmail` here does bounded
retries, and the message bodies follow Platform's `security.password-reset-requested` and
`security.password-changed` wording.

## Changing a password while signed in

`POST /api/auth/password/change` with `{currentPassword, newPassword}`, authenticated by the
session cookie (`resolvePrincipal`: verified token, live session, active account, current token
version) and behind the edge's origin allow-list. Platform's `LoginService.changePassword` proves
the current password, applies policy and the breach check, writes the hash and bumps the token
version. In the same transaction (`unitOfWork`, account row locked) Identity revokes every
outstanding reset link and every session and refresh lineage, **including the caller's**, then
clears the cookies: the person signs in again. A failure part-way changes nothing (tested).

Answers: `200 {ok, signedOut}`, `401 AUTH_UNAUTHENTICATED` (no valid session),
`401 AUTH_INVALID_CREDENTIALS` (wrong current password), `422` policy or breach, `429` after 5
attempts per account in 15 minutes (shared cache; `503` if the cache is unreachable), `503` on a
dependency failure. Audit: `auth.password.changed` (success, or failure with
`reason: current-password`).

Not yet: for an account with MFA enrolled, the change asks for the password only. A TOTP step-up
belongs with the recent-reauthentication helper in the MFA work and should be added to this route
when that lands.

## Operational failures

| Symptom                                        | Meaning                                                                                                                                                | Action                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| Startup fails naming `IDENTITY_PASSWORD_RESET` | Production with recovery on and no production transport                                                                                                | Set `IDENTITY_PASSWORD_RESET=disabled`, or wire a real transport  |
| All recovery routes `404`                      | Recovery disabled                                                                                                                                      | Expected unless it should be on                                   |
| `503 AUTH_RESET_UNAVAILABLE` on every request  | No transport or no reset URL; or Redis unreachable (log `auth.password_reset.limiter_unavailable`)                                                     | Check configuration; check Redis like any login outage            |
| Users get `202` but no email                   | Delivery failing: log `auth.password_reset.request_failed`, audit `auth.password.reset.requested` with `reason: delivery-failed`. The link was revoked | Fix the transport. Users ask again                                |
| `auth.password_reset.backlog_full`             | More than 64 request jobs in flight on one replica; extra requests dropped (still `202`)                                                               | Investigate a flood; the per-address limit should have stopped it |
| Completion returns `503`                       | Database failure during the transaction; nothing changed                                                                                               | The same link works again once the database is healthy            |

## Incident response

**A reset link leaked** (forwarded email, screenshot, compromised mailbox). Until used, the
person can request a new link: only the newest link works. If it was used by someone else, the
account owner's password changed and every session was revoked; treat the account as
compromised: disable it, then follow `revocation.md`.

**A mailbox is compromised.** Recovery trusts the mailbox. Disable the account
(`revocation.md`, which bumps the token version and revokes all sessions) before the attacker
requests a link, then restore access through an administrator once the mailbox is secure. Lost
MFA devices are not recovered by email; see the MFA runbook.

**Suspected mass reset abuse.** Look for `auth.password.reset.requested` volume per organisation
in the audit trail and for `429`s. Setting `IDENTITY_PASSWORD_RESET=disabled` and redeploying
stops the feature at once; outstanding links stay unusable while it is disabled (the routes are
gone) and expire within the TTL.

**The pepper (`IDENTITY_SIGNING_SECRET`) is rotated.** Every outstanding reset link stops working
(as do refresh tokens); users request new ones.

## What remains

- No production email transport (above). Production recovery is off until one exists.
- Access tokens are stateless JWTs. After a reset, Identity's own routes and refresh refuse the
  old session at once, but an access token already issued stays acceptable to services that only
  verify its signature until it expires (`ACCESS_TOKEN_TTL`, 15 minutes by default).
- `PASSWORD_HISTORY` is not enforced: no password-history store is wired (pre-existing).
- The per-replica job cap means a request can be dropped under a flood; the user sees the normal
  "sent" notice and asks again.
