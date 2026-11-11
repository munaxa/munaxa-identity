# ADR-0005 — TOTP MFA, on Platform's `MfaService`

**Status** Accepted · **Date** 2026-11-11 · **Supersedes** [ADR-0003](0003-mfa-deferred.md)

## Context

ADR-0003 deferred MFA and recorded that production is not acceptable without it. `@munaxa/auth`
2.4.1 provides TOTP (RFC 6238), hashed recovery codes and `MfaService`; `@munaxa/crypto` provides
AES-256-GCM envelopes, key rings and HKDF. Identity must add persistence, encryption, enrollment,
the login challenge and the policy — and no second TOTP implementation.

Reading `MfaService` against Identity's needs found four properties the service does not provide on
its own, all of which this ADR closes in Identity's adapter and wiring rather than by forking
Platform:

1. `protectSecret` has no context argument, so it cannot bind ciphertext to an account.
2. `beginTotpEnrollment` saves an unconfirmed record over the method's current one; against a
   one-row-per-method store, starting a replacement would switch MFA off.
3. Recovery codes reach the store as a bare SHA-256.
4. `verifyRecoveryCode` does not check that a factor is still active, and `remove` does not touch
   recovery codes.

## Decision

**Persistence.** Two tables, `identity_mfa_enrollment` and `identity_mfa_recovery_code`, both under
`FORCE ROW LEVEL SECURITY` with the standard `tenant_isolation` policy, granted to `identity_app`
for the four DML verbs and nothing else. `PrismaMfaEnrollmentStore` implements
`MfaEnrollmentStorePort`.

**Two views of the store.** Enrollment rows have a `state`: `pending` or `active`, unique per
account, method and state. The service used for enrollment sees only the pending view; the service
used for verification sees only the active view. Confirming promotes the pending row in one
transaction that deletes the replaced factor, deletes the previous recovery codes and sets
`identity_account.mfa_enrolled`. The pending row is matched on its ciphertext, so a concurrent
restart of enrollment cannot get an unproven secret promoted. Pending enrollments expire after 15
minutes. (Closes 2.)

**Encryption.** A dedicated key ring, `MFA_ENCRYPTION_KEYS` + `MFA_ENCRYPTION_PRIMARY_KID`, supplied
through the `_FILE` convention and required in production. Platform's `MUNAXA_ENCRYPTION_KEY` was
not used: it is one key with no retired set, so rotation would break every stored secret, and it is
described as shared across purposes. Each configured key is an HKDF master for two purpose-bound
subkeys. Secrets are sealed with `@munaxa/crypto` `encrypt` (AES-256-GCM, random 96-bit nonce,
envelope carries the kid) with AAD `["identity-mfa-secret", 1, tenant, account, method]`. A
`MfaService` is constructed per account with `protectSecret` closed over that AAD. (Closes 1.)
Configuration refuses a key that is the signing secret (the refresh-token pepper) or taken from the
signing private key. The database refuses a `secret_ciphertext` that is not an envelope.

**Recovery codes.** The store keeps `HMAC-SHA256(recovery subkey, sha256(code))` with the kid, so a
dump alone cannot be used to test guesses offline (the codes carry 75 bits, so this is defence in
depth, not the primary control). Saving a set replaces the previous set in one transaction.
Consumption is one conditional `UPDATE … WHERE consumed_at IS NULL` across every kid in the ring,
and only while an active factor exists; removing the last factor deletes the codes. (Closes 3, 4.)

**Replay.** `replayGuard` is the shared Redis cache, so a TOTP step accepted by one replica is
refused by all of them for its window. Startup in production refuses an in-process cache or a
missing ring (`assertMfaDistributed`).

**Rotation.** Add a key and make it primary; old envelopes still open; `reencryptTenant` re-seals
each row under the primary with a compare-and-swap on the old ciphertext; retire the old key when
nothing names it. Recovery-code hashes cannot be re-keyed, so their count under retired kids is
reported. Procedure: `docs/runbooks/mfa.md`.

**Login challenge.** When the password is right and a factor is needed, no session and no token
exist. `AuthService` issues a challenge: 256 random bits, held in the shared Redis under
`sha256(token)` with the tenant, account, token version and a user-agent digest, and handed to the
browser as `__Host-mx_mfa` (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, `Max-Age` = TTL).
`POST /api/auth/mfa/verify` checks a TOTP or a recovery code through Platform's `MfaService`, then
spends the challenge with a Redis `DEL` (exactly one winner fleet-wide) and only then calls
`AuthService.completeSignIn`, which creates the session with the methods actually used
(`['password','totp']` or `['password','recovery-code']`) and `mfaSatisfied: true`, carried into the
token's `amr` and `mfa` claims and preserved on refresh. Wrong answers count against the challenge
(`MFA_CHALLENGE_MAX_ATTEMPTS`, then it is destroyed) and against the account across challenges
(`MFA_ACCOUNT_MAX_FAILURES` per `LOGIN_LOCKOUT` window). A challenge whose account was disabled or
whose token version moved is refused. The challenge is not a JWT and no route that reads the session
cookie reads it.

**Policy.** `MFA_POLICY` = `off` | `privileged` (`MFA_PRIVILEGED_ROLES`) | `all`, consulted through
`LoginService.requireMfa` for accounts with no factor. Such an account gets an `enroll` challenge,
which admits only to `POST /api/auth/mfa/enrollment` and `/confirm`; confirming spends it and signs
in with both factors. Configuration refuses enforcement without a key ring and a privileged policy
without roles. No exemption list, no bypass flag, no emergency account. Machine identities do not
sign in through this flow. A factor the policy requires cannot be removed by its holder.

**Reauthentication.** Enrolling from a session, replacing, removing, and regenerating recovery codes
require a session created, or reauthenticated through `POST /api/auth/reauthenticate`, within
`MFA_REAUTH_WINDOW`. Reauthentication needs the password and, when enrolled, a TOTP or recovery
code; the marker is per session, in Redis, and spent by the change it authorised. Confirming an
enrollment or removing a factor revokes every other session of the account.

**Password change step-up.** `POST /api/auth/password/change` from an account with an active factor
also requires that window (`mfa/step-up.ts`), returning 403 `AUTH_REAUTHENTICATION_REQUIRED`
otherwise. The current password alone is not enough: a stolen session plus a phished password would
otherwise turn the session into the account. Fails closed (503) when the account is flagged enrolled
but MFA is not configured. Signing out other sessions (`revoke-others`, `DELETE sessions/:id`) is
deliberately not gated: it is how a victim evicts an attacker, and it only ever removes access.

**Confirmation step.** `MfaService.confirmTotpEnrollment` does not claim the step it accepted;
Identity claims it immediately after through the active factor, so the confirmation code cannot be
replayed at sign-in.

## Consequences

- Identity contains no TOTP arithmetic and no encryption primitive; the adapter and wiring are
  Identity's, the algorithms are Platform's.
- Production cannot start without a dedicated MFA key and a distributed replay guard. That is a new
  deployment prerequisite: a secret to provision before the first image built from this code runs.
- Platform follow-ups (reported, not forked): claim the step in `confirmTotpEnrollment`, a
  `regenerateRecoveryCodes` method (Identity regenerates with `@munaxa/crypto` `recoveryCode` and the
  same `sha256` Platform uses), and a context-bound `protectSecret`.
- Sessions that existed before an account became privileged under `MFA_POLICY` stay valid until
  they expire or are revoked. Enabling enforcement should be followed by revoking the affected
  accounts' sessions (`docs/runbooks/mfa.md`).
- A person who holds a required account's password but has never enrolled can enrol their own
  authenticator (trust on first enrollment). That is inherent to self-service enrollment; accounts
  should be enrolled by their holders promptly after creation.
