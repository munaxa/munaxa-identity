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

## Consequences

- Identity contains no TOTP arithmetic and no encryption primitive; the adapter and wiring are
  Identity's, the algorithms are Platform's.
- Production cannot start without a dedicated MFA key and a distributed replay guard. That is a new
  deployment prerequisite: a secret to provision before the first image built from this code runs.
- The confirmation code is not claimed by `MfaService.confirmTotpEnrollment`; the enrollment endpoint
  claims it explicitly so it cannot be replayed at sign-in. Reported to Platform as a follow-up,
  together with a `regenerateRecoveryCodes` method and a context-bound `protectSecret`, which would
  let the per-account construction go.
