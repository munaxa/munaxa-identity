# TOTP MFA — operations

What MFA is made of in Identity, how its key is provisioned and rotated, and what each failure
looks like. The decision record is [ADR-0005](../adr/0005-totp-mfa.md).

## What is stored, and where

| Data                       | Where                                             | Form                                                                                                   |
| -------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| TOTP secret (active)       | `identity_mfa_enrollment`, `state = 'active'`     | AES-256-GCM envelope `v1.<kid>.<nonce>.<ciphertext>.<tag>`, AAD = tenant, account, method              |
| TOTP secret being enrolled | `identity_mfa_enrollment`, `state = 'pending'`    | Same envelope. Confirmable for 15 minutes, then ignored                                                |
| Recovery codes             | `identity_mfa_recovery_code`                      | `HMAC-SHA256(recovery subkey of <kid>, SHA-256(code))`. The code itself is shown once and never stored |
| Used TOTP steps            | Redis, `identity:mfa:totp:<tenant>:<user>:<step>` | A claim with a TTL of the drift window. Fleet-wide replay protection                                   |
| "Has MFA"                  | `identity_account.mfa_enrolled`                   | Kept equal to "has an active factor" in the same transaction as every change                           |

Both tables carry `FORCE ROW LEVEL SECURITY` with the `tenant_isolation` policy every tenant table
has. A database check constraint refuses any `secret_ciphertext` that is not an envelope, so a
plaintext secret cannot be written even by mistake.

## The key ring

`MFA_ENCRYPTION_KEYS` is `kid=key[,kid=key…]`; each key is 32 random bytes, base64url.
`MFA_ENCRYPTION_PRIMARY_KID` names the entry new secrets are sealed under; the others are kept only
so the secrets they sealed still open.

The configured key is never used directly. Identity derives two subkeys from each entry with HKDF
(`@munaxa/crypto` `deriveKey`): one seals TOTP secrets, one keys recovery-code hashes.

Startup refuses, listing every problem and never a value:

- no ring in production (`NODE_ENV=production`);
- an entry that is not `kid=key`, a key that is not 32 bytes, a repeated-byte key, a duplicate kid;
- a primary kid that is not in the ring, or a primary with no ring;
- a key equal to `IDENTITY_SIGNING_SECRET` (the refresh-token pepper) or taken from the signing
  private key.

### Generating the first key

Generated where the secret is stored, never in a terminal whose history is kept, never pasted into a
ticket. For AWS the owner-approved path is a Secrets Manager secret generated inside AWS, mounted as
`MFA_ENCRYPTION_KEYS_FILE`; that is a deployment step and is not performed by this repository. The
value has the form:

```text
mfa-2026-11=<43 characters of base64url>
```

with `MFA_ENCRYPTION_PRIMARY_KID=mfa-2026-11` as ordinary (non-secret) configuration.

### Rotation

Zero-downtime and two-phase, because every envelope and every recovery-code hash names its kid.

1. **Add.** Append a new entry and make it primary:
   `MFA_ENCRYPTION_KEYS=mfa-2026-11=<old>,mfa-2027-05=<new>`, `MFA_ENCRYPTION_PRIMARY_KID=mfa-2027-05`.
   Deploy. New enrollments and new recovery codes use the new key; existing secrets and codes keep
   working under the old one.
2. **Re-encrypt.** Run `PrismaMfaEnrollmentStore.reencryptTenant` for every organisation (the
   rotation task, `pnpm --filter @identity/api mfa:reencrypt`, added with the production hardening).
   Each secret is decrypted with its own AAD and re-sealed under the primary; a row replaced
   concurrently is skipped, not overwritten. A row that fails to authenticate is counted, left
   alone and never printed — investigate it as possible tampering.
3. **Recovery codes.** Hashes cannot be re-keyed without the code. `recoveryCodesUnderRetiredKeys`
   reports how many unspent codes still name the old kid. Either keep the old entry until those
   people regenerate their codes, or accept that those codes stop working when the key is retired
   (the TOTP factor is unaffected).
4. **Retire.** When step 2 reports zero remaining and step 3 is settled, remove the old entry and
   deploy.

**If a key leaks**, do all four steps at once: a leaked key opens secrets only together with a
database dump, but there is no way to know whether one was taken, so treat every secret sealed under
it as exposed and ask affected people to re-enroll after the rotation.

## Failure modes

| Symptom                                                        | Cause                                                             | What happens                                                                                       |
| -------------------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Service refuses to start: `MFA_ENCRYPTION_KEYS: is required…`  | Production without a ring                                         | Fails closed. Mount the secret.                                                                    |
| Service refuses to start: `…replay guard on the shared Redis…` | Production with an in-process cache                               | Fails closed. Set `REDIS_URL`.                                                                     |
| An enrolled user cannot sign in; `CRYPTO_KEY_UNKNOWN` in logs  | The kid that sealed their secret was retired too early            | Fails closed for that user. Put the old entry back; re-run re-encryption before retiring it again. |
| `CRYPTO_VERIFICATION_FAILED` for one account                   | The row was altered or copied from another account (AAD mismatch) | Fails closed. Treat as tampering; the person re-enrolls through the recovery procedure.            |
| Redis unavailable                                              | Cache outage                                                      | Code verification fails closed (no claim can be made), sign-in answers 503 `AUTH_UNAVAILABLE`.     |
| Development: MFA endpoints answer "unavailable"                | No ring configured                                                | Intended. Set a development-only ring to exercise MFA locally.                                     |
