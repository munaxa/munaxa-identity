# TOTP MFA — operations

What MFA is made of in Identity, how its key is provisioned and rotated, and what each failure
looks like. The decision record is [ADR-0005](../adr/0005-totp-mfa.md).

## Blocking deployment prerequisite

From this release on, **a production-mode Identity (`NODE_ENV=production`) refuses to start**
unless `MFA_ENCRYPTION_KEYS_FILE` (a mounted secret holding the key ring) and
`MFA_ENCRYPTION_PRIMARY_KID` are set, and `REDIS_URL` points at the shared Redis. This applies to
every environment that runs in production mode, including Testing/nonprod on AWS. The image already
pinned for the first nonprod session (release `5277d71`) predates this and is unaffected; any image
built from a later `main` needs the secret provisioned first. Provisioning it is an owner-approved
deployment step and is not done by this repository.

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

## The flows

| Route                                       | Who may call                                   | Effect                                                                                                                         |
| ------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `POST /api/auth/login`                      | anyone                                         | Right password + factor needed → `401 AUTH_MFA_REQUIRED` or `AUTH_MFA_ENROLLMENT_REQUIRED`, `__Host-mx_mfa` cookie, no session |
| `GET /api/auth/mfa`, `/api/auth/mfa/enroll` | anyone                                         | The HTML pages for the two challenges                                                                                          |
| `POST /api/auth/mfa/verify`                 | `verify` challenge                             | TOTP or recovery code → session cookies, `amr`, `mfa: true`                                                                    |
| `POST /api/auth/reauthenticate`             | session                                        | Password (+ code when enrolled) → reauth marker for this session                                                               |
| `POST /api/auth/mfa/enrollment`             | session + recent reauth, or `enroll` challenge | Returns the secret and `otpauth://` URI, once                                                                                  |
| `POST /api/auth/mfa/enrollment/confirm`     | same                                           | Returns 10 recovery codes, once; revokes other sessions; with a challenge, signs in                                            |
| `POST /api/auth/mfa/recovery-codes`         | session + recent reauth                        | New set of 10; the old set stops working                                                                                       |
| `DELETE /api/auth/mfa`                      | session + recent reauth                        | Removes the factor unless policy requires it; revokes other sessions                                                           |
| `GET /api/auth/mfa/status`                  | session                                        | `enrolled`, `required`, `recoveryCodesRemaining`, `available`, `reauthenticated`                                               |

Configuration: `MFA_POLICY` (`off`/`privileged`/`all`), `MFA_PRIVILEGED_ROLES`, `MFA_CHALLENGE_TTL`
(default 5m, 1–10m), `MFA_ENROLLMENT_CHALLENGE_TTL` (10m, 1–15m), `MFA_CHALLENGE_MAX_ATTEMPTS` (5),
`MFA_ACCOUNT_MAX_FAILURES` (10 per `LOGIN_LOCKOUT`), `MFA_REAUTH_WINDOW` (5m, 1–15m), `MFA_ISSUER`.

### Turning enforcement on

1. Deploy with the key ring and `MFA_POLICY=off`; let privileged people enrol from their sessions.
2. Set `MFA_POLICY=privileged` and `MFA_PRIVILEGED_ROLES` (for example `control-operator-admin`).
   Anyone in those roles without a factor is now admitted only to enrollment at their next sign-in.
3. Deal with the sessions those accounts already hold. They were created before enforcement, so
   they carry `mfa_satisfied = false` and `amr = ["password"]`, and they stay valid until they are
   revoked or reach `SESSION_IDLE_TIMEOUT` / `SESSION_ABSOLUTE_TIMEOUT`:
   - **Enrolling at sign-in ends them.** Confirming an enrollment through the enrollment challenge
     revokes every session the account held (reason `mfa-changed`) before the new, MFA-satisfied
     session is created. Enrolling from a session revokes every other session the same way.
   - **An account that does not sign in again** keeps its pre-enforcement sessions until they
     expire. End them with the operator command, run with the same `MFA_POLICY` and
     `MFA_PRIVILEGED_ROLES` as the service, first as a dry run and then with `--apply`:

     ```text
     operator-cli sessions-revoke-unsatisfied --organisation <key>
     operator-cli sessions-revoke-unsatisfied --organisation <key> --reference CHG-123 --apply
     ```

     It revokes (reason `admin-revoked`) every live session with `mfa_satisfied = false` of every
     account the policy covers, leaves MFA-satisfied sessions and uncovered accounts alone, and
     writes one `session.revoked` audit record per account carrying the reference. Enforcement is
     complete for an organisation when the dry run reports zero.

   - Downstream services that need assurance should require the `mfa: true` claim rather than
     assume that enforcement covers every live session.

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
2. **Re-encrypt.** For every organisation, with the new configuration:
   `operator-cli mfa-reencrypt --organisation <key>` (dry run: how many secrets are not under the
   primary), then the same with `--reference <change id> --apply`, which writes
   `crypto.key.rotated` with the counts. Each secret is decrypted with its own AAD and re-sealed under the primary; a row replaced
   concurrently is skipped, not overwritten. A row that fails to authenticate is counted, left
   alone and never printed — investigate it as possible tampering.
3. **Recovery codes.** Hashes cannot be re-keyed without the code. `mfa-reencrypt` also
   reports how many unspent codes still name the old kid. Either keep the old entry until those
   people regenerate their codes, or accept that those codes stop working when the key is retired
   (the TOTP factor is unaffected).
4. **Retire.** When step 2 reports zero remaining and step 3 is settled, remove the old entry and
   deploy.

**If a key leaks**, do all four steps at once: a leaked key opens secrets only together with a
database dump, but there is no way to know whether one was taken, so treat every secret sealed under
it as exposed and ask affected people to re-enroll after the rotation.

## Operator commands

Identity has no administration API. The steps above and the lost-device procedure below are one-off
commands in the Identity image, `node dist/ops/operator-cli.js <command>` (`pnpm ops <command>` in a
checkout). Run them as a one-off task of the **Identity service definition**, so they use its
configuration, its mounted secrets and its `identity_app` connection, under the same row-level
security and audit chain as the service. Never pass a secret, a password or a database URL on the
command line or as a task override: overrides are recorded in plain text.

| Command                       | Changes                                                                                 | Needs                                           |
| ----------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `mfa-reset`                   | Removes a factor and its recovery codes; bumps the token version; revokes every session | `--organisation`, `--account-id`, `--reference` |
| `account-disable`             | Disables the account; bumps the token version; revokes every session                    | `--organisation`, `--account-id`, `--reference` |
| `sessions-revoke-unsatisfied` | Revokes pre-enforcement (`mfa_satisfied = false`) sessions of covered accounts          | `--organisation`, `--reference`                 |
| `mfa-reencrypt`               | Re-seals TOTP secrets under the primary key; audits `crypto.key.rotated`                | `--organisation`, `--reference`                 |

Every command is a dry run without `--apply`. `--reference` is a ticket or incident id (letters,
digits, `. _ : -`; never a name or an email) and is carried into the audit record as the actor,
`operator:<reference>`. Output names accounts by id only. Prefer `--account-id` to
`--account <identifier>`: the arguments of a one-off task are recorded in CloudTrail, and an
identifier is an email address. Look the id up from the ticket's account record, not by pasting
the identifier into the task.

## Lost device (operator recovery)

The person has lost their authenticator and their recovery codes. `mfa-reset` removes the factor;
**it does not establish who is asking, and the procedure around it is the whole of its security**,
because after a reset the account belongs to whoever holds the password.

1. **Open a ticket** and record the request. Never accept the request in the same channel the
   attacker would use (an email from the account's own address proves nothing).
2. **Verify identity out of band** against something the attacker would not have: a call to a
   number on file that predates the request, the person's manager confirming in person or on a
   known channel, or an in-person check. For a privileged account, two people verify.
3. **A second operator approves** the ticket before anything runs. The person who verified is not
   the person who runs the command.
4. **Dry run**, check that the account id is the one in the ticket:
   `operator-cli mfa-reset --organisation <key> --account-id <id>`.
5. **Apply**: the same with `--reference <ticket> --apply`. This removes the TOTP factor (active
   and pending) and every recovery code, bumps the token version (every access token stops
   verifying at the next check) and revokes every session and refresh lineage first, then removes
   the factor, then writes `auth.mfa.removed` with `operator:<ticket>`. If it fails part-way the
   account is left signed out everywhere with its factor intact; run the same command again.
6. **If the password may also be known to someone else**, do not hand the account back on it.
   Where password reset is enabled, the person resets it (`/api/auth/password/forgot`) before
   signing in. Where it is disabled (production, until email delivery exists), run
   `operator-cli account-disable --organisation <key> --account-id <id> --reference <ticket>
--apply` instead and re-establish the account through provisioning. Otherwise the person signs in
   with the password and, if policy covers them, is admitted only to enrollment and enrolls a new
   device straight away.
7. **Close the ticket** with the command's output line and the time.

The reset never touches the password, and a password reset never touches MFA (ADR-0005), so neither
recovery path can be used to strip the other factor.

## Failure modes

| Symptom                                                        | Cause                                                             | What happens                                                                                       |
| -------------------------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Service refuses to start: `MFA_ENCRYPTION_KEYS: is required…`  | Production without a ring                                         | Fails closed. Mount the secret.                                                                    |
| Service refuses to start: `…replay guard on the shared Redis…` | Production with an in-process cache                               | Fails closed. Set `REDIS_URL`.                                                                     |
| An enrolled user cannot sign in; `CRYPTO_KEY_UNKNOWN` in logs  | The kid that sealed their secret was retired too early            | Fails closed for that user. Put the old entry back; re-run re-encryption before retiring it again. |
| `CRYPTO_VERIFICATION_FAILED` for one account                   | The row was altered or copied from another account (AAD mismatch) | Fails closed. Treat as tampering; the person re-enrolls through the recovery procedure.            |
| Redis unavailable                                              | Cache outage                                                      | Code verification fails closed (no claim can be made), sign-in answers 503 `AUTH_UNAVAILABLE`.     |
| Development: MFA endpoints answer "unavailable"                | No ring configured                                                | Intended. Set a development-only ring to exercise MFA locally.                                     |
