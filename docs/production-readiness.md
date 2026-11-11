# Production readiness

What must be true before an Identity image built from this `main` runs with `NODE_ENV=production`.
Every row below is checked by a person and recorded in the deployment ticket. A row marked
**blocking** means the service refuses to start, or a security property this repository claims
does not hold, until it is done.

The image pinned for the first nonprod session (release `5277d71`) predates the security hardening
(MFA, password recovery, session management) and needs none of the configuration below. **Any
image built from a later commit needs all of it.** Nothing in this checklist is performed by the
repository: provisioning secrets, changing task definitions, running migrations against a live
database and changing load-balancer logging are owner-approved deployment steps.

## 1. Secrets (blocking)

| Item                                                                          | Why                                                                                                                                                                                                           |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MFA_ENCRYPTION_KEYS_FILE` mounted from a secret generated where it is stored | Production refuses to start without the MFA key ring. 32 random bytes per entry, base64url, `kid=key`. Never the JWT signing key or `IDENTITY_SIGNING_SECRET`: startup refuses either. `docs/runbooks/mfa.md` |
| `MFA_ENCRYPTION_PRIMARY_KID` set (configuration, not secret)                  | Names the entry new secrets are sealed under. Startup refuses a kid that is not in the ring.                                                                                                                  |
| Existing secrets unchanged                                                    | `IDENTITY_SIGNING_PRIVATE_KEY_FILE`, `IDENTITY_SIGNING_SECRET_FILE`, `DATABASE_URL_FILE`: `docs/runbooks/secrets.md`.                                                                                         |

## 2. Configuration

| Setting                                                                                  | Production value                                                    | Blocking | Why                                                                                                                                                                                  |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `REDIS_URL`                                                                              | the shared Redis                                                    | yes      | TOTP replay protection, MFA challenges, attempt limits and reauthentication markers are fleet-wide only through it. Startup refuses production without it.                           |
| `IDENTITY_PASSWORD_RESET`                                                                | `disabled`                                                          | yes      | There is no production email transport yet; production refuses `enabled`. `docs/runbooks/password-recovery.md`                                                                       |
| `MFA_POLICY`                                                                             | **`privileged`** (target); `off` only for the first roll-out window | yes      | `off` means no account is required to use a second factor. The target is `privileged` with the roles below; `all` when every product's users can enroll.                             |
| `MFA_PRIVILEGED_ROLES`                                                                   | every administrative role key, e.g. `control-operator-admin`        | yes      | Startup refuses `privileged` with an empty list. The list must name every role that can change other people's access or see other tenants' data; review it whenever a role is added. |
| `MFA_CHALLENGE_TTL`, `MFA_ENROLLMENT_CHALLENGE_TTL`                                      | defaults (5m, 10m)                                                  | no       | Bounded at startup (1–10m, 1–15m).                                                                                                                                                   |
| `MFA_CHALLENGE_MAX_ATTEMPTS`, `MFA_ACCOUNT_MAX_FAILURES`                                 | defaults (5, 10)                                                    | no       | Bounded at startup (1–10, 3–50). Enforced by reservation before the check (ADR-0005).                                                                                                |
| `MFA_REAUTH_WINDOW`                                                                      | default (5m)                                                        | no       | Bounded at startup (1–15m).                                                                                                                                                          |
| `MFA_ISSUER`                                                                             | `Munaxa`                                                            | no       | The label people see in their authenticator app.                                                                                                                                     |
| `IDENTITY_SESSION_LIST_IP`                                                               | `prefix` (default) or `hidden`                                      | no       | What the session list shows of each session's address.                                                                                                                               |
| `IDENTITY_PASSWORD_RESET_URL`, `_TTL`, `IDENTITY_EMAIL_TRANSPORT`, `IDENTITY_EMAIL_FROM` | unset while reset is disabled                                       | no       | Only meaningful once a production transport exists.                                                                                                                                  |

## 3. Database (blocking)

- [ ] Migration `20261111130000_identity_mfa` applied by the migration job (`prisma migrate deploy`
      as the owner role) **before** the new image starts. It creates `identity_mfa_enrollment` and
      `identity_mfa_recovery_code` with `FORCE ROW LEVEL SECURITY` and grants `identity_app` the
      four DML verbs on them. It is additive: the previous image keeps working against the migrated
      schema, so the migration can run first and the image roll second.
- [ ] Rollback: rolling the image back is safe; the tables stay and are unused. Do not drop them
      while any account is enrolled; their rows are the only copy of the factors.
- [ ] Any environment provisioned by hand (not by the migration job) applies **every** migration in
      order and the grant list in `docs/runbooks/staging-provisioning.md`, which now includes the MFA
      tables.

## 4. Logs and edges (blocking before password reset is ever enabled)

- [ ] Reset links carry the token in the query string. Before `IDENTITY_PASSWORD_RESET=enabled`
      anywhere, load-balancer and CDN access logs for `/api/auth/password/reset` are either off or
      treated as secret (restricted, short retention). Not needed while reset is disabled.
- [ ] Whatever edge rate limiting the deployment's routing defines for sign-in, MFA verification
      and password recovery is in place. The application's own limits (shared in Redis) are the
      backstop, not the only control.

## 5. Access to operator commands (blocking)

- [ ] Every permission that can act as the Identity service is restricted to the operators who may
      remove a factor or disable an account (ADR-0006). On AWS: `ecs:RunTask` on the Identity task
      definition, `ecs:ExecuteCommand` into Identity tasks, `ecs:RegisterTaskDefinition` /
      `ecs:UpdateService` with `iam:PassRole` on the Identity task or execution role, and read
      access to the secrets the task mounts.
- [ ] Operators pass `--account-id`, not the email identifier, in task overrides (CloudTrail
      records them).
- [ ] The lost-device procedure (`docs/runbooks/mfa.md`, "Lost device") is known to every operator:
      out-of-band identity verification, a second operator's approval, a ticket reference.

## 6. Turning MFA enforcement on

Ordered so that nobody is locked out and no pre-enforcement session survives:

1. [ ] Deploy with sections 1–5 done and `MFA_POLICY=off`.
2. [ ] Every holder of a privileged role enrolls from their own session (sign in, reauthenticate,
       enroll, store the recovery codes). Do this immediately after provisioning each privileged
       account: until an account has a factor, whoever holds its password can enroll theirs (trust
       on first enrollment, ADR-0005).
3. [ ] Review `auth.mfa.enrolled` audit events for privileged accounts against who was expected to
       enroll.
4. [ ] Set `MFA_POLICY=privileged` and `MFA_PRIVILEGED_ROLES`; deploy. Anyone covered without a
       factor is admitted only to enrollment at their next sign-in.
5. [ ] For each organisation:
       `operator-cli sessions-revoke-unsatisfied --organisation <key>` (dry run), then with
       `--reference <change id> --apply`. Enforcement is complete when the dry run reports zero.
6. [ ] Downstream services that need assurance require the `mfa: true` claim rather than assume
       every live session is MFA-satisfied.

## 7. Verification after deploy

- [ ] `GET /api/auth/health/ready` is ready on every replica (it fails if the database is unreachable).
- [ ] Sign in with a non-privileged test account (no factor required), then with a privileged one
      (challenge, then a session whose token has `mfa: true` and `amr` `["password","totp"]`).
- [ ] `GET /api/auth/mfa/status` reports `available: true`.
- [ ] `/api/auth/password/forgot` answers `404` (reset disabled).
- [ ] No secret value in task definitions, overrides, logs or this ticket.

## Known residual risks

Accepted, and recorded where they are decided:

- **Trust on first enrollment** (ADR-0005). Mitigated by enrolling privileged accounts at
  provisioning and reviewing enrollment audits.
- **Revocation reaches Munaxa Work only when its access token expires**, up to about 16½ minutes
  (`docs/runbooks/revocation.md`). Applies to every revocation above, including `mfa-reset` and
  `account-disable`.
- **No self-service account recovery in production** while password reset is disabled: a person
  who loses both their password and their factor is recovered by an operator.
- **Recovery codes cannot be re-keyed.** A retired MFA key must stay in the ring until
  `operator-cli mfa-reencrypt` reports no unused codes under it, or those codes stop working.
