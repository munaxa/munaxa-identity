# ADR-0006 — Operator commands, not an administration API

**Status** Accepted · **Date** 2026-11-11

## Context

Security hardening added operations that only an operator may perform: removing a lost second
factor, disabling a compromised account, ending pre-enforcement sessions when MFA enforcement is
switched on, and re-sealing MFA secrets after a key rotation. Identity has no administration API
and no administrator authorisation model to put in front of one. Building both to host four rarely
used actions would add the largest attack surface in the service for the least-used features.

Running ad-hoc SQL instead is worse: it bypasses the revocation code (refresh lineages, token
version), writes nothing to the hash-chained audit trail, and invites a superuser connection that
row-level security does not constrain.

## Decision

The operations are commands in the Identity image, `dist/ops/operator-cli.js`
(`apps/api/src/ops/`), run as a one-off task of the Identity service definition. They build the
service's own security stack from its own configuration and secrets, and act only through the same
classes the service uses: `CredentialRevocation`, `AccountLockdown`, the MFA store and the audit
service, as `identity_app` under row-level security.

- **Dry run by default.** Nothing changes without `--apply`.
- **A reference for every change.** `--reference` (a ticket or incident id, restricted to a short
  plain token so personal data cannot be pasted in) becomes the audit actor,
  `operator:<reference>`.
- **No secrets in arguments.** The commands take no secret, password, code or connection string;
  they read the service's mounted secrets like the service does. Output names accounts by id, never
  by identifier.
- **Authorisation is the platform's.** Who may run a one-off task of the Identity service is
  decided by the deployment's access control (on AWS, who may call `ecs:RunTask` with that task
  definition), and each procedure adds human controls (out-of-band identity verification and a
  second operator for `mfa-reset`, `docs/runbooks/mfa.md`).

## Consequences

- No new network surface. The commands cannot be reached from the internet.
- Every operator action is in the same audit chain as the user actions it affects.
- The deployment must restrict who can run one-off Identity tasks; that permission now carries the
  power to remove a factor or disable an account. It is listed in the production readiness
  checklist.
- When an administration API exists, it should call the same functions, and these commands remain
  the break-glass path.
