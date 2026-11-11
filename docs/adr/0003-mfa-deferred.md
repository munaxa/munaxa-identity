# ADR-0003 — MFA is deferred, and staging is safe without it

**Status** Superseded by [ADR-0005](0005-totp-mfa.md) · **Date** 2026-09-01 · **Superseded** 2026-11-11

> Kept unchanged below as the record of why MFA was deferred. ADR-0005 implements it.

## Context

`@munaxa/auth` provides TOTP, email and SMS OTP, hashed recovery codes and an `MfaService`.
Implementing it here means one more store, one more endpoint, an enrolment flow, and a recovery
path — the last of which is the part that takes the time, because an MFA rollout without a tested
recovery path locks people out of their own accounts.

Nothing in the staging acceptance test needs it.

## Decision

**Not implemented in this phase, and named as a production requirement rather than a nice-to-have.**

The account model carries `mfa_enrolled` because `CredentialRecord` requires it; it is always false
until MFA exists. `LoginService` still returns `mfa-required` if a policy ever demands a second
factor, and the sign-in page renders an honest message for that case rather than a blank failure —
a deployment that turns on `MUNAXA_MFA_REQUIRED` today gets a clear refusal, not a broken form.

No `identity_mfa_enrolment` table is created. An unused table is a thing a future reader has to
reason about, and the migration that adds it is smaller than the migration that changes it.

## Consequences

- Staging administrator accounts are protected by password policy (≥12 characters, breach-checked),
  lockout, rate limiting and a 12-hour absolute session deadline. That is adequate for staging and
  is not adequate for production.
- Platform's own migration guide makes MFA for administrators part of "done". This ADR is the record
  that we are knowingly short of that line, not unaware of it.
