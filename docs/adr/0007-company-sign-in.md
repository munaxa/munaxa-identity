# ADR-0007 — Company sign-in through Microsoft Entra and Google, into pre-created accounts

**Status** Accepted · **Date** 2026-11-26

## Context

Customers asked to sign in with the Microsoft 365 or Google Workspace account their people already
have, instead of a Munaxa password per person. The owner chose to make it optional per company and
to unify every Munaxa product on Identity, so the feature is built once, here. Identity already
reserved `identity_source`, `identity_provider_id` and `external_id` on the account for this.

## Decision

- **OpenID Connect authorization code flow with PKCE**, to each company's own tenant endpoint
  (Entra `/{tenant}/v2.0`; Google with `hd`). One Munaxa registration per provider (Entra
  multi-tenant app, Google OAuth web client), not one per customer. SAML is not built.
- **The connection is chosen by the email domain**, recorded per organisation in
  `identity_sso_connection` and `identity_sso_domain`. A domain belongs to one connection
  deployment-wide; public mail domains are refused.
- **Pre-created accounts only, no just-in-time creation.** An account is created or converted by an
  operator command with its role. The first sign-in binds the directory's immutable id (Entra `oid`,
  Google `sub`) with a conditional update; later sign-ins match only on that id. A password
  account is never bound by email, so a company cannot take over an existing Munaxa account by
  creating a mailbox.
- **Company accounts have no password.** A database check constraint makes `federated` and a
  password hash mutually exclusive, so password sign-in and reset cannot reach them.
- **Munaxa MFA policy still applies**, unless the connection is explicitly marked to trust the
  provider's MFA.
- **Break-glass:** the last active password account of an organisation cannot be converted.
- **Id-token verification is ported from Munaxa Docs** (node:crypto, JWK, algorithm allow-list,
  exact issuer, audience, nonce, expiry) rather than adding a JOSE dependency.
- **Operator commands, not an administration UI** (ADR-0006).

## Consequences

- Onboarding a company is a short operator procedure ([runbook](../runbooks/sso.md)); a company
  administrator cannot yet self-serve it.
- Leavers are handled by the company: disabling them in Entra/Google stops new sign-ins at once;
  existing Munaxa sessions end at their normal expiry unless the account is disabled in Munaxa
  too. SCIM provisioning is a later step.
- Munaxa holds two new secrets (the client secrets), rotated yearly.
- Docs and School, which have their own sign-in today, move onto Identity so they inherit this.
