# ADR-0008 — Identity is the OpenID Connect provider for every Munaxa product

**Status** Accepted · **Date** 2026-11-26

## Context

The owner decided that every Munaxa product signs people in the same way, through Munaxa
Identity (26 Nov 2026). Work and Control already use Identity's tokens on a shared origin
(ADR-0004). Munaxa Docs and Munaxa School each have their own accounts, sessions, roles and
permission checks, and Docs' documents, approvals and audit trail reference Docs' own user ids.
Replacing those user tables would be a migration of every reference in both products. Docs already
contains a hardened OpenID Connect relying party (its federation module: per-tenant provider,
`state`, `nonce`, signature verification, linking by subject).

## Decision

Identity also answers as a standard **OpenID Connect provider** (authorization code flow), and
Docs and School sign people in by pointing their relying-party code at it.

- Endpoints under `/api/auth/oidc/`: discovery, JWKS (Identity's existing ES256 public key),
  `authorize`, `token`. Off unless `IDENTITY_OIDC_PROVIDER=enabled`.
- **Clients are deployment configuration** (`IDENTITY_OIDC_CLIENTS`, secrets in
  `IDENTITY_OIDC_CLIENT_SECRETS`), never created by a request. Exact redirect URIs. Confidential
  clients only (`client_secret_post` or `_basic`); PKCE S256 enforced when the client sends it.
- **Each client is bound to one Identity organisation.** A session from another organisation gets
  `access_denied`. A Docs tenant therefore only receives its paired organisation's people.
- **The products keep their own users and permissions.** The id token carries who the person is
  (`sub`, `email`, `tid`, `org`, `amr`, `auth_time`); what they may do in Docs or School stays in
  Docs or School. Docs links its existing users to the Identity `sub` on first sign-in, as it does
  for any provider.
- The id token's audience is the client id, which startup refuses to let equal an access-token
  audience, so an id token is never accepted as a Work or Control access token.
- Codes: single use, one minute, bound to client, redirect URI, nonce and PKCE; the person's
  session and account are re-checked when the code is redeemed.

### Review notes (26 Nov 2026)

- `email_verified` is `true` because every Identity identifier is an address an operator
  provisioned (or a company directory asserted, ADR-0007); there is no self-registration. Clients
  must still key a person on `sub` together with `tid`/`org`, and use the address only to link a
  pre-created product account the first time.
- PKCE is enforced when sent and not yet required: Docs' relying party predates it. Requiring S256
  for every client is the next step once Docs sends it.
- `prompt=login` and `max_age` are not implemented; a client needing a fresh sign-in cannot ask for
  one yet.

## Consequences

- One Munaxa sign-in (password, MFA, lockout, Microsoft/Google company sign-in from ADR-0007) for
  every product, without migrating Docs' or School's user tables.
- A product's own session lives on after Identity's ends (Docs keeps its refresh token). Signing
  out of Identity does not sign a person out of Docs; disabling them in Identity stops their next
  sign-in. Back-channel logout is a later step.
- No refresh tokens, userinfo, implicit flow, dynamic registration or consent screen.
- Each product deployment holds one client secret, rotated like any other secret.
