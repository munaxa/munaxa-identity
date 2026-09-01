# ADR-0004 — One browser origin, three services

**Status** Accepted · **Date** 2026-09-01

## Context

Platform's session cookie is `__Host-mx_session`, and the prefix is deliberate: the browser enforces
that such a cookie is `Secure`, `Path=/`, and carries **no `Domain`**, which is what stops a
subdomain setting or overwriting it. The cookie builder has no `domain` option and could not be
given one without giving up that property across every Munaxa product.

A host-only cookie set by an authentication host is therefore never sent to a portal on another
host. Closing that gap needs an authorization-code redirect, and Platform implements none as an
issuer — no `/authorize`, no code exchange, no `redirect_uri` registry, no PKCE state store. The
only such machinery in the platform is `IdentityProviderPort`, where Platform is the _client_ of an
external provider.

## Decision

**One public origin, split by path at a front door; the services stay separate.**

```
https://<host>/            → Work admin portal
https://<host>/api/v1/*    → Work API
https://<host>/api/auth/*  → Munaxa Identity
```

## What this is not

It is not merging the applications. Identity and Work remain separate repositories, separate
databases, separate deployments and separate release cycles. A shared browser origin is a routing
fact. Putting two products in one process to satisfy a cookie rule would be the tail wagging the
dog, and it would put a credential-handling service inside a business system — the thing this whole
architecture exists to avoid.

## Options considered

| Option                                                      | Why not                                                                                                                                                                                                                                                                                                   |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Separate origins** (`identity.…` and `work.…`)            | Cannot deliver the cookie, and closing the gap means inventing a cross-origin protocol Platform does not have.                                                                                                                                                                                            |
| **Drop the `__Host-` prefix, add `Domain=.munaxa.com`**     | Re-opens cookie injection and session fixation across every product sharing the domain, to save a routing rule.                                                                                                                                                                                           |
| **The portal relays the credential** (Munaxa Docs' pattern) | Works, and is the ecosystem's existing convention _within_ one product. Across products it puts the plaintext password through Work's process — precisely what ADR-0001 exists to prevent. Kept as a documented fallback if a front door is ever unavailable, with that cost stated rather than absorbed. |
| **One origin, separate services**                           | **Chosen.**                                                                                                                                                                                                                                                                                               |

## Consequences

- Staging needs a reverse proxy that terminates TLS. `deploy/Caddyfile` is one; any proxy does.
- The `/api/auth` prefix is part of the issuer URL and of the refresh cookie's path, so a deployment
  may not vary it independently.
- Munaxa Work's employee and manager portals join the same origin under their own paths when they
  become authenticated clients. Establishing the front door now is why that will be a routing change
  rather than an architecture one.
