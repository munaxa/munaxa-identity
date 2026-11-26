# Identity as the sign-in provider for Docs and School

How Munaxa Docs and School sign people in through Identity ([ADR-0008](../adr/0008-identity-as-oidc-provider.md)).

## What a person sees

On the Docs sign-in page they enter their work email; Docs sends them to Identity's sign-in page
(organisation already filled in). There they use their Munaxa password, or **Sign in with Microsoft
or Google** if their company has company sign-in (`sso.md`). With MFA if their role requires it.
Then they are back in Docs, signed in.

## Configure a client (once per Docs organisation)

1. Generate a client secret (32 random bytes, base64url), in the secret store, never on a laptop:
   it goes into **two** places, Identity's secret bundle and the Docs provider record.
2. Identity configuration:

   | Variable                       | Example                                                                  |
   | ------------------------------ | ------------------------------------------------------------------------ |
   | `IDENTITY_OIDC_PROVIDER`       | `enabled`                                                                |
   | `IDENTITY_OIDC_CLIENTS`        | `docs-acme\|acme\|https://docs.test.munaxa.com/auth/federation/callback` |
   | `IDENTITY_OIDC_CLIENT_SECRETS` | `docs-acme=<secret>` (secret bundle key, never a plain variable)         |

   `;` separates clients, spaces separate redirect URIs. The middle field is the Identity
   organisation key whose people this client may sign in.

3. Docs, as that tenant's administrator (`PUT /api/v1/admin/identity-provider`):
   issuer `https://<identity host>`, discovery URL
   `https://<identity host>/api/auth/oidc/.well-known/openid-configuration`, client id and secret as
   above, the company's email domains, claim mapping `sub` / `email` / `email`, JIT off (people are
   created in Docs with their roles first; the first sign-in links them by email). Enable the
   tenant setting `feature.federation`. The Docs outbound allow-list must include the identity host.

## Failures

| Symptom                                     | Cause                                                                       |
| ------------------------------------------- | --------------------------------------------------------------------------- |
| "This sign-in link is not valid" (Identity) | Unknown client id, or the redirect URI is not registered exactly.           |
| Back at Docs with `access_denied`           | The person's Identity session is in another organisation than the client's. |
| Docs: "That sign-in could not be completed" | Token exchange refused: wrong secret (`invalid_client`) or a spent code.    |

Logs: `oidc.token.refused` (with a reason), `oidc.token.client_refused`,
`oidc.authorize.organisation_mismatch`. Audit: `auth.token.issued` with `kind: oidc-id-token`.

## Rotation

Add the new secret as the same client's value in Identity's bundle and in Docs at the same time
(one secret per client; there is no overlap window), then roll Identity. Sign-ins in flight during
the change fail once and succeed on retry.
