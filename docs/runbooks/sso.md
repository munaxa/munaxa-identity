# Company sign-in (Microsoft 365 and Google Workspace)

How a company signs its people in to Munaxa with the Microsoft or Google account they already use,
how an operator turns it on for one organisation, and what each failure looks like. The decision
record is [ADR-0007](../adr/0007-company-sign-in.md).

## What it is

- **Optional, per organisation.** A deployment switches the feature on (`IDENTITY_SSO=enabled`);
  then each organisation is connected separately, and stays on Munaxa passwords until it is.
- **Pre-created accounts only.** Nobody gets an account by signing in. An operator creates each
  account (or converts an existing one), with its role, before the person first signs in. The
  first company sign-in binds the account to the person's directory id (Entra `oid`, Google `sub`)
  and every later sign-in matches on that id, never on the email address.
- **The person never types a Munaxa password.** A company account has no password: it cannot sign
  in on the password form and cannot use password reset.
- **Munaxa MFA still applies** (`MFA_POLICY`), unless the connection was created with
  `--trust-provider-mfa`, which accepts the company's own MFA instead. Use that only for a company
  that enforces MFA in Entra Conditional Access or Google 2-Step Verification for every user.
- **Sessions are ordinary Munaxa sessions.** Work, Control, Docs and School see the same token as
  after a password sign-in. `amr` says `microsoft` or `google` (plus `totp` when a factor was used).

## One-time registration by the Munaxa owner

Identity is registered once with Microsoft and once with Google, as Munaxa, not per customer.
Each registration gives a client id (not secret) and a client secret (secret). The redirect URI to
register is, for every host Identity serves (every `CSRF_TRUSTED_ORIGINS` entry that is Identity's
own origin):

```
https://<identity host>/api/auth/sso/callback
```

For Testing that is `https://id.test.munaxa.com/api/auth/sso/callback`.

### Microsoft Entra

1. Sign in to https://entra.microsoft.com with the Munaxa Microsoft account.
2. **Identity → Applications → App registrations → New registration.**
3. Name `Munaxa`. Supported account types: **Accounts in any organizational directory
   (Any Microsoft Entra ID tenant - Multitenant)**. Redirect URI: platform **Web**, the URI above.
4. **Register.** Copy **Application (client) ID**: that is `IDENTITY_SSO_MICROSOFT_CLIENT_ID`.
5. **Certificates & secrets → Client secrets → New client secret**, expiry 12 months (put the
   renewal date in the calendar). Copy the **Value** once: that is
   `IDENTITY_SSO_MICROSOFT_CLIENT_SECRET`. It is never shown again.
6. **API permissions**: leave `Microsoft Graph → User.Read` (delegated). Identity asks only for
   `openid email profile`.
7. **Branding & properties**: set the publisher domain to `munaxa.com` once DNS verification is
   possible, so customers' administrators see a verified publisher.

### Google

1. Sign in to https://console.cloud.google.com with the Munaxa Google account; create a project
   `munaxa-identity`.
2. **APIs & Services → OAuth consent screen**: user type **External**, app name `Munaxa`, support
   email and developer contact a Munaxa mailbox, scopes `openid`, `email`, `profile` only. Publish
   the app (these scopes need no Google verification).
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**, type **Web
   application**, name `Munaxa Identity`, authorised redirect URI: the URI above.
4. Copy the **Client ID** (`IDENTITY_SSO_GOOGLE_CLIENT_ID`) and **Client secret**
   (`IDENTITY_SSO_GOOGLE_CLIENT_SECRET`).

### Configuration

| Variable                                    | Value                                           |
| ------------------------------------------- | ----------------------------------------------- |
| `IDENTITY_SSO`                              | `enabled`                                       |
| `IDENTITY_SSO_MICROSOFT_CLIENT_ID`          | the GUID, plain environment variable            |
| `IDENTITY_SSO_MICROSOFT_CLIENT_SECRET_FILE` | the mounted secret (never a plain variable)     |
| `IDENTITY_SSO_GOOGLE_CLIENT_ID`             | plain environment variable                      |
| `IDENTITY_SSO_GOOGLE_CLIENT_SECRET_FILE`    | the mounted secret                              |
| `IDENTITY_SSO_FLOW_TTL`                     | optional, default `10m`, between `1m` and `15m` |

Either provider may be left out entirely. Startup refuses: the feature enabled with no provider, an
id without its secret (or the reverse), a malformed id, a secret that is another secret Identity
holds, and (in production) a non-https trusted origin.

Each secret holds the value alone. Store it in AWS Secrets Manager with the other Identity secrets
and let the task definition mount it; never put it in an environment variable, a task override, a
ticket or chat.

## Connecting one organisation

What the company gives you: which provider, and

- **Microsoft**: their **Directory (tenant) ID** (Entra admin center → Overview) and the email
  domains their people use.
- **Google**: their primary Workspace domain and any other domains.

Every command is a one-off task of the Identity service (ADR-0006): dry run unless `--apply`, and
`--reference` (the ticket) is the audit actor.

```bash
# 1. Create the connection. It is created disabled.
operator-cli sso-connection-add --organisation acme --provider microsoft \
  --directory 72f988bf-86f1-41af-91ab-2d7cd011db47 --domains acme.com,acme.co.uk \
  --reference CHG-120 --apply
# prints the connection id

# 2. Create each person, with a role (or convert an existing password account, step 2b).
operator-cli sso-account-create --organisation acme --connection-id <id> \
  --account ada@acme.com --role work-employee --reference CHG-120 --apply

# 2b. Existing password account -> company sign-in. Its password, its current sessions and any
#     outstanding reset links stop working at once.
operator-cli sso-account-convert --organisation acme --connection-id <id> \
  --account-id <sub> --reference CHG-120 --apply

# 3. Turn it on.
operator-cli sso-connection-enable --organisation acme --connection-id <id> \
  --reference CHG-120 --apply

# Review.
operator-cli sso-connection-list --organisation acme
```

What the commands refuse:

- a public mail domain (`gmail.com`, `outlook.com`, …) or a domain another connection already has;
- for Google, a domain list that does not include the Workspace domain itself;
- a role that does not exist in the organisation;
- converting the **last active password account** of the organisation. Keep at least one password
  administrator (with MFA) per organisation as break-glass, so a provider outage or a lost
  directory never locks the organisation out.

`--account` (an email) is visible in task overrides and CloudTrail. Where that matters, convert by
`--account-id`.

Then tell the company: people go to the Munaxa sign-in page, choose **Sign in with Microsoft or
Google**, and type their work email. Their administrator may be asked once to consent to the
Munaxa app for the whole company (Entra "admin consent"); Google asks each user once.

## Switching it off

```bash
operator-cli sso-connection-disable --organisation acme --connection-id <id> \
  --end-sessions --reference INC-77 --apply
```

New company sign-ins stop at once. `--end-sessions` also ends every session of every account bound
to the connection (use it for an incident). Without it, existing sessions run to their normal
expiry. Deleting the feature for the whole deployment is `IDENTITY_SSO=disabled`: the three routes
answer 404.

## What happens where

| Route                        | Purpose                                                                   |
| ---------------------------- | ------------------------------------------------------------------------- |
| `GET /api/auth/sso`          | Page: the work email address                                              |
| `POST /api/auth/sso/start`   | Picks the connection from the email domain, redirects to Microsoft/Google |
| `GET /api/auth/sso/callback` | Back from the provider; issues the Munaxa session or the MFA challenge    |

The flow is OpenID Connect authorization code with PKCE (S256), `state`, `nonce`, and a
`__Host-mx_sso` cookie binding the browser that started it to the browser that finishes it. The
flow record is single-use and kept in Redis for `IDENTITY_SSO_FLOW_TTL`. The id token is verified
against the provider's published keys (cached one hour), the exact issuer for that company's
tenant, the audience, expiry and nonce. Microsoft: `tid` must be the connection's directory.
Google: `hd` must be the connection's domain and `email_verified` true.

## Failures

| What the person sees                                   | Cause                                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------------------ |
| "Company sign-in is not set up for this email address" | No enabled connection for that domain, or the organisation is suspended. |
| "Sign-in is temporarily unavailable"                   | Redis or the provider was unreachable. Retry.                            |
| Back on the login page, "could not sign you in"        | Refused: see the `auth.login.failed` audit reason below.                 |

`auth.login.failed` reasons (audit and logs, never with an email address):

| Reason                                                          | Meaning                                                               |
| --------------------------------------------------------------- | --------------------------------------------------------------------- |
| `NOT_PROVISIONED`                                               | No pre-created company account for this person. Create it.            |
| `ACCOUNT_NOT_ACTIVE`                                            | The account is disabled or locked.                                    |
| `DOMAIN_NOT_OWNED`                                              | The provider returned an address outside the connection's domains.    |
| `TENANT_MISMATCH`, `HOSTED_DOMAIN_MISMATCH`, `EMAIL_UNVERIFIED` | The person signed in to a different company's directory.              |
| `ID_TOKEN_*`                                                    | The id token failed verification (signature, issuer, audience, …).    |
| `PROVIDER_ERROR:<code>`                                         | The person cancelled, or the company's policy refused them.           |
| `TOKEN_EXCHANGE_<status>`                                       | Microsoft/Google refused the code: usually a wrong or expired secret. |
| `CONNECTION_UNAVAILABLE`                                        | The connection was disabled while the person was at the provider.     |
| `MFA_UNAVAILABLE`                                               | MFA is required but this deployment has no MFA key ring.              |
| `STATE_*`, `BINDING_*`, `USER_AGENT_MISMATCH` (logs only)       | An expired, replayed or cross-browser flow. Start again.              |

## Secret rotation

Create the new client secret at Microsoft or Google, store it as the new version of the same
Secrets Manager secret, roll the Identity service, then delete the old secret at the provider. No
sign-in is lost: flows in progress finish with whichever secret the replica holds.
