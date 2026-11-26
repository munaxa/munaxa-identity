import type { IdTokenClaims } from './id-token.js';

/**
 * The two company directories Identity signs people in through, and what each one's id token has
 * to say before Identity believes it.
 *
 * Everything that differs between Microsoft and Google is here, and nothing else is: the flow, the
 * verification and the account rules are one implementation (`sso.service.ts`). Each provider is
 * pinned to **one company's directory** per connection, which is what makes a multi-company
 * application registration safe to use:
 *
 * - **Microsoft Entra ID.** The endpoints name the company's tenant id, so the sign-in happens in
 *   that tenant and nowhere else; the issuer is that tenant's; and `tid` must equal it. A person
 *   from any other Entra tenant, or a personal Microsoft account, fails the issuer check. The
 *   stable identifier is `oid` (the person's object id in that tenant), never the email: an Entra
 *   administrator can change a person's `email` and `preferred_username`, and Microsoft documents
 *   that neither is for authorization.
 * - **Google Workspace.** `hd` is sent to steer the account chooser, and **checked** in the token,
 *   because the parameter alone only filters the chooser and any Google account (a personal Gmail
 *   included) can still come back without it. `email_verified` must be true. The identifier is `sub`.
 *
 * The endpoints are injectable (`ProviderCatalogue`) so the integration tests can stand up a
 * provider of their own; production uses `DEFAULT_PROVIDER_CATALOGUE` and nothing else.
 */

export type SsoProviderKind = 'microsoft' | 'google';

export const SSO_PROVIDERS: readonly SsoProviderKind[] = ['microsoft', 'google'];

export interface ProviderEndpoints {
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  /** Every exact `iss` spelling this directory's tokens carry. */
  readonly issuers: readonly string[];
  /** Added to the authorization request, beyond the standard parameters. */
  readonly extraParameters: Readonly<Record<string, string>>;
}

/** Where each provider lives, for one company directory. */
export type ProviderCatalogue = Readonly<
  Record<SsoProviderKind, (directoryId: string) => ProviderEndpoints>
>;

export const DEFAULT_PROVIDER_CATALOGUE: ProviderCatalogue = {
  microsoft: (tenantId) => ({
    authorizationEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
    issuers: [`https://login.microsoftonline.com/${tenantId}/v2.0`],
    extraParameters: {},
  }),
  google: (domain) => ({
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    // Google documents both spellings for `iss`.
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    extraParameters: { hd: domain },
  }),
};

/** What a verified id token says about the person, once the provider's own rules are applied. */
export interface ExternalPerson {
  /** The stable identifier: Entra `oid`, Google `sub`. Stored as `identity_account.external_id`. */
  readonly subject: string;
  /** Lower-cased. Used once, to link a pre-created account, and to check the domain. */
  readonly email: string;
}

export type PersonOutcome =
  | { readonly ok: true; readonly person: ExternalPerson }
  | { readonly ok: false; readonly reason: string };

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Deliberately plain: one `@`, no spaces or angle brackets, a dot in the domain. */
const EMAIL = /^[^\s@<>"]+@([^\s@<>"]+\.[^\s@<>"]+)$/;

const text = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;

/** The domain of an address, lower-cased, or `undefined` when it is not an address. */
export const domainOf = (email: string): string | undefined =>
  EMAIL.exec(email.trim().toLowerCase())?.[1];

/**
 * Apply a provider's own rules to claims whose signature, issuer, audience, expiry and nonce have
 * already been verified (`verifyIdToken`).
 */
/** Whether an Entra `idp` claim names this tenant itself (v1 or v2 issuer form). */
const ownIssuer = (idp: string, directoryId: string): boolean => {
  const tenant = directoryId.toLowerCase();
  const value = idp.toLowerCase().replace(/\/$/, '');
  return (
    value === `https://sts.windows.net/${tenant}` ||
    value === `https://login.microsoftonline.com/${tenant}/v2.0`
  );
};

export const personFrom = (
  provider: SsoProviderKind,
  directoryId: string,
  claims: IdTokenClaims,
): PersonOutcome => {
  if (provider === 'microsoft') {
    // The issuer already names the tenant; `tid` is checked as well because it is the claim
    // Microsoft documents for this, and a mismatch between the two is not a token to reason about.
    if (text(claims['tid'])?.toLowerCase() !== directoryId.toLowerCase()) {
      return { ok: false, reason: 'TENANT_MISMATCH' };
    }
    const oid = text(claims['oid']);
    if (oid === undefined || !GUID.test(oid)) return { ok: false, reason: 'NO_OBJECT_ID' };
    // A B2B guest (another company's user, or a personal Microsoft account invited into the
    // tenant) gets a token with this tenant's `iss` and `tid`, so the checks above pass. Its `idp`
    // names where it really signed in: another tenant's issuer, or `live.com`. A member of the
    // tenant carries no `idp`, or this tenant's own issuer. Anything else is a guest and is refused:
    // the company's directory vouches only for its own people.
    const idp = text(claims['idp']);
    if (idp !== undefined && !ownIssuer(idp, directoryId)) {
      return { ok: false, reason: 'GUEST_ACCOUNT' };
    }
    // The address used for the first bind is the user principal name (`preferred_username`), which
    // Entra only lets an administrator set within a domain the tenant has verified. The optional
    // `email` claim is not: a user or a guest can carry an unverified address there. It is used
    // only when Entra says the tenant owns its domain (`xms_edov`). A guest's UPN carries `#EXT#`
    // and lives under onmicrosoft.com, so it can never match a connection's domain either.
    const upn = text(claims['preferred_username'])?.toLowerCase();
    const verifiedEmail =
      claims['xms_edov'] === true ? text(claims['email'])?.toLowerCase() : undefined;
    const email =
      upn !== undefined && !upn.includes('#ext#') && domainOf(upn) !== undefined
        ? upn
        : verifiedEmail;
    if (email === undefined || domainOf(email) === undefined) {
      return { ok: false, reason: 'NO_EMAIL' };
    }
    return { ok: true, person: { subject: oid.toLowerCase(), email } };
  }

  // Google.
  if (text(claims['hd'])?.toLowerCase() !== directoryId.toLowerCase()) {
    return { ok: false, reason: 'HOSTED_DOMAIN_MISMATCH' };
  }
  if (claims['email_verified'] !== true) return { ok: false, reason: 'EMAIL_UNVERIFIED' };
  const sub = text(claims['sub']);
  if (sub === undefined) return { ok: false, reason: 'NO_SUBJECT' };
  const email = text(claims['email'])?.toLowerCase();
  if (email === undefined || domainOf(email) === undefined)
    return { ok: false, reason: 'NO_EMAIL' };
  return { ok: true, person: { subject: sub, email } };
};
