import { duration, oneOf, string } from '@munaxa/config';

import { reusesSecret } from './mfa-keys.js';

/**
 * Identity as the OpenID Connect provider for other Munaxa products (ADR-0008).
 *
 * Munaxa Docs and School keep their own users, roles and permissions, and sign people in through
 * Identity exactly as they would through any company directory: Identity is the provider their
 * existing OIDC relying-party code points at. So a person has one Munaxa sign-in, with Identity's
 * MFA, lockout, session revocation and Microsoft/Google company sign-in, in every product.
 *
 * Clients are configuration, not data: there are a handful (one per product deployment, or one
 * per Docs organisation), each is a security decision reviewed with the deployment, and none is
 * ever created by a request. Each client is bound to **one Identity organisation**: a person whose
 * Identity session belongs to another organisation is refused with `access_denied`, so a Docs
 * tenant only ever receives people from the organisation it is paired with.
 *
 *     IDENTITY_OIDC_CLIENTS          docs-acme|acme|https://docs.example/auth/federation/callback
 *                                    (`;` between clients, spaces between redirect URIs)
 *     IDENTITY_OIDC_CLIENT_SECRETS   docs-acme=<at least 32 random characters>   (`,` between)
 *
 * The secrets are a mounted secret (`IDENTITY_OIDC_CLIENT_SECRETS_FILE` or an ECS secret
 * reference), compared in constant time, and never logged.
 */
export const OIDC_PROVIDER_FIELDS = {
  /** Whether Identity answers as an OIDC provider at all. `disabled` answers the routes with 404. */
  IDENTITY_OIDC_PROVIDER: oneOf(['enabled', 'disabled'] as const, { default: 'disabled' }),
  IDENTITY_OIDC_CLIENTS: string({ default: '', minLength: 0 }),
  IDENTITY_OIDC_CLIENT_SECRETS: string({ secret: true, default: '', minLength: 0 }),
  /** How long an authorization code may wait to be redeemed. One minute; codes are single use. */
  IDENTITY_OIDC_CODE_TTL: duration({ default: 60 * 1_000 }),
  /** The id token's lifetime. It is redeemed at once by the product, never kept. */
  IDENTITY_OIDC_ID_TOKEN_TTL: duration({ default: 5 * 60 * 1_000 }),
};

export interface OidcClient {
  readonly clientId: string;
  /** The Identity organisation key the client is bound to. */
  readonly organisation: string;
  readonly redirectUris: readonly string[];
  readonly secret: string;
}

const CLIENT_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const ORGANISATION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SECRET = /^[A-Za-z0-9_-]{32,256}$/;

/** The clients as configured, or a list of problems. Pure: shared by startup and the service. */
export const parseOidcClients = (
  clients: string,
  secrets: string,
): { readonly clients: readonly OidcClient[]; readonly problems: readonly string[] } => {
  const problems: string[] = [];
  const secretOf = new Map<string, string>();
  for (const entry of secrets
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')) {
    const at = entry.indexOf('=');
    const id = at < 0 ? '' : entry.slice(0, at).trim();
    const value = at < 0 ? '' : entry.slice(at + 1).trim();
    if (!CLIENT_ID.test(id) || !SECRET.test(value)) {
      problems.push(
        'IDENTITY_OIDC_CLIENT_SECRETS: every entry is client_id=<32+ base64url characters>.',
      );
      continue;
    }
    if (secretOf.has(id)) problems.push(`IDENTITY_OIDC_CLIENT_SECRETS: ${id} is listed twice.`);
    secretOf.set(id, value);
  }

  const parsed: OidcClient[] = [];
  const named = new Set<string>();
  for (const entry of clients
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part !== '')) {
    const [id = '', organisation = '', uris = ''] = entry.split('|').map((part) => part.trim());
    if (!CLIENT_ID.test(id)) {
      problems.push('IDENTITY_OIDC_CLIENTS: a client id is 3-64 characters of a-z, 0-9 and -.');
      continue;
    }
    named.add(id);
    if (!ORGANISATION.test(organisation)) {
      problems.push(`IDENTITY_OIDC_CLIENTS: ${id} names no organisation key.`);
      continue;
    }
    const redirectUris = uris.split(/\s+/).filter((uri) => uri !== '');
    if (redirectUris.length === 0) {
      problems.push(`IDENTITY_OIDC_CLIENTS: ${id} has no redirect URI.`);
      continue;
    }
    for (const uri of redirectUris) {
      if (!isRedirectUri(uri)) {
        problems.push(
          `IDENTITY_OIDC_CLIENTS: ${id} redirect URI is not an absolute http(s) URL without a fragment or credentials.`,
        );
      }
    }
    if (parsed.some((client) => client.clientId === id)) {
      problems.push(`IDENTITY_OIDC_CLIENTS: ${id} is listed twice.`);
      continue;
    }
    const secret = secretOf.get(id);
    if (secret === undefined) {
      problems.push(`IDENTITY_OIDC_CLIENT_SECRETS: ${id} has no secret.`);
      continue;
    }
    parsed.push({ clientId: id, organisation, redirectUris, secret });
  }
  for (const id of secretOf.keys()) {
    if (!named.has(id)) {
      problems.push(`IDENTITY_OIDC_CLIENT_SECRETS: ${id} is not a configured client.`);
    }
  }
  return { clients: parsed, problems };
};

const isRedirectUri = (uri: string): boolean => {
  try {
    const url = new URL(uri);
    return (
      (url.protocol === 'https:' || url.protocol === 'http:') &&
      url.hash === '' &&
      url.username === '' &&
      url.password === '' &&
      url.href === uri
    );
  } catch {
    return false;
  }
};

interface OidcView {
  readonly MUNAXA_ENV: string;
  readonly MUNAXA_TOKEN_AUDIENCE: readonly string[];
  readonly MUNAXA_SIGNING_SECRET: string;
  readonly IDENTITY_SIGNING_PRIVATE_KEY: string;
  readonly MFA_ENCRYPTION_KEYS: string;
  readonly IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: string;
  readonly IDENTITY_SSO_GOOGLE_CLIENT_SECRET: string;
  readonly IDENTITY_OIDC_PROVIDER: 'enabled' | 'disabled';
  readonly IDENTITY_OIDC_CLIENTS: string;
  readonly IDENTITY_OIDC_CLIENT_SECRETS: string;
  readonly IDENTITY_OIDC_CODE_TTL: number;
  readonly IDENTITY_OIDC_ID_TOKEN_TTL: number;
}

export const oidcProviderIssues = (resolved: OidcView): { key: string; problem: string }[] => {
  const issues: { key: string; problem: string }[] = [];
  if (resolved.IDENTITY_OIDC_CODE_TTL < 10_000 || resolved.IDENTITY_OIDC_CODE_TTL > 600_000) {
    issues.push({ key: 'IDENTITY_OIDC_CODE_TTL', problem: 'must be between 10s and 10m.' });
  }
  if (
    resolved.IDENTITY_OIDC_ID_TOKEN_TTL < 60_000 ||
    resolved.IDENTITY_OIDC_ID_TOKEN_TTL > 3_600_000
  ) {
    issues.push({ key: 'IDENTITY_OIDC_ID_TOKEN_TTL', problem: 'must be between 1m and 1h.' });
  }
  if (resolved.IDENTITY_OIDC_PROVIDER === 'disabled') return issues;

  const { clients, problems } = parseOidcClients(
    resolved.IDENTITY_OIDC_CLIENTS,
    resolved.IDENTITY_OIDC_CLIENT_SECRETS,
  );
  for (const problem of problems) {
    const [key = 'IDENTITY_OIDC_CLIENTS', ...rest] = problem.split(': ');
    issues.push({ key, problem: rest.join(': ') });
  }
  if (clients.length === 0 && problems.length === 0) {
    issues.push({
      key: 'IDENTITY_OIDC_CLIENTS',
      problem: 'is empty while IDENTITY_OIDC_PROVIDER=enabled. Configure a client or disable it.',
    });
  }
  const production = resolved.MUNAXA_ENV === 'production';
  for (const client of clients) {
    // An id token for a client whose id is also an access-token audience would be accepted by
    // that product as an access token. The two namespaces must never meet.
    if (resolved.MUNAXA_TOKEN_AUDIENCE.includes(client.clientId)) {
      issues.push({
        key: 'IDENTITY_OIDC_CLIENTS',
        problem: `${client.clientId} is also an access-token audience (IDENTITY_AUTH_AUDIENCE). Use another client id.`,
      });
    }
    if (production && client.redirectUris.some((uri) => !uri.startsWith('https://'))) {
      issues.push({
        key: 'IDENTITY_OIDC_CLIENTS',
        problem: `${client.clientId} redirect URIs must be https in production.`,
      });
    }
    const bytes = Buffer.from(client.secret, 'utf8');
    if (
      reusesSecret(bytes, resolved.MUNAXA_SIGNING_SECRET) ||
      reusesSecret(bytes, resolved.IDENTITY_SIGNING_PRIVATE_KEY) ||
      resolved.MFA_ENCRYPTION_KEYS.includes(client.secret) ||
      [resolved.IDENTITY_SSO_MICROSOFT_CLIENT_SECRET, resolved.IDENTITY_SSO_GOOGLE_CLIENT_SECRET]
        .map((value) => value.trim())
        .includes(client.secret)
    ) {
      issues.push({
        key: 'IDENTITY_OIDC_CLIENT_SECRETS',
        problem: `${client.clientId} uses another secret this service holds. It must be its own.`,
      });
    }
  }
  const secrets = clients.map((client) => client.secret);
  if (new Set(secrets).size !== secrets.length) {
    issues.push({
      key: 'IDENTITY_OIDC_CLIENT_SECRETS',
      problem: 'two clients share a secret. Each must be its own.',
    });
  }
  return issues;
};
