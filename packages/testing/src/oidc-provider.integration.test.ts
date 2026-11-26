import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';

import { defaultPasswordHasher } from '@munaxa/crypto';
import { toCorrelationId, type TenantId, type UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment } from '../../config/src/index.js';
import type { createApplication as CreateApplication } from '../../../apps/api/src/application.js';
import type { AuthService as AuthServiceType } from '../../../apps/api/src/auth/auth.service.js';
import type { SecurityStack } from '../../../apps/api/src/platform/security.js';
import type { verifyIdToken as VerifyIdToken, Jwk } from '../../../apps/api/src/sso/id-token.js';

/**
 * Identity as the OpenID Connect provider for Docs and School (ADR-0008), over real HTTP through
 * the whole application: discovery, keys, the browser leg and the token leg, and every refusal
 * that keeps a code from being worth stealing.
 */

const DIST = new URL('../../../apps/api/dist/', import.meta.url);
if (!existsSync(new URL('application.js', DIST))) {
  throw new Error('apps/api/dist is missing: run `pnpm build` before the integration tests.');
}
const compiled = createRequire(import.meta.url);
const load = <T>(path: string): T => compiled(new URL(path, DIST).pathname) as T;
const { createApplication } = load<{ createApplication: typeof CreateApplication }>(
  'application.js',
);
const { AuthService } = load<{ AuthService: typeof AuthServiceType }>('auth/auth.service.js');
const { PrismaService } = load<{ PrismaService: new (...args: never[]) => unknown }>(
  'persistence/prisma.service.js',
);
const { SECURITY_STACK } = load<{ SECURITY_STACK: symbol }>('tokens.js');
const { verifyIdToken } = load<{ verifyIdToken: typeof VerifyIdToken }>('sso/id-token.js');

const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const PASSWORD = `Correct-Horse-${randomUUID()}`;
const run = randomUUID().slice(0, 8);
const org = { key: `oidc-${run}`, id: randomUUID() as TenantId };
const other = { key: `oidc-other-${run}`, id: randomUUID() as TenantId };
const ISSUER = 'http://localhost:4001';
const CLIENT = 'docs-test';
const SECRET = randomBytes(32).toString('base64url');
const REDIRECT = 'https://docs.example.test/auth/federation/callback';
const VARIABLES = {
  NODE_ENV: 'test',
  IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
  DATABASE_URL: APPLICATION_URL,
  IDENTITY_BASE_URL: ISSUER,
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-oidc-test',
  IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
  CSRF_TRUSTED_ORIGINS: 'http://localhost:3001',
  IDENTITY_OIDC_PROVIDER: 'enabled',
  IDENTITY_OIDC_CLIENTS: `${CLIENT}|${org.key}|${REDIRECT}`,
  IDENTITY_OIDC_CLIENT_SECRETS: `${CLIENT}=${SECRET}`,
};

let saved: NodeJS.ProcessEnv;
let app: Awaited<ReturnType<typeof createApplication>>;
let base = '';
let security: SecurityStack;
let auth: AuthServiceType;
let ownerPool: pg.Pool;

const person = async (
  tenant: { id: TenantId } = org,
): Promise<{ id: UserId; identifier: string }> => {
  const id = randomUUID() as UserId;
  const identifier = `o-${randomUUID().slice(0, 10)}@example.test`;
  const encoded = await defaultPasswordHasher.hash(PASSWORD);
  const owner = await ownerPool.connect();
  try {
    await owner.query('begin');
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenant.id]);
    await owner.query(
      `insert into identity_account
         (id, tenant_id, identifier, identifier_normalized, password_hash, password_algorithm,
          password_updated_at, status, token_version, mfa_enrolled, must_change_password,
          identity_source, created_at, updated_at, version)
       values ($1, $2, $3, $3, $4, $5, now(), 'active', 1, false, false, 'local', now(), now(), 1)`,
      [id, tenant.id, identifier, encoded, encoded.split('$')[1] ?? 'unknown'],
    );
    await owner.query('commit');
  } finally {
    owner.release();
  }
  return { id, identifier };
};

const disable = async (tenant: TenantId, id: UserId): Promise<void> => {
  const owner = await ownerPool.connect();
  try {
    await owner.query('begin');
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenant]);
    await owner.query(`update identity_account set status = 'disabled' where id = $1`, [id]);
    await owner.query('commit');
  } finally {
    owner.release();
  }
};

const sessionFor = async (identifier: string, organisation = org.key): Promise<string> => {
  const result = await auth.login({
    identifier,
    password: PASSWORD,
    organisation,
    correlationId: toCorrelationId(`corr-${randomUUID()}`),
  });
  if (!result.ok) throw new Error('sign-in failed');
  return result.access;
};

interface AuthorizeParams {
  readonly [key: string]: string | undefined;
}

const authorizeUrl = (overrides: AuthorizeParams = {}): string => {
  const params = new URLSearchParams();
  const all: AuthorizeParams = {
    response_type: 'code',
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    scope: 'openid email profile',
    state: `state-${randomUUID()}`,
    nonce: `nonce-${randomUUID()}`,
    ...overrides,
  };
  for (const [key, value] of Object.entries(all)) if (value !== undefined) params.set(key, value);
  return `${base}/api/auth/oidc/authorize?${params.toString()}`;
};

const authorize = (url: string, session?: string): Promise<Response> =>
  fetch(url, {
    redirect: 'manual',
    headers: session === undefined ? {} : { cookie: `__Host-mx_session=${session}` },
  });

const codeFrom = async (session: string, overrides: AuthorizeParams = {}) => {
  const url = authorizeUrl(overrides);
  const response = await authorize(url, session);
  expect(response.status).toBe(303);
  const location = new URL(response.headers.get('location')!);
  return { location, code: location.searchParams.get('code')!, url: new URL(url) };
};

const redeem = (fields: Record<string, string>, authorization?: string): Promise<Response> =>
  fetch(`${base}/api/auth/oidc/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...(authorization === undefined ? {} : { authorization }),
    },
    body: new URLSearchParams(fields).toString(),
  });

const redeemPost = (code: string, extra: Record<string, string> = {}) =>
  redeem({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT,
    client_id: CLIENT,
    client_secret: SECRET,
    ...extra,
  });

const keys = async (): Promise<readonly Jwk[]> =>
  ((await (await fetch(`${base}/api/auth/oidc/jwks`)).json()) as { keys: Jwk[] }).keys;

beforeAll(async () => {
  saved = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (key.endsWith('_FILE')) Reflect.deleteProperty(process.env, key);
  }
  Object.assign(process.env, VARIABLES);
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  const owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
  await createOrganisation(owner, other.key, other.id);
  owner.release();

  app = await createApplication(loadEnvironment(VARIABLES), { quiet: true });
  await app.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${String((app.getHttpServer().address() as AddressInfo).port)}`;
  security = app.get<SecurityStack>(SECURITY_STACK);
  auth = new AuthService(security, loadEnvironment(VARIABLES), app.get(PrismaService) as never);
});

afterAll(async () => {
  await app?.close();
  await ownerPool?.end();
  for (const key of Object.keys(process.env)) {
    if (!(key in saved)) Reflect.deleteProperty(process.env, key);
  }
  Object.assign(process.env, saved);
});

describe('discovery and keys', () => {
  it('publishes a discovery document for the issuer, code flow only', async () => {
    const response = await fetch(`${base}/api/auth/oidc/.well-known/openid-configuration`);
    expect(response.status).toBe(200);
    const document = (await response.json()) as Record<string, unknown>;
    expect(document).toMatchObject({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/api/auth/oidc/authorize`,
      token_endpoint: `${ISSUER}/api/auth/oidc/token`,
      jwks_uri: `${ISSUER}/api/auth/oidc/jwks`,
      response_types_supported: ['code'],
      id_token_signing_alg_values_supported: ['ES256'],
    });
  });

  it('publishes the public signing key and nothing private', async () => {
    const [key, ...rest] = await keys();
    expect(rest).toHaveLength(0);
    expect(key).toMatchObject({ kty: 'EC', crv: 'P-256', kid: 'identity-oidc-test', alg: 'ES256' });
    expect(key).not.toHaveProperty('d');
  });
});

describe('the browser leg', () => {
  it('sends a person without a session to sign in, then back to this exact request', async () => {
    const url = authorizeUrl();
    const response = await authorize(url);
    expect(response.status).toBe(303);
    const location = response.headers.get('location')!;
    expect(location.startsWith(`/api/auth/login?organisation=${org.key}&returnTo=`)).toBe(true);
    const returnTo = decodeURIComponent(location.split('returnTo=')[1]!);
    expect(returnTo).toBe(new URL(url).pathname + new URL(url).search);
    // And the sign-in page it lands on has the organisation filled in.
    const page = await (await fetch(`${base}${location}`)).text();
    expect(page).toContain(`value="${org.key}"`);
  });

  it('answers prompt=none without a session with login_required, at the client', async () => {
    const response = await authorize(authorizeUrl({ prompt: 'none', state: 'state-12345678' }));
    const location = new URL(response.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get('error')).toBe('login_required');
    expect(location.searchParams.get('state')).toBe('state-12345678');
  });

  it('issues a code to the registered redirect URI, with the state and the issuer', async () => {
    const someone = await person();
    const session = await sessionFor(someone.identifier);
    const { location, code, url } = await codeFrom(session);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(code).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(location.searchParams.get('state')).toBe(url.searchParams.get('state'));
    expect(location.searchParams.get('iss')).toBe(ISSUER);
  });

  it.each([
    ['an unknown client', { client_id: 'nobody-here' }],
    ['a redirect URI the client never registered', { redirect_uri: 'https://evil.example/cb' }],
    ['a registered URI with something appended', { redirect_uri: `${REDIRECT}?next=x` }],
  ])('shows an error page and redirects nowhere for %s', async (_name, overrides) => {
    const someone = await person();
    const response = await authorize(authorizeUrl(overrides), await sessionFor(someone.identifier));
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
    expect(await response.text()).toContain('This sign-in link is not valid');
  });

  it.each([
    ['a response type other than code', { response_type: 'token' }, 'unsupported_response_type'],
    ['no openid scope', { scope: 'email' }, 'invalid_scope'],
    ['no nonce', { nonce: undefined }, 'invalid_request'],
    [
      'a plain PKCE challenge',
      { code_challenge: 'x'.repeat(43), code_challenge_method: 'plain' },
      'invalid_request',
    ],
  ])('returns an OAuth error to the client for %s', async (_name, overrides, error) => {
    const someone = await person();
    const response = await authorize(authorizeUrl(overrides), await sessionFor(someone.identifier));
    expect(response.status).toBe(303);
    const location = new URL(response.headers.get('location')!);
    expect(location.searchParams.get('error')).toBe(error);
    expect(location.searchParams.get('code')).toBeNull();
  });

  it('refuses a person from another organisation with access_denied', async () => {
    const stranger = await person(other);
    const response = await authorize(
      authorizeUrl(),
      await sessionFor(stranger.identifier, other.key),
    );
    const location = new URL(response.headers.get('location')!);
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('code')).toBeNull();
  });
});

describe('the token leg', () => {
  it('exchanges a code for an id token the client can verify against the published key', async () => {
    const someone = await person();
    const { code, url } = await codeFrom(await sessionFor(someone.identifier));
    const response = await redeemPost(code);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ token_type: 'Bearer' });
    expect(typeof body['access_token']).toBe('string');
    const outcome = verifyIdToken(body['id_token'] as string, await keys(), {
      issuers: [ISSUER],
      audience: CLIENT,
      nonce: url.searchParams.get('nonce')!,
      now: new Date(),
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.claims).toMatchObject({
      sub: someone.id,
      email: someone.identifier,
      // A password account nobody has checked: the token says so (identity#33 review L-2).
      email_verified: false,
      tid: org.id,
      org: org.key,
      amr: ['password'],
    });
    expect(outcome.claims).not.toHaveProperty('perms');
  });

  it('says the address is checked once an operator confirmed it or a recovery link was used', async () => {
    const someone = await person();
    const owner = await ownerPool.connect();
    try {
      await owner.query('begin');
      await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', org.id]);
      await owner.query('update identity_account set email_verified_at = now() where id = $1', [
        someone.id,
      ]);
      await owner.query('commit');
    } finally {
      owner.release();
    }
    const { code, url } = await codeFrom(await sessionFor(someone.identifier));
    const body = (await (await redeemPost(code)).json()) as Record<string, unknown>;
    const outcome = verifyIdToken(body['id_token'] as string, await keys(), {
      issuers: [ISSUER],
      audience: CLIENT,
      nonce: url.searchParams.get('nonce')!,
      now: new Date(),
    });
    expect(outcome.ok && outcome.claims['email_verified']).toBe(true);
  });

  it('accepts client_secret_basic', async () => {
    const someone = await person();
    const { code } = await codeFrom(await sessionFor(someone.identifier));
    const basic = `Basic ${Buffer.from(`${CLIENT}:${SECRET}`).toString('base64')}`;
    const response = await redeem(
      { grant_type: 'authorization_code', code, redirect_uri: REDIRECT },
      basic,
    );
    expect(response.status).toBe(200);
  });

  it('answers a malformed Basic header with invalid_client, not a server error', async () => {
    const response = await redeem(
      { grant_type: 'authorization_code', code: 'x'.repeat(43), redirect_uri: REDIRECT },
      `Basic ${Buffer.from('%E0%A4%A:secret').toString('base64')}`,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'invalid_client' });
  });

  it('redeems a code once only', async () => {
    const someone = await person();
    const { code } = await codeFrom(await sessionFor(someone.identifier));
    expect((await redeemPost(code)).status).toBe(200);
    const again = await redeemPost(code);
    expect(again.status).toBe(400);
    expect(await again.json()).toEqual({ error: 'invalid_grant' });
  });

  it('refuses a wrong client secret, and leaves the code unspent', async () => {
    const someone = await person();
    const { code } = await codeFrom(await sessionFor(someone.identifier));
    const wrong = await redeemPost(code, { client_secret: randomBytes(32).toString('base64url') });
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: 'invalid_client' });
    expect((await redeemPost(code)).status).toBe(200);
  });

  it('spends a code presented with another redirect URI', async () => {
    const someone = await person();
    const { code } = await codeFrom(await sessionFor(someone.identifier));
    expect((await redeemPost(code, { redirect_uri: 'https://evil.example/cb' })).status).toBe(400);
    expect((await redeemPost(code)).status).toBe(400);
  });

  it('enforces PKCE when the client sent a challenge', async () => {
    const someone = await person();
    const session = await sessionFor(someone.identifier);
    const verifier = randomBytes(48).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const pkce = { code_challenge: challenge, code_challenge_method: 'S256' };

    const missing = await codeFrom(session, pkce);
    expect((await redeemPost(missing.code)).status).toBe(400);
    const wrong = await codeFrom(session, pkce);
    expect(
      (await redeemPost(wrong.code, { code_verifier: randomBytes(48).toString('base64url') }))
        .status,
    ).toBe(400);
    const right = await codeFrom(session, pkce);
    expect((await redeemPost(right.code, { code_verifier: verifier })).status).toBe(200);
  });

  it('refuses a code once the person has been disabled since it was issued', async () => {
    const someone = await person();
    const { code } = await codeFrom(await sessionFor(someone.identifier));
    await disable(org.id, someone.id);
    expect((await redeemPost(code)).status).toBe(400);
  });

  it('refuses an unsupported grant type', async () => {
    const response = await redeem({
      grant_type: 'client_credentials',
      client_id: CLIENT,
      client_secret: SECRET,
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'unsupported_grant_type' });
  });
});
