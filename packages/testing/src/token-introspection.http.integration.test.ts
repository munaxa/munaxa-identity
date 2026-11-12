import { generateKeyPairSync, randomUUID } from 'node:crypto';
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

/**
 * The compiled application, because Nest resolves constructor dependencies from decorator metadata
 * that `tsc` emits and vitest's transform does not. CI builds before it runs integration tests.
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

/**
 * `GET /api/auth/introspect` over real HTTP through the whole application as `main.ts` builds it:
 * the `api` prefix, the edge middleware and its rate limits, and the controller. The decision
 * itself is proved route by route in `token-introspection.integration.test.ts`; this file proves
 * the route is where a product calls it, answers in the shape the product parses, and is limited
 * the way the deployment needs (per caller address for the route, per account for an answer).
 */

const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const PASSWORD = `Correct-Horse-${randomUUID()}`;
const org = { key: `introspect-http-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
const VARIABLES = {
  NODE_ENV: 'test',
  IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
  DATABASE_URL: APPLICATION_URL,
  IDENTITY_BASE_URL: 'http://localhost:4001',
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-http-test',
  IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
  CSRF_TRUSTED_ORIGINS: 'http://localhost:3001',
};

let saved: NodeJS.ProcessEnv;
let app: Awaited<ReturnType<typeof createApplication>>;
let base = '';
let security: SecurityStack;
let auth: AuthServiceType;
let ownerPool: pg.Pool;

const person = async (): Promise<{ id: UserId; identifier: string }> => {
  const id = randomUUID() as UserId;
  const identifier = `h-${randomUUID().slice(0, 10)}@example.test`;
  const encoded = await defaultPasswordHasher.hash(PASSWORD);
  const owner = await ownerPool.connect();
  try {
    await owner.query('begin');
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', org.id]);
    await owner.query(
      `insert into identity_account
         (id, tenant_id, identifier, identifier_normalized, password_hash, password_algorithm,
          password_updated_at, status, token_version, mfa_enrolled, must_change_password,
          identity_source, created_at, updated_at, version)
       values ($1, $2, $3, $3, $4, $5, now(), 'active', 1, false, false, 'local', now(), now(), 1)`,
      [id, org.id, identifier, encoded, encoded.split('$')[1] ?? 'unknown'],
    );
    await owner.query('commit');
  } finally {
    owner.release();
  }
  return { id, identifier };
};

const accessTokenFor = async (identifier: string): Promise<string> => {
  const result = await auth.login({
    identifier,
    password: PASSWORD,
    organisation: org.key,
    correlationId: toCorrelationId(`corr-${randomUUID()}`),
  });
  if (!result.ok) throw new Error('sign-in failed');
  return result.access;
};

const introspect = (token?: string): Promise<Response> =>
  fetch(`${base}/api/auth/introspect`, {
    headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
  });

beforeAll(async () => {
  saved = { ...process.env };
  // The application reads its own environment, and treats any `*_FILE` variable as a secret mount
  // it must read. Only this suite's variables are left for it to see.
  for (const key of Object.keys(process.env)) {
    if (key.endsWith('_FILE')) Reflect.deleteProperty(process.env, key);
  }
  Object.assign(process.env, VARIABLES);
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  const owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
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

describe('GET /api/auth/introspect through the application', () => {
  it('is mounted under /api and answers a live token with its own claims, never cached', async () => {
    const someone = await person();
    const token = await accessTokenFor(someone.identifier);

    const response = await introspect(token);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toMatchObject({ active: true, sub: someone.id, tid: org.id });
  });

  it('answers inactive once every session of the account is revoked', async () => {
    const someone = await person();
    const token = await accessTokenFor(someone.identifier);
    await security.revocation.revokeAllForUser(org.id, someone.id, 'logout');

    const response = await introspect(token);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ active: false });
  });

  it('answers inactive, not an error, without a bearer token', async () => {
    const response = await introspect();

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ active: false });
  });

  it('is not held to the browser per-address limit, which a product NAT address would exhaust', async () => {
    // `api-per-ip` allows 300 a minute; introspection has its own, much higher address limit.
    const statuses = new Set<number>();
    for (let call = 0; call < 320; call += 1) statuses.add((await introspect('not-a-jwt')).status);

    expect([...statuses]).toEqual([200]);
  });

  it('limits answers per account, refusing that account with 429 and leaving others alone', async () => {
    const noisy = await person();
    const quiet = await person();
    const noisyToken = await accessTokenFor(noisy.identifier);
    const quietToken = await accessTokenFor(quiet.identifier);

    let limited: Response | undefined;
    for (let call = 0; call < 601 && limited === undefined; call += 1) {
      const response = await introspect(noisyToken);
      if (response.status === 429) limited = response;
    }

    expect(limited?.status).toBe(429);
    expect(limited?.headers.get('retry-after')).toMatch(/^\d+$/);
    expect(await limited?.json()).toEqual({ code: 'RATE_LIMITED' });
    expect(await (await introspect(quietToken)).json()).toMatchObject({ active: true });
  }, 60_000);

  it('sees the whole path at the edge, so path-matched limits such as login-per-ip fire', async () => {
    // Before the edge read the full path, Express reported `/` for every request and no
    // path-matched rule ever matched. `login-per-ip` allows 10 sign-in attempts per 15 minutes.
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 12; attempt += 1) {
      const response = await fetch(`${base}/api/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3001' },
        body: JSON.stringify({ identifier: 'nobody@example.test', password: 'wrong' }),
      });
      statuses.push(response.status);
    }

    expect(statuses.slice(0, 10)).not.toContain(429);
    expect(statuses[10]).toBe(429);
  });
});
