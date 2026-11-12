import { generateKeyPairSync, randomInt, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { connect } from 'node:net';
import type { AddressInfo } from 'node:net';

import { defaultPasswordHasher } from '@munaxa/crypto';
import type { CachePort } from '@munaxa/interfaces';
import { FixedClock, toCorrelationId, type TenantId, type UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment } from '../../config/src/index.js';
import type { createApplication as CreateApplication } from '../../../apps/api/src/application.js';
import type { AuthService as AuthServiceType } from '../../../apps/api/src/auth/auth.service.js';
import type * as AuthEdge from '../../../apps/api/src/security/auth-edge-limits.js';
import type { openCache as OpenCache } from '../../../apps/api/src/platform/cache.js';
import type { SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * The credential-route limits through the compiled application over real HTTP, as `main.ts` builds
 * it (the `api` prefix, proxy trust, body parsers, the edge middleware on every route), on a real
 * Redis shared by two application instances — the shape of two Identity tasks on one store.
 *
 * What it proves, route by route: the policy applies to the route Express actually serves, under
 * every spelling of it; it does not apply to another method or route; the counter is the intended
 * one (address, identifier, challenge or session) and survives refusals; a refusal for one
 * identifier is not charged to the shared address; introspection keeps its own limits; a store that
 * cannot be read refuses (503) rather than admits.
 *
 * Requests carry `X-Forwarded-For` with `TRUST_PROXY_HOPS=1`, the stack's setting behind the ALB:
 * the address the limiter counts is the one the proxy reports. Each test uses fresh addresses and
 * identifiers, so a rerun against the same Redis starts clean.
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
const edge = load<typeof AuthEdge>('security/auth-edge-limits.js');
const { openCache } = load<{ openCache: typeof OpenCache }>('platform/cache.js');

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const PASSWORD = `Correct-Horse-${randomUUID()}`;
const org = { key: `edge-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
const ORIGIN = 'http://localhost:3001';
const LIMITS = {
  loginPerIp: 30,
  loginPerIdentifier: 10,
  passwordResetPerIp: 10,
  mfaPerIp: 30,
  mfaPerSession: 5,
  lockoutAfter: 5,
};
const VARIABLES = {
  NODE_ENV: 'test',
  IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
  DATABASE_URL: APPLICATION_URL,
  REDIS_URL,
  TRUST_PROXY_HOPS: '1',
  IDENTITY_BASE_URL: 'http://localhost:4001',
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-edge-test',
  IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
  CSRF_TRUSTED_ORIGINS: ORIGIN,
  EDGE_LOGIN_PER_IP_LIMIT: String(LIMITS.loginPerIp),
  EDGE_LOGIN_PER_IDENTIFIER_LIMIT: String(LIMITS.loginPerIdentifier),
  EDGE_PASSWORD_RESET_PER_IP_LIMIT: String(LIMITS.passwordResetPerIp),
  EDGE_MFA_PER_IP_LIMIT: String(LIMITS.mfaPerIp),
  EDGE_MFA_PER_SESSION_LIMIT: String(LIMITS.mfaPerSession),
  LOGIN_MAX_ATTEMPTS: String(LIMITS.lockoutAfter),
  IDENTITY_DEFAULT_ORGANISATION: org.key,
};

type App = Awaited<ReturnType<typeof createApplication>>;
let saved: NodeJS.ProcessEnv;
const apps: App[] = [];
const ports: number[] = [];
let security: SecurityStack;
let auth: AuthServiceType;
let ownerPool: pg.Pool;

const freshIp = (): string =>
  `10.${String(randomInt(1, 255))}.${String(randomInt(1, 255))}.${String(randomInt(1, 255))}`;
const freshIdentifier = (): string => `e-${randomUUID().slice(0, 12)}@example.test`;

interface Reply {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/**
 * One request, written byte for byte: `fetch` would normalise the very spellings under test (dot
 * segments, absolute-form targets), so the request line is sent exactly as given.
 */
const send = (
  method: string,
  target: string,
  options: {
    readonly ip: string;
    readonly body?: Record<string, string>;
    readonly form?: boolean;
    readonly cookies?: Record<string, string>;
    readonly headers?: Record<string, string>;
    readonly instance?: number;
  },
): Promise<Reply> =>
  new Promise((resolve, reject) => {
    const payload =
      options.body === undefined
        ? ''
        : options.form === true
          ? new URLSearchParams(options.body).toString()
          : JSON.stringify(options.body);
    const lines = [
      `${method} ${target} HTTP/1.1`,
      'Host: localhost',
      `Origin: ${ORIGIN}`,
      `X-Forwarded-For: ${options.ip}`,
      'Connection: close',
      `Content-Length: ${String(Buffer.byteLength(payload))}`,
    ];
    if (options.body !== undefined) {
      lines.push(
        `Content-Type: ${options.form === true ? 'application/x-www-form-urlencoded' : 'application/json'}`,
      );
    }
    if (options.cookies !== undefined) {
      lines.push(
        `Cookie: ${Object.entries(options.cookies)
          .map(([name, value]) => `${name}=${value}`)
          .join('; ')}`,
      );
    }
    for (const [name, value] of Object.entries(options.headers ?? {}))
      lines.push(`${name}: ${value}`);
    const socket = connect(ports[options.instance ?? 0]!, '127.0.0.1', () => {
      socket.write(`${lines.join('\r\n')}\r\n\r\n${payload}`);
    });
    let raw = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => (raw += chunk));
    socket.on('error', reject);
    socket.on('end', () => {
      const [head = '', ...rest] = raw.split('\r\n\r\n');
      const [statusLine = '', ...headerLines] = head.split('\r\n');
      const headers: Record<string, string> = {};
      for (const line of headerLines) {
        const at = line.indexOf(':');
        headers[line.slice(0, at).toLowerCase()] = line.slice(at + 1).trim();
      }
      resolve({ status: Number(statusLine.split(' ')[1]), headers, body: rest.join('\r\n\r\n') });
    });
  });

const loginAs = (
  ip: string,
  identifier = freshIdentifier(),
  options: {
    readonly target?: string;
    readonly password?: string;
    readonly instance?: number;
  } = {},
): Promise<Reply> =>
  send('POST', options.target ?? '/api/auth/login', {
    ip,
    body: { identifier, password: options.password ?? 'wrong-password', organisation: org.key },
    ...(options.instance === undefined ? {} : { instance: options.instance }),
  });

const edgeLimited = (reply: Reply): boolean =>
  reply.status === 429 && reply.body.includes('SECURITY_RATE_LIMITED');

const person = async (): Promise<{ id: UserId; identifier: string }> => {
  const id = randomUUID() as UserId;
  const identifier = freshIdentifier();
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

beforeAll(async () => {
  saved = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (key.endsWith('_FILE')) Reflect.deleteProperty(process.env, key);
  }
  Object.assign(process.env, VARIABLES);
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  const owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
  owner.release();

  for (let instance = 0; instance < 2; instance += 1) {
    const app = await createApplication(loadEnvironment(VARIABLES), { quiet: true });
    await app.listen(0, '127.0.0.1');
    apps.push(app);
    ports.push((app.getHttpServer().address() as AddressInfo).port);
  }
  security = apps[0]!.get<SecurityStack>(SECURITY_STACK);
  expect(security.cacheKind).toBe('redis');
  auth = new AuthService(
    security,
    loadEnvironment(VARIABLES),
    apps[0]!.get(PrismaService) as never,
  );
});

afterAll(async () => {
  for (const app of apps) await app.close();
  await ownerPool?.end();
  for (const key of Object.keys(process.env)) {
    if (!(key in saved)) Reflect.deleteProperty(process.env, key);
  }
  Object.assign(process.env, saved);
});

describe('sign-in: POST /api/auth/login', () => {
  it('limits one address to its allowance, then 429 with Retry-After, and keeps refusing', async () => {
    const ip = freshIp();
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 2 * LIMITS.loginPerIp; attempt += 1) {
      statuses.push((await loginAs(ip)).status);
    }
    expect(statuses.slice(0, LIMITS.loginPerIp).every((status) => status === 401)).toBe(true);
    // Every attempt past the limit is refused: no restart after a refusal (the 11/22 pattern).
    expect(statuses.slice(LIMITS.loginPerIp).every((status) => status === 429)).toBe(true);

    const refused = await loginAs(ip);
    expect(edgeLimited(refused)).toBe(true);
    expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
    expect(Number(refused.headers['retry-after'])).toBeLessThanOrEqual(5 * 60);
    expect(refused.headers['ratelimit-limit']).toBe(String(LIMITS.loginPerIp));
    expect(JSON.parse(refused.body)).toMatchObject({ code: 'SECURITY_RATE_LIMITED' });
  });

  it('counts every spelling of the route against the same counter, and refuses every spelling', async () => {
    const spellings = [
      '/api/auth/LOGIN',
      '/API/Auth/Login',
      '/api/auth/login/',
      '/api/auth/login?next=%2F',
      'http://identity.example/api/auth/login',
      '/api//auth//login',
      '/api/auth/%6Cogin',
      '/api/auth/%6cogin/',
      '/api/auth/./login',
      '/api/auth/x/../login',
      '/api/auth/login%2F',
    ];
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.loginPerIp; attempt += 1) {
      const reply = await loginAs(ip, freshIdentifier(), {
        target: spellings[attempt % spellings.length]!,
      });
      // Routed spellings reach the handler (401); the rest are not routed by Express (404).
      expect([401, 404]).toContain(reply.status);
    }
    expect(edgeLimited(await loginAs(ip))).toBe(true);
    for (const target of spellings) {
      expect(edgeLimited(await loginAs(ip, freshIdentifier(), { target })), target).toBe(true);
    }
  });

  it('counts a form post the same as JSON', async () => {
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.loginPerIp; attempt += 1) {
      await send('POST', '/api/auth/login', {
        ip,
        form: true,
        body: { identifier: freshIdentifier(), password: 'x', organisation: org.key },
      });
    }
    expect(edgeLimited(await loginAs(ip))).toBe(true);
  });

  it('does not apply to another method or another route', async () => {
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.loginPerIp; attempt += 1) await loginAs(ip);
    expect(edgeLimited(await loginAs(ip))).toBe(true);

    expect((await send('GET', '/api/auth/login', { ip })).status).toBe(200);
    expect((await send('POST', '/api/auth/logout', { ip, body: {} })).status).toBe(200);
    expect((await send('GET', '/api/auth/health/live', { ip })).status).toBe(200);
    // A path that merely ends in "login" is another route.
    expect((await loginAs(ip, freshIdentifier(), { target: '/api/auth/login/extra' })).status).toBe(
      404,
    );
  });

  it('limits one identifier from any number of addresses, whatever its case or whitespace', async () => {
    const identifier = freshIdentifier();
    const spellings = [
      identifier,
      ` ${identifier}`,
      `${identifier.toUpperCase()}\t`,
      `  ${identifier}  `,
    ];
    const replies: Reply[] = [];
    for (let attempt = 0; attempt <= LIMITS.loginPerIdentifier; attempt += 1) {
      replies.push(await loginAs(freshIp(), spellings[attempt % spellings.length]));
    }
    // The account lockout (LOGIN_MAX_ATTEMPTS) answers first, for an unknown identifier as for a
    // real one; the edge's own identifier limit is the outer bound, counted whatever the address.
    expect(replies.slice(0, LIMITS.lockoutAfter).every((reply) => reply.status === 401)).toBe(true);
    expect(
      replies
        .slice(LIMITS.lockoutAfter, LIMITS.loginPerIdentifier)
        .every((reply) => reply.status === 429 && reply.body.includes('AUTH_RATE_LIMITED')),
    ).toBe(true);
    expect(edgeLimited(replies.at(-1)!)).toBe(true);
    // An unknown identifier is limited exactly like a real one: the limit is not an oracle.
    expect(replies.at(-1)!.body).not.toContain('identifier');
  });

  it('does not charge a shared address for an identifier refused on its own count', async () => {
    // One account hammered from inside a school: its own limit refuses it, and the school's other
    // users still have the address's whole allowance less the ten that counted.
    const school = freshIp();
    const hammered = freshIdentifier();
    for (let attempt = 0; attempt < 3 * LIMITS.loginPerIdentifier; attempt += 1) {
      await loginAs(school, hammered);
    }
    const colleagues: number[] = [];
    for (let attempt = 0; attempt < LIMITS.loginPerIp - LIMITS.loginPerIdentifier; attempt += 1) {
      colleagues.push((await loginAs(school)).status);
    }
    expect(colleagues.every((status) => status === 401)).toBe(true);
    expect(edgeLimited(await loginAs(school))).toBe(true);
  });

  it('lets a whole shared address sign in: many people, one address, within the allowance', async () => {
    const school = freshIp();
    const pupils = await Promise.all(Array.from({ length: LIMITS.loginPerIp }, () => person()));
    const statuses: number[] = [];
    for (const pupil of pupils) {
      statuses.push((await loginAs(school, pupil.identifier, { password: PASSWORD })).status);
    }
    expect(statuses.every((status) => status === 200)).toBe(true);
    // Another address is untouched by this one's use.
    const elsewhere = await person();
    expect((await loginAs(freshIp(), elsewhere.identifier, { password: PASSWORD })).status).toBe(
      200,
    );
  }, 120_000);

  it('shares one count between two application instances on one store', async () => {
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.loginPerIp; attempt += 1) {
      expect((await loginAs(ip, freshIdentifier(), { instance: attempt % 2 })).status).toBe(401);
    }
    expect(edgeLimited(await loginAs(ip, freshIdentifier(), { instance: 0 }))).toBe(true);
    expect(edgeLimited(await loginAs(ip, freshIdentifier(), { instance: 1 }))).toBe(true);
  });

  it('keeps one lockout per account whatever the spelling (no respelling around it)', async () => {
    const someone = await person();
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.lockoutAfter; attempt += 1) {
      expect((await loginAs(ip, someone.identifier)).status).toBe(401);
    }
    // Locked. Before the fix, `"  " + identifier` signed in here with the right password (200).
    for (const spelling of [`  ${someone.identifier}`, `${someone.identifier} `]) {
      const reply = await loginAs(ip, spelling, { password: PASSWORD });
      expect(reply.status, JSON.stringify(spelling)).toBe(429);
      expect(JSON.parse(reply.body)).toMatchObject({ code: 'AUTH_RATE_LIMITED' });
    }
  });
});

describe('review round 1', () => {
  it('counts the default organisation once: leaving it out, blank or naming it is one budget', async () => {
    const identifier = freshIdentifier();
    const spellings = [undefined, '', '  ', org.key, ` ${org.key.toUpperCase()} `];
    const outcomes: string[] = [];
    for (let attempt = 0; attempt < LIMITS.loginPerIdentifier + 2; attempt += 1) {
      const organisation = spellings[attempt % spellings.length];
      const response = await send('POST', '/api/auth/login', {
        ip: freshIp(),
        body: {
          identifier,
          password: 'wrong-password',
          ...(organisation === undefined ? {} : { organisation }),
        },
      });
      outcomes.push(edgeLimited(response) ? 'edge' : String(response.status));
    }
    expect(outcomes.slice(0, LIMITS.loginPerIdentifier)).not.toContain('edge');
    expect(outcomes.slice(LIMITS.loginPerIdentifier)).toEqual(['edge', 'edge']);
  });

  it('scopes the identifier limit by organisation: a made-up organisation cannot hold a real sign-in', async () => {
    const someone = await person();
    for (let attempt = 0; attempt <= LIMITS.loginPerIdentifier; attempt += 1) {
      await send('POST', '/api/auth/login', {
        ip: freshIp(),
        body: {
          identifier: someone.identifier,
          password: 'x',
          organisation: `made-up-${String(attempt % 3)}`,
        },
      });
    }
    expect((await loginAs(freshIp(), someone.identifier, { password: PASSWORD })).status).toBe(200);
  });

  it('counts an IPv6 client by its /64: rotating the interface identifier does not escape', async () => {
    const prefix = `2001:db8:${randomInt(1, 0xffff).toString(16)}:${randomInt(1, 0xffff).toString(16)}`;
    for (let attempt = 0; attempt < LIMITS.loginPerIp; attempt += 1) {
      expect((await loginAs(`${prefix}::${(attempt + 1).toString(16)}`)).status).toBe(401);
    }
    expect(edgeLimited(await loginAs(`${prefix}:1:2:3:4`))).toBe(true);
  });

  it('keeps a percent-encoded introspection spelling (a 404) under the browser address limit', async () => {
    const encoded = await send('GET', '/api/auth/%69ntrospect', { ip: freshIp() });
    expect(encoded.status).toBe(404);
    expect(encoded.headers['ratelimit-limit']).toBe('300');
    const routed = await send('GET', '/api/auth/INTROSPECT/', { ip: freshIp() });
    expect(routed.status).toBe(200);
    expect(routed.headers['ratelimit-limit']).toBe('12000');
  });
});

describe('password reset: POST /api/auth/password/forgot and /reset', () => {
  it('shares one per-address limit across request and completion and their spellings', async () => {
    const ip = freshIp();
    const targets = [
      '/api/auth/password/forgot',
      '/api/auth/password/reset',
      '/api/auth/Password/Forgot/',
      '/api/auth/password/reset?token=x',
    ];
    for (let attempt = 0; attempt < LIMITS.passwordResetPerIp; attempt += 1) {
      const reply = await send('POST', targets[attempt % targets.length]!, {
        ip,
        body: { identifier: freshIdentifier(), organisation: org.key, token: 'x', password: 'y' },
      });
      expect(reply.status).not.toBe(429);
    }
    for (const target of targets) {
      expect(edgeLimited(await send('POST', target, { ip, body: {} })), target).toBe(true);
    }
    // Viewing the reset page is not a reset attempt.
    expect((await send('GET', '/api/auth/password/reset?token=x', { ip })).status).not.toBe(429);
  });
});

describe('second factor and reauthentication', () => {
  it('limits one challenge, and leaves another challenge on the same address alone', async () => {
    const ip = freshIp();
    const challenge = { '__Host-mx_mfa': `challenge-${randomUUID()}` };
    for (let attempt = 0; attempt < LIMITS.mfaPerSession; attempt += 1) {
      const reply = await send('POST', '/api/auth/mfa/verify', {
        ip,
        cookies: challenge,
        body: { code: '000000' },
      });
      expect(reply.status).not.toBe(429);
    }
    expect(
      edgeLimited(
        await send('POST', '/api/auth/MFA/Verify/', {
          ip,
          cookies: challenge,
          body: { code: '1' },
        }),
      ),
    ).toBe(true);
    const other = { '__Host-mx_mfa': `challenge-${randomUUID()}` };
    expect(
      (await send('POST', '/api/auth/mfa/verify', { ip, cookies: other, body: { code: '1' } }))
        .status,
    ).not.toBe(429);
  });

  it('limits one session by its sid on the session routes', async () => {
    const someone = await person();
    const token = await accessTokenFor(someone.identifier);
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.mfaPerSession; attempt += 1) {
      const reply = await send('POST', '/api/auth/reauthenticate', {
        ip,
        cookies: { '__Host-mx_session': token },
        body: { password: 'wrong' },
      });
      expect(reply.status).not.toBe(429);
    }
    expect(
      edgeLimited(
        await send('DELETE', '/api/auth/mfa', { ip, cookies: { '__Host-mx_session': token } }),
      ),
    ).toBe(true);
    const another = await accessTokenFor((await person()).identifier);
    expect(
      (
        await send('POST', '/api/auth/reauthenticate', {
          ip,
          cookies: { '__Host-mx_session': another },
          body: { password: 'wrong' },
        })
      ).status,
    ).not.toBe(429);
  });

  it('with no usable identity (none, or a forged cookie per request), the address limit still holds', async () => {
    const ip = freshIp();
    for (let attempt = 0; attempt < LIMITS.mfaPerIp; attempt += 1) {
      await send('POST', '/api/auth/reauthenticate', {
        ip,
        // A fresh unverifiable cookie each time: it must not become a fresh counter each time.
        ...(attempt % 2 === 0
          ? { cookies: { '__Host-mx_session': `forged.${randomUUID()}.x` } }
          : {}),
        body: { password: 'x' },
      });
    }
    expect(edgeLimited(await send('POST', '/api/auth/reauthenticate', { ip, body: {} }))).toBe(
      true,
    );
    // Page views are not counted.
    expect((await send('GET', '/api/auth/mfa', { ip })).status).toBe(200);
  });
});

describe('introspection keeps its own limits', () => {
  it('is not refused because sign-in is exhausted on the same address, and does not count toward it', async () => {
    const someone = await person();
    const token = await accessTokenFor(someone.identifier);
    const ip = freshIp();
    for (let call = 0; call < 2 * LIMITS.loginPerIp; call += 1) {
      const reply = await send('GET', '/api/auth/introspect', {
        ip,
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(reply.status).toBe(200);
    }
    // Introspection did not spend the sign-in allowance.
    for (let attempt = 0; attempt < LIMITS.loginPerIp; attempt += 1) {
      expect((await loginAs(ip)).status).toBe(401);
    }
    expect(edgeLimited(await loginAs(ip))).toBe(true);
    const after = await send('GET', '/api/auth/introspect', {
      ip,
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(after.status).toBe(200);
    expect(JSON.parse(after.body)).toMatchObject({ active: true });
  });
});

describe('when the counter store cannot be read', () => {
  it('refuses credential routes with 503 and leaves other routes working', async () => {
    const original = security.authEdgeLimiter;
    const broken = new Proxy({} as CachePort, {
      get: () => () => Promise.reject(new Error('ECONNRESET')),
    });
    Reflect.set(
      security,
      'authEdgeLimiter',
      new edge.AuthEdgeLimiter(broken, {
        loginPerIp: LIMITS.loginPerIp,
        loginPerIdentifier: LIMITS.loginPerIdentifier,
        passwordResetPerIp: LIMITS.passwordResetPerIp,
        mfaPerIp: LIMITS.mfaPerIp,
        mfaPerSession: LIMITS.mfaPerSession,
      }),
    );
    try {
      const ip = freshIp();
      const login = await loginAs(ip);
      expect(login.status).toBe(503);
      expect(login.headers['retry-after']).toBe('5');
      expect(JSON.parse(login.body)).toEqual({ code: 'AUTH_UNAVAILABLE' });
      expect((await send('POST', '/api/auth/password/forgot', { ip, body: {} })).status).toBe(503);
      expect((await send('POST', '/api/auth/mfa/verify', { ip, body: {} })).status).toBe(503);
      expect((await send('GET', '/api/auth/login', { ip })).status).toBe(200);
    } finally {
      Reflect.set(security, 'authEdgeLimiter', original);
    }
  });
});

describe('when the counter store hangs', () => {
  it('turns a hung command into a refusal within the command timeout, not a held request', async () => {
    const { hostname, port } = new URL(REDIS_URL);
    // Pause every client of the server for 10 s: connections stay open, commands get no answer.
    // Each command fails after 2 s (`REDIS_COMMAND_TIMEOUT_MS`); the request makes two before it is
    // refused (the general address limit, which admits on failure, then the sign-in limit, which
    // does not), so the refusal comes in about 4 s, well before the pause ends.
    await new Promise<void>((resolve, reject) => {
      const socket = connect(Number(port || 6379), hostname, () => {
        socket.write('*4\r\n$6\r\nCLIENT\r\n$5\r\nPAUSE\r\n$5\r\n10000\r\n$3\r\nALL\r\n');
      });
      socket.once('data', () => {
        socket.destroy();
        resolve();
      });
      socket.once('error', reject);
    });
    const started = Date.now();
    const reply = await loginAs(freshIp());
    const elapsed = Date.now() - started;

    expect(reply.status).toBe(503);
    expect(elapsed).toBeLessThan(6_500);
    await new Promise((resolve) => setTimeout(resolve, 10_300 - elapsed));
  }, 20_000);
});

describe('the edge limiter on a real Redis, under a controlled clock', () => {
  const policy = {
    loginPerIp: 30,
    loginPerIdentifier: 10,
    passwordResetPerIp: 10,
    mfaPerIp: 30,
    mfaPerSession: 5,
  };

  it('admits again once the window has passed, and not before', async () => {
    const handle = await openCache(REDIS_URL);
    try {
      const clock = new FixedClock(Date.UTC(2030, 0, 1, 8, 0, 0));
      const limiter = new edge.AuthEdgeLimiter(handle.cache, policy, clock);
      const request = { method: 'POST', route: '/api/auth/login', ipAddress: freshIp() };
      for (let attempt = 0; attempt < policy.loginPerIp; attempt += 1) {
        expect((await limiter.check(request)).kind).toBe('allowed');
      }
      const refused = await limiter.check(request);
      expect(refused).toMatchObject({ kind: 'limited', rule: 'login-per-ip' });

      clock.advance(4 * 60 * 1_000);
      expect((await limiter.check(request)).kind).toBe('limited');
      // Two windows later (5 min each) the history has aged out: the full allowance is back.
      clock.advance(2 * 5 * 60 * 1_000);
      for (let attempt = 0; attempt < policy.loginPerIp; attempt += 1) {
        expect((await limiter.check(request)).kind).toBe('allowed');
      }
    } finally {
      await handle.close();
    }
  });

  it('admits exactly the allowance from concurrent requests on two connections', async () => {
    const one = await openCache(REDIS_URL);
    const two = await openCache(REDIS_URL);
    try {
      const limiters = [
        new edge.AuthEdgeLimiter(one.cache, policy),
        new edge.AuthEdgeLimiter(two.cache, policy),
      ];
      const request = { method: 'POST', route: '/api/auth/login', ipAddress: freshIp() };
      const decisions = await Promise.all(
        Array.from({ length: 100 }, (_, index) => limiters[index % 2]!.check(request)),
      );
      expect(decisions.filter((decision) => decision.kind === 'allowed')).toHaveLength(
        policy.loginPerIp,
      );
    } finally {
      await one.close();
      await two.close();
    }
  });
});

describe('route identity', () => {
  it.each([
    ['/api/auth/login', '/api/auth/login'],
    ['/API/AUTH/LOGIN/', '/api/auth/login'],
    ['//api//auth//login//', '/api/auth/login'],
    ['/api/auth/%6Cogin?x=1#y', '/api/auth/login'],
    ['https://identity.munaxa.com:443/api/auth/login', '/api/auth/login'],
    ['/api/auth/a/../login', '/api/auth/login'],
    ['/api/auth/introspect', '/api/auth/introspect'],
    ['/', '/'],
  ])('%s is %s', (target, route) => {
    expect(edge.canonicalRoute(target)).toBe(route);
  });

  it('matches only the intended method and route for each policy', () => {
    expect(edge.isLogin('POST', '/api/auth/login')).toBe(true);
    expect(edge.isLogin('GET', '/api/auth/login')).toBe(false);
    expect(edge.isLogin('POST', '/api/auth/introspect')).toBe(false);
    expect(edge.isPasswordReset('POST', '/api/auth/password/change')).toBe(false);
    expect(edge.isMfa('GET', '/api/auth/mfa')).toBe(false);
    expect(edge.isMfa('DELETE', '/api/auth/mfa')).toBe(true);
    expect(edge.isMfa('POST', '/api/auth/introspect')).toBe(false);
  });

  it('never carries an identifier or a credential in a counter key', () => {
    expect(edge.identifierSubject(' Someone@Example.com ', 'Acme ')).toBe(
      edge.identifierSubject('someone@example.com', 'acme'),
    );
    expect(edge.identifierSubject('someone@example.com', 'acme')).not.toBe(
      edge.identifierSubject('someone@example.com', 'globex'),
    );
    expect(edge.addressSubject('2001:DB8:1:2::9')).toBe('2001:db8:1:2::/64');
    expect(edge.addressSubject('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(edge.identifierSubject('someone@example.com')).not.toContain('someone');
    expect(edge.identifierSubject('')).toBeUndefined();
    expect(edge.identifierSubject(42)).toBeUndefined();
    expect(edge.credentialSubject('session', 'sid-1')).not.toContain('sid-1');
  });
});
