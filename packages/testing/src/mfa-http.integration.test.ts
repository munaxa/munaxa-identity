import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

import { totpCode } from '@munaxa/auth';
import { defaultPasswordHasher } from '@munaxa/crypto';
import type { TenantId, UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment } from '../../config/src/index.js';
import { AccountSessionsController } from '../../../apps/api/src/account/account-sessions.controller.js';
import { AccountSessionsService } from '../../../apps/api/src/account/account-sessions.service.js';
import { AuthController } from '../../../apps/api/src/auth/auth.controller.js';
import { AuthService } from '../../../apps/api/src/auth/auth.service.js';
import { MfaController } from '../../../apps/api/src/mfa/mfa.controller.js';
import { MfaFlowService } from '../../../apps/api/src/mfa/mfa-flow.service.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * The MFA routes as a browser meets them: the cookies they set, the cookies they read, the bodies
 * and headers they answer with, and what reaches the log. Controllers are driven directly with a
 * recording response, against the real stack (PostgreSQL as `identity_app`, Redis, ES256).
 */

const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const PASSWORD = `Correct-Horse-${randomUUID()}`;
const UA = 'Mozilla/5.0 (Macintosh) Safari/605.1.15';
const org = { key: `mfa-http-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };

const environment = loadEnvironment({
  NODE_ENV: 'test',
  IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
  DATABASE_URL: APPLICATION_URL,
  IDENTITY_BASE_URL: 'http://localhost:4001',
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-test-2026-11',
  IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
  CSRF_TRUSTED_ORIGINS: 'http://localhost:3001',
  REDIS_URL: process.env.TEST_REDIS_URL ?? 'redis://localhost:6379',
  MFA_ENCRYPTION_KEYS: `k=${randomBytes(32).toString('base64url')}`,
  MFA_ENCRYPTION_PRIMARY_KID: 'k',
});

/** Everything the logger was asked to write, as text. */
const logged: string[] = [];
const logger = {
  error: (...args: unknown[]) => logged.push(JSON.stringify(args)),
  warn: (...args: unknown[]) => logged.push(JSON.stringify(args)),
  info: (...args: unknown[]) => logged.push(JSON.stringify(args)),
  debug: (...args: unknown[]) => logged.push(JSON.stringify(args)),
} as never;

interface Recorded {
  status: number;
  headers: Record<string, unknown>;
  body: unknown;
  redirect?: string;
  cookies: string[];
}

const response = () => {
  const recorded: Recorded = { status: 200, headers: {}, body: undefined, cookies: [] };
  const res = {
    headersSent: false,
    status(code: number) {
      recorded.status = code;
      return res;
    },
    setHeader(name: string, value: unknown) {
      recorded.headers[name.toLowerCase()] = value;
      if (name.toLowerCase() === 'set-cookie') recorded.cookies = value as string[];
      return res;
    },
    getHeader(name: string) {
      return recorded.headers[name.toLowerCase()];
    },
    json(body: unknown) {
      recorded.body = body;
      return res;
    },
    type() {
      return res;
    },
    send(body: unknown) {
      recorded.body = body;
      return res;
    },
    redirect(status: number, to: string) {
      recorded.status = status;
      recorded.redirect = to;
    },
  };
  return { res: res as never, recorded };
};

const request = (cookies: Record<string, string> = {}, body: Record<string, unknown> = {}) =>
  ({
    cookies,
    body,
    headers: { 'user-agent': UA, 'content-type': 'application/json' },
    ip: '198.51.100.7',
  }) as never;

/** The value of `name` from a recorded Set-Cookie list. */
const cookieValue = (recorded: Recorded, name: string): string | undefined => {
  const line = recorded.cookies.find((c) => c.startsWith(`${name}=`));
  return line === undefined
    ? undefined
    : decodeURIComponent(line.split(';')[0]!.slice(name.length + 1));
};

let prisma: PrismaService;
let security: SecurityStack;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;
let authController: AuthController;
let mfaController: MfaController;
let sessionsController: AccountSessionsController;
let email: string;
let userId: UserId;

const steadyNow = async (): Promise<number> => {
  for (;;) {
    const into = (Date.now() / 1_000) % 30;
    if (into > 1 && into < 27) return Date.now();
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
};

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
  userId = randomUUID() as UserId;
  email = `${randomUUID().slice(0, 8)}@mfa-http.test`;
  await owner.query('begin');
  await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', org.id]);
  await owner.query(
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, password_hash, status, token_version,
        mfa_enrolled, must_change_password, identity_source, created_at, updated_at, version)
     values ($1, $2, $3, $3, $4, 'active', 1, false, false, 'local', now(), now(), 1)`,
    [userId, org.id, email, await defaultPasswordHasher.hash(PASSWORD)],
  );
  await owner.query('commit');

  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();
  security = await buildSecurityStack(environment, prisma);
  const auth = new AuthService(security, environment, prisma);
  authController = new AuthController(auth, logger);
  mfaController = new MfaController(new MfaFlowService(security, environment, auth), auth, logger);
  sessionsController = new AccountSessionsController(
    new AccountSessionsService(security, environment),
    logger,
  );
});

afterAll(async () => {
  await security.close();
  await prisma.$disconnect();
  owner.release();
  await ownerPool.end();
});

describe('the MFA routes over HTTP', () => {
  let secret = '';
  let recoveryCodes: string[] = [];

  it('enrolls from a signed-in session, returning the secret and the codes once, no-store', async () => {
    const signIn = response();
    await authController.login(
      { identifier: email, password: PASSWORD, organisation: org.key },
      request(),
      signIn.res,
    );
    const session = cookieValue(signIn.recorded, '__Host-mx_session')!;
    expect(session).toBeDefined();

    const start = response();
    await mfaController.startEnrollment({}, request({ '__Host-mx_session': session }), start.res);
    expect(start.recorded.status).toBe(200);
    expect(start.recorded.headers['cache-control']).toBe('no-store');
    expect(start.recorded.headers['referrer-policy']).toBe('no-referrer');
    secret = (start.recorded.body as { secret: string }).secret;
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);

    const confirm = response();
    await mfaController.confirmEnrollment(
      { code: totpCode(secret, await steadyNow()) },
      request({ '__Host-mx_session': session }),
      confirm.res,
    );
    expect(confirm.recorded.status).toBe(200);
    recoveryCodes = (confirm.recorded.body as { recoveryCodes: string[] }).recoveryCodes;
    expect(recoveryCodes).toHaveLength(10);

    // No route returns the stored secret: status says only what it may.
    const status = response();
    await mfaController.status(request({ '__Host-mx_session': session }), status.res);
    expect(Object.keys(status.recorded.body as object).sort()).toEqual(
      ['available', 'enrolled', 'reauthenticated', 'recoveryCodesRemaining', 'required'].sort(),
    );
    expect(JSON.stringify(status.recorded.body)).not.toContain(secret);
  });

  it('answers sign-in with a strict, short-lived challenge cookie and no session cookie', async () => {
    const signIn = response();
    await authController.login(
      { identifier: email, password: PASSWORD, organisation: org.key },
      request(),
      signIn.res,
    );

    expect(signIn.recorded.status).toBe(401);
    expect(signIn.recorded.body).toMatchObject({ code: 'AUTH_MFA_REQUIRED' });
    expect(cookieValue(signIn.recorded, '__Host-mx_session')).toBeUndefined();
    expect(cookieValue(signIn.recorded, '__Secure-mx_refresh')).toBeUndefined();
    const line = signIn.recorded.cookies.find((c) => c.startsWith('__Host-mx_mfa='))!;
    expect(line).toMatch(/; Path=\//);
    expect(line).toMatch(/; Max-Age=300/);
    expect(line).toMatch(/; Secure/);
    expect(line).toMatch(/; HttpOnly/);
    expect(line).toMatch(/; SameSite=Strict/);
    expect(line).not.toMatch(/Domain=/i);
  });

  it('does not let the challenge cookie stand in for a session anywhere', async () => {
    const signIn = response();
    await authController.login(
      { identifier: email, password: PASSWORD, organisation: org.key },
      request(),
      signIn.res,
    );
    const challenge = cookieValue(signIn.recorded, '__Host-mx_mfa')!;

    const jars: Record<string, string>[] = [
      { '__Host-mx_mfa': challenge },
      { '__Host-mx_session': challenge },
    ];
    for (const jar of jars) {
      const list = response();
      await sessionsController.list(request(jar), list.res);
      expect(list.recorded.status).toBe(401);
      const status = response();
      await mfaController.status(request(jar), status.res);
      expect(status.recorded.status).toBe(401);
      const regenerate = response();
      await mfaController.regenerate(request(jar), regenerate.res);
      expect(regenerate.recorded.status).toBe(401);
      expect(await authController.session(request(jar))).toEqual({ signedIn: false });
    }
    // A `verify` challenge does not open the enrollment routes either.
    const start = response();
    await mfaController.startEnrollment({}, request({ '__Host-mx_mfa': challenge }), start.res);
    expect(start.recorded.status).toBe(401);
  });

  it('redeems the challenge into session cookies and clears it', async () => {
    const signIn = response();
    await authController.login(
      { identifier: email, password: PASSWORD, organisation: org.key },
      request(),
      signIn.res,
    );
    const challenge = cookieValue(signIn.recorded, '__Host-mx_mfa')!;

    const wrong = response();
    await mfaController.verify(
      { code: '000000' },
      request({ '__Host-mx_mfa': challenge }),
      wrong.res,
    );
    expect(wrong.recorded.status).toBe(401);
    expect(wrong.recorded.body).toEqual({ code: 'AUTH_MFA_INVALID' });

    const right = response();
    await mfaController.verify(
      { code: totpCode(secret, (await steadyNow()) + 30_000) },
      request({ '__Host-mx_mfa': challenge }),
      right.res,
    );
    expect(right.recorded.status).toBe(200);
    expect(cookieValue(right.recorded, '__Host-mx_session')).toBeDefined();
    expect(right.recorded.cookies.find((c) => c.startsWith('__Host-mx_mfa='))).toMatch(
      /Max-Age=0|Expires=Thu, 01 Jan 1970/,
    );
    expect(JSON.stringify(right.recorded.body)).toBe('{"ok":true}');
  });

  it('never writes a code, a secret, a recovery code or a challenge to the log', async () => {
    const signIn = response();
    await authController.login(
      { identifier: email, password: PASSWORD, organisation: org.key },
      request(),
      signIn.res,
    );
    const challenge = cookieValue(signIn.recorded, '__Host-mx_mfa')!;
    const verify = response();
    await mfaController.verify(
      { recoveryCode: recoveryCodes[0] },
      request({ '__Host-mx_mfa': challenge }),
      verify.res,
    );
    expect(verify.recorded.status).toBe(200);

    const text = logged.join('\n');
    expect(text).not.toContain(secret);
    expect(text).not.toContain(challenge);
    for (const code of recoveryCodes) expect(text).not.toContain(code);
  });
});
