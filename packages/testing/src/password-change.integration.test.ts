import { generateKeyPairSync, randomUUID } from 'node:crypto';

import { defaultPasswordHasher } from '@munaxa/crypto';
import type { CachePort } from '@munaxa/interfaces';
import { toCorrelationId, type SessionId, type TenantId, type UserId } from '@munaxa/types';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';

import { APPLICATION_URL, OWNER_URL, createOrganisation, truncateAll } from './index.js';
import { loadEnvironment } from '../../config/src/index.js';
import {
  PasswordChange,
  createChangeLimiter,
  type PasswordChangeOptions,
} from '../../../apps/api/src/password/password-change.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { openCache } from '../../../apps/api/src/platform/cache.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * Changing a password while signed in, against a real PostgreSQL as the application role.
 *
 * What matters: the current password is required, every session and refresh lineage ends
 * (including the caller's), outstanding reset links die, and a failure part-way changes nothing.
 */

const KEY = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
}).privateKey;

const ORG = 'change-org';
const OLD = 'the-old-password-is-long-enough';
const NEW = 'a-brand-new-password-of-length';
const correlationId = toCorrelationId('corr-change');

const environment = loadEnvironment({
  NODE_ENV: 'test',
  IDENTITY_SIGNING_SECRET: 'a-test-signing-secret-that-is-at-least-32-characters',
  DATABASE_URL: APPLICATION_URL,
  IDENTITY_BASE_URL: 'https://id.example.test',
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-test-2026-11',
  IDENTITY_SIGNING_PRIVATE_KEY: KEY,
  CSRF_TRUSTED_ORIGINS: 'https://id.example.test',
  IDENTITY_DEFAULT_ORGANISATION: ORG,
  REDIS_URL: '',
});

let prisma: PrismaService;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;
let stack: SecurityStack;
let tenant: TenantId;

const asOwner = async <T>(sql: string, params: unknown[]): Promise<T[]> => {
  await owner.query('begin');
  try {
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenant]);
    const result = await owner.query(sql, params);
    await owner.query('commit');
    return result.rows as T[];
  } catch (error) {
    await owner.query('rollback');
    throw error;
  }
};

const account = async (): Promise<UserId> => {
  const id = randomUUID() as UserId;
  const hash = await defaultPasswordHasher.hash(OLD);
  await asOwner(
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, password_hash, status, token_version,
        mfa_enrolled, must_change_password, identity_source, created_at, updated_at, version)
     values ($1, $2, $3, $3, $4, 'active', 1, false, false, 'local', now(), now(), 1)`,
    [id, tenant, `${id}@example.test`, hash],
  );
  return id;
};

const signIn = async (userId: UserId) => {
  const session = await stack.sessions.create({
    tenantId: tenant,
    userId,
    authMethods: ['password'],
    mfaSatisfied: false,
    tokenVersion: 1,
  });
  const refresh = await stack.refreshTokens.issue({
    tenantId: tenant,
    userId,
    tokenVersion: 1,
    sessionId: session.id,
  });
  const access = stack.tokens.issueAccessToken({
    subject: userId,
    tenantId: tenant,
    tokenVersion: 1,
    permissions: [],
    sessionId: session.id,
  });
  return { sessionId: session.id as SessionId, refresh: refresh.token, access: access.token };
};

const build = async (overrides: Partial<PasswordChangeOptions> & { cache?: CachePort } = {}) =>
  new PasswordChange({
    security: stack,
    prisma,
    login: stack.login,
    revocation: stack.revocation,
    revokeResetLinks: (tenantId, userId) => stack.recovery.revokeOutstanding(tenantId, userId),
    limiter: createChangeLimiter(overrides.cache ?? (await openCache('')).cache),
    audit: stack.audit,
    ...overrides,
  });

const row = async (userId: UserId) =>
  (
    await asOwner<{ password_hash: string; token_version: number }>(
      'select password_hash, token_version from identity_account where id = $1',
      [userId],
    )
  )[0]!;

const liveResetLink = async (userId: UserId): Promise<void> => {
  await asOwner(
    `insert into identity_reset_token
       (id, tenant_id, account_id, token_hash, issued_at, expires_at, password_hash_fingerprint)
     values ($1, $2, $3, $4, now(), now() + interval '30 minutes', 'fp')`,
    [`rst_${randomUUID()}`, tenant, userId, randomUUID()],
  );
};

const liveResetLinks = async (userId: UserId) =>
  (
    await asOwner<{ n: string }>(
      'select count(*)::text as n from identity_reset_token where account_id = $1 and revoked_at is null and consumed_at is null',
      [userId],
    )
  )[0]!.n;

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await truncateAll(owner);
  tenant = (await createOrganisation(owner, ORG)) as TenantId;
  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();
  stack = await buildSecurityStack(environment, prisma);
});

afterAll(async () => {
  await stack.close();
  await prisma.$disconnect();
  await truncateAll(owner);
  owner.release();
  await ownerPool.end();
});

describe('changing a password while signed in', () => {
  it('changes it and ends every session, refresh lineage and reset link, the current one included', async () => {
    const userId = await account();
    const current = await signIn(userId);
    const other = await signIn(userId);
    await liveResetLink(userId);
    const change = await build();

    const outcome = await change.change({
      accessToken: current.access,
      currentPassword: OLD,
      newPassword: NEW,
      correlationId,
    });
    expect(outcome).toEqual({ kind: 'changed', revokedSessions: 2 });

    const after = await row(userId);
    expect(await defaultPasswordHasher.verify(NEW, after.password_hash)).toBe(true);
    expect(after.token_version).toBe(2);
    for (const signedIn of [current, other]) {
      expect((await stack.sessions.validate(tenant, signedIn.sessionId)).valid).toBe(false);
      await expect(stack.refreshTokens.rotate(tenant, signedIn.refresh)).rejects.toThrow();
    }
    expect(await liveResetLinks(userId)).toBe('0');
    // The old access token no longer authenticates on Identity's routes.
    expect(
      await change.change({
        accessToken: current.access,
        currentPassword: NEW,
        newPassword: 'yet-another-long-password',
        correlationId,
      }),
    ).toEqual({ kind: 'unauthenticated' });
  });

  it('requires the current password and changes nothing without it', async () => {
    const userId = await account();
    const signedIn = await signIn(userId);
    const before = await row(userId);
    const change = await build();

    expect(
      await change.change({
        accessToken: signedIn.access,
        currentPassword: 'not-the-password-at-all',
        newPassword: NEW,
        correlationId,
      }),
    ).toEqual({ kind: 'invalid-current-password' });
    expect(await row(userId)).toEqual(before);
    expect((await stack.sessions.validate(tenant, signedIn.sessionId)).valid).toBe(true);
  });

  it('refuses without a valid session', async () => {
    const change = await build();
    for (const accessToken of [undefined, '', 'not.a.token']) {
      expect(
        await change.change({ accessToken, currentPassword: OLD, newPassword: NEW, correlationId }),
      ).toEqual({ kind: 'unauthenticated' });
    }
  });

  it('enforces the password policy and the breach check', async () => {
    const userId = await account();
    const signedIn = await signIn(userId);
    const change = await build();
    const short = await change.change({
      accessToken: signedIn.access,
      currentPassword: OLD,
      newPassword: 'short',
      correlationId,
    });
    expect(short).toMatchObject({ kind: 'password-rejected', code: 'AUTH_PASSWORD_POLICY' });
    const breached = await change.change({
      accessToken: signedIn.access,
      currentPassword: OLD,
      newPassword: 'correct horse battery staple',
      correlationId,
    });
    expect(breached).toMatchObject({ kind: 'password-rejected', code: 'AUTH_PASSWORD_BREACHED' });
    expect((await stack.sessions.validate(tenant, signedIn.sessionId)).valid).toBe(true);
  });

  it('limits guesses at the current password per account, and fails closed without the cache', async () => {
    const userId = await account();
    const signedIn = await signIn(userId);
    const change = await build();
    const outcomes = [];
    for (let i = 0; i < 6; i += 1) {
      outcomes.push(
        await change.change({
          accessToken: signedIn.access,
          currentPassword: `wrong-guess-${String(i)}`,
          newPassword: NEW,
          correlationId,
        }),
      );
    }
    expect(outcomes.slice(0, 5).every((o) => o.kind === 'invalid-current-password')).toBe(true);
    expect(outcomes[5]?.kind).toBe('rate-limited');

    const broken = new Proxy({} as CachePort, {
      get: () => () => Promise.reject(new Error('ECONNREFUSED')),
    });
    const offline = await build({ cache: broken });
    expect(
      await offline.change({
        accessToken: signedIn.access,
        currentPassword: OLD,
        newPassword: NEW,
        correlationId,
      }),
    ).toEqual({ kind: 'unavailable' });
  });

  it('rolls everything back when the revocation fails part-way', async () => {
    const userId = await account();
    const signedIn = await signIn(userId);
    await liveResetLink(userId);
    const before = await row(userId);
    const change = await build({
      revocation: {
        revokeAllForUser: async (tenantId, user, reason) => {
          await stack.revocation.revokeAllForUser(tenantId, user, reason);
          throw new Error('injected failure');
        },
      },
    });

    expect(
      await change.change({
        accessToken: signedIn.access,
        currentPassword: OLD,
        newPassword: NEW,
        correlationId,
      }),
    ).toEqual({ kind: 'unavailable' });
    expect(await row(userId)).toEqual(before);
    expect(await liveResetLinks(userId)).toBe('1');
    expect((await stack.sessions.validate(tenant, signedIn.sessionId)).valid).toBe(true);
  });
});
