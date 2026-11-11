import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { PasswordPolicyService, StaticBreachRegistry } from '@munaxa/auth';
import { defaultPasswordHasher } from '@munaxa/crypto';
import type { CachePort, NotificationMessage } from '@munaxa/interfaces';
import { toCorrelationId, type SessionId, type TenantId, type UserId } from '@munaxa/types';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';

import { APPLICATION_URL, OWNER_URL, createOrganisation, truncateAll } from './index.js';
import { loadEnvironment } from '../../config/src/index.js';
import {
  MemoryEmailTransport,
  OutboxEmailTransport,
} from '../../../apps/api/src/delivery/email.js';
import {
  PasswordRecovery,
  createResetLimiter,
  type PasswordRecoveryOptions,
} from '../../../apps/api/src/password/password-recovery.js';
import { PasswordRecoveryController } from '../../../apps/api/src/password/password-recovery.controller.js';
import { PrismaResetTokenStore } from '../../../apps/api/src/persistence/reset-token-store.adapter.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { openCache } from '../../../apps/api/src/platform/cache.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * Password recovery, end to end against a real PostgreSQL as the application role.
 *
 * The properties under test are the ones that cannot be read off the code: that completion is one
 * transaction even though Platform performs it as five port calls (proved by failing each step,
 * and by killing the database connection half-way), that a mailed link survives being fetched,
 * that exactly one of many concurrent uses wins, and that the request answer is the same whether
 * or not the account exists.
 */

const KEY = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
}).privateKey;

const SUPERUSER_URL =
  process.env.TEST_SUPERUSER_URL ?? 'postgresql://identity:identity@localhost:5432/identity_test';

const RESET_URL = 'https://id.example.test/api/auth/password/reset';
const ORG = 'recovery-org';
const OTHER_ORG = 'recovery-other';
const OLD_PASSWORD = 'the-old-password-is-long-enough';
const NEW_PASSWORD = 'a-brand-new-password-of-length';

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
let otherTenant: TenantId;

const correlationId = toCorrelationId('corr-recovery');

interface Built {
  readonly recovery: PasswordRecovery;
  readonly transport: MemoryEmailTransport;
  readonly logs: { level: string; event: string; fields: Record<string, unknown> }[];
}

const build = async (
  overrides: Partial<PasswordRecoveryOptions> & { cache?: CachePort } = {},
): Promise<Built> => {
  const transport = new MemoryEmailTransport();
  const logs: Built['logs'] = [];
  const cache = overrides.cache ?? (await openCache('')).cache;
  const recovery = new PasswordRecovery({
    prisma,
    store: new PrismaResetTokenStore(prisma),
    directory: stack.directory,
    hasher: defaultPasswordHasher,
    policy: new PasswordPolicyService({
      policy: { minLength: 12, historyCount: 0, checkBreaches: true },
      breachRegistry: new StaticBreachRegistry(),
    }),
    tenants: stack.tenants,
    revokeCredentials: async (tenantId, userId) => {
      await stack.revocation.revokeAllForUser(tenantId, userId, 'password-reset');
    },
    limiter: createResetLimiter(cache),
    audit: stack.audit,
    transport,
    enabled: true,
    resetUrl: RESET_URL,
    ttl: 30 * 60 * 1_000,
    from: 'no-reply@example.test',
    pepper: environment.MUNAXA_SIGNING_SECRET,
    retryDelayMs: 1,
    log: (level, event, fields) => logs.push({ level, event, fields }),
    ...overrides,
  });
  return { recovery, transport, logs };
};

const createAccount = async (
  tenantId: TenantId,
  identifier: string,
  status = 'active',
): Promise<UserId> => {
  const id = randomUUID() as UserId;
  const hash = await defaultPasswordHasher.hash(OLD_PASSWORD);
  await owner.query('begin');
  await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
  await owner.query(
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, password_hash, status, token_version,
        mfa_enrolled, must_change_password, identity_source, created_at, updated_at, version)
     values ($1, $2, $3, $4, $5, $6, 1, false, false, 'local', now(), now(), 1)`,
    [id, tenantId, identifier, identifier.toLowerCase(), hash, status],
  );
  await owner.query('commit');
  return id;
};

const asOwner = async <T>(tenantId: string, sql: string, params: unknown[]): Promise<T[]> => {
  await owner.query('begin');
  try {
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
    const result = await owner.query(sql, params);
    await owner.query('commit');
    return result.rows as T[];
  } catch (error) {
    await owner.query('rollback');
    throw error;
  }
};

const accountRow = async (userId: UserId, tenantId: TenantId = tenant) =>
  (
    await asOwner<{ password_hash: string; token_version: number }>(
      tenantId,
      'select password_hash, token_version from identity_account where id = $1',
      [userId],
    )
  )[0]!;

const resetRows = (userId: UserId) =>
  asOwner<{ consumed_at: Date | null; revoked_at: Date | null; token_hash: string }>(
    tenant,
    'select consumed_at, revoked_at, token_hash from identity_reset_token where account_id = $1 order by issued_at',
    [userId],
  );

/** The token a user would find in the link in their mailbox. */
const tokenFrom = (message: NotificationMessage | undefined): { org: string; token: string } => {
  const match = /https:\/\/\S+/.exec(message?.body ?? '');
  if (match === null) throw new Error('no link in the message');
  const url = new URL(match[0]);
  return { org: url.searchParams.get('org') ?? '', token: url.searchParams.get('token') ?? '' };
};

const requestLink = async (built: Built, identifier: string, ip = '203.0.113.1') => {
  const outcome = await built.recovery.request({
    organisation: ORG,
    identifier,
    ipAddress: ip,
    correlationId,
  });
  await built.recovery.idle();
  return outcome;
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
  return { sessionId: session.id as SessionId, refresh: refresh.token };
};

let counter = 0;
const freshAccount = async (status = 'active') => {
  counter += 1;
  const identifier = `person${String(counter)}@example.test`;
  const userId = await createAccount(tenant, identifier, status);
  return { identifier, userId };
};

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 2 });
  owner = await ownerPool.connect();
  await truncateAll(owner);
  tenant = (await createOrganisation(owner, ORG)) as TenantId;
  otherTenant = (await createOrganisation(owner, OTHER_ORG)) as TenantId;

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

describe('the request', () => {
  it('answers identically for a known, an unknown and a disabled account and an unknown organisation', async () => {
    const built = await build();
    const known = await freshAccount();
    const disabled = await freshAccount('disabled');

    const outcomes = [
      await requestLink(built, known.identifier, '203.0.113.10'),
      await requestLink(built, 'nobody@example.test', '203.0.113.11'),
      await requestLink(built, disabled.identifier, '203.0.113.12'),
      await built.recovery.request({
        organisation: 'no-such-org',
        identifier: known.identifier,
        ipAddress: '203.0.113.13',
        correlationId,
      }),
    ];
    await built.recovery.idle();

    expect(outcomes).toEqual([
      { kind: 'accepted' },
      { kind: 'accepted' },
      { kind: 'accepted' },
      { kind: 'accepted' },
    ]);
    // Only the real, active account received anything.
    expect(built.transport.sent).toHaveLength(1);
    expect(built.transport.sent[0]?.recipient.email).toBe(known.identifier);
    expect(await resetRows(disabled.userId)).toHaveLength(0);
  });

  it('answers before any account is looked up, so latency cannot depend on the account', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const built = await build({
      tenants: {
        idForKey: async (key) => {
          await gate;
          return stack.tenants.idForKey(key);
        },
      },
    });
    const known = await freshAccount();

    // The lookup is blocked; the request must still have been answered.
    const outcome = await built.recovery.request({
      organisation: ORG,
      identifier: known.identifier,
      ipAddress: '203.0.113.20',
      correlationId,
    });
    expect(outcome).toEqual({ kind: 'accepted' });
    expect(built.transport.sent).toHaveLength(0);

    release();
    await built.recovery.idle();
    expect(built.transport.sent).toHaveLength(1);
  });

  it('builds the link from configuration only, never from the request', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.21');

    const body = built.transport.sent[0]?.body ?? '';
    expect(body).toContain(`${RESET_URL}?org=${ORG}&token=`);
    expect(body).not.toContain('evil');
  });

  it('keeps only the newest of several outstanding links usable', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.22');
    await requestLink(built, known.identifier, '203.0.113.23');

    const first = tokenFrom(built.transport.sent[0]);
    const second = tokenFrom(built.transport.sent[1]);
    expect(await built.recovery.inspect({ organisation: ORG, token: first.token })).toBe('invalid');
    expect(await built.recovery.inspect({ organisation: ORG, token: second.token })).toBe('valid');
  });

  it('stores only a hash of the token', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.24');
    const { token } = tokenFrom(built.transport.sent[0]);
    const rows = await resetRows(known.userId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.token_hash).not.toContain(token);
  });

  it('revokes the token when delivery fails, so no live credential is left behind', async () => {
    const built = await build();
    const known = await freshAccount();
    built.transport.failures = 10;

    expect(await requestLink(built, known.identifier, '203.0.113.25')).toEqual({
      kind: 'accepted',
    });

    const rows = await resetRows(known.userId);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.revoked_at).not.toBeNull();
    expect(built.logs.map((entry) => entry.event)).toContain('auth.password_reset.request_failed');
  });

  it('creates nothing and says so when no transport is configured', async () => {
    const built = await build({ transport: undefined });
    const known = await freshAccount();
    expect(built.recovery.availability).toBe('unavailable');
    expect(await requestLink(built, known.identifier)).toEqual({ kind: 'unavailable' });
    expect(await resetRows(known.userId)).toHaveLength(0);
  });

  it('is off entirely when disabled', async () => {
    const built = await build({ enabled: false });
    expect(built.recovery.availability).toBe('disabled');
    expect(await requestLink(built, 'x@example.test')).toEqual({ kind: 'disabled' });
  });

  it('limits requests per identifier and per address, whether or not the account exists', async () => {
    const built = await build();
    const outcomes = [];
    for (let i = 0; i < 4; i += 1) {
      outcomes.push(await requestLink(built, 'ghost@example.test', `198.51.100.${String(i)}`));
    }
    expect(outcomes.slice(0, 3)).toEqual([
      { kind: 'accepted' },
      { kind: 'accepted' },
      { kind: 'accepted' },
    ]);
    expect(outcomes[3]?.kind).toBe('rate-limited');

    const perIp = [];
    for (let i = 0; i < 6; i += 1) {
      perIp.push(await requestLink(built, `ip${String(i)}@example.test`, '198.51.100.200'));
    }
    expect(perIp.slice(0, 5).every((outcome) => outcome.kind === 'accepted')).toBe(true);
    expect(perIp[5]?.kind).toBe('rate-limited');
  });

  it('fails closed when the shared limiter store is unreachable', async () => {
    const broken = new Proxy({} as CachePort, {
      get: () => () => Promise.reject(new Error('ECONNREFUSED')),
    });
    const built = await build({ cache: broken });
    const known = await freshAccount();
    expect(await requestLink(built, known.identifier)).toEqual({ kind: 'unavailable' });
    expect(await resetRows(known.userId)).toHaveLength(0);
  });

  it('never logs a token, an address or a link', async () => {
    const built = await build();
    const known = await freshAccount();
    built.transport.failures = 10;
    await requestLink(built, known.identifier, '203.0.113.26');
    built.transport.failures = 0;
    await requestLink(built, known.identifier, '203.0.113.27');
    const { token } = tokenFrom(built.transport.sent[0]);
    await built.recovery.complete({ organisation: ORG, token, password: 'short', correlationId });

    const logged = JSON.stringify(built.logs);
    expect(logged).not.toContain(token);
    expect(logged).not.toContain(known.identifier);
    expect(logged).not.toContain('https://');
  });
});

describe('inspecting a link', () => {
  it('never consumes it, however many times it is fetched', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.30');
    const { token } = tokenFrom(built.transport.sent[0]);

    for (let i = 0; i < 5; i += 1) {
      expect(await built.recovery.inspect({ organisation: ORG, token })).toBe('valid');
    }
    expect((await resetRows(known.userId))[0]?.consumed_at).toBeNull();
    expect(
      await built.recovery.complete({
        organisation: ORG,
        token,
        password: NEW_PASSWORD,
        correlationId,
      }),
    ).toEqual({ kind: 'completed' });
  });

  it('refuses a token from another organisation', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.31');
    const { token } = tokenFrom(built.transport.sent[0]);
    expect(await built.recovery.inspect({ organisation: OTHER_ORG, token })).toBe('invalid');
    expect(
      await built.recovery.complete({
        organisation: OTHER_ORG,
        token,
        password: NEW_PASSWORD,
        correlationId,
      }),
    ).toEqual({ kind: 'invalid-token' });
  });
});

describe('completing a reset', () => {
  it('changes the password, bumps the token version and revokes every session and refresh lineage', async () => {
    const built = await build();
    const known = await freshAccount();
    const first = await signIn(known.userId);
    const second = await signIn(known.userId);
    await requestLink(built, known.identifier, '203.0.113.40');
    const { token } = tokenFrom(built.transport.sent[0]);

    expect(
      await built.recovery.complete({
        organisation: ORG,
        token,
        password: NEW_PASSWORD,
        correlationId,
      }),
    ).toEqual({ kind: 'completed' });

    const row = await accountRow(known.userId);
    expect(await defaultPasswordHasher.verify(NEW_PASSWORD, row.password_hash)).toBe(true);
    expect(row.token_version).toBe(2);
    for (const signedIn of [first, second]) {
      expect((await stack.sessions.validate(tenant, signedIn.sessionId)).valid).toBe(false);
      await expect(stack.refreshTokens.rotate(tenant, signedIn.refresh)).rejects.toThrow();
    }
    expect((await resetRows(known.userId))[0]?.consumed_at).not.toBeNull();
    // The account owner is told.
    await built.recovery.idle();
    expect(built.transport.sent.map((message) => message.templateId)).toContain(
      'security.password-changed',
    );
  });

  it('is single use', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.41');
    const { token } = tokenFrom(built.transport.sent[0]);
    const input = { organisation: ORG, token, password: NEW_PASSWORD, correlationId };
    expect(await built.recovery.complete(input)).toEqual({ kind: 'completed' });
    expect(
      await built.recovery.complete({ ...input, password: 'yet-another-long-password' }),
    ).toEqual({
      kind: 'invalid-token',
    });
  });

  it('lets exactly one of many concurrent uses win', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.42');
    const { token } = tokenFrom(built.transport.sent[0]);

    const passwords = Array.from(
      { length: 8 },
      (_, i) => `concurrent-password-number-${String(i)}`,
    );
    const outcomes = await Promise.all(
      passwords.map((password) =>
        built.recovery.complete({ organisation: ORG, token, password, correlationId }),
      ),
    );
    const winners = outcomes
      .map((outcome, i) => ({ outcome, password: passwords[i]! }))
      .filter((entry) => entry.outcome.kind === 'completed');
    expect(winners).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.kind === 'invalid-token')).toHaveLength(7);

    const row = await accountRow(known.userId);
    expect(await defaultPasswordHasher.verify(winners[0]!.password, row.password_hash)).toBe(true);
    expect(row.token_version).toBe(2);
  });

  it('refuses an expired link', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.43');
    const { token } = tokenFrom(built.transport.sent[0]);
    await asOwner(
      tenant,
      `update identity_reset_token set expires_at = now() - interval '1 second' where account_id = $1`,
      [known.userId],
    );
    expect(await built.recovery.inspect({ organisation: ORG, token })).toBe('invalid');
    expect(
      await built.recovery.complete({
        organisation: ORG,
        token,
        password: NEW_PASSWORD,
        correlationId,
      }),
    ).toEqual({ kind: 'invalid-token' });
  });

  it('refuses a link for an account disabled after it was issued', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.45');
    const { token } = tokenFrom(built.transport.sent[0]);
    await asOwner(tenant, `update identity_account set status = 'disabled' where id = $1`, [
      known.userId,
    ]);
    const before = await accountRow(known.userId);
    expect(
      await built.recovery.complete({
        organisation: ORG,
        token,
        password: NEW_PASSWORD,
        correlationId,
      }),
    ).toEqual({ kind: 'invalid-token' });
    expect(await accountRow(known.userId)).toEqual(before);
  });

  it('enforces the password policy and the breach check without spending the link', async () => {
    const built = await build();
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.44');
    const { token } = tokenFrom(built.transport.sent[0]);

    const short = await built.recovery.complete({
      organisation: ORG,
      token,
      password: 'short',
      correlationId,
    });
    expect(short).toMatchObject({ kind: 'password-rejected', code: 'AUTH_PASSWORD_POLICY' });
    const breached = await built.recovery.complete({
      organisation: ORG,
      token,
      password: 'correct horse battery staple',
      correlationId,
    });
    expect(breached).toMatchObject({ kind: 'password-rejected', code: 'AUTH_PASSWORD_BREACHED' });

    expect(await built.recovery.inspect({ organisation: ORG, token })).toBe('valid');
    expect(
      await built.recovery.complete({
        organisation: ORG,
        token,
        password: NEW_PASSWORD,
        correlationId,
      }),
    ).toEqual({ kind: 'completed' });
  });
});

describe('completion is atomic', () => {
  /** Everything a half-finished completion could have changed, before and after. */
  const snapshot = async (userId: UserId, signedIn: { sessionId: SessionId; refresh: string }) => ({
    account: await accountRow(userId),
    resets: (await resetRows(userId)).map((row) => ({
      consumed: row.consumed_at !== null,
      revoked: row.revoked_at !== null,
    })),
    sessionValid: (await stack.sessions.validate(tenant, signedIn.sessionId)).valid,
    refreshRevoked: (
      await asOwner<{ revoked_at: Date | null }>(
        tenant,
        'select revoked_at from identity_refresh_token where account_id = $1',
        [userId],
      )
    ).map((row) => row.revoked_at !== null),
  });

  const failureCases: [string, (fail: () => never) => Partial<PasswordRecoveryOptions>][] = [
    [
      'the session and refresh revocation',
      (fail) => ({
        revokeCredentials: async (tenantId, userId) => {
          await stack.revocation.revokeAllForUser(tenantId, userId, 'password-reset');
          fail();
        },
      }),
    ],
    [
      'the token-version bump',
      (fail) => ({
        directory: new Proxy(stack.directory, {
          get: (target, property, receiver) =>
            property === 'incrementTokenVersion'
              ? async () => fail()
              : (Reflect.get(target, property, receiver) as unknown),
        }),
      }),
    ],
    [
      'hashing the new password',
      (fail) => ({
        hasher: { ...defaultPasswordHasher, hash: async () => fail() } as never,
      }),
    ],
  ];

  for (const [step, inject] of failureCases) {
    it(`rolls everything back when ${step} fails`, async () => {
      const healthy = await build();
      const known = await freshAccount();
      const signedIn = await signIn(known.userId);
      await requestLink(healthy, known.identifier, `192.0.2.${String(counter)}`);
      const { token } = tokenFrom(healthy.transport.sent[0]);
      const before = await snapshot(known.userId, signedIn);

      const broken = await build(
        inject(() => {
          throw new Error('injected failure');
        }),
      );
      expect(
        await broken.recovery.complete({
          organisation: ORG,
          token,
          password: NEW_PASSWORD,
          correlationId,
        }),
      ).toEqual({ kind: 'unavailable' });

      // Nothing moved: the link is unspent, the password and version unchanged, the session alive.
      expect(await snapshot(known.userId, signedIn)).toEqual(before);
      expect(before.sessionValid).toBe(true);

      // And the same link still works once the fault is gone.
      expect(
        await healthy.recovery.complete({
          organisation: ORG,
          token,
          password: NEW_PASSWORD,
          correlationId,
        }),
      ).toEqual({ kind: 'completed' });
    });
  }

  it('rolls everything back when the database connection dies mid-way (a crashed process)', async () => {
    const healthy = await build();
    const known = await freshAccount();
    const signedIn = await signIn(known.userId);
    await requestLink(healthy, known.identifier, '192.0.2.250');
    const { token } = tokenFrom(healthy.transport.sent[0]);
    const before = await snapshot(known.userId, signedIn);

    const killer = await build({
      revokeCredentials: async (tenantId) => {
        // By now the claim, the password write, the version bump and the reset-token revocation
        // have all been issued inside the transaction. Kill its backend, as a dead process would.
        const [{ pid }] = await prisma.withTenant(
          tenantId,
          (tx) => tx.$queryRaw<{ pid: number }[]>`select pg_backend_pid() as pid`,
        );
        // Only a superuser may signal another role's backend; CI provides one for setup.
        const terminator = new pg.Client({ connectionString: SUPERUSER_URL });
        await terminator.connect();
        const killed = await terminator.query<{ ok: boolean }>(
          'select pg_terminate_backend($1) as ok',
          [pid],
        );
        await terminator.end();
        expect(killed.rows[0]?.ok).toBe(true);
        await prisma.withTenant(tenantId, (tx) => tx.$queryRaw`select 1`);
      },
    });
    const outcome = await killer.recovery.complete({
      organisation: ORG,
      token,
      password: NEW_PASSWORD,
      correlationId,
    });
    expect(outcome.kind).not.toBe('completed');
    expect(await snapshot(known.userId, signedIn)).toEqual(before);
  });
});

describe('the unit of work', () => {
  it('refuses to touch another organisation, and does not nest', async () => {
    await expect(
      prisma.unitOfWork(tenant, () => prisma.withTenant(otherTenant, async () => 1)),
    ).rejects.toThrow(/another/);
    await expect(
      prisma.unitOfWork(tenant, () => prisma.unitOfWork(tenant, async () => 1)),
    ).rejects.toThrow(/nest/);
    expect(prisma.inUnitOfWork).toBe(false);
  });
});

describe('the HTTP surface', () => {
  interface Captured {
    status: number;
    headers: Record<string, string>;
    body: unknown;
    redirect?: string;
  }

  const fakeResponse = () => {
    const captured: Captured = { status: 200, headers: {}, body: undefined };
    const response = {
      status(code: number) {
        captured.status = code;
        return response;
      },
      setHeader(name: string, value: string) {
        captured.headers[name.toLowerCase()] = value;
        return response;
      },
      getHeader(name: string) {
        return captured.headers[name.toLowerCase()];
      },
      type() {
        return response;
      },
      json(body: unknown) {
        captured.body = body;
        return response;
      },
      send(body: unknown) {
        captured.body = body;
        return response;
      },
      redirect(code: number, location: string) {
        captured.status = code;
        captured.redirect = location;
      },
      clearCookie() {
        return response;
      },
      cookie() {
        return response;
      },
    };
    return { response: response as never, captured };
  };

  const fakeRequest = (headers: Record<string, string>, ip: string) =>
    ({ headers, ip, correlationId: 'corr-http' }) as never;

  it('returns byte-identical responses for a known and an unknown address, whatever the Host header says', async () => {
    const built = await build();
    const controller = new PasswordRecoveryController(
      { ...stack, recovery: built.recovery } as SecurityStack,
      environment,
    );
    const known = await freshAccount();

    const answers: Captured[] = [];
    for (const [identifier, ip] of [
      [known.identifier, '203.0.113.60'],
      ['unknown-person@example.test', '203.0.113.61'],
    ] as const) {
      const { response, captured } = fakeResponse();
      await controller.requestReset(
        { identifier },
        fakeRequest(
          {
            'content-type': 'application/json',
            host: 'evil.example',
            'x-forwarded-host': 'evil.example',
          },
          ip,
        ),
        response,
      );
      answers.push(captured);
    }
    await built.recovery.idle();

    expect(answers[0]).toEqual(answers[1]);
    expect(answers[0]).toEqual({ status: 202, headers: {}, body: { ok: true } });
    expect(built.transport.sent[0]?.body).toContain(RESET_URL);
    expect(built.transport.sent[0]?.body).not.toContain('evil.example');
  });

  it('serves the reset form on GET without consuming the link, and completes on POST', async () => {
    const built = await build();
    const controller = new PasswordRecoveryController(
      { ...stack, recovery: built.recovery } as SecurityStack,
      environment,
    );
    const known = await freshAccount();
    await requestLink(built, known.identifier, '203.0.113.62');
    const { org, token } = tokenFrom(built.transport.sent[0]);

    for (let i = 0; i < 3; i += 1) {
      const { response, captured } = fakeResponse();
      await controller.inspect(org, token, 'en', fakeRequest({}, '203.0.113.62'), response);
      expect(captured.status).toBe(200);
      expect(String(captured.body)).toContain('name="token"');
    }

    const { response, captured } = fakeResponse();
    await controller.complete(
      { organisation: org, token, password: NEW_PASSWORD, confirm: NEW_PASSWORD },
      fakeRequest({ 'content-type': 'application/x-www-form-urlencoded' }, '203.0.113.62'),
      response,
    );
    expect(captured.status).toBe(200);

    const again = fakeResponse();
    await controller.inspect(
      org,
      token,
      'en',
      fakeRequest({ accept: 'application/json' }, '1.1.1.1'),
      again.response,
    );
    expect(again.captured.body).toEqual({ valid: false });
  });

  it('answers 404 everywhere when recovery is disabled and 503 when it cannot deliver', async () => {
    for (const [overrides, status] of [
      [{ enabled: false }, 404],
      [{ transport: undefined }, 503],
    ] as const) {
      const built = await build(overrides);
      const controller = new PasswordRecoveryController(
        { ...stack, recovery: built.recovery } as SecurityStack,
        environment,
      );
      const post = fakeResponse();
      await controller.requestReset(
        { identifier: 'a@example.test' },
        fakeRequest({ 'content-type': 'application/json' }, '203.0.113.70'),
        post.response,
      );
      expect(post.captured.status).toBe(status);
      const get = fakeResponse();
      await controller.inspect(
        ORG,
        'x'.repeat(43),
        'en',
        fakeRequest({}, '203.0.113.70'),
        get.response,
      );
      expect(get.captured.status).toBe(status);
    }
  });
});

describe('the outbox transport', () => {
  it('writes each message to its own owner-only file and never overwrites', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'identity-outbox-'));
    const transport = new OutboxEmailTransport(directory);
    const message = {
      id: 'mail_1',
      tenantId: tenant,
      channel: 'email' as const,
      recipient: { email: 'a@example.test' },
      body: 'hello',
      priority: 'critical' as const,
    };
    expect((await transport.send(message)).delivered).toBe(true);
    expect((await transport.send(message)).delivered).toBe(false);
    const files = await readdir(directory);
    expect(files).toEqual(['mail_1.json']);
    expect((await stat(join(directory, files[0]!))).mode & 0o077).toBe(0);
    expect(JSON.parse(await readFile(join(directory, files[0]!), 'utf8'))).toMatchObject({
      body: 'hello',
    });
  });
});
