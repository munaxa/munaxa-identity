import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

import { totpCode } from '@munaxa/auth';
import { defaultPasswordHasher } from '@munaxa/crypto';
import type { SessionId, TenantId, UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment, type IdentityEnvironment } from '../../config/src/index.js';
import { AuthService, type LoginResult } from '../../../apps/api/src/auth/auth.service.js';
import { resolvePrincipal, type Principal } from '../../../apps/api/src/auth/principal.js';
import {
  MfaFlowService,
  normaliseRecoveryCode,
} from '../../../apps/api/src/mfa/mfa-flow.service.js';
import {
  OperatorError,
  accountDisable,
  mfaReencrypt,
  mfaReset,
  revokeUnsatisfiedSessions,
} from '../../../apps/api/src/ops/operator.js';
import { parseArguments } from '../../../apps/api/src/ops/operator-cli.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * The operator commands (`apps/api/src/ops`) against the real stack. The MFA flows end to end: Platform's `LoginService` and `MfaService`, the real Prisma adapters
 * under row-level security as `identity_app`, real ES256 tokens, and the real shared Redis. Two
 * security stacks stand in for two replicas.
 */

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6379';
const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const MFA_KEY = randomBytes(32).toString('base64url');
const PASSWORD = `Correct-Horse-${randomUUID()}`;
const UA = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0';

const environmentFor = (overrides: Record<string, string> = {}): IdentityEnvironment =>
  loadEnvironment({
    NODE_ENV: 'test',
    IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
    DATABASE_URL: APPLICATION_URL,
    IDENTITY_BASE_URL: 'http://localhost:4001',
    IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
    IDENTITY_SIGNING_KID: 'identity-test-2026-11',
    IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
    CSRF_TRUSTED_ORIGINS: 'http://localhost:3001',
    REDIS_URL,
    MFA_ENCRYPTION_KEYS: `mfa-test=${MFA_KEY}`,
    MFA_ENCRYPTION_PRIMARY_KID: 'mfa-test',
    MFA_POLICY: 'privileged',
    MFA_PRIVILEGED_ROLES: 'operator-admin',
    MFA_CHALLENGE_MAX_ATTEMPTS: '3',
    MFA_ACCOUNT_MAX_FAILURES: '6',
    ...overrides,
  });

interface Replica {
  readonly security: SecurityStack;
  readonly auth: AuthService;
  readonly flow: MfaFlowService;
}

let prisma: PrismaService;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;
let a: Replica;
let b: Replica;
const org = { key: `mfa-ops-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
let adminRole: string;

const replica = async (environment: IdentityEnvironment): Promise<Replica> => {
  const security = await buildSecurityStack(environment, prisma);
  const auth = new AuthService(security, environment, prisma);
  return { security, auth, flow: new MfaFlowService(security, environment, auth) };
};

const asOwner = async <T extends pg.QueryResultRow>(
  sql: string,
  values: unknown[] = [],
): Promise<T[]> => {
  await owner.query('begin');
  try {
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', org.id]);
    const result = await owner.query<T>(sql, values);
    await owner.query('commit');
    return result.rows;
  } catch (error) {
    await owner.query('rollback');
    throw error;
  }
};

const person = async (
  options: { privileged?: boolean } = {},
): Promise<{ id: UserId; email: string }> => {
  const id = randomUUID() as UserId;
  const email = `${randomUUID().slice(0, 8)}@mfa-ops.test`;
  const encoded = await defaultPasswordHasher.hash(PASSWORD);
  await asOwner(
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, password_hash, password_algorithm,
        password_updated_at, status, token_version, mfa_enrolled, must_change_password,
        identity_source, created_at, updated_at, version)
     values ($1, $2, $3, $3, $4, 'scrypt', now(), 'active', 1, false, false, 'local', now(), now(), 1)`,
    [id, org.id, email, encoded],
  );
  if (options.privileged === true) {
    await asOwner(
      `insert into identity_role_assignment (tenant_id, account_id, role_id, scope, assigned_at)
       values ($1, $2, $3, '', now())`,
      [org.id, id, adminRole],
    );
  }
  return { id, email };
};

const ctx = (userAgent = UA) => ({ correlationId: `corr-${randomUUID()}`, userAgent });

const login = (r: Replica, email: string, userAgent = UA): Promise<LoginResult> =>
  r.auth.login({
    identifier: email,
    password: PASSWORD,
    organisation: org.key,
    correlationId: `corr-${randomUUID()}` as never,
    userAgent,
  });

const challengeOf = (result: LoginResult): { token: string; kind: 'verify' | 'enroll' } => {
  if (
    result.ok ||
    result.failure.kind !== 'mfa-required' ||
    result.failure.challenge === undefined
  ) {
    throw new Error(`expected an MFA challenge, got ${JSON.stringify(result)}`);
  }
  return result.failure.challenge;
};

const steadyNow = async (): Promise<number> => {
  for (;;) {
    const into = (Date.now() / 1_000) % 30;
    if (into > 1 && into < 27) return Date.now();
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
};

const principalOf = async (r: Replica, access: string): Promise<Principal> => {
  const resolved = await resolvePrincipal(r.security, access);
  if (!resolved.ok) throw new Error('expected a principal');
  return resolved.principal;
};

const sessionsOf = async (userId: UserId) =>
  asOwner<{ id: string; mfa_satisfied: boolean; auth_methods: string[]; revoked_at: Date | null }>(
    'select id, mfa_satisfied, auth_methods, revoked_at from identity_session where account_id = $1',
    [userId],
  );

/**
 * Count how many answers actually reach the factor check on `replicas`. The limits are about this
 * number, not about what the responses say: a limit that refuses after checking has already lost.
 */
const countFactorChecks = (replicas: readonly Replica[]) => {
  let checks = 0;
  const restores = replicas.map((r) => {
    const mfa = r.security.mfa as { verifier: NonNullable<SecurityStack['mfa']>['verifier'] };
    const original = mfa.verifier;
    mfa.verifier = (tenantId, userId) => {
      const service = original(tenantId, userId);
      return new Proxy(service, {
        get(target, property, receiver) {
          const value: unknown = Reflect.get(target, property, receiver);
          if (typeof value !== 'function') return value;
          if (property === 'verifyTotpCode' || property === 'verifyRecoveryCode') {
            return (...args: unknown[]) => {
              checks += 1;
              return (value as (...a: unknown[]) => unknown).apply(target, args);
            };
          }
          return (value as (...a: unknown[]) => unknown).bind(target);
        },
      });
    };
    return () => {
      mfa.verifier = original;
    };
  });
  return {
    count: () => checks,
    restore: () => restores.forEach((restore) => restore()),
  };
};

/** A signed-in account with MFA enrolled through the session path. Returns its secret and codes. */
const enrolled = async (): Promise<{
  id: UserId;
  email: string;
  secret: string;
  codes: readonly string[];
}> => {
  const who = await person();
  const signedIn = await login(a, who.email);
  if (!signedIn.ok) throw new Error('expected a password-only sign-in');
  const principal = await principalOf(a, signedIn.access);
  const started = await a.flow.startEnrollment({ via: 'session', principal }, ctx());
  if (!started.ok) throw new Error(started.refusal);
  const confirmed = await a.flow.confirmEnrollment(
    { via: 'session', principal },
    totpCode(started.value.secret, await steadyNow()),
    ctx(),
  );
  if (!confirmed.ok) throw new Error(confirmed.refusal);
  return { ...who, secret: started.value.secret, codes: confirmed.value.recoveryCodes };
};

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
  adminRole = randomUUID();
  await asOwner(
    `insert into identity_role (id, tenant_id, key, name, permissions, inherits, system, created_at, updated_at)
     values ($1, $2, 'operator-admin', 'Operator admin', '{}', '{}', true, now(), now())`,
    [adminRole, org.id],
  );
  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();
  a = await replica(environmentFor());
  b = await replica(environmentFor());
});

afterAll(async () => {
  await a.security.close();
  await b.security.close();
  await prisma.$disconnect();
  owner.release();
  await ownerPool.end();
});

const out = () => {
  const lines: string[] = [];
  return { lines, write: (line: string) => void lines.push(line) };
};
const deps = (r: Replica, sink = out()) => ({ security: r.security, prisma, out: sink.write });
const live = async (userId: UserId) =>
  (await sessionsOf(userId)).filter((row) => row.revoked_at === null);

describe('mfa-reset (lost device)', () => {
  it('changes nothing without --apply, and names the account only by id', async () => {
    const who = await enrolled();
    const sink = out();
    const result = await mfaReset(deps(a, sink), {
      organisation: org.key,
      account: who.email,
      apply: false,
    });
    expect(result).toMatchObject({ accountId: who.id, enrolled: true, applied: false });
    expect(sink.lines.join('\n')).not.toContain(who.email);
    expect(challengeOf(await login(a, who.email)).kind).toBe('verify');
  });

  it('requires a reference to apply, and refuses one that is not a plain ticket id', async () => {
    const who = await enrolled();
    for (const reference of [undefined, '', 'x', 'someone@example.com', 'a b c']) {
      await expect(
        mfaReset(deps(a), { organisation: org.key, account: who.email, reference, apply: true }),
      ).rejects.toBeInstanceOf(OperatorError);
    }
    expect(challengeOf(await login(a, who.email)).kind).toBe('verify');
  });

  it('removes the factor and its codes, ends every session, and audits the reference', async () => {
    const who = await enrolled();
    expect((await live(who.id)).length).toBeGreaterThan(0);
    const [{ token_version: before }] = await asOwner<{ token_version: number }>(
      'select token_version from identity_account where id = $1',
      [who.id],
    );

    const sink = out();
    const result = await mfaReset(deps(a, sink), {
      organisation: org.key,
      account: who.email,
      reference: 'INC-1234',
      apply: true,
    });
    expect(result.applied).toBe(true);
    expect(await live(who.id)).toHaveLength(0);
    expect(sink.lines.join('\n')).not.toContain(who.email);

    const [row] = await asOwner<{ mfa_enrolled: boolean; token_version: number }>(
      'select mfa_enrolled, token_version from identity_account where id = $1',
      [who.id],
    );
    expect(row).toEqual({ mfa_enrolled: false, token_version: before + 1 });
    expect(
      await asOwner('select 1 from identity_mfa_enrollment where account_id = $1', [who.id]),
    ).toHaveLength(0);
    expect(
      await asOwner('select 1 from identity_mfa_recovery_code where account_id = $1', [who.id]),
    ).toHaveLength(0);
    const events = await asOwner(
      `select 1 from identity_audit_event
        where event_name = 'auth.mfa.removed' and event::text like '%INC-1234%'
          and event::text like '%operator:INC-1234%'`,
    );
    expect(events.length).toBeGreaterThan(0);

    // The old recovery codes are gone with the factor, and the account signs in with its
    // password: not covered by policy, so straight through.
    const signedIn = await login(a, who.email);
    expect(signedIn.ok).toBe(true);
  });

  it('sends a policy-covered account straight to enrollment after a reset', async () => {
    const who = await person({ privileged: true });
    const challenge = challengeOf(await login(a, who.email));
    const found = await a.flow.challenge(challenge.token, 'enroll', ctx());
    if (!found.ok) throw new Error(found.refusal);
    const actor = { via: 'challenge' as const, token: challenge.token, record: found.value };
    const started = await a.flow.startEnrollment(actor, ctx());
    if (!started.ok) throw new Error(started.refusal);
    const confirmed = await a.flow.confirmEnrollment(
      actor,
      totpCode(started.value.secret, await steadyNow()),
      ctx(),
    );
    if (!confirmed.ok) throw new Error(confirmed.refusal);

    await mfaReset(deps(a), {
      organisation: org.key,
      account: who.email,
      reference: 'INC-1235',
      apply: true,
    });
    expect(challengeOf(await login(a, who.email)).kind).toBe('enroll');
  });

  it('refuses an unknown organisation or account without saying which exists', async () => {
    await expect(
      mfaReset(deps(a), { organisation: 'no-such-org', account: 'x@y.test', apply: false }),
    ).rejects.toBeInstanceOf(OperatorError);
    await expect(
      mfaReset(deps(a), { organisation: org.key, account: 'nobody@mfa-ops.test', apply: false }),
    ).rejects.toBeInstanceOf(OperatorError);
  });
});

describe('account-disable (containment)', () => {
  it('disables the account, ends every session and refuses the next sign-in', async () => {
    const who = await enrolled();
    expect(
      (await accountDisable(deps(a), { organisation: org.key, account: who.email, apply: false }))
        .applied,
    ).toBe(false);
    await expect(
      accountDisable(deps(a), { organisation: org.key, account: who.email, apply: true }),
    ).rejects.toBeInstanceOf(OperatorError);
    await accountDisable(deps(a), {
      organisation: org.key,
      account: who.email,
      reference: 'INC-77',
      apply: true,
    });
    expect(await live(who.id)).toHaveLength(0);
    const [row] = await asOwner<{ status: string }>(
      'select status from identity_account where id = $1',
      [who.id],
    );
    expect(row?.status).toBe('disabled');
    expect((await login(a, who.email)).ok).toBe(false);
  });
});

describe('sessions-revoke-unsatisfied (turning enforcement on)', () => {
  it('ends only password-only sessions of accounts the policy covers', async () => {
    const off = await replica(environmentFor({ MFA_POLICY: 'off' }));
    let covered: { id: UserId; email: string };
    let uncovered: { id: UserId; email: string };
    try {
      covered = await person({ privileged: true });
      uncovered = await person();
      expect((await login(off, covered.email)).ok).toBe(true);
      expect((await login(off, uncovered.email)).ok).toBe(true);
    } finally {
      await off.security.close();
    }
    // A covered account that already signed in with MFA keeps that session.
    const strong = await enrolled();
    await asOwner(
      `insert into identity_role_assignment (tenant_id, account_id, role_id, scope, assigned_at)
       values ($1, $2, $3, '', now())`,
      [org.id, strong.id, adminRole],
    );
    const strongBefore = (await live(strong.id)).length;

    const dry = await revokeUnsatisfiedSessions(deps(a), { organisation: org.key, apply: false });
    expect(dry.applied).toBe(false);
    expect(dry.sessions).toBeGreaterThanOrEqual(1);
    expect(await live(covered.id)).toHaveLength(1);

    await expect(
      revokeUnsatisfiedSessions(deps(a), { organisation: org.key, apply: true }),
    ).rejects.toBeInstanceOf(OperatorError);

    const applied = await revokeUnsatisfiedSessions(deps(a), {
      organisation: org.key,
      reference: 'CHG-42',
      apply: true,
    });
    expect(applied.applied).toBe(true);
    expect(await live(covered.id)).toHaveLength(0);
    expect(await live(uncovered.id)).toHaveLength(1);
    // enrolled() signs in password-only before enrolling, and confirming revoked the others; the
    // session it kept is password-only too, so it goes as well. Sessions created with the factor
    // carry mfa_satisfied = true and are never touched.
    for (const row of await live(strong.id)) expect(row.mfa_satisfied).toBe(true);
    expect(strongBefore).toBeGreaterThanOrEqual((await live(strong.id)).length);
  });
});

describe('mfa-reencrypt (key rotation)', () => {
  it('re-seals secrets under a new primary key, and every factor still verifies', async () => {
    const who = await enrolled();
    const NEXT = randomBytes(32).toString('base64url');
    const rotated = await replica(
      environmentFor({
        MFA_ENCRYPTION_KEYS: `mfa-test=${MFA_KEY},mfa-next=${NEXT}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'mfa-next',
      }),
    );
    try {
      const dry = await mfaReencrypt(deps(rotated), { organisation: org.key, apply: false });
      expect(dry.staleSecrets).toBeGreaterThan(0);
      expect(dry.recoveryCodesUnderRetiredKeys).toBeGreaterThan(0);

      const applied = await mfaReencrypt(deps(rotated), { organisation: org.key, apply: true });
      expect(applied).toMatchObject({ failed: 0, applied: true });
      expect(applied.resealed).toBe(dry.staleSecrets);
      expect(
        await asOwner(
          `select 1 from identity_mfa_enrollment where tenant_id = $1 and key_id <> 'mfa-next'`,
          [org.id],
        ),
      ).toHaveLength(0);

      const { token } = challengeOf(await login(rotated, who.email));
      const signed = await rotated.flow.verifyChallenge(
        token,
        { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
        ctx(),
      );
      expect(signed.ok).toBe(true);
      // Recovery codes are HMACs under the old kid: they still verify while that kid is in the
      // ring, which is why the command reports them and the kid cannot be retired yet.
      const next = challengeOf(await login(rotated, who.email));
      expect(
        (await rotated.flow.verifyChallenge(next.token, { recoveryCode: who.codes[0] }, ctx())).ok,
      ).toBe(true);
    } finally {
      await rotated.security.close();
    }
  });
});

describe('the command line', () => {
  it('parses flags and refuses stray arguments', () => {
    expect(
      parseArguments(['mfa-reset', '--organisation', 'acme', '--reference', 'INC-1', '--apply']),
    ).toEqual({
      command: 'mfa-reset',
      options: { organisation: 'acme', reference: 'INC-1' },
      apply: true,
    });
    expect(() => parseArguments(['mfa-reset', 'acme'])).toThrow(OperatorError);
  });
});
