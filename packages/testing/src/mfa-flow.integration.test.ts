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
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * The MFA flows end to end: Platform's `LoginService` and `MfaService`, the real Prisma adapters
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
const org = { key: `mfa-flow-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
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
  const email = `${randomUUID().slice(0, 8)}@mfa-flow.test`;
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

describe('signing in to an account with MFA', () => {
  it('creates no session and no token until the second factor is proven', async () => {
    const who = await enrolled();
    const before = (await sessionsOf(who.id)).length;
    const result = await login(a, who.email);

    expect(challengeOf(result).kind).toBe('verify');
    expect(JSON.stringify(result)).not.toMatch(/"access"|"refresh"/);
    expect((await sessionsOf(who.id)).length).toBe(before);
  });

  it('never accepts the challenge as an access token', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));

    expect(await resolvePrincipal(a.security, token)).toEqual({ ok: false });
    expect(await a.auth.session(token)).toEqual({ signedIn: false });
    expect(await a.flow.principal(token)).toBeUndefined();
  });

  it('signs in with a valid code, recording the methods used and mfaSatisfied', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    const result = await a.flow.verifyChallenge(
      token,
      { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
      ctx(),
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.claims.amr).toEqual(['password', 'totp']);
    expect(result.value.claims.mfa).toBe(true);
    const row = (await sessionsOf(who.id)).find((s) => s.id === result.value.claims.sid);
    expect(row).toMatchObject({ mfa_satisfied: true, auth_methods: ['password', 'totp'] });

    // A refresh keeps the factors the session was established with.
    const refreshed = await a.auth.refresh({
      refreshToken: result.value.refresh,
      organisation: org.key,
    });
    expect(refreshed.ok && refreshed.claims.mfa).toBe(true);
    expect(refreshed.ok && refreshed.claims.amr).toEqual(['password', 'totp']);
  });

  it('spends the challenge exactly once', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    const at = await steadyNow();

    expect(
      (await a.flow.verifyChallenge(token, { code: totpCode(who.secret, at + 30_000) }, ctx())).ok,
    ).toBe(true);
    const again = await b.flow.verifyChallenge(
      token,
      { code: totpCode(who.secret, at - 30_000) },
      ctx(),
    );
    expect(again).toEqual({ ok: false, refusal: 'expired' });
  });

  it('lets exactly one of many concurrent redemptions across replicas through', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    const code = totpCode(who.secret, (await steadyNow()) + 30_000);

    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        (i % 2 === 0 ? a : b).flow.verifyChallenge(token, { code }, ctx()),
      ),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('refuses a replayed code on a fresh challenge, from another replica', async () => {
    const who = await enrolled();
    const code = totpCode(who.secret, (await steadyNow()) + 30_000);
    const first = challengeOf(await login(a, who.email));
    expect((await a.flow.verifyChallenge(first.token, { code }, ctx())).ok).toBe(true);

    const second = challengeOf(await login(b, who.email));
    expect(await b.flow.verifyChallenge(second.token, { code }, ctx())).toEqual({
      ok: false,
      refusal: 'invalid',
    });
  });

  it('refuses the code that confirmed enrollment', async () => {
    const who = await person();
    const signedIn = await login(a, who.email);
    if (!signedIn.ok) throw new Error('expected sign-in');
    const principal = await principalOf(a, signedIn.access);
    const started = await a.flow.startEnrollment({ via: 'session', principal }, ctx());
    if (!started.ok) throw new Error(started.refusal);
    const code = totpCode(started.value.secret, await steadyNow());
    expect((await a.flow.confirmEnrollment({ via: 'session', principal }, code, ctx())).ok).toBe(
      true,
    );

    const { token } = challengeOf(await login(b, who.email));
    expect(await b.flow.verifyChallenge(token, { code }, ctx())).toEqual({
      ok: false,
      refusal: 'invalid',
    });
  });

  it('destroys the challenge after its attempt limit', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));

    expect(await a.flow.verifyChallenge(token, { code: '000000' }, ctx())).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    expect(await a.flow.verifyChallenge(token, { code: '111111' }, ctx())).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    expect(await a.flow.verifyChallenge(token, { code: '222222' }, ctx())).toEqual({
      ok: false,
      refusal: 'locked',
    });
    // Even the right code no longer works: the holder must prove the password again.
    const right = totpCode(who.secret, (await steadyNow()) + 30_000);
    expect((await a.flow.verifyChallenge(token, { code: right }, ctx())).ok).toBe(false);
  });

  it('locks second-factor checks for the account across challenges', async () => {
    const who = await enrolled();
    for (let i = 0; i < 3; i++) {
      const { token } = challengeOf(await login(a, who.email));
      await a.flow.verifyChallenge(token, { code: '000000' }, ctx());
      await a.flow.verifyChallenge(token, { code: '999999' }, ctx());
    }
    const { token } = challengeOf(await login(a, who.email));
    const right = totpCode(who.secret, (await steadyNow()) + 30_000);
    expect(await a.flow.verifyChallenge(token, { code: right }, ctx())).toEqual({
      ok: false,
      refusal: 'locked',
    });
  });

  it('is bound to the browser it was issued to', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email, UA));
    const right = totpCode(who.secret, (await steadyNow()) + 30_000);

    expect(await a.flow.verifyChallenge(token, { code: right }, ctx('curl/8.0'))).toEqual({
      ok: false,
      refusal: 'expired',
    });
  });

  it('dies when the account’s token version moves (password change or reset)', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    await a.security.directory.incrementTokenVersion(org.id, who.id);

    const right = totpCode(who.secret, (await steadyNow()) + 30_000);
    expect(await a.flow.verifyChallenge(token, { code: right }, ctx())).toEqual({
      ok: false,
      refusal: 'expired',
    });
  });

  it('accepts a recovery code once, however it is typed', async () => {
    const who = await enrolled();
    const first = challengeOf(await login(a, who.email));
    const typed = who.codes[0]!.toLowerCase().replaceAll('-', ' ');
    const result = await a.flow.verifyChallenge(first.token, { recoveryCode: typed }, ctx());
    expect(result.ok && result.value.claims.amr).toEqual(['password', 'recovery-code']);

    const second = challengeOf(await login(a, who.email));
    expect(
      await a.flow.verifyChallenge(second.token, { recoveryCode: who.codes[0]! }, ctx()),
    ).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    expect(normaliseRecoveryCode('abcde fghij klmno')).toBe('ABCDE-FGHIJ-KLMNO');
  });
});

describe('policy-required enrollment at sign-in', () => {
  it('admits a privileged account without MFA only to enrollment, then signs it in', async () => {
    const who = await person({ privileged: true });
    const challenge = challengeOf(await login(a, who.email));
    expect(challenge.kind).toBe('enroll');
    expect((await sessionsOf(who.id)).length).toBe(0);

    // The enrollment challenge is not a sign-in challenge, nor a session.
    expect(await a.flow.verifyChallenge(challenge.token, { code: '123456' }, ctx())).toEqual({
      ok: false,
      refusal: 'expired',
    });
    expect(await resolvePrincipal(a.security, challenge.token)).toEqual({ ok: false });

    const found = await a.flow.challenge(challenge.token, 'enroll', ctx());
    if (!found.ok) throw new Error(found.refusal);
    const actor = { via: 'challenge' as const, token: challenge.token, record: found.value };
    const started = await a.flow.startEnrollment(actor, ctx());
    if (!started.ok) throw new Error(started.refusal);

    expect(await a.flow.confirmEnrollment(actor, '000000', ctx())).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    const code = totpCode(started.value.secret, await steadyNow());
    const confirmed = await b.flow.confirmEnrollment(actor, code, ctx());
    expect(confirmed.ok).toBe(true);
    if (!confirmed.ok) return;
    expect(confirmed.value.recoveryCodes).toHaveLength(10);
    expect(confirmed.value.signIn?.claims.mfa).toBe(true);
    expect(confirmed.value.signIn?.claims.amr).toEqual(['password', 'totp']);

    // The challenge is spent, and the next sign-in is an ordinary MFA challenge.
    expect((await a.flow.challenge(challenge.token, 'enroll', ctx())).ok).toBe(false);
    expect(challengeOf(await login(a, who.email)).kind).toBe('verify');
  });

  it('does not let an enrollment challenge replace an existing factor', async () => {
    const who = await person({ privileged: true });
    const { token } = challengeOf(await login(a, who.email));
    const found = await a.flow.challenge(token, 'enroll', ctx());
    if (!found.ok) throw new Error(found.refusal);
    const started = await a.flow.startEnrollment(
      { via: 'challenge', token, record: found.value },
      ctx(),
    );
    if (!started.ok) throw new Error(started.refusal);
    const code = totpCode(started.value.secret, await steadyNow());
    await a.flow.confirmEnrollment({ via: 'challenge', token, record: found.value }, code, ctx());

    // A second, stale enrollment challenge for the now-enrolled account is dead.
    expect((await a.flow.challenge(token, 'enroll', ctx())).ok).toBe(false);
  });

  it('refuses to start without MFA keys when policy is enforced', () => {
    expect(() =>
      environmentFor({ MFA_ENCRYPTION_KEYS: '', MFA_ENCRYPTION_PRIMARY_KID: '' }),
    ).toThrow(/required accounts would have no way to enrol/);
  });

  it('does not challenge an account that policy does not cover', async () => {
    const who = await person();
    const result = await login(a, who.email);
    expect(result.ok).toBe(true);
    expect(result.ok && result.claims.mfa).toBe(false);
  });
});

describe('sensitive changes require recent reauthentication', () => {
  const age = async (sessionId: string): Promise<void> => {
    await asOwner(
      `update identity_session set created_at = now() - interval '1 hour' where id = $1`,
      [sessionId],
    );
  };

  it('refuses enrollment, replacement, regeneration and removal from a stale session', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    const signed = await a.flow.verifyChallenge(
      token,
      { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
      ctx(),
    );
    if (!signed.ok) throw new Error(signed.refusal);
    await age(signed.value.claims.sid as string);
    const principal = await principalOf(a, signed.value.access);

    expect(await a.flow.startEnrollment({ via: 'session', principal }, ctx())).toEqual({
      ok: false,
      refusal: 'reauth-required',
    });
    expect(await a.flow.confirmEnrollment({ via: 'session', principal }, '123456', ctx())).toEqual({
      ok: false,
      refusal: 'reauth-required',
    });
    expect(await a.flow.regenerateRecoveryCodes(principal, ctx())).toEqual({
      ok: false,
      refusal: 'reauth-required',
    });
    expect(await a.flow.remove(principal, ctx())).toEqual({
      ok: false,
      refusal: 'reauth-required',
    });
  });

  it('requires the second factor, not just the password, to reauthenticate an enrolled account', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    const signed = await a.flow.verifyChallenge(
      token,
      { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
      ctx(),
    );
    if (!signed.ok) throw new Error(signed.refusal);
    await age(signed.value.claims.sid as string);
    const principal = await principalOf(a, signed.value.access);

    expect(await a.flow.reauthenticate(principal, { password: PASSWORD }, ctx())).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    expect(
      await a.flow.reauthenticate(
        principal,
        { password: 'wrong', recoveryCode: who.codes[1] },
        ctx(),
      ),
    ).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    const reauth = await a.flow.reauthenticate(
      principal,
      { password: PASSWORD, recoveryCode: who.codes[2] },
      ctx(),
    );
    expect(reauth.ok).toBe(true);

    // One reauthentication authorises one change: regeneration spends the marker.
    const regenerated = await a.flow.regenerateRecoveryCodes(principal, ctx());
    expect(regenerated.ok).toBe(true);
    expect(await a.flow.regenerateRecoveryCodes(principal, ctx())).toEqual({
      ok: false,
      refusal: 'reauth-required',
    });

    // The previous set is dead, the new one works.
    const next = challengeOf(await login(a, who.email));
    expect(
      await a.flow.verifyChallenge(next.token, { recoveryCode: who.codes[3]! }, ctx()),
    ).toEqual({
      ok: false,
      refusal: 'invalid',
    });
    if (!regenerated.ok) return;
    expect(
      (
        await a.flow.verifyChallenge(
          next.token,
          { recoveryCode: regenerated.value.recoveryCodes[0]! },
          ctx(),
        )
      ).ok,
    ).toBe(true);
  });

  it('refuses a password change from an enrolled account until it reauthenticates', async () => {
    const who = await enrolled();
    const { token } = challengeOf(await login(a, who.email));
    const signed = await a.flow.verifyChallenge(
      token,
      { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
      ctx(),
    );
    if (!signed.ok) throw new Error(signed.refusal);
    await age(signed.value.claims.sid as string);
    const principal = await principalOf(a, signed.value.access);
    const hashOf = async () =>
      (
        await asOwner<{ password_hash: string }>(
          'select password_hash from identity_account where id = $1',
          [who.id],
        )
      )[0]!.password_hash;
    const before = await hashOf();
    const change = () =>
      a.security.passwordChange.change({
        accessToken: signed.value.access,
        currentPassword: PASSWORD,
        newPassword: `Brand-New-Passphrase-${randomUUID()}`,
        correlationId: `corr-${randomUUID()}` as never,
      });

    // The current password is right, and it is still not enough: the session needs the factor.
    expect(await change()).toEqual({ kind: 'reauthentication-required' });
    expect(await hashOf()).toBe(before);

    const reauth = await a.flow.reauthenticate(
      principal,
      { password: PASSWORD, recoveryCode: who.codes[0] },
      ctx(),
    );
    expect(reauth.ok).toBe(true);
    expect(await change()).toMatchObject({ kind: 'changed' });
    expect(await hashOf()).not.toBe(before);
  });

  it('replaces the factor only once confirmed, and signs out every other session', async () => {
    const who = await enrolled();
    const sign = async () => {
      const { token } = challengeOf(await login(a, who.email));
      const r = await a.flow.verifyChallenge(
        token,
        { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
        ctx(),
      );
      if (r.ok) return r.value;
      // Same step already claimed by an earlier sign-in in this test: wait for the next one.
      await new Promise((resolve) => setTimeout(resolve, 30_000));
      const again = challengeOf(await login(a, who.email));
      const r2 = await a.flow.verifyChallenge(
        again.token,
        { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
        ctx(),
      );
      if (!r2.ok) throw new Error(r2.refusal);
      return r2.value;
    };
    const current = await sign();
    const principal = await principalOf(a, current.access);
    const other = (await sessionsOf(who.id)).filter(
      (s) => s.id !== current.claims.sid && s.revoked_at === null,
    );

    const started = await a.flow.startEnrollment({ via: 'session', principal }, ctx());
    if (!started.ok) throw new Error(started.refusal);
    const confirmed = await a.flow.confirmEnrollment(
      { via: 'session', principal },
      totpCode(started.value.secret, await steadyNow()),
      ctx(),
    );
    expect(confirmed.ok).toBe(true);

    const rows = await sessionsOf(who.id);
    expect(rows.find((s) => s.id === current.claims.sid)?.revoked_at).toBeNull();
    for (const s of other) expect(rows.find((r) => r.id === s.id)?.revoked_at).not.toBeNull();
    // The old secret no longer signs in.
    const { token } = challengeOf(await login(a, who.email));
    expect(
      await a.flow.verifyChallenge(token, { code: totpCode(who.secret, Date.now()) }, ctx()),
    ).toEqual({
      ok: false,
      refusal: 'invalid',
    });
  }, 70_000);

  it('removes the factor when policy allows, and refuses when it requires it', async () => {
    const who = await enrolled();
    const fresh = challengeOf(await login(a, who.email));
    const signed = await a.flow.verifyChallenge(
      fresh.token,
      { code: totpCode(who.secret, (await steadyNow()) + 30_000) },
      ctx(),
    );
    if (!signed.ok) throw new Error(signed.refusal);
    const principal = await principalOf(a, signed.value.access);

    // Make the account privileged: removal is now refused.
    await asOwner(
      `insert into identity_role_assignment (tenant_id, account_id, role_id, scope, assigned_at) values ($1, $2, $3, '', now())`,
      [org.id, who.id, adminRole],
    );
    expect(await a.flow.remove(principal, ctx())).toEqual({
      ok: false,
      refusal: 'required-by-policy',
    });
    await asOwner('delete from identity_role_assignment where account_id = $1', [who.id]);

    expect(await a.flow.remove(principal, ctx())).toEqual({ ok: true, value: null });
    const status = await a.flow.status(principal);
    expect(status).toMatchObject({ enrolled: false, recoveryCodesRemaining: 0 });
    // The next sign-in is password-only again.
    expect((await login(a, who.email)).ok).toBe(true);
  });
});
