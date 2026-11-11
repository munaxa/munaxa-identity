import { randomBytes, randomUUID } from 'node:crypto';

import { generateTotpSecret, totpCode, verifyTotp } from '@munaxa/auth';
import { sha256Hex } from '@munaxa/crypto';
import type { TenantId, UserId } from '@munaxa/types';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import pg from 'pg';

import {
  APPLICATION_URL,
  OWNER_URL,
  connect,
  createAccount,
  createOrganisation,
  truncateAll,
  type Connection,
} from './index.js';
import { buildMfaKeys, type MfaKeys } from '../../../apps/api/src/mfa/mfa-keys.js';
import { buildIdentityMfa, type IdentityMfa } from '../../../apps/api/src/mfa/mfa-runtime.js';
import { openCache, type CacheHandle } from '../../../apps/api/src/platform/cache.js';
import { assertMfaDistributed } from '../../../apps/api/src/platform/security.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';

/**
 * TOTP MFA persistence and encryption, against a real PostgreSQL as `identity_app` and a real Redis.
 *
 * Everything here goes through Platform's `MfaService` exactly as the service wires it — Identity
 * implements no TOTP — so what is being proved is the adapter and the wiring: that the secret is
 * sealed and bound, that the replay claim is shared, that recovery codes are spent once, and that
 * the two-view store never lets a started enrollment switch the current factor off.
 */

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6379';
const PENDING_TTL = 15 * 60 * 1_000;

const key = (): string => randomBytes(32).toString('base64url');
const K1 = key();
const K2 = key();

let prisma: PrismaService;
let app: Connection;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;
let cacheA: CacheHandle;
let cacheB: CacheHandle;
let keys: MfaKeys;
/** Two replicas: separate services, separate Redis connections, one Redis. */
let replicaA: IdentityMfa;
let replicaB: IdentityMfa;
let tenant: TenantId;
let otherTenant: TenantId;

const build = (k: MfaKeys, cache: CacheHandle): IdentityMfa =>
  buildIdentityMfa({ prisma, keys: k, replayGuard: cache.cache, pendingTtlMs: PENDING_TTL });

/**
 * Wait until we are not within three seconds of a TOTP step boundary, so a code computed now is
 * still the current step when it is verified a few milliseconds later.
 */
const steadyNow = async (): Promise<number> => {
  for (;;) {
    const now = Date.now();
    const into = (now / 1_000) % 30;
    if (into > 1 && into < 27) return now;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
};

const account = async (organisation: TenantId = tenant): Promise<UserId> =>
  (await createAccount(app, organisation, `${randomUUID()}@mfa.example`)) as UserId;

/** Start and confirm an enrollment, returning the secret and the recovery codes. */
const enrol = async (
  mfa: IdentityMfa,
  userId: UserId,
  organisation: TenantId = tenant,
): Promise<{ secret: string; codes: readonly string[] }> => {
  const { secret } = await mfa
    .enroller(organisation, userId)
    .beginTotpEnrollment(organisation, userId, { issuer: 'Munaxa', account: 'test' });
  const codes = await mfa
    .enroller(organisation, userId)
    .confirmTotpEnrollment(organisation, userId, totpCode(secret, await steadyNow()));
  return { secret, codes };
};

const rowsFor = async (userId: UserId, organisation: TenantId = tenant) =>
  app.withTenant(organisation, async () => {
    const { rows } = await app.client.query(
      `select state, secret_ciphertext, key_id, confirmed_at from identity_mfa_enrollment
        where account_id = $1 order by state`,
      [userId],
    );
    return rows as { state: string; secret_ciphertext: string; key_id: string }[];
  });

const enrolledFlag = async (userId: UserId, organisation: TenantId = tenant): Promise<boolean> =>
  app.withTenant(organisation, async () => {
    const { rows } = await app.client.query(
      'select mfa_enrolled from identity_account where id = $1',
      [userId],
    );
    return rows[0]?.mfa_enrolled as boolean;
  });

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await truncateAll(owner);
  app = await connect(APPLICATION_URL);
  tenant = (await createOrganisation(owner, 'mfa-alpha')) as TenantId;
  otherTenant = (await createOrganisation(owner, 'mfa-beta')) as TenantId;

  // The runtime role, exactly as the service connects.
  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();

  cacheA = await openCache(REDIS_URL);
  cacheB = await openCache(REDIS_URL);
  keys = buildMfaKeys(`k1=${K1}`, 'k1') as MfaKeys;
  replicaA = build(keys, cacheA);
  replicaB = build(keys, cacheB);
});

afterAll(async () => {
  await truncateAll(owner);
  await prisma.$disconnect();
  await app.release();
  owner.release();
  await ownerPool.end();
  await cacheA.close();
  await cacheB.close();
});

describe('the TOTP algorithm in use is Platform’s, and it is RFC 6238', () => {
  // RFC 6238 Appendix B, SHA-1, secret "12345678901234567890", eight digits.
  const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  it.each([
    [59, '94287082'],
    [1_111_111_109, '07081804'],
    [1_111_111_111, '14050471'],
    [1_234_567_890, '89005924'],
    [2_000_000_000, '69279037'],
    [20_000_000_000, '65353130'],
  ])('at T=%i the code is %s', (seconds, expected) => {
    expect(totpCode(RFC_SECRET, seconds * 1_000, { digits: 8 })).toBe(expected);
  });

  it('accepts one step of drift either side and no more', () => {
    const secret = generateTotpSecret();
    const now = 1_700_000_015_000;
    expect(verifyTotp(secret, totpCode(secret, now - 30_000), now)).toBeDefined();
    expect(verifyTotp(secret, totpCode(secret, now + 30_000), now)).toBeDefined();
    expect(verifyTotp(secret, totpCode(secret, now - 60_000), now)).toBeUndefined();
    expect(verifyTotp(secret, totpCode(secret, now + 60_000), now)).toBeUndefined();
  });
});

describe('enrollment', () => {
  it('does not count until it is confirmed with a valid code', async () => {
    const user = await account();
    const enroller = replicaA.enroller(tenant, user);
    const { secret, uri } = await enroller.beginTotpEnrollment(tenant, user, {
      issuer: 'Munaxa',
      account: 'someone',
    });

    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(await replicaA.verifier(tenant, user).isEnrolled(tenant, user)).toBe(false);
    expect(await enrolledFlag(user)).toBe(false);
    // A pending factor cannot be used to sign in.
    expect(
      await replicaA
        .verifier(tenant, user)
        .verifyTotpCode(tenant, user, totpCode(secret, Date.now())),
    ).toBe(false);

    await expect(enroller.confirmTotpEnrollment(tenant, user, '000000')).rejects.toMatchObject({
      code: 'AUTH_MFA_INVALID',
    });
    expect(await enrolledFlag(user)).toBe(false);

    const codes = await enroller.confirmTotpEnrollment(
      tenant,
      user,
      totpCode(secret, await steadyNow()),
    );
    expect(codes).toHaveLength(10);
    expect(await replicaA.verifier(tenant, user).isEnrolled(tenant, user)).toBe(true);
    expect(await enrolledFlag(user)).toBe(true);
    expect((await rowsFor(user)).map((row) => row.state)).toEqual(['active']);
  });

  it('expires a pending enrollment that is not confirmed in time', async () => {
    const user = await account();
    const { secret } = await replicaA
      .enroller(tenant, user)
      .beginTotpEnrollment(tenant, user, { issuer: 'Munaxa', account: 'x' });
    await app.withTenant(tenant, () =>
      app.client.query(
        `update identity_mfa_enrollment set created_at = now() - interval '16 minutes'
          where account_id = $1`,
        [user],
      ),
    );

    await expect(
      replicaA
        .enroller(tenant, user)
        .confirmTotpEnrollment(tenant, user, totpCode(secret, await steadyNow())),
    ).rejects.toMatchObject({ code: 'AUTH_MFA_INVALID' });
    expect(await enrolledFlag(user)).toBe(false);
  });

  it('refuses to activate a secret replaced while it was being confirmed', async () => {
    const user = await account();
    const enroller = replicaA.enroller(tenant, user);
    await enroller.beginTotpEnrollment(tenant, user, { issuer: 'Munaxa', account: 'x' });
    const [first] = await replicaA.store.view('pending').list(tenant, user);
    // A second start lands between the read and the save of the first confirmation.
    await enroller.beginTotpEnrollment(tenant, user, { issuer: 'Munaxa', account: 'x' });

    await expect(
      replicaA.store.view('pending').save({ ...first!, confirmedAt: Date.now() }),
    ).rejects.toMatchObject({ code: 'AUTH_MFA_INVALID' });
    expect(await enrolledFlag(user)).toBe(false);
  });

  it('keeps the current factor in force while a replacement is pending, then replaces it whole', async () => {
    const user = await account();
    const original = await enrol(replicaA, user);

    const { secret: next } = await replicaA
      .enroller(tenant, user)
      .beginTotpEnrollment(tenant, user, { issuer: 'Munaxa', account: 'x' });

    // Starting a replacement switched nothing off.
    expect(await enrolledFlag(user)).toBe(true);
    expect((await rowsFor(user)).map((row) => row.state)).toEqual(['active', 'pending']);
    const before = await steadyNow();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(
      await replicaA
        .verifier(tenant, user)
        .verifyTotpCode(tenant, user, totpCode(original.secret, before + 30_000)),
    ).toBe(true);
    expect(
      await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, totpCode(next, before)),
    ).toBe(false);

    const fresh = await replicaA
      .enroller(tenant, user)
      .confirmTotpEnrollment(tenant, user, totpCode(next, await steadyNow()));

    expect((await rowsFor(user)).map((row) => row.state)).toEqual(['active']);
    // The old factor and every old recovery code are gone.
    expect(
      await replicaA
        .verifier(tenant, user)
        .verifyTotpCode(tenant, user, totpCode(original.secret, Date.now())),
    ).toBe(false);
    expect(
      await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, original.codes[0]!),
    ).toBe(false);
    expect(await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, fresh[0]!)).toBe(
      true,
    );
  });
});

describe('the secret at rest', () => {
  it('is an AES-256-GCM envelope under the primary key, never the secret itself', async () => {
    const user = await account();
    const { secret } = await enrol(replicaA, user);
    const [row] = await rowsFor(user);

    expect(row!.secret_ciphertext.startsWith('v1.k1.')).toBe(true);
    expect(row!.key_id).toBe('k1');
    expect(row!.secret_ciphertext).not.toContain(secret);

    // Nothing in either MFA table, read as the owner, contains the base32 secret.
    await owner.query('begin');
    await owner.query("select set_config('identity.tenant_id', $1, true)", [tenant]);
    const dump = await owner.query(
      `select row_to_json(e)::text as r from identity_mfa_enrollment e
       union all select row_to_json(c)::text from identity_mfa_recovery_code c`,
    );
    await owner.query('commit');
    for (const { r } of dump.rows as { r: string }[]) expect(r).not.toContain(secret);
  });

  it('is refused by the store if it arrives unsealed', async () => {
    const user = await account();
    await expect(
      replicaA.store.view('pending').save({
        tenantId: tenant,
        userId: user,
        method: 'totp',
        secret: generateTotpSecret(),
        createdAt: Date.now(),
      }),
    ).rejects.toMatchObject({ code: 'CRYPTO_VERIFICATION_FAILED' });
  });

  it('is refused by the database if it is not an envelope', async () => {
    const user = await account();
    await expect(
      app.withTenant(tenant, () =>
        app.client.query(
          `insert into identity_mfa_enrollment
             (id, tenant_id, account_id, method, state, secret_ciphertext, key_id, created_at)
           values (gen_random_uuid(), $1, $2, 'totp', 'pending', $3, 'k1', now())`,
          [tenant, user, generateTotpSecret()],
        ),
      ),
    ).rejects.toThrow(/ck_identity_mfa_enrollment_sealed/);
  });

  it('does not open for another account: the envelope is bound to tenant, account and method', async () => {
    const victim = await account();
    const attacker = await account();
    await enrol(replicaA, victim);
    await enrol(replicaA, attacker);
    const [victimRow] = await rowsFor(victim);

    // Copy the victim's sealed secret onto the attacker's factor.
    await app.withTenant(tenant, () =>
      app.client.query(
        `update identity_mfa_enrollment set secret_ciphertext = $1 where account_id = $2`,
        [victimRow!.secret_ciphertext, attacker],
      ),
    );

    await expect(
      replicaA.verifier(tenant, attacker).verifyTotpCode(tenant, attacker, '123456'),
    ).rejects.toMatchObject({ code: 'CRYPTO_VERIFICATION_FAILED' });
  });

  it('does not open under a different key with the same id', async () => {
    const user = await account();
    await enrol(replicaA, user);
    const impostor = build(buildMfaKeys(`k1=${K2}`, 'k1') as MfaKeys, cacheA);

    await expect(
      impostor.verifier(tenant, user).verifyTotpCode(tenant, user, '123456'),
    ).rejects.toMatchObject({ code: 'CRYPTO_VERIFICATION_FAILED' });
  });

  it('does not open when the key it names has been dropped from the ring', async () => {
    const user = await account();
    await enrol(replicaA, user);
    const rotatedAway = build(buildMfaKeys(`k2=${K2}`, 'k2') as MfaKeys, cacheA);

    await expect(
      rotatedAway.verifier(tenant, user).verifyTotpCode(tenant, user, '123456'),
    ).rejects.toMatchObject({ code: 'CRYPTO_KEY_UNKNOWN' });
  });
});

describe('key rotation', () => {
  it('keeps old secrets and recovery codes working, then re-seals under the new primary', async () => {
    // An organisation of its own: the tampering tests above leave rows that rightly fail to open.
    const rotating = (await createOrganisation(owner, 'mfa-rotation')) as TenantId;
    const tenant = rotating;
    const user = await account(rotating);
    const { secret, codes } = await enrol(replicaA, user, rotating);

    const rotated = build(buildMfaKeys(`k1=${K1},k2=${K2}`, 'k2') as MfaKeys, cacheA);
    const at = await steadyNow();
    expect(
      await rotated.verifier(tenant, user).verifyTotpCode(tenant, user, totpCode(secret, at)),
    ).toBe(true);
    expect(await rotated.verifier(tenant, user).verifyRecoveryCode(tenant, user, codes[0]!)).toBe(
      true,
    );

    const result = await rotated.store.reencryptTenant(tenant);
    expect(result.failed).toBe(0);
    expect(result.resealed).toBeGreaterThanOrEqual(1);
    const [row] = await rowsFor(user, rotating);
    expect(row!.key_id).toBe('k2');
    expect(row!.secret_ciphertext.startsWith('v1.k2.')).toBe(true);

    // Codes keyed under k1 still block retiring it, and are reported.
    expect(await rotated.store.recoveryCodesUnderRetiredKeys(tenant)).toBeGreaterThan(0);

    // After re-encryption the secret opens under a ring that no longer has k1 at all.
    const k2only = build(buildMfaKeys(`k2=${K2}`, 'k2') as MfaKeys, cacheB);
    expect(
      await k2only
        .verifier(tenant, user)
        .verifyTotpCode(tenant, user, totpCode(secret, at + 30_000)),
    ).toBe(true);
  });
});

describe('replay', () => {
  it('refuses the same code twice on one replica', async () => {
    const user = await account();
    const { secret } = await enrol(replicaA, user);
    const code = totpCode(secret, (await steadyNow()) + 30_000);

    expect(await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, code)).toBe(true);
    expect(await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, code)).toBe(false);
  });

  it('refuses a code on one replica that another replica has accepted', async () => {
    const user = await account();
    const { secret } = await enrol(replicaA, user);
    const code = totpCode(secret, (await steadyNow()) + 30_000);

    expect(await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, code)).toBe(true);
    expect(await replicaB.verifier(tenant, user).verifyTotpCode(tenant, user, code)).toBe(false);
  });

  it('accepts exactly one of many concurrent submissions of one code', async () => {
    const user = await account();
    const { secret } = await enrol(replicaA, user);
    const code = totpCode(secret, (await steadyNow()) + 30_000);

    const results = await Promise.all(
      Array.from({ length: 12 }, (_, index) =>
        (index % 2 === 0 ? replicaA : replicaB)
          .verifier(tenant, user)
          .verifyTotpCode(tenant, user, code),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('refuses an invalid code', async () => {
    const user = await account();
    const { secret } = await enrol(replicaA, user);
    const valid = totpCode(secret, await steadyNow());
    const wrong = valid === '000000' ? '000001' : '000000';

    expect(await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, wrong)).toBe(false);
    expect(await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, '')).toBe(false);
    expect(await replicaA.verifier(tenant, user).verifyTotpCode(tenant, user, 'abcdef')).toBe(
      false,
    );
  });
});

describe('recovery codes', () => {
  it('are stored only as keyed hashes', async () => {
    const user = await account();
    const { codes } = await enrol(replicaA, user);
    const stored = await app.withTenant(tenant, async () => {
      const { rows } = await app.client.query(
        'select code_hash, key_id from identity_mfa_recovery_code where account_id = $1',
        [user],
      );
      return rows as { code_hash: string; key_id: string }[];
    });

    expect(stored).toHaveLength(10);
    const hashes = new Set(stored.map((row) => row.code_hash));
    for (const code of codes) {
      expect(hashes.has(sha256Hex(code))).toBe(false);
      for (const hash of hashes) expect(hash).not.toContain(code);
    }
    expect(new Set(stored.map((row) => row.key_id))).toEqual(new Set(['k1']));
  });

  it('are single use', async () => {
    const user = await account();
    const { codes } = await enrol(replicaA, user);

    expect(await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, codes[0]!)).toBe(
      true,
    );
    expect(await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, codes[0]!)).toBe(
      false,
    );
    expect(await replicaB.verifier(tenant, user).verifyRecoveryCode(tenant, user, codes[0]!)).toBe(
      false,
    );
    expect(await replicaA.store.remainingRecoveryCodes(tenant, user)).toBe(9);
  });

  it('are spent exactly once under concurrent presentation across replicas', async () => {
    const user = await account();
    const { codes } = await enrol(replicaA, user);

    const results = await Promise.all(
      Array.from({ length: 16 }, (_, index) =>
        (index % 2 === 0 ? replicaA : replicaB)
          .verifier(tenant, user)
          .verifyRecoveryCode(tenant, user, codes[1]!),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('accept the code however it is cased, and refuse anything else', async () => {
    const user = await account();
    const { codes } = await enrol(replicaA, user);

    expect(
      await replicaA
        .verifier(tenant, user)
        .verifyRecoveryCode(tenant, user, ` ${codes[2]!.toLowerCase()} `),
    ).toBe(true);
    expect(
      await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, 'AAAAA-BBBBB-CCCCC'),
    ).toBe(false);
  });

  it('are replaced, not added to, when a new set is saved', async () => {
    const user = await account();
    const { codes } = await enrol(replicaA, user);
    await replicaA.store.saveRecoveryCodes(tenant, user, [sha256Hex('NEW00-CODE0-SET00')]);

    expect(await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, codes[3]!)).toBe(
      false,
    );
    expect(
      await replicaA.verifier(tenant, user).verifyRecoveryCode(tenant, user, 'NEW00-CODE0-SET00'),
    ).toBe(true);
  });

  it('cannot be saved or spent without an active factor', async () => {
    const user = await account();
    await expect(
      replicaA.store.saveRecoveryCodes(tenant, user, [sha256Hex('X')]),
    ).rejects.toMatchObject({ code: 'AUTH_MFA_INVALID' });

    const enrolled = await account();
    const { codes } = await enrol(replicaA, enrolled);
    await replicaA.verifier(tenant, enrolled).remove(tenant, enrolled, 'totp');

    expect(await enrolledFlag(enrolled)).toBe(false);
    expect(await replicaA.store.remainingRecoveryCodes(tenant, enrolled)).toBe(0);
    expect(
      await replicaA.verifier(tenant, enrolled).verifyRecoveryCode(tenant, enrolled, codes[0]!),
    ).toBe(false);
  });

  it('are not spendable through the enrollment view', async () => {
    const user = await account();
    const { codes } = await enrol(replicaA, user);
    expect(await replicaA.enroller(tenant, user).verifyRecoveryCode(tenant, user, codes[0]!)).toBe(
      false,
    );
  });
});

describe('tenant isolation', () => {
  let user: UserId;
  let secret: string;
  let codes: readonly string[];

  beforeEach(async () => {
    user = await account(tenant);
    ({ secret, codes } = await enrol(replicaA, user, tenant));
  });

  it('does not show one organisation’s factor to another, even for the same account id', async () => {
    expect(await replicaA.verifier(otherTenant, user).isEnrolled(otherTenant, user)).toBe(false);
    expect(await replicaA.store.list(otherTenant, user)).toEqual([]);
    expect(
      await replicaA
        .verifier(otherTenant, user)
        .verifyTotpCode(otherTenant, user, totpCode(secret, Date.now())),
    ).toBe(false);
    expect(
      await replicaA.verifier(otherTenant, user).verifyRecoveryCode(otherTenant, user, codes[0]!),
    ).toBe(false);
  });

  it('shows nothing at all without a tenant context', async () => {
    const seen = await app.withoutTenant(async () => {
      const enrollments = await app.client.query('select id from identity_mfa_enrollment');
      const recovery = await app.client.query('select id from identity_mfa_recovery_code');
      return enrollments.rowCount! + recovery.rowCount!;
    });
    expect(seen).toBe(0);
  });

  it('cannot write a factor into another organisation', async () => {
    await expect(
      app.withTenant(tenant, () =>
        app.client.query(
          `insert into identity_mfa_recovery_code (id, tenant_id, account_id, code_hash, key_id, created_at)
           values (gen_random_uuid(), $1, $2, $3, 'k1', now())`,
          [otherTenant, user, 'a'.repeat(64)],
        ),
      ),
    ).rejects.toThrow(/row-level security/i);
  });

  it('carries the same tenant_isolation policy as every other tenant table', async () => {
    const { rows } = await app.client.query(
      `select tablename, policyname, qual, with_check from pg_policies
        where tablename in ('identity_mfa_enrollment', 'identity_mfa_recovery_code')
        order by tablename`,
    );
    expect(rows.map((row) => [row.tablename, row.policyname])).toEqual([
      ['identity_mfa_enrollment', 'tenant_isolation'],
      ['identity_mfa_recovery_code', 'tenant_isolation'],
    ]);
    for (const row of rows) {
      expect(row.qual).toContain('identity_current_tenant()');
      expect(row.with_check).toContain('identity_current_tenant()');
    }
  });
});

describe('production startup', () => {
  const production = { MUNAXA_ENV: 'production' } as const;

  it('refuses to run without MFA', () => {
    expect(() => assertMfaDistributed(production, 'redis', undefined)).toThrow(
      /MFA_ENCRYPTION_KEYS/,
    );
  });

  it('refuses process-local replay protection', () => {
    expect(() => assertMfaDistributed(production, 'memory', replicaA)).toThrow(/replay guard/);
  });

  it('runs with a Redis replay guard', () => {
    expect(replicaA.distributed).toBe(true);
    expect(() => assertMfaDistributed(production, 'redis', replicaA)).not.toThrow();
  });

  it('allows development to run without MFA', () => {
    expect(() =>
      assertMfaDistributed({ MUNAXA_ENV: 'development' }, 'memory', undefined),
    ).not.toThrow();
  });
});
