import { describe, expect, it } from 'vitest';
import pg from 'pg';

import { OWNER_URL, assertDestroyable } from './index.js';
import { REQUIRED_TABLES, probeReadiness } from '../../../apps/api/src/health/readiness.js';

/**
 * Readiness, proved by taking each dependency away in turn.
 *
 * Against a real PostgreSQL rather than a mocked client, because the failure this suite exists to
 * catch is precisely the one a mock cannot have: `select 1` succeeding against a database whose
 * application tables are gone. That query answers "is something listening", which is not the
 * question a load balancer is asking.
 */

/** A Prisma-shaped stand-in — `probeReadiness` uses exactly one method of it. */
const database = (
  onQuery: (sql: string) => Promise<unknown>,
): Parameters<typeof probeReadiness>[0] =>
  ({
    $queryRaw: (strings: TemplateStringsArray) => onQuery(strings.join('')),
  }) as unknown as Parameters<typeof probeReadiness>[0];

const realDatabase = (): Parameters<typeof probeReadiness>[0] => {
  const pool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  return database(async (sql) => (await pool.query(sql)).rows);
};

const signer = (works = true) => ({
  sign: (payload: string) => {
    if (!works) throw new Error('key unusable');
    return { value: `signed:${payload}` } as never;
  },
  verify: (payload: string, signature: { value: string }) =>
    works && signature.value === `signed:${payload}`,
});

const security = (options: {
  cache?: boolean;
  signing?: boolean;
}): Parameters<typeof probeReadiness>[1] =>
  ({
    cacheReachable: () => Promise.resolve(options.cache ?? true),
    signing: { signer: signer(options.signing ?? true), kid: 'test-kid' },
  }) as unknown as Parameters<typeof probeReadiness>[1];

const tables = (present: readonly string[]) =>
  database((sql) =>
    sql.includes('information_schema')
      ? Promise.resolve(present.map((table_name) => ({ table_name })))
      : Promise.resolve([{ '?column?': 1 }]),
  );

describe('readiness', () => {
  it('is ready when every dependency answers', async () => {
    const probe = await probeReadiness(tables(REQUIRED_TABLES), security({}));
    expect(probe).toEqual({ ok: true });
  });

  it('is not ready when the database is unreachable', async () => {
    const probe = await probeReadiness(
      database(() => Promise.reject(new Error('ECONNREFUSED'))),
      security({}),
    );
    expect(probe).toEqual({ ok: false, failed: 'database' });
  });

  it('is not ready when a required table is missing', async () => {
    // The exact hole this suite was written for: the connection is healthy and `select 1` passes.
    const present = REQUIRED_TABLES.filter((table) => table !== 'identity_account');
    const probe = await probeReadiness(tables(present), security({}));
    expect(probe.ok).toBe(false);
    expect(probe.failed).toBe('schema');
    expect(probe.missing).toEqual(['identity_account']);
  });

  it('is not ready on a schema that predates the MFA migration', async () => {
    // A new image rolled before `20261111130000_identity_mfa` ran must not take traffic: every
    // MFA, step-up and password-change request would fail against the missing tables.
    const mfaTables = ['identity_mfa_enrollment', 'identity_mfa_recovery_code'];
    const present = REQUIRED_TABLES.filter((table) => !mfaTables.includes(table));
    const probe = await probeReadiness(tables(present), security({}));
    expect(probe.ok).toBe(false);
    expect(probe.failed).toBe('schema');
    expect(probe.missing).toEqual(mfaTables);
  });

  it('is not ready when the cache is unreachable', async () => {
    const probe = await probeReadiness(tables(REQUIRED_TABLES), security({ cache: false }));
    expect(probe).toEqual({ ok: false, failed: 'cache' });
  });

  it('is not ready when the signing key cannot produce a verifiable signature', async () => {
    const probe = await probeReadiness(tables(REQUIRED_TABLES), security({ signing: false }));
    expect(probe).toEqual({ ok: false, failed: 'signing' });
  });

  it('finds every required table in a provisioned database', async () => {
    // Against the real schema, so the required-table list cannot drift away from the migration
    // without this failing.
    const probe = await probeReadiness(realDatabase(), security({}));
    expect(probe).toEqual({ ok: true });
  });
});

describe('the harness refuses to destroy a database that is in use', () => {
  it('accepts a name that identifies a throwaway', () => {
    for (const name of ['identity_test', 'test_identity', 'identity-test', 'testing']) {
      expect(() => assertDestroyable(`postgresql://u:p@localhost:5432/${name}`)).not.toThrow();
    }
  });

  it('refuses a name that does not', () => {
    // The exact mistake this guard exists for: the suite was pointed at a live staging database
    // and `truncateAll` emptied it, because nothing in the harness could tell the difference.
    for (const name of ['identity', 'work', 'identity_staging', 'production']) {
      expect(() => assertDestroyable(`postgresql://u:p@db.example:5432/${name}`)).toThrow(
        /Refusing to truncate/,
      );
    }
  });
});
