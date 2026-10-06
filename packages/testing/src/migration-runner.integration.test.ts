import { randomUUID } from 'node:crypto';

import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL } from './index.js';
import { main } from '../../../apps/api/src/migrate.js';

/**
 * The migration runner against a real PostgreSQL. **Requires a server**: it needs
 * `TEST_SUPERUSER_URL` (CI sets it) to create and drop its own throwaway databases, and skips —
 * saying so — without it. It never touches `identity_test` or any other existing database.
 *
 * Each database is created owned by the migration role, as the provisioning runbook and RDS have
 * it, and the runner is invoked through the same `main` the image's `node dist/migrate.js` runs.
 * The unit suites in `apps/api/test` prove the runner's decisions against a stand-in; this proves
 * the parts a stand-in cannot have — the real baseline executing, the ledger in its own schema,
 * row-level security forced afterwards, and the roles being refused by the real catalogue.
 */

const SUPERUSER_URL = process.env.TEST_SUPERUSER_URL;

const withDatabase = (url: string, database: string): string => {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
};

const roleOf = (url: string): string => decodeURIComponent(new URL(url).username);

const created: string[] = [];
let admin: pg.Client | undefined;

const freshDatabase = async (): Promise<string> => {
  if (admin === undefined) throw new Error('no superuser connection');
  const name = `identity_migrate_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
  await admin.query(`create database ${name} owner ${roleOf(OWNER_URL)}`);
  created.push(name);
  return name;
};

const migrate = async (
  database: string,
  argv: readonly string[] = [],
  url = OWNER_URL,
): Promise<{ code: number; events: Record<string, unknown>[]; errors: string[] }> => {
  const events: Record<string, unknown>[] = [];
  const errors: string[] = [];
  const code = await main(argv, {
    env: { DIRECT_DATABASE_URL: withDatabase(url, database) },
    stdout: (line) => events.push(JSON.parse(line) as Record<string, unknown>),
    stderr: (line) => errors.push(line),
  });
  return { code, events, errors };
};

const query = async (database: string, sql: string): Promise<Record<string, unknown>[]> => {
  const client = new pg.Client({ connectionString: withDatabase(OWNER_URL, database) });
  await client.connect();
  try {
    return (await client.query(sql)).rows as Record<string, unknown>[];
  } finally {
    await client.end();
  }
};

describe.skipIf(SUPERUSER_URL === undefined)('the migration runner against PostgreSQL', () => {
  beforeAll(async () => {
    admin = new pg.Client({ connectionString: SUPERUSER_URL });
    await admin.connect();
  });

  afterAll(async () => {
    for (const name of created) {
      await admin?.query(`drop database if exists ${name} with (force)`);
    }
    await admin?.end();
  });

  it('applies the baseline once, records it, and leaves every public table with forced RLS', async () => {
    const database = await freshDatabase();

    const first = await migrate(database);

    expect(first.code).toBe(0);
    expect(first.events.at(-1)).toMatchObject({
      event: 'migrate.done',
      applied: ['20260901120000_identity_baseline'],
    });
    expect(
      await query(database, 'select name, mode, applied_by from identity_migration.applied'),
    ).toEqual([
      { name: '20260901120000_identity_baseline', mode: 'applied', applied_by: roleOf(OWNER_URL) },
    ]);

    const unforced = await query(
      database,
      `select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind = 'r' and c.relname <> 'identity_tenant'
          and not (c.relrowsecurity and c.relforcerowsecurity)`,
    );
    expect(unforced).toEqual([]);
  });

  it('is idempotent: a second run applies nothing and changes nothing', async () => {
    const database = await freshDatabase();
    await migrate(database);
    const before = await query(database, 'select name, applied_at from identity_migration.applied');

    const second = await migrate(database);

    expect(second.code).toBe(0);
    expect(second.events.at(-1)).toMatchObject({ applied: [], alreadyApplied: 1 });
    expect(
      await query(database, 'select name, applied_at from identity_migration.applied'),
    ).toEqual(before);
  });

  /** A migrations tree: the real baseline, then whatever the test adds after it. */
  const migrationsWith = async (extra: Readonly<Record<string, string>>): Promise<string> => {
    const { cpSync, mkdtempSync, mkdirSync, writeFileSync } = await import('node:fs');
    const { join, resolve } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const directory = mkdtempSync(join(tmpdir(), 'identity-migrations-'));
    cpSync(resolve(__dirname, '../../../prisma/migrations'), directory, { recursive: true });
    for (const [name, sql] of Object.entries(extra)) {
      mkdirSync(join(directory, name));
      writeFileSync(join(directory, name, 'migration.sql'), sql);
    }
    return directory;
  };

  const migrateFrom = async (database: string, migrationsDirectory: string) => {
    const errors: string[] = [];
    const code = await main([], {
      env: { DIRECT_DATABASE_URL: withDatabase(OWNER_URL, database) },
      migrationsDirectory,
      stdout: () => undefined,
      stderr: (line) => errors.push(line),
    });
    return { code, errors };
  };

  it('rolls a failing migration back entirely — its partial DDL too — and records nothing', async () => {
    const database = await freshDatabase();
    const directory = await migrationsWith({
      '20261001000000_half_done': 'create table identity_half_done (id int);\nselect 1 / 0;',
    });

    const failed = await migrateFrom(database, directory);

    expect(failed.code).toBe(1);
    expect(JSON.parse(failed.errors[0] ?? '{}')).toMatchObject({
      event: 'migrate.failed',
      migration: '20261001000000_half_done',
    });
    expect(await query(database, 'select name from identity_migration.applied')).toEqual([
      { name: '20260901120000_identity_baseline' },
    ]);
    expect(
      await query(database, `select to_regclass('public.identity_half_done') is null as gone`),
    ).toEqual([{ gone: true }]);
  });

  it('reports a connection dropped mid-migration as a failure, instead of crashing', async () => {
    const database = await freshDatabase();
    const directory = await migrationsWith({ '20261001000000_slow': 'select pg_sleep(10);' });

    const terminate = (async () => {
      // Wait until the slow migration is the statement running, then end the session as a
      // failover would.
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const { rows } = (await admin?.query(
          `select pg_terminate_backend(pid) as ended from pg_stat_activity
            where datname = $1 and query like 'select pg_sleep%'`,
          [database],
        )) ?? { rows: [] };
        if (rows.length > 0) return;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    })();

    const failed = await migrateFrom(database, directory);
    await terminate;

    expect(failed.code).toBe(1);
    expect(JSON.parse(failed.errors[0] ?? '{}')).toMatchObject({
      event: 'migrate.failed',
      migration: '20261001000000_slow',
    });
    expect(await query(database, 'select name from identity_migration.applied')).toEqual([
      { name: '20260901120000_identity_baseline' },
    ]);
  });

  it('refuses the runtime role and writes nothing', async () => {
    const database = await freshDatabase();

    const refused = await migrate(database, [], APPLICATION_URL);

    expect(refused.code).toBe(1);
    expect(refused.errors.join('\n')).toMatch(/runtime role/);
    expect(
      await query(
        database,
        `select count(*)::int as n from information_schema.schemata where schema_name = 'identity_migration'`,
      ),
    ).toEqual([{ n: 0 }]);
  });

  it('refuses a psql-provisioned database until it is adopted, then adopts without re-running', async () => {
    const database = await freshDatabase();
    const { readFileSync } = await import('node:fs');
    const { resolve } = await import('node:path');
    const baseline = readFileSync(
      resolve(
        __dirname,
        '../../../prisma/migrations/20260901120000_identity_baseline/migration.sql',
      ),
      'utf8',
    );
    await query(database, baseline);

    const refused = await migrate(database);
    expect(refused.code).toBe(1);
    expect(refused.errors.join('\n')).toMatch(/--adopt-baseline/);

    const adopted = await migrate(database, ['--adopt-baseline']);
    expect(adopted.code).toBe(0);
    expect(await query(database, 'select mode from identity_migration.applied')).toEqual([
      { mode: 'adopted' },
    ]);

    const after = await migrate(database);
    expect(after.code).toBe(0);
    expect(after.events.at(-1)).toMatchObject({ applied: [], alreadyApplied: 1 });
  });
});
