import { describe, expect, it } from 'vitest';

import { REQUIRED_TABLES } from '../src/health/readiness.js';
import {
  MigrationError,
  checksumOf,
  discoverMigrations,
  runMigrations,
  type Migration,
  type MigrationFiles,
} from '../src/migrations/migration-runner.js';
import { FakeDatabase } from './fake-database.js';

/**
 * The runner's decisions, against an in-memory stand-in for PostgreSQL. No database is needed;
 * the same behaviour against a real server is `packages/testing/src/migration-runner.integration.test.ts`.
 */

const migration = (name: string, sql = `-- ${name}\nselect 1;`): Migration => ({
  name,
  sql,
  checksum: checksumOf(sql),
});

const BASELINE = migration('20260901120000_identity_baseline', 'create table identity_account ();');
const SECOND = migration('20261001090000_second', 'alter table identity_account add column x int;');
const THIRD = migration('20261101090000_third', 'alter table identity_account add column y int;');

const database = (): FakeDatabase => {
  const fake = new FakeDatabase();
  fake.createsTables = REQUIRED_TABLES;
  return fake;
};

describe('the first run against an empty database', () => {
  it('creates the ledger, applies the baseline and records it', async () => {
    const db = database();

    const summary = await runMigrations({ client: db, migrations: [BASELINE] });

    expect(db.ledgerExists).toBe(true);
    expect(db.executed).toEqual([BASELINE.sql]);
    expect(db.ledger).toEqual([
      { name: BASELINE.name, checksum: BASELINE.checksum, mode: 'applied' },
    ]);
    expect(summary).toEqual({ applied: [BASELINE.name], adopted: [], alreadyApplied: 0 });
  });

  it('runs each migration and its ledger row in one transaction', async () => {
    const db = database();

    await runMigrations({ client: db, migrations: [BASELINE] });

    const relevant = db.statements
      .map((statement) => statement.trim().split(/\s+/).slice(0, 3).join(' ').toLowerCase())
      .filter((statement) =>
        [
          'begin',
          'commit',
          'insert into identity_migration.applied',
          'create table identity_account',
        ].some((prefix) => statement.startsWith(prefix)),
      );
    expect(relevant).toEqual([
      'begin',
      'create table identity_account',
      'insert into identity_migration.applied',
      'commit',
    ]);
  });
});

describe('a second run', () => {
  it('applies nothing and records nothing new', async () => {
    const db = database();

    await runMigrations({ client: db, migrations: [BASELINE] });
    const again = await runMigrations({ client: db, migrations: [BASELINE] });

    expect(db.executed).toEqual([BASELINE.sql]);
    expect(db.ledger).toHaveLength(1);
    expect(again).toEqual({ applied: [], adopted: [], alreadyApplied: 1 });
  });

  it('applies only what is new since', async () => {
    const db = database();

    await runMigrations({ client: db, migrations: [BASELINE] });
    const next = await runMigrations({ client: db, migrations: [BASELINE, SECOND] });

    expect(db.executed).toEqual([BASELINE.sql, SECOND.sql]);
    expect(next.applied).toEqual([SECOND.name]);
  });
});

describe('a migration that fails', () => {
  it('is rolled back and never recorded as applied', async () => {
    const db = database();
    db.failOn = SECOND.sql;

    const run = runMigrations({ client: db, migrations: [BASELINE, SECOND, THIRD] });

    await expect(run).rejects.toThrow(MigrationError);
    await expect(run).rejects.toMatchObject({ migration: SECOND.name });
    expect(db.ledger.map((row) => row.name)).toEqual([BASELINE.name]);
    expect(db.statements.map((statement) => statement.trim().toLowerCase())).toContain('rollback');
  });

  it('stops the run, so nothing after it is attempted', async () => {
    const db = database();
    db.failOn = SECOND.sql;

    await expect(
      runMigrations({ client: db, migrations: [BASELINE, SECOND, THIRD] }),
    ).rejects.toThrow();

    expect(db.executed).toEqual([BASELINE.sql]);
  });

  it('is retried by the next run, because it was never recorded', async () => {
    const db = database();
    db.failOn = SECOND.sql;
    await expect(runMigrations({ client: db, migrations: [BASELINE, SECOND] })).rejects.toThrow();

    db.failOn = undefined;
    const retry = await runMigrations({ client: db, migrations: [BASELINE, SECOND] });

    expect(retry.applied).toEqual([SECOND.name]);
  });

  it('still releases the advisory lock', async () => {
    const db = database();
    db.failOn = BASELINE.sql;

    await expect(runMigrations({ client: db, migrations: [BASELINE] })).rejects.toThrow();

    expect(db.lockAcquisitions).toBe(1);
    expect(db.locked).toBe(false);
  });
});

describe('order', () => {
  const files = (names: readonly string[]): MigrationFiles => ({
    list: () => names,
    isDirectory: () => true,
    exists: () => true,
    read: (path) => `-- ${path}`,
  });

  it('is by directory name, whatever order the filesystem lists them in', () => {
    const shuffled = [THIRD.name, BASELINE.name, SECOND.name];

    expect(discoverMigrations('/m', files(shuffled)).map((found) => found.name)).toEqual([
      BASELINE.name,
      SECOND.name,
      THIRD.name,
    ]);
  });

  it('is the same on every run', () => {
    const one = discoverMigrations('/m', files([SECOND.name, BASELINE.name]));
    const two = discoverMigrations('/m', files([BASELINE.name, SECOND.name]));

    expect(one).toEqual(two);
  });

  it('is the order migrations are applied in', async () => {
    const db = database();

    await runMigrations({ client: db, migrations: [BASELINE, SECOND, THIRD] });

    expect(db.executed).toEqual([BASELINE.sql, SECOND.sql, THIRD.sql]);
  });

  it('refuses a directory that is not a migration rather than skipping it', () => {
    expect(() => discoverMigrations('/m', files([BASELINE.name, 'notes']))).toThrow(
      /not a migration directory/,
    );
  });

  it('refuses a migration directory without its SQL', () => {
    const missing: MigrationFiles = { ...files([BASELINE.name]), exists: (path) => path === '/m' };

    expect(() => discoverMigrations('/m', missing)).toThrow(/has no migration\.sql/);
  });
});

describe('a ledger that disagrees with the build', () => {
  it('refuses a recorded migration whose file has changed, and writes nothing', async () => {
    const db = database();
    db.ledger = [{ name: BASELINE.name, checksum: checksumOf('something else'), mode: 'applied' }];

    await expect(runMigrations({ client: db, migrations: [BASELINE, SECOND] })).rejects.toThrow(
      /checksum mismatch/,
    );
    expect(db.executed).toEqual([]);
    expect(db.ledger).toHaveLength(1);
  });

  it('refuses a database that is ahead of the build', async () => {
    const db = database();
    db.ledger = [
      { name: BASELINE.name, checksum: BASELINE.checksum, mode: 'applied' },
      { name: SECOND.name, checksum: SECOND.checksum, mode: 'applied' },
    ];

    await expect(runMigrations({ client: db, migrations: [BASELINE] })).rejects.toThrow(
      /not in this build/,
    );
  });

  it('refuses a pending migration older than one already applied', async () => {
    const db = database();
    db.ledger = [
      { name: BASELINE.name, checksum: BASELINE.checksum, mode: 'applied' },
      { name: THIRD.name, checksum: THIRD.checksum, mode: 'applied' },
    ];

    await expect(
      runMigrations({ client: db, migrations: [BASELINE, SECOND, THIRD] }),
    ).rejects.toThrow(/older than/);
    expect(db.executed).toEqual([]);
  });
});

describe('the role it runs as', () => {
  it('refuses the runtime role', async () => {
    const db = database();
    db.role = { role: 'identity_app', superuser: false, bypass: false };

    await expect(runMigrations({ client: db, migrations: [BASELINE] })).rejects.toThrow(
      /runtime role/,
    );
    expect(db.ledgerExists).toBe(false);
    expect(db.lockAcquisitions).toBe(0);
  });

  it('refuses a superuser and a role that bypasses row-level security', async () => {
    for (const role of [
      { role: 'postgres', superuser: true, bypass: true },
      { role: 'admin', superuser: false, bypass: true },
    ]) {
      const db = database();
      db.role = role;

      await expect(runMigrations({ client: db, migrations: [BASELINE] })).rejects.toThrow(
        /bypass row-level security/,
      );
      expect(db.executed).toEqual([]);
    }
  });
});

describe('a database provisioned with psql before the ledger existed', () => {
  const provisioned = (): FakeDatabase => {
    const db = database();
    db.tables = [...REQUIRED_TABLES];
    return db;
  };

  it('is refused rather than having the baseline run a second time', async () => {
    const db = provisioned();

    await expect(runMigrations({ client: db, migrations: [BASELINE] })).rejects.toThrow(
      /--adopt-baseline/,
    );
    expect(db.executed).toEqual([]);
    expect(db.ledger).toEqual([]);
  });

  it('is adopted on request: the baseline is recorded, not executed, and later ones apply', async () => {
    const db = provisioned();

    const summary = await runMigrations({
      client: db,
      migrations: [BASELINE, SECOND],
      adoptBaseline: true,
    });

    expect(summary).toEqual({
      applied: [SECOND.name],
      adopted: [BASELINE.name],
      alreadyApplied: 0,
    });
    expect(db.executed).toEqual([SECOND.sql]);
    expect(db.ledger.map((row) => [row.name, row.mode])).toEqual([
      [BASELINE.name, 'adopted'],
      [SECOND.name, 'applied'],
    ]);
  });

  it('cannot be adopted when the schema is incomplete', async () => {
    const db = database();
    db.tables = ['identity_account'];

    await expect(
      runMigrations({ client: db, migrations: [BASELINE], adoptBaseline: true }),
    ).rejects.toThrow(/missing/);
    expect(db.ledger).toEqual([]);
  });

  it('refuses --adopt-baseline once the ledger records anything', async () => {
    const db = database();
    await runMigrations({ client: db, migrations: [BASELINE] });

    await expect(
      runMigrations({ client: db, migrations: [BASELINE], adoptBaseline: true }),
    ).rejects.toThrow(/empty ledger/);
  });
});

describe('the real migrations directory', () => {
  it('holds the baseline, which the runner reads as written', async () => {
    const { resolve } = await import('node:path');
    const found = discoverMigrations(resolve(__dirname, '..', '..', '..', 'prisma', 'migrations'));

    expect(found[0]?.name).toBe('20260901120000_identity_baseline');
    expect(found[0]?.sql).toContain('force row level security');
  });
});
