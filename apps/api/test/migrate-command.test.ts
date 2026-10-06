import { describe, expect, it, vi } from 'vitest';

import { REQUIRED_TABLES } from '../src/health/readiness.js';
import { main } from '../src/migrate.js';
import { FakeDatabase } from './fake-database.js';

/**
 * The `node dist/migrate.js` entrypoint, end to end against an in-memory database.
 *
 * The mocks below are the assertion that the migration command does not start the HTTP service.
 * `vi.mock` factories run only if the module is actually imported, so if the migration command —
 * or anything it imports — ever reached Nest, the application module or the service's
 * configuration, these would throw and every test in this file would fail. Nothing is mocked out of
 * the way of the code under test; the mocks exist only to detect an import that must not happen.
 */
vi.mock('@nestjs/core', () => {
  throw new Error('the migration command imported @nestjs/core');
});
vi.mock('@nestjs/platform-express', () => {
  throw new Error('the migration command imported @nestjs/platform-express');
});
vi.mock('../src/app.module.js', () => {
  throw new Error('the migration command imported the application module');
});
vi.mock('../src/main.js', () => {
  throw new Error('the migration command imported the service entrypoint');
});
vi.mock('@identity/config', () => {
  throw new Error('the migration command loaded the service configuration');
});

const ENV = {
  DIRECT_DATABASE_URL: 'postgresql://identity_mig:not-a-real-password@localhost:5432/identity',
};

const run = async (
  argv: readonly string[],
  db: FakeDatabase,
  env: Record<string, string> = ENV,
) => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const code = await main(argv, {
    env,
    connect: () => Promise.resolve(db),
    stdout: (line) => stdout.push(line),
    stderr: (line) => stderr.push(line),
  });
  return { code, stdout, stderr };
};

const database = (): FakeDatabase => {
  const db = new FakeDatabase();
  db.createsTables = REQUIRED_TABLES;
  return db;
};

describe('node dist/migrate.js', () => {
  it('applies the real baseline from the repository and exits 0, without the HTTP service', async () => {
    const db = database();

    const { code, stdout } = await run([], db);

    expect(code).toBe(0);
    expect(db.executed).toHaveLength(1);
    expect(db.ledger.map((row) => row.name)).toEqual(['20260901120000_identity_baseline']);
    expect(stdout.map((line) => (JSON.parse(line) as { event: string }).event)).toEqual([
      'migrate.start',
      'migrate.role',
      'migrate.applied',
      'migrate.done',
    ]);
  });

  it('exits 0 and applies nothing the second time', async () => {
    const db = database();

    await run([], db);
    const second = await run([], db);

    expect(second.code).toBe(0);
    expect(db.executed).toHaveLength(1);
  });

  it('exits non-zero when a migration fails, and records nothing', async () => {
    const db = database();
    const { readFileSync } = await import('node:fs');
    const { resolve } = await import('node:path');
    db.failOn = readFileSync(
      resolve(
        __dirname,
        '../../../prisma/migrations/20260901120000_identity_baseline/migration.sql',
      ),
      'utf8',
    );

    const { code, stderr } = await run([], db);

    expect(code).toBe(1);
    expect(db.ledger).toEqual([]);
    expect(JSON.parse(stderr[0] ?? '{}')).toMatchObject({
      event: 'migrate.failed',
      migration: '20260901120000_identity_baseline',
    });
  });

  it('exits non-zero, without connecting, when the owner credential is missing', async () => {
    const db = database();

    const { code, stderr } = await run([], db, { DATABASE_URL: ENV.DIRECT_DATABASE_URL });

    expect(code).toBe(1);
    expect(db.statements).toEqual([]);
    expect(stderr.join('\n')).not.toContain('not-a-real-password');
  });

  it('never prints the password, on success or failure', async () => {
    const db = database();
    const ok = await run([], db);
    const refused = database();
    refused.role = { role: 'identity_app', superuser: false, bypass: false };
    const failed = await run([], refused);

    expect(
      [...ok.stdout, ...ok.stderr, ...failed.stdout, ...failed.stderr].join('\n'),
    ).not.toContain('not-a-real-password');
    expect(failed.code).toBe(1);
  });

  it('exits 2 on an unknown argument, before touching the database', async () => {
    const db = database();

    const { code } = await run(['--yes-really'], db);

    expect(code).toBe(2);
    expect(db.statements).toEqual([]);
  });

  it('passes --adopt-baseline through', async () => {
    const db = database();
    db.tables = [...REQUIRED_TABLES];

    const { code } = await run(['--adopt-baseline'], db);

    expect(code).toBe(0);
    expect(db.executed).toEqual([]);
    expect(db.ledger).toMatchObject([{ mode: 'adopted' }]);
  });
});
