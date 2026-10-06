import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';

import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { OWNER_URL } from './index.js';
import { main as migrate } from '../../../apps/api/src/migrate.js';

/**
 * `bootstrap-account.mjs` and `seed-work-roles.mjs` against a real PostgreSQL, through the shared
 * owner connection. **Requires a server**: `TEST_SUPERUSER_URL` creates and drops a throwaway
 * database (CI sets it); without it the suite skips and says so. Needs `apps/api/dist` built, which
 * is where the scripts load the shared connection module from.
 *
 * This is the "nothing else changed" half. Their TLS behaviour is proved against a real handshake in
 * `apps/api/test/provisioning-scripts-tls.test.ts`; here the database is local and plain text, and
 * what is asserted is that organisations, accounts, roles and assignments come out exactly as they
 * did before the connection moved.
 */

const SUPERUSER_URL = process.env.TEST_SUPERUSER_URL;
const SCRIPTS = resolve(__dirname, '../../../apps/api/scripts');
const PASSWORD = 'integration-Passphrase-Long-Enough-2026';

const withDatabase = (url: string, database: string): string => {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
};

const script = (
  name: 'bootstrap-account' | 'seed-work-roles',
  args: readonly string[],
  env: Readonly<Record<string, string>>,
): Promise<{ code: number; output: string }> =>
  new Promise((done) => {
    execFile(
      process.execPath,
      [resolve(SCRIPTS, `${name}.mjs`), ...args],
      { env: { PATH: process.env.PATH ?? '', ...env }, timeout: 30_000 },
      (error, stdout, stderr) =>
        done({
          code: error === null ? 0 : typeof error.code === 'number' ? error.code : 1,
          output: `${stdout}${stderr}`,
        }),
    );
  });

describe.skipIf(SUPERUSER_URL === undefined)('the provisioning scripts against PostgreSQL', () => {
  let admin: pg.Client;
  let database: string;
  let ownerUrl: string;

  /** As the owner, inside an organisation's context — FORCE row-level security binds the owner too. */
  const inOrganisation = async (tenantId: string, sql: string, values: unknown[] = []) => {
    const client = new pg.Client({ connectionString: ownerUrl });
    await client.connect();
    try {
      await client.query('begin');
      await client.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
      const { rows } = await client.query(sql, values);
      await client.query('commit');
      return rows as Record<string, unknown>[];
    } finally {
      await client.end();
    }
  };

  const organisationId = async (slug: string): Promise<string> => {
    const client = new pg.Client({ connectionString: ownerUrl });
    await client.connect();
    try {
      const { rows } = await client.query('select id from identity_tenant where key = $1', [slug]);
      return String((rows[0] as { id: string }).id);
    } finally {
      await client.end();
    }
  };

  beforeAll(async () => {
    admin = new pg.Client({ connectionString: SUPERUSER_URL });
    await admin.connect();
    database = `identity_scripts_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
    await admin.query(
      `create database ${database} owner ${decodeURIComponent(new URL(OWNER_URL).username)}`,
    );
    ownerUrl = withDatabase(OWNER_URL, database);
    const migrated = await migrate([], {
      env: { DIRECT_DATABASE_URL: ownerUrl },
      stdout: () => undefined,
      stderr: () => undefined,
    });
    expect(migrated).toBe(0);
  });

  afterAll(async () => {
    await admin?.query(`drop database if exists ${database} with (force)`);
    await admin?.end();
  });

  const env = (): Record<string, string> => ({
    DIRECT_DATABASE_URL: ownerUrl,
    IDENTITY_OWNER_EMAIL: 'operator@example.invalid',
    IDENTITY_OWNER_PASSWORD: PASSWORD,
  });

  it('bootstraps an organisation and its first account, through the shared connection', async () => {
    const first = await script(
      'bootstrap-account',
      ['--organisation', 'acme', '--organisation-name', 'Acme'],
      env(),
    );

    expect(first.code).toBe(0);
    expect(first.output).toContain('TLS none');
    expect(first.output).toContain('Created operator@example.invalid in organisation acme.');

    const tenant = await organisationId('acme');
    const accounts = await inOrganisation(
      tenant,
      'select identifier, status, created_by from identity_account',
    );
    expect(accounts).toEqual([
      { identifier: 'operator@example.invalid', status: 'active', created_by: 'system:bootstrap' },
    ]);
    expect(first.output).toContain('sub ');
  });

  it('is still idempotent: a second run writes nothing', async () => {
    const tenant = await organisationId('acme');
    const before = await inOrganisation(
      tenant,
      'select password_hash, updated_at from identity_account',
    );

    const again = await script('bootstrap-account', ['--organisation', 'acme'], env());

    expect(again.code).toBe(0);
    expect(again.output).toContain('Already bootstrapped.');
    expect(
      await inOrganisation(tenant, 'select password_hash, updated_at from identity_account'),
    ).toEqual(before);
  });

  it('seeds the Work roles, then assigns one, exactly as before', async () => {
    const seeded = await script('seed-work-roles', ['--organisation', 'acme'], {
      DIRECT_DATABASE_URL: ownerUrl,
    });
    expect(seeded.code).toBe(0);
    expect(seeded.output).toContain('work-staging-operator:');

    const tenant = await organisationId('acme');
    const roles = await inOrganisation(
      tenant,
      'select key, system from identity_role order by key',
    );
    expect(roles.length).toBeGreaterThan(0);
    expect(roles.every((role) => role.system === true)).toBe(true);

    const assigned = await script(
      'bootstrap-account',
      ['--organisation', 'acme', '--role', 'work-staging-operator'],
      env(),
    );
    expect(assigned.code).toBe(0);
    expect(assigned.output).toContain('Assigned work-staging-operator, unscoped.');
    expect(
      await inOrganisation(
        tenant,
        `select a.scope, r.key from identity_role_assignment a join identity_role r on r.id = a.role_id`,
      ),
    ).toEqual([{ scope: '', key: 'work-staging-operator' }]);
  });

  it('still applies the real password policy before touching the database', async () => {
    const weak = await script('bootstrap-account', ['--organisation', 'other'], {
      ...env(),
      IDENTITY_OWNER_PASSWORD: 'short',
    });

    expect(weak.code).toBe(1);
    expect(weak.output).toContain('does not meet the password policy');
  });
});
