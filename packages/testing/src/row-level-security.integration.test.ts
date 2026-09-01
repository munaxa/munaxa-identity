import { readFileSync } from 'node:fs';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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

/**
 * Row-level security, proved against a real PostgreSQL as the roles a deployment uses.
 *
 * Reading the generated SQL proves nothing here. Every property below is a property of a *role*
 * meeting a *policy* at runtime, and the two ways to get it wrong — a superuser connection, or an
 * owner connection without FORCE — both leave the schema looking identical and the isolation gone.
 * Munaxa Work shipped exactly that defect and its every gate passed (its ADR-0077), which is why
 * this suite connects as `identity_app` and checks what that role is before checking what it can
 * see.
 */

let app: Connection;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;
let alpha: string;
let beta: string;
let alphaAccount: string;
let betaAccount: string;

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await truncateAll(owner);

  app = await connect(APPLICATION_URL);
  alpha = await createOrganisation(owner, 'alpha');
  beta = await createOrganisation(owner, 'beta');
  alphaAccount = await createAccount(app, alpha, 'someone@alpha.example');
  betaAccount = await createAccount(app, beta, 'someone@beta.example');
});

afterAll(async () => {
  await truncateAll(owner);
  await app.release();
  owner.release();
  await ownerPool.end();
});

describe('the role the service connects as', () => {
  it('is not a superuser and cannot bypass row-level security', async () => {
    const { rows } = await app.client.query(
      `select rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication
         from pg_roles where rolname = current_user`,
    );

    expect(rows[0]).toEqual({
      rolsuper: false,
      rolbypassrls: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolreplication: false,
    });
  });

  it('cannot grant itself the bypass', async () => {
    await expect(app.client.query('alter role current_user with bypassrls')).rejects.toThrow();
  });

  it('cannot write an organisation, because provisioning is not the application’s to do', async () => {
    await expect(
      app.client.query(
        "insert into identity_tenant (id, key, name) values (gen_random_uuid(), 'x', 'x')",
      ),
    ).rejects.toThrow(/permission denied/i);
  });

  it('cannot rewrite or erase the audit trail', async () => {
    await expect(
      app.client.query('update identity_audit_event set hash = $1', ['x']),
    ).rejects.toThrow(/permission denied/i);
    await expect(app.client.query('delete from identity_audit_event')).rejects.toThrow(
      /permission denied/i,
    );
  });
});

describe('every table that carries a tenant', () => {
  it('has row-level security enabled and forced', async () => {
    const { rows } = await app.client.query(
      `select c.relname, c.relrowsecurity as enabled, c.relforcerowsecurity as forced
         from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind = 'r' and c.relname <> 'identity_tenant'
        order by c.relname`,
    );

    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      // Enabled without forced is the trap: it looks identical in a schema diff and exempts the
      // owner, so an application misconfigured to connect as the owner reads every organisation.
      expect([row.relname, row.enabled, row.forced]).toEqual([row.relname, true, true]);
    }
  });
});

describe('what a query can see', () => {
  it('sees nothing at all with no tenant context', async () => {
    const seen = await app.withoutTenant(async () =>
      app.client.query('select id from identity_account'),
    );

    // Not an error — no rows. The safe direction: a forgotten context returns nothing rather than
    // everything, and a bug reads as missing data rather than as a breach.
    expect(seen.rowCount).toBe(0);
  });

  it('sees its own organisation’s accounts', async () => {
    const seen = await app.withTenant(alpha, async () =>
      app.client.query('select id from identity_account'),
    );

    expect(seen.rows.map((row) => row.id)).toEqual([alphaAccount]);
  });

  it('sees the other organisation’s accounts when acting as it, and only those', async () => {
    const seen = await app.withTenant(beta, async () =>
      app.client.query('select id from identity_account'),
    );

    expect(seen.rows.map((row) => row.id)).toEqual([betaAccount]);
  });

  it('cannot read another organisation by naming its rows explicitly', async () => {
    const seen = await app.withTenant(alpha, async () =>
      app.client.query('select id from identity_account where id = $1', [betaAccount]),
    );

    expect(seen.rowCount).toBe(0);
  });

  it('cannot write into another organisation', async () => {
    await expect(
      app.withTenant(alpha, async () =>
        app.client.query(
          `insert into identity_account
             (id, tenant_id, identifier, identifier_normalized, status, token_version,
              mfa_enrolled, must_change_password, identity_source, created_at, updated_at, version)
           values (gen_random_uuid(), $1, 'smuggled@beta.example', 'smuggled@beta.example',
                   'active', 1, false, false, 'local', now(), now(), 1)`,
          [beta],
        ),
      ),
    ).rejects.toThrow(/row-level security/i);
  });

  it('cannot move a row into another organisation by updating its tenant', async () => {
    await expect(
      app.withTenant(alpha, async () =>
        app.client.query('update identity_account set tenant_id = $1 where id = $2', [
          beta,
          alphaAccount,
        ]),
      ),
    ).rejects.toThrow(/row-level security/i);
  });

  it('cannot delete another organisation’s rows', async () => {
    const deleted = await app.withTenant(alpha, async () =>
      app.client.query('delete from identity_account where id = $1', [betaAccount]),
    );

    // No error and no effect: the row is simply not visible to the statement.
    expect(deleted.rowCount).toBe(0);
  });
});

describe('the owner, whom FORCE also applies to', () => {
  it('reads nothing without a tenant context either', async () => {
    await owner.query('begin');
    const seen = await owner.query('select id from identity_account');
    await owner.query('commit');

    expect(seen.rowCount).toBe(0);
  });

  it('is not a superuser, so this suite is testing what a deployment has', async () => {
    const { rows } = await owner.query(
      'select rolsuper, rolbypassrls from pg_roles where rolname = current_user',
    );

    expect(rows[0]).toEqual({ rolsuper: false, rolbypassrls: false });
  });
});

describe('what Identity deliberately does not copy from Munaxa Work', () => {
  it('has no SECURITY DEFINER function, because it has no cross-tenant read to make', async () => {
    const { rows } = await app.client.query(
      `select p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public' and p.prosecdef`,
    );

    // Work needs one to answer "which tenants may this person act in?" before a tenant exists.
    // Every Platform port method here takes a tenant as its first argument, so the question never
    // arises — and a mechanism added by analogy would be a hole opened for a problem we do not have.
    expect(rows).toEqual([]);
  });
});

describe('the connection the service actually opens', () => {
  /**
   * Prisma resolves `env("DATABASE_URL")` itself and loads a `.env` file to do it. A client built
   * without an explicit datasource therefore connects to whatever `DATABASE_URL` is ambient — and
   * under the `*_FILE` secret convention that variable is deliberately unset, so a development
   * `.env` wins. The service starts, passes readiness, and answers every sign-in with a generic
   * 401 from the wrong database. This asserts the datasource is taken from configuration, which is
   * the only thing that stops it.
   */
  it('is the one the configuration names, not whatever DATABASE_URL happens to be', () => {
    const source = readFileSync(
      new URL('../../../apps/api/src/persistence/prisma.service.ts', import.meta.url),
      'utf8',
    );

    expect(source).toContain('datasources: { db: { url: environment.DATABASE_URL } }');
  });
});
