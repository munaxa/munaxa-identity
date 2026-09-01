import { randomUUID } from 'node:crypto';

import pg from 'pg';

/**
 * A real PostgreSQL, connected as the roles a deployment actually uses.
 *
 * Every security property this repository claims about the database is a property of *roles and
 * policies*, and none of them can be observed from a schema file or from a client that connects as
 * a superuser. Munaxa Work learned this the expensive way: its migrations ran as a superuser in CI,
 * `force row level security` does not apply to superusers, and a defect that would have taken every
 * authenticated request down in staging passed every gate (its ADR-0077). So the harness below
 * connects as `identity_app` — non-superuser, `NOBYPASSRLS` — and asserts that first.
 */

/** The restricted role the service runs as. */
export const APPLICATION_URL =
  process.env.TEST_DATABASE_URL ??
  'postgresql://identity_app:identity_app@localhost:5432/identity_test';

/** The migration owner. FORCE applies to it too, which is the point of using it in tests. */
export const OWNER_URL =
  process.env.TEST_DIRECT_DATABASE_URL ??
  'postgresql://identity:identity@localhost:5432/identity_test';

export interface Connection {
  readonly client: pg.PoolClient;
  /** Run `work` inside a transaction scoped to `tenantId`, exactly as the service does. */
  withTenant<T>(tenantId: string, work: () => Promise<T>): Promise<T>;
  /** Run `work` in a transaction with no tenant context at all. */
  withoutTenant<T>(work: () => Promise<T>): Promise<T>;
  release(): Promise<void>;
}

export const connect = async (url = APPLICATION_URL): Promise<Connection> => {
  const pool = new pg.Pool({ connectionString: url, max: 1 });
  const client = await pool.connect();

  const inTransaction = async <T>(
    tenantId: string | undefined,
    work: () => Promise<T>,
  ): Promise<T> => {
    await client.query('begin');
    try {
      if (tenantId !== undefined) {
        await client.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
      }
      const result = await work();
      await client.query('commit');
      return result;
    } catch (error) {
      await client.query('rollback').catch(() => undefined);
      throw error;
    }
  };

  return {
    client,
    withTenant: (tenantId, work) => inTransaction(tenantId, work),
    withoutTenant: (work) => inTransaction(undefined, work),
    release: async () => {
      client.release();
      await pool.end();
    },
  };
};

/** An organisation, created as the owner because provisioning is not the application's to do. */
export const createOrganisation = async (
  owner: pg.PoolClient,
  key: string,
  id: string = randomUUID(),
): Promise<string> => {
  await owner.query(
    `insert into identity_tenant (id, key, name, status, created_at)
     values ($1, $2, $3, 'active', now())`,
    [id, key, key],
  );
  return id;
};

/** An account in an organisation, written under that organisation's row-level security context. */
export const createAccount = async (
  connection: Connection,
  tenantId: string,
  identifier: string,
): Promise<string> => {
  const id = randomUUID();
  await connection.withTenant(tenantId, async () => {
    await connection.client.query(
      `insert into identity_account
         (id, tenant_id, identifier, identifier_normalized, password_hash, status, token_version,
          mfa_enrolled, must_change_password, identity_source, created_at, updated_at, version)
       values ($1, $2, $3, $4, '$scrypt$v=1$n=16384,r=8,p=1$c2FsdA$aGFzaA', 'active', 1,
               false, false, 'local', now(), now(), 1)`,
      [id, tenantId, identifier, identifier.toLowerCase()],
    );
  });
  return id;
};

/** Remove everything this suite wrote, as the owner, so a rerun starts clean. */
export const truncateAll = async (owner: pg.PoolClient): Promise<void> => {
  await owner.query(
    `truncate identity_audit_event, identity_reset_token, identity_role_assignment,
              identity_refresh_token, identity_session, identity_role, identity_account,
              identity_tenant restart identity cascade`,
  );
};
