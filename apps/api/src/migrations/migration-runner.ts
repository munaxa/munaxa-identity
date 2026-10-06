import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { REQUIRED_TABLES } from '../health/readiness.js';

/**
 * Applying Identity's SQL migrations, each exactly once, and remembering that it did.
 *
 * **The SQL files stay authoritative.** `prisma/migrations/<name>/migration.sql` is executed as
 * written — no translation, no Prisma Migrate. Prisma has no concept of row-level security, roles
 * or policies, which is most of what the baseline is, and the readiness probe deliberately does not
 * key on `_prisma_migrations`. This is the smallest thing that turns "run `psql -f` in the right
 * order, once" into something an ECS one-off task can do from the image.
 *
 * **The ledger lives in its own schema**, `identity_migration`, not in `public`. Everything in
 * `public` except `identity_tenant` is required to carry forced row-level security, and the suite
 * that proves it enumerates the schema; a bookkeeping table there would either break that rule or
 * need a policy that exists only to be exempt from it. The runtime role is granted nothing on the
 * schema and has no reason to know it exists.
 *
 * **What makes it safe to run again**, which is the whole point of a ledger:
 *
 * - each migration runs in one transaction *together with its ledger row*, so a migration is either
 *   applied and recorded or neither — a failure rolls both back and is never recorded as success;
 * - a session advisory lock serialises runners, so two tasks started by one deploy cannot both
 *   apply the same file;
 * - a recorded migration whose file has changed since (checksum), one recorded but absent from the
 *   image (a database ahead of the code), and a pending migration older than one already applied
 *   (out of order) all stop the run before anything is written. Each is a deployment that does not
 *   match its database, and guessing which side is right is how a schema drifts;
 * - order is the directory names compared by code point: Prisma-style timestamps, so the order is
 *   chronological and identical on every machine regardless of locale or filesystem.
 *
 * **Adopting a database that predates the ledger.** Every environment provisioned before this
 * existed had the baseline applied with `psql -f`, so its tables are present and its ledger is not.
 * Running the baseline again would fail on the first `CREATE TABLE`, which is safe but useless. The
 * runner refuses and says so; `--adopt-baseline` then records the *first* migration as `adopted`
 * without executing it, and only if every table the service requires is already there. It is an
 * explicit operator act, never inferred.
 */

export interface Migration {
  /** The directory name, e.g. `20260901120000_identity_baseline`. Also the ledger key. */
  readonly name: string;
  readonly sql: string;
  /** SHA-256 of the file's exact bytes. */
  readonly checksum: string;
}

/** The part of `pg.Client` this needs, so the logic can be proved without a database. */
export interface SqlClient {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

export interface MigrationLog {
  (event: string, fields: Readonly<Record<string, unknown>>): void;
}

export interface RunOptions {
  readonly client: SqlClient;
  readonly migrations: readonly Migration[];
  readonly adoptBaseline?: boolean;
  readonly log?: MigrationLog;
  readonly now?: () => number;
}

export interface RunSummary {
  readonly applied: readonly string[];
  readonly adopted: readonly string[];
  readonly alreadyApplied: number;
}

export const LEDGER_SCHEMA = 'identity_migration';
export const LEDGER_TABLE = `${LEDGER_SCHEMA}.applied`;
export const RUNTIME_ROLE = 'identity_app';

/** Arbitrary but fixed, so every runner against this database contends for the same lock. */
export const MIGRATION_LOCK_KEY = '4990771566428914004';

const MIGRATION_NAME = /^\d{14}_[a-z0-9_]+$/;

export class MigrationError extends Error {
  public constructor(
    message: string,
    public readonly migration?: string,
  ) {
    super(message);
    this.name = 'MigrationError';
  }
}

export const checksumOf = (sql: string): string => createHash('sha256').update(sql).digest('hex');

/** Code-point order, not locale order: the same answer on every machine. */
const byName = (a: { readonly name: string }, b: { readonly name: string }): number =>
  a.name < b.name ? -1 : a.name > b.name ? 1 : 0;

export interface MigrationFiles {
  list(directory: string): readonly string[];
  isDirectory(path: string): boolean;
  exists(path: string): boolean;
  read(path: string): string;
}

const nodeFiles: MigrationFiles = {
  list: (directory) => readdirSync(directory),
  isDirectory: (path) => statSync(path).isDirectory(),
  exists: (path) => existsSync(path),
  read: (path) => readFileSync(path, 'utf8'),
};

/**
 * Every `<name>/migration.sql` under `directory`, in the order they must run.
 *
 * A directory that does not look like a migration, or one without its SQL file, is an error rather
 * than something to skip: a half-copied migrations tree is exactly the image that should not reach
 * a database.
 */
export const discoverMigrations = (
  directory: string,
  files: MigrationFiles = nodeFiles,
): readonly Migration[] => {
  if (!files.exists(directory)) {
    throw new MigrationError(`No migrations directory at ${directory}.`);
  }
  const migrations = files
    .list(directory)
    .filter((entry) => files.isDirectory(join(directory, entry)))
    .map((name) => {
      if (!MIGRATION_NAME.test(name)) {
        throw new MigrationError(
          `${name} is not a migration directory name (<14-digit timestamp>_<snake_case>).`,
          name,
        );
      }
      const path = join(directory, name, 'migration.sql');
      if (!files.exists(path)) {
        throw new MigrationError(`${name} has no migration.sql.`, name);
      }
      const sql = files.read(path);
      return { name, sql, checksum: checksumOf(sql) };
    })
    .sort(byName);

  if (migrations.length === 0) {
    throw new MigrationError(`No migrations found in ${directory}.`);
  }
  return migrations;
};

const ensureLedger = async (client: SqlClient): Promise<void> => {
  await client.query(`create schema if not exists ${LEDGER_SCHEMA}`);
  await client.query(
    `create table if not exists ${LEDGER_TABLE} (
       name          text        primary key,
       checksum      char(64)    not null,
       mode          text        not null check (mode in ('applied', 'adopted')),
       applied_at    timestamptz not null default now(),
       applied_by    name        not null default current_user,
       execution_ms  integer     not null
     )`,
  );
};

/**
 * Refuses a connection the runner must not migrate as.
 *
 * The runtime role first, by name, because that is the realistic mistake — the service's
 * `DATABASE_URL` pasted where the owner's belongs. Then any role that can bypass row-level security:
 * tables created by a superuser are owned by it, `FORCE ROW LEVEL SECURITY` does not bind a
 * superuser, and the provisioning model has no role with `BYPASSRLS` in it at all.
 */
const assertMigrationRole = async (client: SqlClient): Promise<string> => {
  const { rows } = await client.query(
    `select current_user as role, r.rolsuper as superuser, r.rolbypassrls as bypass
       from pg_roles r where r.rolname = current_user`,
  );
  const row = rows[0];
  const role = typeof row?.role === 'string' ? row.role : 'unknown';

  if (role === RUNTIME_ROLE) {
    throw new MigrationError(
      `Connected as ${RUNTIME_ROLE}, the runtime role. Migrations run as the owner (identity_mig) ` +
        'via DIRECT_DATABASE_URL; the runtime role owns nothing and must not.',
    );
  }
  if (row?.superuser === true || row?.bypass === true) {
    throw new MigrationError(
      `Connected as ${role}, which can bypass row-level security. Tables it created would be owned ` +
        'by a role FORCE does not bind. Use the migration owner (identity_mig).',
    );
  }
  return role;
};

const recordedMigrations = async (
  client: SqlClient,
): Promise<readonly { name: string; checksum: string }[]> => {
  const { rows } = await client.query(`select name, checksum from ${LEDGER_TABLE} order by name`);
  return rows.map((row) => ({ name: String(row.name), checksum: String(row.checksum) }));
};

const presentTables = async (client: SqlClient): Promise<readonly string[]> => {
  const { rows } = await client.query(
    `select table_name from information_schema.tables
      where table_schema = 'public' and table_type = 'BASE TABLE'`,
  );
  return rows.map((row) => String(row.table_name));
};

/** Stops the run on any disagreement between the ledger and the files. Writes nothing. */
const assertConsistent = (
  recorded: readonly { name: string; checksum: string }[],
  migrations: readonly Migration[],
): void => {
  const byNameInFiles = new Map(migrations.map((migration) => [migration.name, migration]));

  for (const entry of recorded) {
    const file = byNameInFiles.get(entry.name);
    if (file === undefined) {
      throw new MigrationError(
        `${entry.name} is recorded as applied but is not in this build. The database is ahead of ` +
          'the code; deploy the build that carries it.',
        entry.name,
      );
    }
    if (file.checksum !== entry.checksum.trim()) {
      throw new MigrationError(
        `${entry.name} has changed since it was applied (checksum mismatch). An applied migration ` +
          'is immutable; add a new one instead.',
        entry.name,
      );
    }
  }

  const latest = recorded.at(-1)?.name;
  if (latest === undefined) return;
  const appliedNames = new Set(recorded.map((entry) => entry.name));
  const late = migrations.find(
    (migration) => !appliedNames.has(migration.name) && migration.name < latest,
  );
  if (late !== undefined) {
    throw new MigrationError(
      `${late.name} is pending but older than ${latest}, which is already applied. Migrations ` +
        'apply in order; rename it after the latest applied migration.',
      late.name,
    );
  }
};

export const runMigrations = async (options: RunOptions): Promise<RunSummary> => {
  const { client, migrations } = options;
  const log: MigrationLog = options.log ?? (() => undefined);
  const now = options.now ?? Date.now;

  const role = await assertMigrationRole(client);
  log('migrate.role', { role });

  await client.query('select pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_KEY]);
  try {
    await ensureLedger(client);
    const recorded = await recordedMigrations(client);
    assertConsistent(recorded, migrations);

    const applied: string[] = [];
    const adopted: string[] = [];
    const done = new Set(recorded.map((entry) => entry.name));
    let pending = migrations.filter((migration) => !done.has(migration.name));

    const baseline = migrations[0];
    if (recorded.length === 0 && baseline !== undefined) {
      const tables = await presentTables(client);
      const missing = REQUIRED_TABLES.filter((table) => !tables.includes(table));
      const anyPresent = REQUIRED_TABLES.some((table) => tables.includes(table));

      if (options.adoptBaseline === true) {
        if (missing.length > 0) {
          throw new MigrationError(
            `--adopt-baseline needs every required table present; missing: ${missing.join(', ')}. ` +
              'Run without it to apply the baseline instead.',
            baseline.name,
          );
        }
        await client.query(
          `insert into ${LEDGER_TABLE} (name, checksum, mode, execution_ms) values ($1, $2, 'adopted', 0)`,
          [baseline.name, baseline.checksum],
        );
        adopted.push(baseline.name);
        log('migrate.adopted', { migration: baseline.name, checksum: baseline.checksum });
        pending = pending.filter((migration) => migration.name !== baseline.name);
      } else if (anyPresent) {
        throw new MigrationError(
          'The Identity schema is already present but no migration is recorded — it was applied ' +
            'with psql before the ledger existed. Verify it is the baseline, then run once with ' +
            '--adopt-baseline to record it without re-executing it.',
          baseline.name,
        );
      }
    } else if (options.adoptBaseline === true) {
      throw new MigrationError(
        '--adopt-baseline applies only to a database with an empty ledger. This one already ' +
          'records migrations; run without it.',
      );
    }

    for (const migration of pending) {
      const started = now();
      await client.query('begin');
      try {
        await client.query(migration.sql);
        const elapsed = Math.max(0, Math.round(now() - started));
        await client.query(
          `insert into ${LEDGER_TABLE} (name, checksum, mode, execution_ms) values ($1, $2, 'applied', $3)`,
          [migration.name, migration.checksum, elapsed],
        );
        await client.query('commit');
        applied.push(migration.name);
        log('migrate.applied', { migration: migration.name, executionMs: elapsed });
      } catch (cause) {
        // Best effort: if the connection itself is gone, the transaction died with it.
        await client.query('rollback').catch(() => undefined);
        throw new MigrationError(
          `${migration.name} failed and was rolled back; nothing was recorded. ${
            cause instanceof Error ? cause.message : String(cause)
          }`,
          migration.name,
        );
      }
    }

    return { applied, adopted, alreadyApplied: recorded.length };
  } finally {
    await client
      .query('select pg_advisory_unlock($1::bigint)', [MIGRATION_LOCK_KEY])
      .catch(() => undefined);
  }
};
