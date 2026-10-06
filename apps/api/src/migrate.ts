import { resolve } from 'node:path';

import { Client, type ClientConfig } from 'pg';

import { directConnection, ownerClientConfig } from './database/direct-connection.js';
import {
  discoverMigrations,
  runMigrations,
  type MigrationLog,
  type SqlClient,
} from './migrations/migration-runner.js';

/**
 * `node dist/migrate.js` — apply pending Identity migrations, then exit.
 *
 * A separate entrypoint in the same image, for an ECS one-off task (or any orchestrator's job): the
 * service's `CMD` is unchanged and the service never migrates on startup. A deployment runs this
 * first, as the migration owner, and starts or rolls the service only if it exits 0.
 *
 * It imports no part of the HTTP application — no Nest, no `AppModule`, no controller — so it
 * cannot open a port, and it needs none of the service's configuration: no signing key, no Redis,
 * no runtime `DATABASE_URL`. What it does need is `DIRECT_DATABASE_URL` (the owner) and, in
 * production, a CA to verify the database with; see `database/direct-connection.ts`.
 *
 * Exit codes: `0` applied or nothing to do, `1` refused or failed (nothing partial is recorded),
 * `2` unusable invocation. Output is one JSON object per line, for CloudWatch, and never carries a
 * password, a connection string or a certificate.
 */

const USAGE =
  'Usage: node dist/migrate.js [--adopt-baseline]\n\n' +
  '  --adopt-baseline   Record the baseline as applied without executing it. Only for a database\n' +
  '                     whose schema was applied with psql before the migration ledger existed.\n';

export interface MainDependencies {
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly connect?: (config: ClientConfig) => Promise<SqlClient & { end(): Promise<void> }>;
  readonly migrationsDirectory?: string;
  readonly stdout?: (line: string) => void;
  readonly stderr?: (line: string) => void;
}

/**
 * `prisma/migrations` at the repository root. This file runs from `/app/apps/api/dist` in the image
 * (and from `apps/api/src` under a test runner), so the root is three levels up either way. Resolved
 * when asked for, not at import, so importing this module has no side effect at all.
 */
const defaultMigrationsDirectory = (): string =>
  resolve(__dirname, '..', '..', '..', 'prisma', 'migrations');

const connectWithPg = async (
  config: ClientConfig,
): Promise<SqlClient & { end(): Promise<void> }> => {
  const client = new Client(config);
  // A connection the server drops — an RDS failover or reboot mid-migration — is emitted as an
  // `error` event as well as rejecting the query in flight. With no listener, Node treats the event
  // as fatal and the task dies with a stack trace instead of the `migrate.failed` line an operator
  // searches for. Reproduced by terminating the backend during a migration. The rejection still
  // reaches the runner, which reports it; the transaction died with the connection, so nothing was
  // recorded.
  client.on('error', () => undefined);
  await client.connect();
  return client;
};

export const main = async (
  argv: readonly string[],
  dependencies: MainDependencies = {},
): Promise<number> => {
  const env = dependencies.env ?? process.env;
  const out = dependencies.stdout ?? ((line: string) => process.stdout.write(`${line}\n`));
  const err = dependencies.stderr ?? ((line: string) => process.stderr.write(`${line}\n`));
  const log: MigrationLog = (event, fields) => {
    out(JSON.stringify({ event, ...fields }));
  };

  if (argv.includes('--help') || argv.includes('-h')) {
    out(USAGE);
    return 0;
  }
  const unknown = argv.filter((argument) => argument !== '--adopt-baseline');
  if (unknown.length > 0) {
    err(JSON.stringify({ event: 'migrate.usage', unknown }));
    err(USAGE);
    return 2;
  }

  let client: (SqlClient & { end(): Promise<void> }) | undefined;
  try {
    const connection = directConnection(env);
    const configured = env.IDENTITY_MIGRATIONS_DIR?.trim();
    const migrations = discoverMigrations(
      dependencies.migrationsDirectory ??
        (configured === undefined || configured === '' ? defaultMigrationsDirectory() : configured),
    );

    log('migrate.start', {
      ...connection.describe,
      migrations: migrations.map((migration) => migration.name),
    });

    client = await (dependencies.connect ?? connectWithPg)(
      ownerClientConfig(connection, 'munaxa-identity-migrate'),
    );
    const summary = await runMigrations({
      client,
      migrations,
      adoptBaseline: argv.includes('--adopt-baseline'),
      log,
    });

    log('migrate.done', { ...summary });
    return 0;
  } catch (error) {
    err(
      JSON.stringify({
        event: 'migrate.failed',
        error: error instanceof Error ? error.name : 'Error',
        ...(error instanceof Error && 'migration' in error && error.migration !== undefined
          ? { migration: error.migration }
          : {}),
        message: error instanceof Error ? error.message : String(error),
      }),
    );
    return 1;
  } finally {
    await client?.end().catch(() => undefined);
  }
};

// Run only when executed (`node dist/migrate.js`), never when imported by a test.
if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
