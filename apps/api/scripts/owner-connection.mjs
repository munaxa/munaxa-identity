/**
 * The migration owner's database connection, for the provisioning scripts.
 *
 * **Not a second implementation.** Everything about which credential is used and how the connection
 * is verified lives in `src/database/direct-connection.ts` — `DIRECT_DATABASE_URL` /
 * `DIRECT_DATABASE_URL_FILE` for the owner, `DATABASE_TLS_CA` / `DATABASE_TLS_CA_FILE` for the CA,
 * every TLS parameter taken out of the URL when a CA is configured, verified TLS required in
 * production. This file loads that module as compiled into `dist` — the same code the migration
 * runner runs — and only turns its configuration into a `pg` pool.
 *
 * Loaded from `dist` because these are plain `.mjs` scripts run with `node`, with no TypeScript
 * toolchain at runtime: in the image `dist` is beside them, and in a checkout `pnpm build` produces
 * it. Without it the scripts refuse to connect rather than fall back to a connection of their own.
 *
 * It imports `pg` and that module, and nothing of the HTTP service: no Nest, no application module,
 * no service configuration, no Redis.
 */
import pg from 'pg';

const COMPILED = '../dist/database/direct-connection.js';

const loadConnectionModule = async () => {
  try {
    const loaded = await import(COMPILED);
    // A CommonJS module imported from ESM: named exports when Node can detect them, `default` always.
    return loaded.directConnection === undefined ? loaded.default : loaded;
  } catch (error) {
    if (error?.code === 'ERR_MODULE_NOT_FOUND') {
      throw new Error(
        'The shared database connection module is not built (apps/api/dist is missing). Run ' +
          '`pnpm build` first. These scripts do not connect any other way.',
      );
    }
    throw error;
  }
};

/**
 * Resolves and validates the owner connection, without connecting.
 *
 * Called first, so a missing credential or an unverifiable TLS configuration stops the script
 * before it does anything else. `openPool` connects lazily, on the first query.
 */
export const ownerDatabase = async (applicationName, source = process.env) => {
  const { directConnection, ownerClientConfig } = await loadConnectionModule();
  const connection = directConnection(source);

  return {
    describe: connection.describe,
    openPool: () => {
      const pool = new pg.Pool({ ...ownerClientConfig(connection, applicationName), max: 1 });
      // A connection the server drops (an RDS failover mid-script) is emitted as an `error` event as
      // well as failing the query in flight. Unlistened, Node treats the event as fatal and the task
      // dies with a stack trace instead of the script's own failure message; the query's rejection
      // still reaches the caller, which reports it.
      pool.on('error', () => undefined);
      return pool;
    },
  };
};

/** One line an operator can check: where, as whom, and how the connection is verified. */
export const describeOwnerDatabase = ({ user, host, port, database, tls }) =>
  `Database ${user}@${host}:${port}/${database} — TLS ${tls}.\n`;
