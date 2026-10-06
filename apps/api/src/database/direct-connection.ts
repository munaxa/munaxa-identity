import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import type { ClientConfig } from 'pg';

/**
 * The owner's connection — the one the migration runner uses — and its TLS, decided in one place.
 *
 * **Which credential.** `DIRECT_DATABASE_URL`, the migration owner (`identity_mig`), as the
 * provisioning scripts already name it. Never `DATABASE_URL`: that is the runtime role, which owns
 * nothing and cannot create a table, and a runner that fell back to it would fail in the least
 * helpful place. The runner additionally refuses to proceed as `identity_app` once connected.
 *
 * **Why TLS is built here rather than left to the URL.** `pg` lets a connection string's TLS
 * parameters *replace* an explicit `ssl` object, silently. Measured against the installed version:
 * `?sslmode=require` beside a configured CA discards the CA, and `?sslmode=no-verify` turns
 * verification off, with nothing said either way. So when a CA is configured, every TLS parameter
 * is taken out of the URL and TLS is set from configuration alone — there is exactly one source of
 * truth for how the connection is verified, and it is not a query string.
 *
 * **What counts as verified.** Certificate chain *and* host name: Node's default checks, against
 * either the supplied CA (`DATABASE_TLS_CA` / `DATABASE_TLS_CA_FILE` — for RDS, Amazon's public
 * bundle for the region) or, with `sslmode=verify-full` and no CA, the system trust store. In
 * production one of the two is required; nothing here can produce an encrypted-but-unverified
 * connection, and a URL asking for one is refused rather than honoured.
 *
 * Outside production a URL without TLS parameters connects in plain text, which is what a laptop
 * and CI's service container both are.
 */

export type TlsMode = 'verify-full (configured CA)' | 'verify-full (system trust store)' | 'none';

export interface DirectConnection {
  readonly config: ClientConfig;
  /** Safe to log: no password, no certificate. */
  readonly describe: {
    readonly host: string;
    readonly port: string;
    readonly database: string;
    readonly user: string;
    readonly tls: TlsMode;
  };
}

export class ConnectionConfigurationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'ConnectionConfigurationError';
  }
}

type Source = Readonly<Record<string, string | undefined>>;

/** Every query parameter through which a connection string can say something about TLS. */
const TLS_PARAMETERS = [
  'ssl',
  'sslmode',
  'sslrootcert',
  'sslcert',
  'sslkey',
  'sslpassword',
  'sslnegotiation',
  'uselibpqcompat',
] as const;

/** Modes that are either plain text or encrypted without verification. */
const UNVERIFIED_MODES = new Set([
  'disable',
  'allow',
  'prefer',
  'require',
  'verify-ca',
  'no-verify',
]);

/**
 * `NAME_FILE` wins over `NAME`, as in `@identity/config`: a mounted secret is a deliberate act, an
 * ambient variable is not. An unreadable file is an error, never a fallback.
 */
const fromSourceOrFile = (
  source: Source,
  name: string,
  read: (path: string) => string,
): string | undefined => {
  const path = source[`${name}_FILE`]?.trim();
  if (path !== undefined && path !== '') {
    try {
      return read(path).replace(/\s+$/, '');
    } catch {
      throw new ConnectionConfigurationError(
        `${name}_FILE names ${path}, which could not be read. Refusing to fall back to anything else.`,
      );
    }
  }
  const value = source[name]?.trim();
  return value === undefined || value === '' ? undefined : value;
};

export const directConnection = (
  source: Source = process.env,
  read: (path: string) => string = (path) => readFileSync(path, 'utf8'),
): DirectConnection => {
  const raw = fromSourceOrFile(source, 'DIRECT_DATABASE_URL', read);
  if (raw === undefined) {
    throw new ConnectionConfigurationError(
      'DIRECT_DATABASE_URL (or DIRECT_DATABASE_URL_FILE) is required: the migration owner, ' +
        'identity_mig. The runtime DATABASE_URL is deliberately not used — that role owns nothing.',
    );
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // The value is a credential, so it is never echoed — not even to say what is wrong with it.
    throw new ConnectionConfigurationError('DIRECT_DATABASE_URL is not a URL.');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new ConnectionConfigurationError('DIRECT_DATABASE_URL must be a postgresql:// URL.');
  }

  const production = source.NODE_ENV === 'production';

  /**
   * Verified TLS needs a host *name*. For an IP-literal host `pg` sends no server name, and Node then
   * checks the certificate against "localhost" rather than the address connected to — measured: a
   * certificate issued only for `localhost` verified a connection to 127.0.0.1. Against RDS that
   * fails closed (no RDS certificate names localhost), but it is not host-name verification, so it is
   * refused outright. An RDS endpoint is always a DNS name; use it.
   */
  const refuseAddressForVerifiedTls = (): void => {
    if (isIP(url.hostname.replace(/^\[|\]$/g, '')) !== 0) {
      throw new ConnectionConfigurationError(
        `DIRECT_DATABASE_URL names the host by IP address (${url.hostname}). Verified TLS checks the ` +
          'certificate against a host name, and pg cannot do that for an address. Use the database ' +
          'endpoint’s DNS name — for RDS, the instance endpoint.',
      );
    }
  };
  const ca = fromSourceOrFile(source, 'DATABASE_TLS_CA', read);
  const sslmode = url.searchParams.get('sslmode') ?? undefined;
  const describe = {
    host: url.hostname,
    port: url.port === '' ? '5432' : url.port,
    database: decodeURIComponent(url.pathname.replace(/^\//, '')),
    user: decodeURIComponent(url.username),
  };

  if (ca !== undefined) {
    refuseAddressForVerifiedTls();
    if (!ca.includes('-----BEGIN CERTIFICATE-----')) {
      throw new ConnectionConfigurationError(
        'DATABASE_TLS_CA is not a PEM certificate bundle. For RDS it is the region bundle from ' +
          'Amazon’s public trust store.',
      );
    }
    if (sslmode !== undefined && sslmode !== 'verify-full') {
      // A URL asking for less than a configured CA provides is a contradiction, and the answer to a
      // contradiction about verification is never to pick the weaker side.
      throw new ConnectionConfigurationError(
        `DIRECT_DATABASE_URL asks for sslmode=${sslmode}, but DATABASE_TLS_CA is configured. ` +
          'Remove sslmode from the URL; verification is set from the CA.',
      );
    }
    for (const parameter of TLS_PARAMETERS) url.searchParams.delete(parameter);
    return {
      config: { connectionString: url.toString(), ssl: { ca, rejectUnauthorized: true } },
      describe: { ...describe, tls: 'verify-full (configured CA)' },
    };
  }

  if (sslmode === 'verify-full') {
    refuseAddressForVerifiedTls();
    return {
      config: { connectionString: url.toString() },
      describe: { ...describe, tls: 'verify-full (system trust store)' },
    };
  }

  if (production) {
    throw new ConnectionConfigurationError(
      'Refusing an unverified database connection in production. Set DATABASE_TLS_CA (or ' +
        'DATABASE_TLS_CA_FILE) to the CA bundle — for RDS, the region bundle — or use ' +
        'sslmode=verify-full for a certificate the system trust store already verifies.',
    );
  }

  if (sslmode !== undefined && UNVERIFIED_MODES.has(sslmode) && sslmode !== 'disable') {
    // `pg` would treat several of these as verify-full and fail obscurely, and `no-verify` as no
    // verification at all. Neither is something to drift into outside production either.
    throw new ConnectionConfigurationError(
      `sslmode=${sslmode} is not supported here. Use sslmode=verify-full, configure ` +
        'DATABASE_TLS_CA, or omit TLS entirely for a local database.',
    );
  }
  for (const parameter of TLS_PARAMETERS) url.searchParams.delete(parameter);
  return {
    config: { connectionString: url.toString(), ssl: false },
    describe: { ...describe, tls: 'none' },
  };
};

/**
 * The client settings every owner connection uses: the verified connection above, named so it can
 * be found in `pg_stat_activity`, and bounded so an unreachable database fails the task instead of
 * hanging it.
 *
 * The one place these are set, for every consumer: the migration runner (`migrate.ts`) and the
 * provisioning scripts (`scripts/owner-connection.mjs`, which loads this module from `dist`). Nothing
 * else builds an owner connection, so nothing else can build one with weaker TLS.
 */
export const ownerClientConfig = (
  connection: DirectConnection,
  applicationName: string,
): ClientConfig => ({
  ...connection.config,
  application_name: applicationName,
  connectionTimeoutMillis: 15_000,
});
