import { Client } from 'pg';
import { describe, expect, it } from 'vitest';

import {
  ConnectionConfigurationError,
  directConnection,
} from '../src/database/direct-connection.js';

/**
 * How the migration owner's connection is verified. The certificate below is a placeholder with
 * the right framing — nothing here connects, and `pg` is used only to read back what it would do.
 */

const URL_ = 'postgresql://identity_mig:not-a-real-password@db.example.internal:5432/identity';
const CA = '-----BEGIN CERTIFICATE-----\nMIIBplaceholder\n-----END CERTIFICATE-----\n';

/** What `pg` itself will use for TLS, given the configuration — the thing that actually matters. */
const effectiveSsl = (config: ReturnType<typeof directConnection>['config']): unknown =>
  (new Client(config) as unknown as { connectionParameters: { ssl: unknown } }).connectionParameters
    .ssl;

describe('the credential', () => {
  it('is DIRECT_DATABASE_URL — the owner — and never the runtime DATABASE_URL', () => {
    expect(() => directConnection({ DATABASE_URL: URL_ })).toThrow(/DIRECT_DATABASE_URL/);
  });

  it('prefers a mounted file to an ambient variable', () => {
    const connection = directConnection(
      {
        DIRECT_DATABASE_URL: 'postgresql://wrong@elsewhere/x',
        DIRECT_DATABASE_URL_FILE: '/run/secrets/url',
      },
      () => `${URL_}\n`,
    );

    expect(connection.describe.host).toBe('db.example.internal');
  });

  it('refuses an unreadable file instead of falling back', () => {
    expect(() =>
      directConnection({ DIRECT_DATABASE_URL: URL_, DIRECT_DATABASE_URL_FILE: '/nope' }, () => {
        throw new Error('ENOENT');
      }),
    ).toThrow(/could not be read/);
  });

  it('never repeats the connection string, even when it is malformed', () => {
    const attempt = () => directConnection({ DIRECT_DATABASE_URL: 'not a url with secret-value' });

    expect(attempt).toThrow(ConnectionConfigurationError);
    expect(attempt).not.toThrow(/secret-value/);
  });

  it('describes itself without the password', () => {
    const { describe: described } = directConnection({ DIRECT_DATABASE_URL: URL_ });

    expect(JSON.stringify(described)).not.toContain('not-a-real-password');
    expect(described).toMatchObject({ user: 'identity_mig', database: 'identity', port: '5432' });
  });
});

describe('TLS with a configured CA — RDS', () => {
  it('verifies the chain and the host name against that CA', () => {
    const connection = directConnection({
      DIRECT_DATABASE_URL: URL_,
      DATABASE_TLS_CA: CA,
      NODE_ENV: 'production',
    });

    expect(connection.describe.tls).toBe('verify-full (configured CA)');
    expect(effectiveSsl(connection.config)).toEqual({ ca: CA.trim(), rejectUnauthorized: true });
  });

  it('reads the CA from a file as well', () => {
    const connection = directConnection(
      { DIRECT_DATABASE_URL: URL_, DATABASE_TLS_CA_FILE: '/etc/rds/bundle.pem' },
      () => CA,
    );

    expect(effectiveSsl(connection.config)).toMatchObject({ rejectUnauthorized: true });
  });

  it('takes TLS out of the URL, where pg would let it override the CA', () => {
    const connection = directConnection({
      DIRECT_DATABASE_URL: `${URL_}?sslmode=verify-full&application_name=x`,
      DATABASE_TLS_CA: CA,
    });

    expect(connection.config.connectionString).not.toMatch(/ssl/);
    expect(connection.config.connectionString).toContain('application_name=x');
    expect(effectiveSsl(connection.config)).toMatchObject({
      ca: CA.trim(),
      rejectUnauthorized: true,
    });
  });

  it('refuses a URL asking for weaker verification than the CA provides', () => {
    for (const mode of ['require', 'no-verify', 'prefer', 'disable']) {
      expect(() =>
        directConnection({ DIRECT_DATABASE_URL: `${URL_}?sslmode=${mode}`, DATABASE_TLS_CA: CA }),
      ).toThrow(/Remove sslmode/);
    }
  });

  it('refuses something that is not a certificate', () => {
    expect(() =>
      directConnection({ DIRECT_DATABASE_URL: URL_, DATABASE_TLS_CA: 'arn:aws:secretsmanager:…' }),
    ).toThrow(/not a PEM certificate/);
  });
});

describe('TLS without a configured CA', () => {
  it('is refused in production unless it is verify-full against the system trust store', () => {
    expect(() => directConnection({ DIRECT_DATABASE_URL: URL_, NODE_ENV: 'production' })).toThrow(
      /Refusing an unverified database connection in production/,
    );
    expect(() =>
      directConnection({ DIRECT_DATABASE_URL: `${URL_}?sslmode=require`, NODE_ENV: 'production' }),
    ).toThrow(/production/);

    const verified = directConnection({
      DIRECT_DATABASE_URL: `${URL_}?sslmode=verify-full`,
      NODE_ENV: 'production',
    });
    expect(verified.describe.tls).toBe('verify-full (system trust store)');
  });

  it('never produces encrypted-but-unverified, in any environment', () => {
    for (const mode of ['no-verify', 'require', 'prefer', 'allow', 'verify-ca']) {
      expect(() => directConnection({ DIRECT_DATABASE_URL: `${URL_}?sslmode=${mode}` })).toThrow(
        /not supported here/,
      );
    }
  });

  it('connects in plain text to a local database outside production', () => {
    const connection = directConnection({
      DIRECT_DATABASE_URL: 'postgresql://identity_mig@localhost/identity',
    });

    expect(connection.describe.tls).toBe('none');
    expect(effectiveSsl(connection.config)).toBe(false);
  });
});
