import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { loadEnvironment, describeEnvironment } from './environment.js';

/**
 * What this suite is actually about: a misconfigured authentication authority must refuse to
 * start, and must say everything that is wrong in one breath. The alternative — a service that
 * boots and mints tokens nobody can verify — is indistinguishable from an outage and takes an
 * afternoon to diagnose.
 */

/**
 * A real key, generated when the suite runs rather than written down.
 *
 * The configuration refuses anything that is not a PEM private key, so this branch cannot be
 * reached with a placeholder — which is the point of refusing it. Generating one here keeps
 * key-shaped material out of the repository entirely, so the CI check for a committed key can be a
 * blunt search rather than a list of exceptions.
 */
const EC_KEY = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
}).privateKey;

const complete: Record<string, string> = {
  NODE_ENV: 'development',
  IDENTITY_SIGNING_SECRET: 'a-development-signing-secret-at-least-32-chars',
  DATABASE_URL: 'postgresql://identity_app:pw@localhost:5432/identity',
  IDENTITY_BASE_URL: 'http://localhost:4001',
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-dev-2026-09',
  IDENTITY_SIGNING_PRIVATE_KEY: EC_KEY,
  CSRF_TRUSTED_ORIGINS: 'http://localhost:3001',
};

describe('a complete environment', () => {
  it('resolves, with the platform owning the security defaults', () => {
    const env = loadEnvironment(complete);

    expect(env.MUNAXA_ACCESS_TOKEN_TTL).toBe(900_000);
    expect(env.MUNAXA_REFRESH_TOKEN_TTL).toBe(2_592_000_000);
    expect(env.MUNAXA_SESSION_IDLE_TIMEOUT).toBe(900_000);
    expect(env.MUNAXA_SESSION_ABSOLUTE_TIMEOUT).toBe(43_200_000);
    expect(env.MUNAXA_PASSWORD_MIN_LENGTH).toBe(12);
    expect(env.IDENTITY_SIGNING_ALGORITHM).toBe('ES256');
  });

  it('reads the issuer and the audience from the names an operator sets', () => {
    const env = loadEnvironment(complete);

    expect(env.MUNAXA_TOKEN_ISSUER).toBe('http://localhost:4001');
    expect(env.MUNAXA_TOKEN_AUDIENCE).toEqual(['munaxa-work']);
  });
});

describe('the proxies in front', () => {
  it('trusts none unless told how many there are', () => {
    expect(loadEnvironment(complete).TRUST_PROXY_HOPS).toBe(0);
  });

  it('takes the count an operator sets behind a load balancer', () => {
    expect(loadEnvironment({ ...complete, TRUST_PROXY_HOPS: '1' }).TRUST_PROXY_HOPS).toBe(1);
  });

  it('refuses a count that is not a small whole number', () => {
    expect(() => loadEnvironment({ ...complete, TRUST_PROXY_HOPS: '-1' })).toThrow(
      /TRUST_PROXY_HOPS/,
    );
    expect(() => loadEnvironment({ ...complete, TRUST_PROXY_HOPS: 'true' })).toThrow(
      /TRUST_PROXY_HOPS/,
    );
  });
});

describe('what it refuses', () => {
  const rejects = (overrides: Record<string, string | undefined>, expected: RegExp): void => {
    expect(() => loadEnvironment({ ...complete, ...overrides })).toThrowError(expected);
  };

  it('a public key where the private half belongs', () => {
    rejects(
      {
        IDENTITY_SIGNING_PRIVATE_KEY: `-----BEGIN PUBLIC KEY-----\n${'A'.repeat(120)}\n-----END PUBLIC KEY-----`,
      },
      /public key/,
    );
  });

  it('anything that is not a PEM private key', () => {
    rejects({ IDENTITY_SIGNING_PRIVATE_KEY: 'x'.repeat(120) }, /not a PEM private key/);
  });

  it('an issuer that is not an absolute URL', () => {
    rejects({ IDENTITY_BASE_URL: 'identity.example' }, /absolute URL/);
  });

  it('an empty audience', () => {
    rejects({ IDENTITY_AUTH_AUDIENCE: '' }, /at least one audience/);
  });

  it('no trusted origin, because empty accepts every cross-site post', () => {
    rejects({ CSRF_TRUSTED_ORIGINS: '' }, /every cross-site post/);
  });

  it('a symmetric algorithm, which would hand Munaxa Work the minting key', () => {
    rejects({ IDENTITY_SIGNING_ALGORITHM: 'HS256' }, /IDENTITY_SIGNING_ALGORITHM/);
  });

  it('a missing database URL', () => {
    rejects({ DATABASE_URL: undefined }, /DATABASE_URL/);
  });

  it('reports every problem at once, not one per restart', () => {
    let message = '';
    try {
      loadEnvironment({ NODE_ENV: 'development' });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    for (const key of ['DATABASE_URL', 'IDENTITY_SIGNING_KID', 'IDENTITY_SIGNING_PRIVATE_KEY']) {
      expect(message).toContain(key);
    }
  });
});

describe('production fails closed', () => {
  const production = {
    ...complete,
    NODE_ENV: 'production',
    IDENTITY_BASE_URL: 'https://id.example',
  };

  it('requires https for the issuer', () => {
    expect(() =>
      loadEnvironment({ ...production, IDENTITY_BASE_URL: 'http://id.example' }),
    ).toThrowError(/https in production/);
  });

  it('requires Redis, because without it lockout is silently disabled', () => {
    expect(() => loadEnvironment(production)).toThrowError(/login lockout is disabled/);
  });

  it('refuses pretty logging', () => {
    expect(() =>
      loadEnvironment({ ...production, REDIS_URL: 'redis://cache:6379', LOG_PRETTY: 'true' }),
    ).toThrowError(/LOG_PRETTY/);
  });

  it('requires the MFA key ring', () => {
    expect(() => loadEnvironment({ ...production, REDIS_URL: 'redis://cache:6379' })).toThrowError(
      /MFA_ENCRYPTION_KEYS: is required in production/,
    );
  });

  it('accepts a complete production environment', () => {
    expect(() =>
      loadEnvironment({ ...production, REDIS_URL: 'redis://cache:6379', ...MFA }),
    ).not.toThrow();
  });
});

const MFA_KEY = randomBytes(32).toString('base64url');
const MFA = { MFA_ENCRYPTION_KEYS: `mfa-1=${MFA_KEY}`, MFA_ENCRYPTION_PRIMARY_KID: 'mfa-1' };

describe('the MFA key ring', () => {
  it('is optional in development, where MFA is then unavailable', () => {
    const env = loadEnvironment(complete);
    expect(env.MFA_ENCRYPTION_KEYS).toBe('');
  });

  it('resolves a ring with a primary and a retired key', () => {
    const retired = randomBytes(32).toString('base64');
    const env = loadEnvironment({
      ...complete,
      MFA_ENCRYPTION_KEYS: `mfa-1=${MFA_KEY}, mfa-0=${retired}`,
      MFA_ENCRYPTION_PRIMARY_KID: 'mfa-1',
    });
    expect(env.MFA_ENCRYPTION_PRIMARY_KID).toBe('mfa-1');
  });

  it('refuses a key that is not 32 bytes, without echoing it', () => {
    const short = randomBytes(16).toString('base64url');
    let message = '';
    try {
      loadEnvironment({
        ...complete,
        MFA_ENCRYPTION_KEYS: `k=${short}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'k',
      });
    } catch (error) {
      message = String(error);
    }
    expect(message).toMatch(/key k is not 32 bytes/);
    expect(message).not.toContain(short);
  });

  it('refuses a ring with no primary, or a primary it does not contain', () => {
    expect(() =>
      loadEnvironment({ ...complete, MFA_ENCRYPTION_KEYS: `a=${MFA_KEY}` }),
    ).toThrowError(/MFA_ENCRYPTION_PRIMARY_KID: is required/);
    expect(() =>
      loadEnvironment({
        ...complete,
        MFA_ENCRYPTION_KEYS: `a=${MFA_KEY}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'b',
      }),
    ).toThrowError(/names b, which is not a key/);
  });

  it('refuses duplicate key ids and malformed entries', () => {
    expect(() =>
      loadEnvironment({
        ...complete,
        MFA_ENCRYPTION_KEYS: `a=${MFA_KEY},a=${MFA_KEY}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'a',
      }),
    ).toThrowError(/more than once/);
    expect(() =>
      loadEnvironment({
        ...complete,
        MFA_ENCRYPTION_KEYS: MFA_KEY,
        MFA_ENCRYPTION_PRIMARY_KID: 'a',
      }),
    ).toThrowError(/not of the form kid=key/);
  });

  it('refuses a repeated-byte key', () => {
    expect(() =>
      loadEnvironment({
        ...complete,
        MFA_ENCRYPTION_KEYS: `a=${Buffer.alloc(32, 7).toString('base64')}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'a',
      }),
    ).toThrowError(/repeated byte/);
  });

  it('refuses the signing secret — the refresh-token pepper — as the MFA key', () => {
    const pepper = randomBytes(32);
    expect(() =>
      loadEnvironment({
        ...complete,
        IDENTITY_SIGNING_SECRET: pepper.toString('base64url'),
        MFA_ENCRYPTION_KEYS: `a=${pepper.toString('base64url')}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'a',
      }),
    ).toThrowError(/is IDENTITY_SIGNING_SECRET/);
    const textual = 'p'.repeat(16) + 'q'.repeat(16);
    expect(() =>
      loadEnvironment({
        ...complete,
        IDENTITY_SIGNING_SECRET: textual,
        MFA_ENCRYPTION_KEYS: `a=${Buffer.from(textual).toString('base64')}`,
        MFA_ENCRYPTION_PRIMARY_KID: 'a',
      }),
    ).toThrowError(/is IDENTITY_SIGNING_SECRET/);
  });

  it('is read from a secret file and never rendered', () => {
    const env = loadEnvironment(
      {
        ...complete,
        MFA_ENCRYPTION_KEYS_FILE: '/run/secrets/mfa',
        MFA_ENCRYPTION_PRIMARY_KID: 'mfa-1',
      },
      (path) => {
        if (path !== '/run/secrets/mfa') throw new Error('no such file');
        return `mfa-1=${MFA_KEY}\n`;
      },
    );
    expect(env.MFA_ENCRYPTION_KEYS).toBe(`mfa-1=${MFA_KEY}`);
    expect(JSON.stringify(describeEnvironment(env))).not.toContain(MFA_KEY);
  });

  it('names a primary only when there is a ring', () => {
    expect(() => loadEnvironment({ ...complete, MFA_ENCRYPTION_PRIMARY_KID: 'a' })).toThrowError(
      /MFA_ENCRYPTION_KEYS is empty/,
    );
  });
});

describe('rendering the configuration', () => {
  it('never reveals the signing key or the signing secret', () => {
    const rendered = JSON.stringify(describeEnvironment(loadEnvironment(complete)));

    expect(rendered).not.toContain('BEGIN PRIVATE KEY');
    expect(rendered).not.toContain('a-development-signing-secret');
    expect(rendered).toContain('identity-dev-2026-09');
  });
});

describe('secrets mounted as files', () => {
  const files: Record<string, string> = {
    '/run/secrets/key': `${EC_KEY}\n`,
    '/run/secrets/db': 'postgresql://identity_app:mounted@db:5432/identity\n',
  };
  const read = (path: string): string => {
    const contents = files[path];
    if (contents === undefined) throw new Error(`no such file ${path}`);
    return contents;
  };

  it('reads a value from the file its _FILE variable names', () => {
    const env = loadEnvironment(
      {
        ...complete,
        IDENTITY_SIGNING_PRIVATE_KEY: undefined,
        IDENTITY_SIGNING_PRIVATE_KEY_FILE: '/run/secrets/key',
        DATABASE_URL: undefined,
        DATABASE_URL_FILE: '/run/secrets/db',
      },
      read,
    );

    expect(env.IDENTITY_SIGNING_PRIVATE_KEY.startsWith('-----BEGIN')).toBe(true);
    expect(env.DATABASE_URL).toBe('postgresql://identity_app:mounted@db:5432/identity');
  });

  it('strips the trailing newline every editor and `echo` adds', () => {
    const env = loadEnvironment(
      { ...complete, DATABASE_URL: undefined, DATABASE_URL_FILE: '/run/secrets/db' },
      read,
    );

    expect(env.DATABASE_URL.endsWith('\n')).toBe(false);
  });

  it('overrides an ambient value, because a mount is deliberate and an inherited variable is not', () => {
    // The rule that cost a staging afternoon when it ran the other way. Prisma's client loads a
    // `.env` at import time to resolve its own datasource, so `DATABASE_URL` is populated from a
    // development file before configuration is read at all. Preferring it meant the service
    // started, passed readiness, and answered every sign-in with a generic 401 — from the wrong
    // database, which is indistinguishable from a wrong password.
    const env = loadEnvironment(
      {
        ...complete,
        DATABASE_URL: 'postgresql://a-stray-dot-env@localhost:5432/development',
        DATABASE_URL_FILE: '/run/secrets/db',
      },
      read,
    );

    expect(env.DATABASE_URL).toBe('postgresql://identity_app:mounted@db:5432/identity');
  });

  it('still runs on a plain variable when no mount is named', () => {
    const env = loadEnvironment(
      { ...complete, DATABASE_URL: 'postgresql://direct@localhost:5432/x' },
      read,
    );

    expect(env.DATABASE_URL).toBe('postgresql://direct@localhost:5432/x');
  });

  it('refuses to start when the named mount is absent', () => {
    // The alternative is a service that runs without the secret it was configured to need, which
    // for a signing key means every token it issues is signed by something nobody chose.
    expect(() =>
      loadEnvironment(
        { ...complete, DATABASE_URL: undefined, DATABASE_URL_FILE: '/run/secrets/gone' },
        read,
      ),
    ).toThrowError(/could not be read/);
  });
});
