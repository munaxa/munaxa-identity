import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { loadEnvironment } from './environment.js';

/**
 * Company sign-in configuration: off unless asked for, and refused when half-configured, so a
 * deployment cannot believe it offers Microsoft or Google when it does not.
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

const MICROSOFT_ID = '00000000-1111-4222-8333-444444444444';
const GOOGLE_ID = '123456789012-abcdefghijklmnop.apps.googleusercontent.com';
const secret = () => randomBytes(24).toString('base64url');

describe('company sign-in configuration', () => {
  it('is off by default, with nothing to configure', () => {
    const env = loadEnvironment(complete);
    expect(env.IDENTITY_SSO).toBe('disabled');
    expect(env.IDENTITY_SSO_FLOW_TTL).toBe(600_000);
  });

  it('accepts Microsoft alone, Google alone, or both', () => {
    const ms = {
      IDENTITY_SSO_MICROSOFT_CLIENT_ID: MICROSOFT_ID,
      IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: secret(),
    };
    const google = {
      IDENTITY_SSO_GOOGLE_CLIENT_ID: GOOGLE_ID,
      IDENTITY_SSO_GOOGLE_CLIENT_SECRET: secret(),
    };
    for (const providers of [ms, google, { ...ms, ...google }]) {
      expect(() =>
        loadEnvironment({ ...complete, IDENTITY_SSO: 'enabled', ...providers }),
      ).not.toThrow();
    }
  });

  it('refuses enabled with no provider', () => {
    expect(() => loadEnvironment({ ...complete, IDENTITY_SSO: 'enabled' })).toThrowError(
      /neither Microsoft nor Google is configured/,
    );
  });

  it('refuses a client id without its secret, and a secret without its id, even when off', () => {
    expect(() =>
      loadEnvironment({ ...complete, IDENTITY_SSO_MICROSOFT_CLIENT_ID: MICROSOFT_ID }),
    ).toThrowError(/IDENTITY_SSO_MICROSOFT_CLIENT_SECRET/);
    expect(() =>
      loadEnvironment({ ...complete, IDENTITY_SSO_GOOGLE_CLIENT_SECRET: secret() }),
    ).toThrowError(/IDENTITY_SSO_GOOGLE_CLIENT_SECRET/);
  });

  it('refuses client ids of the wrong shape', () => {
    expect(() =>
      loadEnvironment({
        ...complete,
        IDENTITY_SSO_MICROSOFT_CLIENT_ID: 'contoso.onmicrosoft.com',
        IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: secret(),
      }),
    ).toThrowError(/lower-case GUID/);
    expect(() =>
      loadEnvironment({
        ...complete,
        IDENTITY_SSO_GOOGLE_CLIENT_ID: 'my-client',
        IDENTITY_SSO_GOOGLE_CLIENT_SECRET: secret(),
      }),
    ).toThrowError(/apps\.googleusercontent\.com/);
  });

  it('refuses a provider secret that is another secret this service holds', () => {
    expect(() =>
      loadEnvironment({
        ...complete,
        IDENTITY_SSO_MICROSOFT_CLIENT_ID: MICROSOFT_ID,
        IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: complete.IDENTITY_SIGNING_SECRET!,
      }),
    ).toThrowError(/must be its own/);
  });

  it('bounds how long a sign-in may take at the provider', () => {
    expect(() => loadEnvironment({ ...complete, IDENTITY_SSO_FLOW_TTL: '30s' })).toThrowError(
      /IDENTITY_SSO_FLOW_TTL/,
    );
    expect(() => loadEnvironment({ ...complete, IDENTITY_SSO_FLOW_TTL: '1h' })).toThrowError(
      /IDENTITY_SSO_FLOW_TTL/,
    );
  });

  it('never prints the client secrets', () => {
    const value = secret();
    try {
      loadEnvironment({ ...complete, IDENTITY_SSO_GOOGLE_CLIENT_SECRET: value });
      expect.unreachable();
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(value);
    }
  });
});
