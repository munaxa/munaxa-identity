import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { loadEnvironment } from './environment.js';

/**
 * Recovery must fail closed at startup. Each case below is a deployment that would otherwise have
 * started and then either mailed links nowhere, mailed them to a host nobody controls, or written
 * live links to local disk.
 */

const EC_KEY = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
}).privateKey;

const base: Record<string, string> = {
  NODE_ENV: 'development',
  IDENTITY_SIGNING_SECRET: 'a-development-signing-secret-at-least-32-chars',
  DATABASE_URL: 'postgresql://identity_app:pw@localhost:5432/identity',
  IDENTITY_BASE_URL: 'http://localhost:4001',
  IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
  IDENTITY_SIGNING_KID: 'identity-dev-2026-09',
  IDENTITY_SIGNING_PRIVATE_KEY: EC_KEY,
  CSRF_TRUSTED_ORIGINS: 'http://localhost:4001',
};

/** What production needs apart from recovery, so a failure below is about recovery alone. */
const production: Record<string, string> = {
  ...base,
  NODE_ENV: 'production',
  IDENTITY_BASE_URL: 'https://id.example.test',
  CSRF_TRUSTED_ORIGINS: 'https://id.example.test',
  REDIS_URL: 'redis://cache.internal:6379',
};

const outbox = {
  IDENTITY_EMAIL_TRANSPORT: 'outbox',
  IDENTITY_EMAIL_FROM: 'no-reply@example.test',
  IDENTITY_EMAIL_OUTBOX_DIR: '/tmp/identity-outbox',
};

const problems = (source: Record<string, string>): string => {
  try {
    loadEnvironment(source);
    return '';
  } catch (error) {
    return String((error as Error).message);
  }
};

describe('password recovery configuration', () => {
  it('defaults to enabled with no transport in development, which makes recovery unavailable rather than fake', () => {
    const env = loadEnvironment(base);
    expect(env.IDENTITY_PASSWORD_RESET).toBe('enabled');
    expect(env.IDENTITY_EMAIL_TRANSPORT).toBe('none');
    expect(env.IDENTITY_PASSWORD_RESET_TTL).toBe(30 * 60 * 1_000);
  });

  it('accepts the development outbox with a reset URL on a trusted origin', () => {
    const env = loadEnvironment({
      ...base,
      ...outbox,
      IDENTITY_PASSWORD_RESET_URL: 'http://localhost:4001/api/auth/password/reset',
    });
    expect(env.IDENTITY_EMAIL_TRANSPORT).toBe('outbox');
  });

  it('refuses production with recovery enabled and no production transport', () => {
    expect(problems(production)).toContain('IDENTITY_PASSWORD_RESET');
  });

  it('starts in production when recovery is explicitly disabled', () => {
    const env = loadEnvironment({ ...production, IDENTITY_PASSWORD_RESET: 'disabled' });
    expect(env.IDENTITY_PASSWORD_RESET).toBe('disabled');
  });

  it('refuses the outbox transport in production even with recovery disabled', () => {
    expect(problems({ ...production, ...outbox, IDENTITY_PASSWORD_RESET: 'disabled' })).toContain(
      'IDENTITY_EMAIL_TRANSPORT',
    );
  });

  it('requires a reset URL once a transport could send a link', () => {
    expect(problems({ ...base, ...outbox })).toContain('IDENTITY_PASSWORD_RESET_URL');
  });

  it('refuses a reset URL on an origin the edge does not trust', () => {
    expect(
      problems({
        ...base,
        ...outbox,
        IDENTITY_PASSWORD_RESET_URL: 'https://evil.example/api/auth/password/reset',
      }),
    ).toContain('CSRF_TRUSTED_ORIGINS');
  });

  it('refuses a reset URL with a query string or fragment', () => {
    for (const url of [
      'http://localhost:4001/api/auth/password/reset?x=1',
      'http://localhost:4001/api/auth/password/reset#x',
    ]) {
      expect(problems({ ...base, ...outbox, IDENTITY_PASSWORD_RESET_URL: url })).toContain(
        'query string',
      );
    }
  });

  it('refuses a link lifetime over an hour or under a minute', () => {
    expect(problems({ ...base, IDENTITY_PASSWORD_RESET_TTL: '2h' })).toContain(
      'IDENTITY_PASSWORD_RESET_TTL',
    );
    expect(problems({ ...base, IDENTITY_PASSWORD_RESET_TTL: '10s' })).toContain(
      'IDENTITY_PASSWORD_RESET_TTL',
    );
  });

  it('requires a sender address for any real transport', () => {
    expect(
      problems({
        ...base,
        IDENTITY_EMAIL_TRANSPORT: 'outbox',
        IDENTITY_EMAIL_OUTBOX_DIR: '/tmp/x',
        IDENTITY_PASSWORD_RESET_URL: 'http://localhost:4001/api/auth/password/reset',
      }),
    ).toContain('IDENTITY_EMAIL_FROM');
  });
});
