import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { loadEnvironment } from './environment.js';
import { parseOidcClients } from './oidc-provider.js';

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

const secret = () => randomBytes(32).toString('base64url');
const REDIRECT = 'https://docs.example/auth/federation/callback';
const enabled = (clients: string, secrets: string) => ({
  ...complete,
  IDENTITY_OIDC_PROVIDER: 'enabled',
  IDENTITY_OIDC_CLIENTS: clients,
  IDENTITY_OIDC_CLIENT_SECRETS: secrets,
});

describe('Identity as an OIDC provider: configuration', () => {
  it('is off by default', () => {
    expect(loadEnvironment(complete).IDENTITY_OIDC_PROVIDER).toBe('disabled');
  });

  it('parses clients bound to one organisation each, with several redirect URIs', () => {
    const a = secret();
    const b = secret();
    const parsed = parseOidcClients(
      `docs-acme|acme|${REDIRECT} https://docs.example/other; school|acme|https://school.example/cb`,
      `docs-acme=${a},school=${b}`,
    );
    expect(parsed.problems).toEqual([]);
    expect(parsed.clients).toEqual([
      {
        clientId: 'docs-acme',
        organisation: 'acme',
        redirectUris: [REDIRECT, 'https://docs.example/other'],
        secret: a,
      },
      {
        clientId: 'school',
        organisation: 'acme',
        redirectUris: ['https://school.example/cb'],
        secret: b,
      },
    ]);
    expect(() =>
      loadEnvironment(enabled(`docs-acme|acme|${REDIRECT}`, `docs-acme=${a}`)),
    ).not.toThrow();
  });

  it.each([
    ['enabled with no client', '', ''],
    ['a client without a secret', `docs|acme|${REDIRECT}`, ''],
    ['a secret for no client', `docs|acme|${REDIRECT}`, `docs=${secret()},stray=${secret()}`],
    ['a short secret', `docs|acme|${REDIRECT}`, 'docs=short'],
    ['a redirect URI with a fragment', `docs|acme|${REDIRECT}#x`, `docs=${secret()}`],
    ['a relative redirect URI', 'docs|acme|/callback', `docs=${secret()}`],
    ['no organisation', `docs||${REDIRECT}`, `docs=${secret()}`],
    [
      'a client id that is also an access-token audience',
      `munaxa-work|acme|${REDIRECT}`,
      `munaxa-work=${secret()}`,
    ],
  ])('refuses %s', (_name, clients, secrets) => {
    expect(() => loadEnvironment(enabled(clients, secrets))).toThrowError(/IDENTITY_OIDC/);
  });

  it('refuses two clients sharing one secret, and a secret this service already holds', () => {
    const shared = secret();
    expect(() =>
      loadEnvironment(
        enabled(
          `a-one|acme|${REDIRECT}; b-two|acme|${REDIRECT}`,
          `a-one=${shared},b-two=${shared}`,
        ),
      ),
    ).toThrowError(/share a secret/);
    const signing = 'a-development-signing-secret-at-least-32-chars';
    expect(() => loadEnvironment(enabled(`docs|acme|${REDIRECT}`, `docs=${signing}`))).toThrowError(
      /must be its own/,
    );
  });

  it('requires https redirect URIs in production', () => {
    const problems = parseOidcClients(`docs|acme|http://docs.example/cb`, `docs=${secret()}`);
    expect(problems.problems).toEqual([]);
    expect(() =>
      loadEnvironment({
        ...enabled(`docs|acme|http://docs.example/cb`, `docs=${secret()}`),
        NODE_ENV: 'production',
      }),
    ).toThrowError(/docs redirect URIs must be https in production/);
  });

  it('never prints a client secret', () => {
    const value = secret();
    try {
      loadEnvironment(enabled(`docs|acme|${REDIRECT}#frag`, `docs=${value}`));
      expect.unreachable();
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(value);
    }
  });
});
