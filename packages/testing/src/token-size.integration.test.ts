import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { TokenService } from '@munaxa/auth';
import { AsymmetricSigner } from '@munaxa/crypto';
import { generateKeyPairSync } from 'node:crypto';
import { toSessionId, toTenantId } from '@munaxa/types';
import { describe, expect, it } from 'vitest';

/**
 * The size of a real token, measured with the real signer.
 *
 * A browser refuses a cookie over 4096 bytes, and the access token travels in one. So the number of
 * grants a role may hold is bounded by transport rather than by taste, and the failure when it is
 * exceeded is silent: the browser simply does not store the cookie, and every subsequent request
 * looks like a caller who never signed in. Estimating this from average string lengths is not good
 * enough — the ceiling has to be measured with a real ES256 signature, which is what this does.
 */

const CATALOGUE: readonly string[] = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../../artifacts/work-permissions.json', import.meta.url)),
    'utf8',
  ),
) as readonly string[];

/** The bytes a `Set-Cookie` spends before the value: the name, and the attributes Platform sets. */
const COOKIE_OVERHEAD = '__Host-mx_session=; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Lax'
  .length;
const BROWSER_LIMIT = 4096;

const { privateKey, publicKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const tokens = new TokenService({
  signer: new AsymmetricSigner('ES256', [
    { kid: 'identity-staging-2026-09', privateKey, publicKey },
  ]),
  issuer: 'https://work-staging.example/api/auth',
  audience: ['munaxa-work'],
});

const cookieBytes = (permissions: readonly string[]): number =>
  tokens.issueAccessToken({
    subject: '01920000-0000-7000-8000-00000000abcd',
    tenantId: toTenantId('01920000-0000-7000-8000-0000000000aa'),
    tokenVersion: 1,
    sessionId: toSessionId('sess_01920000000070008000000000000001'),
    permissions,
  }).token.length + COOKIE_OVERHEAD;

const module_ = (name: string): string[] => CATALOGUE.filter((g) => g.startsWith(`work:${name}:`));
const reads = (name: string): string[] => module_(name).filter((g) => g.endsWith(':read'));

/** The role `seed-work-roles.mjs` provisions, composed the same way. */
const STAGING_OPERATOR = [
  ...module_('identity'),
  ...reads('people'),
  ...module_('leave'),
  ...reads('attendance'),
];

describe('the staging role', () => {
  it('is composed of exactly the grants the seed script provisions', () => {
    expect(STAGING_OPERATOR.length).toBe(45);
  });

  it('fits in a cookie, with room left for a claim somebody adds later', () => {
    const bytes = cookieBytes(STAGING_OPERATOR);

    expect(bytes).toBeLessThanOrEqual(BROWSER_LIMIT);
    // Not merely "fits": a role at 99% of the limit is one added claim away from a session that
    // silently stops working, so the design limit is 75% and this is the assertion that holds it.
    expect(bytes).toBeLessThanOrEqual(BROWSER_LIMIT * 0.75);
  });

  it('holds no wildcard and no scope, which Munaxa Work would drop', () => {
    for (const grant of STAGING_OPERATOR) {
      expect([grant, grant.includes('*')]).toEqual([grant, false]);
      expect([grant, CATALOGUE.includes(grant)]).toEqual([grant, true]);
    }
  });
});

describe('the ceiling this imposes on role design', () => {
  it('refuses a role holding every Work permission, three times over', () => {
    const bytes = cookieBytes(CATALOGUE);

    expect(CATALOGUE.length).toBe(285);
    expect(bytes).toBeGreaterThan(BROWSER_LIMIT);
  });

  it('finds the measured maximum, so a role can be designed against a number rather than a guess', () => {
    let fits = 0;
    while (fits < CATALOGUE.length && cookieBytes(CATALOGUE.slice(0, fits + 1)) <= BROWSER_LIMIT) {
      fits += 1;
    }

    // Recorded rather than asserted tightly: the exact figure moves with the claim set, and a test
    // that pinned it would fail on a change that is fine. What matters is that it is comfortably
    // above the largest role provisioned and far below the whole catalogue.
    expect(fits).toBeGreaterThan(STAGING_OPERATOR.length);
    expect(fits).toBeLessThan(CATALOGUE.length);
    process.stdout.write(`  measured ceiling: ${fits} grants in a 4096-byte cookie (ES256)\n`);
  });
});
