import { execFileSync, spawnSync } from 'node:child_process';
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

/** The role definitions the seed script provisions, read from the script itself rather than retyped. */
interface SeededRole {
  readonly key: string;
  readonly name: string;
  readonly description: string;
  readonly grants: readonly string[];
}

const script = (name: string): string =>
  fileURLToPath(new URL(`../../../apps/api/scripts/${name}`, import.meta.url));

const SEEDED: readonly SeededRole[] = JSON.parse(
  execFileSync(process.execPath, [script('work-roles.mjs')], { encoding: 'utf8' }),
) as readonly SeededRole[];

const seeded = (key: string): SeededRole => {
  const role = SEEDED.find((candidate) => candidate.key === key);
  if (role === undefined) throw new Error(`The seed script provisions no role ${key}.`);
  return role;
};

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
    expect(seeded('work-staging-operator').grants).toEqual([...STAGING_OPERATOR].sort());
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

/**
 * The Testing personas (MW-003).
 *
 * Eight roles, fixed by key because Munaxa Work's persona test and the Testing smoke tooling name
 * them. Between them they must reach every screen, so they must hold every grant in the catalogue;
 * each must fit the cookie at the same 75% design limit as the staging role; and no persona may
 * hold a decision next to the grants that prepare what it decides.
 */
const PERSONAS = [
  'work-testing-org-admin',
  'work-testing-hr-officer',
  'work-testing-time-leave-officer',
  'work-testing-payroll-preparer',
  'work-testing-payroll-approver',
  'work-testing-recruiter',
  'work-testing-manager',
  'work-testing-employee',
] as const;

const PAYROLL_DECISIONS = [
  'work:payroll:approve',
  'work:payroll:finalize',
  'work:payroll:payment',
  'work:payroll:reverse',
  'work:compensation:approve',
];

/**
 * Approves, finalizes, decides or confirms: the grants that must sit apart from what they decide
 * on. Written out here rather than imported, so the test does not take the definition's word for
 * which grants are decisions.
 */
const isDecision = (grant: string): boolean =>
  PAYROLL_DECISIONS.includes(grant) || /:(approve|finalize|decide|confirm)$/.test(grant);

/** A read, or a grant over the holder's own record: neither prepares anything somebody decides. */
const isReadOrOwn = (grant: string): boolean =>
  /:read(-[a-z-]+)?$/.test(grant) || grant.endsWith('-own');

const moduleOf = (grant: string): string => grant.split(':')[1] ?? '';

const PAYROLL_PREPARATION = [
  'work:payroll:manage',
  'work:payroll:calculate',
  'work:payroll:adjust',
  'work:compensation:manage',
  'work:compensation:adjust',
];

describe('the Testing personas', () => {
  const personas = SEEDED.filter((role) => role.key.startsWith('work-testing-'));

  it('are exactly the eight fixed keys', () => {
    expect(personas.map((role) => role.key)).toEqual([...PERSONAS]);
  });

  it.each(PERSONAS)('%s fits in a cookie at the 75%% design limit', (key) => {
    const bytes = cookieBytes(seeded(key).grants);

    process.stdout.write(
      `  ${key}: ${seeded(key).grants.length} grants, ${bytes} bytes (${((bytes / BROWSER_LIMIT) * 100).toFixed(1)}%)\n`,
    );
    expect(bytes).toBeLessThanOrEqual(BROWSER_LIMIT * 0.75);
  });

  it.each(PERSONAS)('%s is marked as Testing only', (key) => {
    const role = seeded(key);

    expect(role.name).toContain('Testing only');
    expect(role.description.startsWith('TESTING ONLY.')).toBe(true);
  });

  it.each(PERSONAS)('%s holds only declared grants, with no wildcard', (key) => {
    for (const grant of seeded(key).grants) {
      expect([grant, grant.includes('*')]).toEqual([grant, false]);
      expect([grant, CATALOGUE.includes(grant)]).toEqual([grant, true]);
    }
  });

  it('together hold every grant in the catalogue', () => {
    const held = new Set(personas.flatMap((role) => role.grants));

    expect(CATALOGUE.filter((grant) => !held.has(grant))).toEqual([]);
    expect(held.size).toBe(CATALOGUE.length);
  });

  it('keep payroll approval apart from payroll preparation', () => {
    const preparer = seeded('work-testing-payroll-preparer').grants;
    const approver = seeded('work-testing-payroll-approver').grants;

    expect(preparer).toContain('work:payroll:calculate');
    expect(approver).toContain('work:payroll:approve');
    for (const role of personas) {
      const decides = role.grants.filter((grant) => PAYROLL_DECISIONS.includes(grant));
      const prepares = role.grants.filter((grant) => PAYROLL_PREPARATION.includes(grant));

      // A role may hold one side or the other; holding both is the whole cycle in one pair of hands.
      expect([role.key, decides.length > 0 && prepares.length > 0]).toEqual([role.key, false]);
    }
    for (const grant of PAYROLL_DECISIONS) {
      expect([
        grant,
        personas.filter((role) => role.grants.includes(grant)).map((role) => role.key),
      ]).toEqual([grant, ['work-testing-payroll-approver']]);
    }
  });

  it('never hold a decision beside anything else in its module but reads and own records', () => {
    // One rule for every persona, with no persona exempt by name: whoever decides in a module
    // prepares nothing there, so nobody can decide what they prepared.
    for (const role of personas) {
      const deciding = new Set(role.grants.filter(isDecision).map(moduleOf));
      const besideADecision = role.grants.filter(
        (grant) => deciding.has(moduleOf(grant)) && !isDecision(grant) && !isReadOrOwn(grant),
      );

      expect([role.key, besideADecision]).toEqual([role.key, []]);
    }
  });

  it('keep career nominations and recommendations apart from confirming and deciding them', () => {
    const holders = (grant: string): string[] =>
      personas.filter((role) => role.grants.includes(grant)).map((role) => role.key);

    expect(holders('work:career:successor:nominate')).toEqual(['work-testing-manager']);
    expect(holders('work:career:mobility:recommend')).toEqual(['work-testing-manager']);
    expect(holders('work:career:successor:confirm')).toEqual(['work-testing-hr-officer']);
    expect(holders('work:career:mobility:decide')).toEqual(['work-testing-hr-officer']);
  });
});

describe('the seed script, asked for the Testing personas', () => {
  const seed = (args: readonly string[], env: Record<string, string>) =>
    spawnSync(process.execPath, [script('seed-work-roles.mjs'), ...args], {
      encoding: 'utf8',
      // No database URL anywhere: a refusal has to happen before a connection is even attempted.
      env: { PATH: process.env['PATH'] ?? '', ...env },
    });

  const TESTING = { IDENTITY_BASE_URL: 'https://id.test.munaxa.com' };
  const PERSONAS = ['--testing-personas', '--environment', 'testing'];

  it.each([
    ['no environment named', ['--testing-personas'], { ...TESTING, NODE_ENV: 'development' }],
    ['production named', ['--testing-personas', '--environment', 'production'], TESTING],
    [
      'production mode with no base URL to confirm the target',
      PERSONAS,
      { NODE_ENV: 'production' },
    ],
    // M1: no NODE_ENV at all is not permission to skip the issuer check.
    ['no NODE_ENV and no base URL', PERSONAS, {}],
    [
      'a production Identity host',
      PERSONAS,
      { NODE_ENV: 'production', IDENTITY_BASE_URL: 'https://id.munaxa.com' },
    ],
    [
      "production's RDS instance, with no NODE_ENV",
      PERSONAS,
      {
        ...TESTING,
        DIRECT_DATABASE_URL:
          'postgresql://owner:placeholder@munaxa-prod-pg.abc123.eu-central-1.rds.amazonaws.com:5432/identity',
      },
    ],
    [
      "production's private namespace",
      PERSONAS,
      {
        ...TESTING,
        DATABASE_MIGRATION_URL:
          'postgresql://owner:placeholder@db.prod.munaxa.internal:5432/identity',
      },
    ],
    [
      'a database named for production',
      PERSONAS,
      {
        ...TESTING,
        DIRECT_DATABASE_URL: 'postgresql://owner:placeholder@localhost:5432/identity_prod',
      },
    ],
    [
      'a database URL that cannot be read',
      PERSONAS,
      { ...TESTING, DIRECT_DATABASE_URL: 'not a url' },
    ],
  ])('refuses with %s', (_case, args, env) => {
    const result = seed(['--organisation', 'acme', ...args], env);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Refused:');
  });

  it('accepts the non-production database names the platform uses', () => {
    const refusal = (databaseUrl: string): string =>
      execFileSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import { testingPersonasRefusal } from ${JSON.stringify(script('work-roles.mjs'))};
           process.stdout.write(String(testingPersonasRefusal(JSON.parse(process.argv[1]))));`,
          JSON.stringify({
            environment: 'testing',
            baseUrl: 'https://id.test.munaxa.com',
            databaseUrl,
          }),
        ],
        { encoding: 'utf8' },
      );

    expect(
      refusal(
        'postgresql://owner:placeholder@munaxa-nonprod-pg.abc123.eu-central-1.rds.amazonaws.com:5432/identity',
      ),
    ).toBe('undefined');
    expect(
      refusal('postgresql://owner:placeholder@db.nonprod.munaxa.internal:5432/identity_nonprod'),
    ).toBe('undefined');
    expect(refusal('postgresql://owner:placeholder@localhost:5432/identity')).toBe('undefined');
  });

  it('passes the guard for the Testing Identity, and only then asks for a database', () => {
    const result = seed(
      ['--organisation', 'acme', '--testing-personas', '--environment', 'testing'],
      {
        NODE_ENV: 'production',
        IDENTITY_BASE_URL: 'https://id.test.munaxa.com',
      },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).not.toContain('Refused:');
    expect(result.stderr).toContain('DIRECT_DATABASE_URL');
  });
});
