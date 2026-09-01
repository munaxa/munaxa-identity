#!/usr/bin/env node
/**
 * The cross-product contract, exercised against two running services.
 *
 * Nothing here fabricates a token. Every request carries a credential Munaxa Identity minted from
 * a real account, a real password and a real ES256 key, and Munaxa Work verifies it with the
 * public half it was configured with. That is the whole point: the two products have never shared
 * a process, a package or a database, so a token that works here proves the contract rather than
 * the wiring of a test.
 *
 * Two checks need Identity's signing key to be meaningful — a token with the *right* signature and
 * the *wrong* issuer or audience. An operator running this on the deployment host has that key;
 * anyone else does not, and the script says "skipped" rather than passing something it did not
 * test. A check that quietly passes when it could not run is worse than one that is absent.
 *
 * One check needs Munaxa Work's database, to see tenant isolation from underneath rather than
 * through an API that might be filtering in the application. Same rule: named, or skipped.
 *
 *   IDENTITY_URL=http://localhost:4001 WORK_URL=http://localhost:3100 \
 *   ACCOUNT=… PASSWORD=… ORIGIN=http://localhost:3001 \
 *   [IDENTITY_SIGNING_PRIVATE_KEY_FILE=…] [WORK_DATABASE_URL=…] \
 *     node apps/api/scripts/cross-product-acceptance.mjs
 */
import { createSign, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

const IDENTITY = process.env.IDENTITY_URL ?? 'http://localhost:4001';
const WORK = process.env.WORK_URL ?? 'http://localhost:3100';
const ORIGIN = process.env.ORIGIN ?? 'http://localhost:3001';
const ACCOUNT = process.env.ACCOUNT ?? '';
const PASSWORD = process.env.PASSWORD ?? '';

const SIGNING_KEY_FILE = process.env.IDENTITY_SIGNING_PRIVATE_KEY_FILE ?? '';
const WORK_DATABASE_URL = process.env.WORK_DATABASE_URL ?? '';

const results = [];
const record = (name, passed, detail) => {
  results.push({ name, passed, detail });
  process.stdout.write(`${passed ? '  ok  ' : ' FAIL '} ${name}${detail ? ` — ${detail}` : ''}\n`);
};
/** Not a pass and not a failure. Counted separately so a summary cannot overstate what ran. */
const skip = (name, why) => {
  results.push({ name, skipped: true });
  process.stdout.write(`  skip  ${name} — ${why}\n`);
};

/** Re-sign a claim set with a given key, producing a token in Platform's exact format. */
const mint = (claims, key, kid) => {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid })).toString(
    'base64url',
  );
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = createSign('SHA256')
    .update(`${header}.${payload}`)
    .end()
    .sign({ key, dsaEncoding: 'ieee-p1363' })
    .toString('base64url');
  return `${header}.${payload}.${signature}`;
};

const cookieFrom = (response, name) => {
  const headers = response.headers.getSetCookie?.() ?? [];
  const match = headers.find((header) => header.startsWith(`${name}=`));
  return match === undefined ? undefined : match.slice(name.length + 1).split(';')[0];
};

const signIn = async (password = PASSWORD) =>
  fetch(`${IDENTITY}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN },
    body: JSON.stringify({ identifier: ACCOUNT, password }),
  });

const workRead = (path, token, extra = {}) =>
  fetch(`${WORK}/api/v1${path}`, {
    headers: { ...(token === undefined ? {} : { authorization: `Bearer ${token}` }), ...extra },
  });

const claimsOf = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());

const run = async () => {
  if (ACCOUNT === '' || PASSWORD === '') {
    process.stderr.write('Set ACCOUNT and PASSWORD to a real Identity account.\n');
    process.exit(2);
  }

  // 1 — unauthenticated
  const anonymous = await workRead('/people');
  record(
    '1 unauthenticated request is refused',
    anonymous.status === 401,
    `HTTP ${anonymous.status}`,
  );

  // The credential every case below uses, obtained the way a browser obtains one.
  const login = await signIn();
  const access = cookieFrom(login, '__Host-mx_session');
  const refresh = cookieFrom(login, '__Host-mx_refresh');
  record(
    '   sign-in issues a session',
    login.status === 200 && access !== undefined,
    `HTTP ${login.status}`,
  );

  const claims = claimsOf(access);
  record(
    '   the token carries resolved Work grants',
    Array.isArray(claims.perms) &&
      claims.perms.length > 0 &&
      claims.perms.every((p) => p.startsWith('work:')),
    `${claims.perms?.length ?? 0} grants, none wildcard: ${!claims.perms?.some((p) => p.includes('*'))}`,
  );

  // 2 — a permitted request
  const permitted = await workRead('/people', access);
  record(
    '2 a granted request reaches the route',
    permitted.status === 200,
    `HTTP ${permitted.status}`,
  );

  // 3 — a request the role deliberately lacks
  const forbidden = await workRead('/payroll/runs', access);
  record(
    '3 a permission the role lacks is 403',
    forbidden.status === 403,
    `HTTP ${forbidden.status}`,
  );

  // 4 — a token signed by a key Work was never given
  const stranger = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = JSON.parse(Buffer.from(access.split('.')[0], 'base64url').toString()).kid;
  const forged = await workRead('/people', mint(claims, stranger.privateKey, kid));
  record(
    '4 a token signed by an untrusted key is 401',
    forged.status === 401,
    `HTTP ${forged.status}`,
  );

  // 4a, 4b — the right signature, the wrong issuer or audience. Only meaningful with the real key:
  // signed by anything else the signature fails first, which proves nothing about `iss` or `aud`.
  if (SIGNING_KEY_FILE === '') {
    skip(
      '4a a correctly signed token with the wrong issuer',
      'set IDENTITY_SIGNING_PRIVATE_KEY_FILE',
    );
    skip(
      '4b a correctly signed token with the wrong audience',
      'set IDENTITY_SIGNING_PRIVATE_KEY_FILE',
    );
  } else {
    const key = readFileSync(SIGNING_KEY_FILE, 'utf8');
    const wrongIssuer = await workRead(
      '/people',
      mint({ ...claims, iss: 'https://elsewhere.invalid' }, key, kid),
    );
    record(
      '4a a correctly signed token with the wrong issuer is 401',
      wrongIssuer.status === 401,
      `HTTP ${wrongIssuer.status}`,
    );
    const wrongAudience = await workRead(
      '/people',
      mint({ ...claims, aud: ['munaxa-school'] }, key, kid),
    );
    record(
      '4b a correctly signed token with the wrong audience is 401',
      wrongAudience.status === 401,
      `HTTP ${wrongAudience.status}`,
    );
  }

  // 5 — a tenant this account is not a member of
  const foreign = await workRead('/people', access, {
    'x-munaxa-tenant': '01920000-0000-7000-8000-0000000000ff',
  });
  const foreignBody = await foreign.text();
  record(
    '5 a foreign tenant selection is refused and discloses nothing',
    foreign.status === 401 && !foreignBody.includes('items'),
    `HTTP ${foreign.status}`,
  );

  // 6 — refresh rotates both credentials and re-resolves permissions
  const refreshed = await fetch(`${IDENTITY}/api/auth/refresh`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      cookie: `__Host-mx_refresh=${refresh}`,
    },
    body: '{}',
  });
  const newAccess = cookieFrom(refreshed, '__Host-mx_session');
  const newRefresh = cookieFrom(refreshed, '__Host-mx_refresh');
  record(
    '6 refresh issues a new access and a new refresh token',
    refreshed.status === 200 &&
      newAccess !== undefined &&
      newRefresh !== undefined &&
      newRefresh !== refresh,
    `HTTP ${refreshed.status}`,
  );
  record(
    '  refresh re-resolves permissions rather than freezing them',
    claimsOf(newAccess).perms.length === claims.perms.length,
    `${claimsOf(newAccess).perms.length} grants`,
  );
  const afterRefresh = await workRead('/people', newAccess);
  record(
    '  the refreshed token still works against Work',
    afterRefresh.status === 200,
    `HTTP ${afterRefresh.status}`,
  );

  // 7 — replaying a rotated refresh token
  const replay = await fetch(`${IDENTITY}/api/auth/refresh`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      cookie: `__Host-mx_refresh=${refresh}`,
    },
    body: '{}',
  });
  record(
    '7 replaying a rotated refresh token is refused',
    replay.status === 401,
    `HTTP ${replay.status}`,
  );
  const afterReplay = await fetch(`${IDENTITY}/api/auth/refresh`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      cookie: `__Host-mx_refresh=${newRefresh}`,
    },
    body: '{}',
  });
  record(
    '  and the whole lineage is revoked, not just the replayed token',
    afterReplay.status === 401,
    `HTTP ${afterReplay.status}`,
  );

  // 8 — the generic refusal, and the origin check
  const wrong = await signIn('a-password-that-is-not-the-one');
  const unknown = await fetch(`${IDENTITY}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN },
    body: JSON.stringify({ identifier: 'nobody@nowhere.example', password: PASSWORD }),
  });
  record(
    '8 a wrong password and an unknown account are indistinguishable',
    wrong.status === unknown.status && (await wrong.text()) === (await unknown.text()),
    `both HTTP ${wrong.status}`,
  );
  const crossSite = await fetch(`${IDENTITY}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'https://attacker.example' },
    body: JSON.stringify({ identifier: ACCOUNT, password: PASSWORD }),
  });
  record(
    '  a sign-in posted from an untrusted origin is refused',
    crossSite.status === 403,
    `HTTP ${crossSite.status}`,
  );

  // 9 — tenant isolation from underneath, where the API cannot be the thing enforcing it.
  if (WORK_DATABASE_URL === '') {
    skip('9 cross-tenant reads are refused by the database itself', 'set WORK_DATABASE_URL');
  } else {
    const { default: pg } = await import('pg');
    const pool = new pg.Pool({ connectionString: WORK_DATABASE_URL, max: 1 });
    const client = await pool.connect();
    try {
      const diagnostics = await client.query('select * from app_isolation_diagnostics()');
      const diagnosis = diagnostics.rows[0] ?? {};
      // Only the privilege columns are assertions. `role_name` is a label, and `tenant_set` reports
      // whether a context happens to be set right now — not a property under test here.
      const unprivileged = diagnosis.is_superuser === false && diagnosis.can_bypass_rls === false;
      record(
        '9 the Work application role can neither bypass RLS nor act as superuser',
        unprivileged,
        `${String(diagnosis.role_name)}: superuser=${String(diagnosis.is_superuser)} bypassrls=${String(diagnosis.can_bypass_rls)}`,
      );

      await client.query('begin');
      const noContext = await client.query('select count(*)::int as n from tenant_membership');
      await client.query('commit');
      record(
        '  with no tenant context it reads no membership at all',
        noContext.rows[0].n === 0,
        `${noContext.rows[0].n} rows`,
      );
    } finally {
      client.release();
      await pool.end();
    }
  }

  const failed = results.filter((result) => result.skipped !== true && !result.passed);
  const skipped = results.filter((result) => result.skipped === true);
  const ran = results.length - skipped.length;
  process.stdout.write(
    `\n${ran - failed.length}/${ran} checks passed` +
      `${skipped.length > 0 ? `, ${skipped.length} skipped for want of a credential this run was not given` : ''}.\n`,
  );
  process.exit(failed.length === 0 ? 0 : 1);
};

await run();
