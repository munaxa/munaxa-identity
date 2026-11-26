import { createHash, createSign, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { totpCode } from '@munaxa/auth';
import { defaultPasswordHasher } from '@munaxa/crypto';
import type { TenantId, UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment, type IdentityEnvironment } from '../../config/src/index.js';
import { AuthController } from '../../../apps/api/src/auth/auth.controller.js';
import { AuthService } from '../../../apps/api/src/auth/auth.service.js';
import { resolvePrincipal } from '../../../apps/api/src/auth/principal.js';
import { MfaFlowService } from '../../../apps/api/src/mfa/mfa-flow.service.js';
import { OperatorError, type OperatorDeps } from '../../../apps/api/src/ops/operator.js';
import { parseArguments, runCommand } from '../../../apps/api/src/ops/operator-cli.js';
import {
  ssoAccountConvert,
  ssoAccountCreate,
  ssoConnectionAdd,
  ssoConnectionSetEnabled,
} from '../../../apps/api/src/ops/sso-operator.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';
import { authEdgeRules, canonicalRoute } from '../../../apps/api/src/security/auth-edge-limits.js';
import { verifyIdToken } from '../../../apps/api/src/sso/id-token.js';
import type { ProviderCatalogue } from '../../../apps/api/src/sso/providers.js';
import { SSO_BINDING_COOKIE, SsoController } from '../../../apps/api/src/sso/sso.controller.js';
import { SsoService, type CallbackOutcome } from '../../../apps/api/src/sso/sso.service.js';
import { signInPage } from '../../../apps/api/src/ui/sign-in.page.js';
import { ssoPage } from '../../../apps/api/src/ui/sso.page.js';

/**
 * Company sign-in end to end, against a provider this file stands up: a real HTTP token endpoint
 * and JWKS, RS256 id tokens signed with a key generated here, and the real stack behind it
 * (PostgreSQL as `identity_app` under row-level security, Redis, ES256 Munaxa tokens).
 *
 * The provider is honest by default and each test makes it lie in one specific way. What is
 * asserted is the security property, not the code path: an id token from the wrong tenant, for the
 * wrong application, with the wrong nonce, unsigned, or for a person nobody provisioned never
 * becomes a session, and a flow can be finished once, by the browser that started it.
 */

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6379';
const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
const UA = 'Mozilla/5.0 (Windows NT 10.0) Edg/131.0';
const PASSWORD = `Correct-Horse-${randomUUID()}`;
const MICROSOFT_CLIENT = randomUUID();
const GOOGLE_CLIENT = '1234567890-testclient.apps.googleusercontent.com';
const CLIENT_SECRET = {
  microsoft: `ms-secret-${randomUUID()}`,
  google: `g-secret-${randomUUID()}`,
};
const ORIGIN = 'https://work.test.example';
const run = randomUUID().slice(0, 8);
const MS_DOMAIN = `contoso-${run}.example`;
const GOOGLE_DOMAIN = `fabrikam-${run}.example`;
const MS_TENANT = randomUUID();

// -------------------------------------------------------------------------------------------------
// The provider
// -------------------------------------------------------------------------------------------------

const providerKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const strangerKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = `kid-${run}`;

interface Issued {
  readonly provider: 'microsoft' | 'google';
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly claims: Record<string, unknown>;
  readonly signWith?: 'stranger' | 'none';
}

const codes = new Map<string, Issued>();
let tokenRequests = 0;
let server: Server;
let base: string;

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

const jwt = (claims: Record<string, unknown>, signWith?: 'stranger' | 'none'): string => {
  if (signWith === 'none') return `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.`;
  const header = b64({ alg: 'RS256', typ: 'JWT', kid: KID });
  const payload = b64(claims);
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  const key = signWith === 'stranger' ? strangerKey.privateKey : providerKey.privateKey;
  return `${header}.${payload}.${signer.sign(key).toString('base64url')}`;
};

const startProvider = async (): Promise<void> => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/jwks') {
      const jwk = {
        ...providerKey.publicKey.export({ format: 'jwk' }),
        kid: KID,
        alg: 'RS256',
        use: 'sig',
      };
      res
        .writeHead(200, { 'content-type': 'application/json' })
        .end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    if (req.method === 'POST' && url.pathname.endsWith('/token')) {
      tokenRequests += 1;
      let body = '';
      req.on('data', (chunk: Buffer) => (body += chunk.toString()));
      req.on('end', () => {
        const form = new URLSearchParams(body);
        const issued = codes.get(form.get('code') ?? '');
        const secret = issued === undefined ? undefined : CLIENT_SECRET[issued.provider];
        const verifier = form.get('code_verifier') ?? '';
        const challenge = createHash('sha256').update(verifier).digest('base64url');
        if (
          issued === undefined ||
          form.get('grant_type') !== 'authorization_code' ||
          form.get('client_id') !== issued.clientId ||
          form.get('client_secret') !== secret ||
          form.get('redirect_uri') !== issued.redirectUri ||
          challenge !== issued.codeChallenge
        ) {
          res
            .writeHead(400, { 'content-type': 'application/json' })
            .end('{"error":"invalid_grant"}');
          return;
        }
        // A code is single use at the provider too.
        codes.delete(form.get('code') ?? '');
        res
          .writeHead(200, { 'content-type': 'application/json' })
          .end(
            JSON.stringify({ id_token: jwt(issued.claims, issued.signWith), token_type: 'Bearer' }),
          );
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

const catalogue = (): ProviderCatalogue => ({
  microsoft: (tenant) => ({
    authorizationEndpoint: `${base}/${tenant}/authorize`,
    tokenEndpoint: `${base}/${tenant}/token`,
    jwksUri: `${base}/jwks`,
    issuers: [`${base}/${tenant}/v2.0`],
    extraParameters: {},
  }),
  google: (domain) => ({
    authorizationEndpoint: `${base}/google/authorize`,
    tokenEndpoint: `${base}/google/token`,
    jwksUri: `${base}/jwks`,
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    extraParameters: { hd: domain },
  }),
});

// -------------------------------------------------------------------------------------------------
// Identity
// -------------------------------------------------------------------------------------------------

const environmentFor = (overrides: Record<string, string> = {}): IdentityEnvironment =>
  loadEnvironment({
    NODE_ENV: 'test',
    IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
    DATABASE_URL: APPLICATION_URL,
    IDENTITY_BASE_URL: 'https://id.test.example',
    IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
    IDENTITY_SIGNING_KID: 'identity-test-2026-11',
    IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
    CSRF_TRUSTED_ORIGINS: `${ORIGIN},https://id.test.example`,
    REDIS_URL,
    MFA_ENCRYPTION_KEYS: `k=${randomBytes(32).toString('base64url')}`,
    MFA_ENCRYPTION_PRIMARY_KID: 'k',
    MFA_POLICY: 'privileged',
    MFA_PRIVILEGED_ROLES: 'operator-admin',
    IDENTITY_SSO: 'enabled',
    IDENTITY_SSO_MICROSOFT_CLIENT_ID: MICROSOFT_CLIENT,
    IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: CLIENT_SECRET.microsoft,
    IDENTITY_SSO_GOOGLE_CLIENT_ID: GOOGLE_CLIENT,
    IDENTITY_SSO_GOOGLE_CLIENT_SECRET: CLIENT_SECRET.google,
    ...overrides,
  });

const logged: string[] = [];
const logger = {
  error: (...args: unknown[]) => logged.push(JSON.stringify(args)),
  warn: (...args: unknown[]) => logged.push(JSON.stringify(args)),
  info: (...args: unknown[]) => logged.push(JSON.stringify(args)),
  debug: (...args: unknown[]) => logged.push(JSON.stringify(args)),
} as never;

const org = { key: `sso-${run}`, id: randomUUID() as TenantId };
const other = { key: `sso-other-${run}`, id: randomUUID() as TenantId };

let prisma: PrismaService;
let security: SecurityStack;
let environment: IdentityEnvironment;
let auth: AuthService;
let mfaFlow: MfaFlowService;
let sso: SsoService;
let controller: SsoController;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;
let microsoft: string;
let google: string;

const deps = (): OperatorDeps => ({ security, prisma, out: () => undefined });

const asOwner = async <T extends pg.QueryResultRow>(
  tenantId: string,
  sql: string,
  values: unknown[] = [],
): Promise<T[]> => {
  await owner.query('begin');
  try {
    await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
    const result = await owner.query<T>(sql, values);
    await owner.query('commit');
    return result.rows;
  } catch (error) {
    await owner.query('rollback');
    throw error;
  }
};

const localAccount = async (email: string, tenantId: string = org.id): Promise<UserId> => {
  const id = randomUUID() as UserId;
  await asOwner(
    tenantId,
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, password_hash, password_algorithm,
        password_updated_at, status, token_version, mfa_enrolled, must_change_password,
        identity_source, created_at, updated_at, version)
     values ($1, $2, $3, $3, $4, 'scrypt', now(), 'active', 1, false, false, 'local', now(), now(), 1)`,
    [id, tenantId, email, await defaultPasswordHasher.hash(PASSWORD)],
  );
  return id;
};

const preCreate = async (
  email: string,
  connectionId = microsoft,
  role?: string,
): Promise<UserId> => {
  const created = await ssoAccountCreate(deps(), {
    organisation: org.key,
    connectionId,
    account: email,
    ...(role === undefined ? {} : { role }),
    reference: 'TEST-1',
    apply: true,
  });
  return created.accountId!;
};

const accountRow = async (id: string) =>
  (
    await asOwner<{
      external_id: string | null;
      identity_source: string;
      password_hash: string | null;
      token_version: number;
    }>(
      org.id,
      'select external_id, identity_source, password_hash, token_version from identity_account where id = $1',
      [id],
    )
  )[0]!;

const context = (userAgent = UA) => ({
  origin: ORIGIN,
  userAgent,
  ipAddress: '203.0.113.9',
  correlationId: `corr-${randomUUID()}`,
});

/** What the provider would put in the id token for this person, honest by default. */
const claimsFor = (
  provider: 'microsoft' | 'google',
  person: { email: string; oid?: string; sub?: string },
  nonce: string,
  directory: string = MS_TENANT,
): Record<string, unknown> => {
  const now = Math.floor(Date.now() / 1_000);
  return provider === 'microsoft'
    ? {
        iss: `${base}/${directory}/v2.0`,
        aud: MICROSOFT_CLIENT,
        sub: `pairwise-${person.oid ?? 'x'}`,
        oid: person.oid ?? randomUUID(),
        tid: directory,
        preferred_username: person.email,
        email: person.email,
        nonce,
        iat: now,
        nbf: now,
        exp: now + 3_600,
      }
    : {
        iss: 'https://accounts.google.com',
        aud: GOOGLE_CLIENT,
        azp: GOOGLE_CLIENT,
        sub: person.sub ?? `${Date.now()}${Math.floor(Math.random() * 1e6)}`,
        hd: GOOGLE_DOMAIN,
        email: person.email,
        email_verified: true,
        nonce,
        iat: now,
        exp: now + 3_600,
      };
};

interface SignInOptions {
  readonly oid?: string;
  readonly sub?: string;
  /** Change the honest claims into a lie. */
  readonly tamper?: (claims: Record<string, unknown>) => Record<string, unknown>;
  readonly signWith?: 'stranger' | 'none';
  /** What the browser presents as `__Host-mx_sso` at the callback. */
  readonly binding?: (real: string) => string | undefined;
  readonly userAgent?: string;
  readonly redirectUri?: (real: string) => string;
}

/** Run a whole company sign-in as a browser would, with the provider issuing a code. */
const signIn = async (
  email: string,
  options: SignInOptions = {},
): Promise<{ outcome: CallbackOutcome; state: string; binding: string }> => {
  const started = await sso.start({
    email,
    returnTo: '/admin',
    language: 'en',
    context: context(),
  });
  if (started.kind !== 'redirect') throw new Error(`expected a redirect, got ${started.kind}`);
  const url = new URL(started.url);
  const provider = url.pathname.startsWith('/google') ? 'google' : 'microsoft';
  const state = url.searchParams.get('state')!;
  const nonce = url.searchParams.get('nonce')!;
  const code = randomBytes(24).toString('base64url');
  // The Entra tenant is the first path segment of a Microsoft authorize URL.
  const directory = provider === 'microsoft' ? url.pathname.split('/')[1]! : MS_TENANT;
  const honest = claimsFor(
    provider,
    {
      email,
      ...(options.oid ? { oid: options.oid } : {}),
      ...(options.sub ? { sub: options.sub } : {}),
    },
    nonce,
    directory,
  );
  codes.set(code, {
    provider,
    clientId: url.searchParams.get('client_id')!,
    redirectUri: (options.redirectUri ?? ((r) => r))(url.searchParams.get('redirect_uri')!),
    codeChallenge: url.searchParams.get('code_challenge')!,
    claims: options.tamper === undefined ? honest : options.tamper(honest),
    ...(options.signWith === undefined ? {} : { signWith: options.signWith }),
  });
  const outcome = await sso.callback({
    params: { code, state },
    binding: options.binding === undefined ? started.binding : options.binding(started.binding),
    context: context(options.userAgent),
  });
  return { outcome, state, binding: started.binding };
};

const sessionMethods = async (access: string) => {
  const resolved = await resolvePrincipal(security, access);
  if (!resolved.ok) throw new Error('expected a principal');
  return resolved.principal;
};

beforeAll(async () => {
  await startProvider();
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
  await createOrganisation(owner, other.key, other.id);
  await asOwner(
    org.id,
    `insert into identity_role (id, tenant_id, key, name, permissions, inherits, system, created_at, updated_at)
     values ($1, $2, 'operator-admin', 'Operator admin', '{}', '{}', true, now(), now()),
            ($3, $2, 'work-employee', 'Employee', '{}', '{}', true, now(), now())`,
    [randomUUID(), org.id, randomUUID()],
  );
  // The organisation's break-glass administrator: a password account.
  await localAccount(`admin@${MS_DOMAIN}`);

  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();
  environment = environmentFor();
  security = await buildSecurityStack(environment, prisma);
  auth = new AuthService(security, environment, prisma);
  mfaFlow = new MfaFlowService(security, environment, auth);
  sso = new SsoService(security, environment, prisma, auth, logger, {
    catalogue: catalogue(),
    fetcher: fetch as never,
    now: Date.now,
  });
  controller = new SsoController(sso);

  microsoft = (
    await ssoConnectionAdd(deps(), {
      organisation: org.key,
      provider: 'microsoft',
      directory: MS_TENANT,
      domains: MS_DOMAIN,
      trustProviderMfa: false,
      reference: 'TEST-1',
      apply: true,
    })
  ).connectionId!;
  google = (
    await ssoConnectionAdd(deps(), {
      organisation: org.key,
      provider: 'google',
      directory: GOOGLE_DOMAIN,
      domains: GOOGLE_DOMAIN,
      trustProviderMfa: false,
      reference: 'TEST-1',
      apply: true,
    })
  ).connectionId!;
  for (const connectionId of [microsoft, google]) {
    await ssoConnectionSetEnabled(deps(), {
      organisation: org.key,
      connectionId,
      enabled: true,
      endSessions: false,
      reference: 'TEST-1',
      apply: true,
    });
  }
});

afterAll(async () => {
  await security.close();
  await prisma.$disconnect();
  owner.release();
  await ownerPool.end();
  await new Promise((resolve) => server.close(resolve));
});

// -------------------------------------------------------------------------------------------------

describe('starting a company sign-in', () => {
  it('sends the browser to the company directory with PKCE, state, nonce and a browser binding', async () => {
    const started = await sso.start({
      email: `Someone@${MS_DOMAIN.toUpperCase()}`,
      returnTo: '/admin',
      language: 'en',
      context: context(),
    });
    expect(started.kind).toBe('redirect');
    if (started.kind !== 'redirect') return;
    const url = new URL(started.url);
    expect(url.origin + url.pathname).toBe(`${base}/${MS_TENANT}/authorize`);
    expect(url.searchParams.get('client_id')).toBe(MICROSOFT_CLIENT);
    expect(url.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/api/auth/sso/callback`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(url.searchParams.get('nonce')).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(url.searchParams.get('scope')).toBe('openid email profile');
    // The client secret never travels through the browser.
    expect(started.url).not.toContain(CLIENT_SECRET.microsoft);
    expect(started.binding).toMatch(/^[A-Za-z0-9_-]{40,}$/);
  });

  it('pins Google to the Workspace domain with hd', async () => {
    const started = await sso.start({
      email: `a@${GOOGLE_DOMAIN}`,
      returnTo: '/',
      language: 'en',
      context: context(),
    });
    if (started.kind !== 'redirect') throw new Error(started.kind);
    expect(new URL(started.url).searchParams.get('hd')).toBe(GOOGLE_DOMAIN);
    expect(new URL(started.url).searchParams.get('client_id')).toBe(GOOGLE_CLIENT);
  });

  it('offers nothing for a domain no enabled connection owns', async () => {
    for (const email of [
      'someone@unknown-domain.example',
      'not-an-address',
      `x@sub.${MS_DOMAIN}`,
    ]) {
      expect(
        (await sso.start({ email, returnTo: '/', language: 'en', context: context() })).kind,
      ).toBe('not-offered');
    }
  });

  it('refuses to build a callback for an origin Identity does not serve', async () => {
    const started = await sso.start({
      email: `a@${MS_DOMAIN}`,
      returnTo: '/',
      language: 'en',
      context: { ...context(), origin: 'https://evil.example' },
    });
    expect(started.kind).toBe('bad-origin');
  });

  it('answers 404 everywhere when the deployment has not enabled it', async () => {
    const off = new SsoService(
      security,
      environmentFor({ IDENTITY_SSO: 'disabled' }),
      prisma,
      auth,
      logger,
      {
        catalogue: catalogue(),
        fetcher: fetch as never,
        now: Date.now,
      },
    );
    const page = new SsoController(off);
    expect(() => page.page(undefined, undefined, undefined, {} as never)).toThrow(/Not Found/);
    expect(
      (
        await off.start({
          email: `a@${MS_DOMAIN}`,
          returnTo: '/',
          language: 'en',
          context: context(),
        })
      ).kind,
    ).toBe('not-offered');
  });
});

describe('a pre-created account signing in through Microsoft', () => {
  it('becomes an ordinary Munaxa session, bound to the Entra object id', async () => {
    const email = `ada-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await preCreate(email, microsoft, 'work-employee');
    const oid = randomUUID();
    const { outcome } = await signIn(email, { oid });
    expect(outcome.kind).toBe('signed-in');
    if (outcome.kind !== 'signed-in') return;
    expect(outcome.returnTo).toBe('/admin');
    expect(outcome.result.claims.sub).toBe(id);
    expect(outcome.result.claims.tid).toBe(org.id);
    const principal = await sessionMethods(outcome.result.access);
    expect(principal.claims.amr).toEqual(['microsoft']);
    expect(principal.claims.mfa).not.toBe(true);
    const row = await accountRow(id);
    expect(row.external_id).toBe(oid);
    expect(row.identity_source).toBe('federated');
    expect(row.password_hash).toBeNull();
    // The audit chain records the bind and the sign-in, by provider.
    const events = await asOwner<{ event_name: string }>(
      org.id,
      `select event_name from identity_audit_event where tenant_id = $1 and event::text like '%' || $2 || '%' order by sequence`,
      [org.id, id],
    );
    expect(events.map((e) => e.event_name)).toEqual(
      expect.arrayContaining(['auth.provider.linked', 'auth.login.succeeded']),
    );
  });

  it('matches on the object id from then on, whatever the address now says', async () => {
    const email = `grace-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await preCreate(email);
    const oid = randomUUID();
    expect((await signIn(email, { oid })).outcome.kind).toBe('signed-in');
    const renamed = await signIn(email, {
      oid,
      tamper: (c) => ({
        ...c,
        email: `renamed@${MS_DOMAIN}`,
        preferred_username: `renamed@${MS_DOMAIN}`,
      }),
    });
    expect(renamed.outcome.kind).toBe('signed-in');
    if (renamed.outcome.kind === 'signed-in') expect(renamed.outcome.result.claims.sub).toBe(id);
  });

  it('never binds a second person to an account already bound', async () => {
    const email = `linus-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    expect((await signIn(email, { oid: randomUUID() })).outcome.kind).toBe('signed-in');
    // A different Entra user whose directory entry carries the same address.
    expect((await signIn(email, { oid: randomUUID() })).outcome.kind).toBe('refused');
  });

  it('refuses a person nobody provisioned, and creates nothing', async () => {
    const email = `stranger-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    expect((await signIn(email, { oid: randomUUID() })).outcome.kind).toBe('refused');
    expect(await security.directory.findByIdentifier(org.id, email)).toBeUndefined();
  });

  it('never binds a password account by its address', async () => {
    const email = `local-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await localAccount(email);
    expect((await signIn(email, { oid: randomUUID() })).outcome.kind).toBe('refused');
    expect((await accountRow(id)).external_id).toBeNull();
  });

  it('refuses a disabled account', async () => {
    const email = `gone-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await preCreate(email);
    await security.lockdown.disable(org.id, id, { kind: 'system', id: 'operator:TEST-1' });
    expect((await signIn(email, { oid: randomUUID() })).outcome.kind).toBe('refused');
  });
});

describe('an id token that lies', () => {
  const cases: [string, SignInOptions][] = [
    [
      'from another Entra tenant',
      { tamper: (c) => ({ ...c, tid: randomUUID(), iss: `${base}/${randomUUID()}/v2.0` }) },
    ],
    ['naming another tenant in tid only', { tamper: (c) => ({ ...c, tid: randomUUID() }) }],
    ['issued for another application', { tamper: (c) => ({ ...c, aud: randomUUID() }) }],
    ['carrying another flow’s nonce', { tamper: (c) => ({ ...c, nonce: 'n'.repeat(43) }) }],
    ['expired', { tamper: (c) => ({ ...c, exp: Math.floor(Date.now() / 1_000) - 600 }) }],
    ['signed by a key the provider never published', { signWith: 'stranger' }],
    ['unsigned (alg none)', { signWith: 'none' }],
    [
      'for an address outside the connection’s domains',
      {
        tamper: (c) => ({
          ...c,
          email: 'x@elsewhere.example',
          preferred_username: 'x@elsewhere.example',
        }),
      },
    ],
    ['with no object id', { tamper: (c) => ({ ...c, oid: undefined }) }],
  ];
  for (const [name, options] of cases) {
    it(`is refused when ${name}`, async () => {
      const email = `lie-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
      const id = await preCreate(email);
      const { outcome } = await signIn(email, { oid: randomUUID(), ...options });
      expect(outcome.kind).toBe('refused');
      // And nothing was bound on the strength of it.
      expect((await accountRow(id)).external_id).toBeNull();
    });
  }
});

describe('Google Workspace', () => {
  it('signs a pre-created Workspace account in, bound to sub', async () => {
    const email = `wk-${randomUUID().slice(0, 6)}@${GOOGLE_DOMAIN}`;
    const id = await preCreate(email, google);
    const sub = `1${Date.now()}`;
    const { outcome } = await signIn(email, { sub });
    expect(outcome.kind).toBe('signed-in');
    if (outcome.kind === 'signed-in') {
      expect((await sessionMethods(outcome.result.access)).claims.amr).toEqual(['google']);
    }
    expect((await accountRow(id)).external_id).toBe(sub);
  });

  it('refuses a personal Google account (no hd), whatever the address says', async () => {
    const email = `gm-${randomUUID().slice(0, 6)}@${GOOGLE_DOMAIN}`;
    await preCreate(email, google);
    const { outcome } = await signIn(email, { tamper: (c) => ({ ...c, hd: undefined }) });
    expect(outcome.kind).toBe('refused');
  });

  it('refuses another Workspace domain and an unverified address', async () => {
    const email = `gv-${randomUUID().slice(0, 6)}@${GOOGLE_DOMAIN}`;
    await preCreate(email, google);
    expect(
      (await signIn(email, { tamper: (c) => ({ ...c, hd: 'other.example' }) })).outcome.kind,
    ).toBe('refused');
    expect(
      (await signIn(email, { tamper: (c) => ({ ...c, email_verified: false }) })).outcome.kind,
    ).toBe('refused');
  });
});

describe('the flow itself', () => {
  it('refuses a callback from a browser that did not start the flow (login CSRF), and spends it', async () => {
    const email = `csrf-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await preCreate(email);
    const noCookie = await signIn(email, { oid: randomUUID(), binding: () => undefined });
    expect(noCookie.outcome.kind).toBe('refused');
    const wrongCookie = await signIn(email, {
      oid: randomUUID(),
      binding: () => randomBytes(32).toString('base64url'),
    });
    expect(wrongCookie.outcome.kind).toBe('refused');
    // The flow the attacker presented is gone: the right cookie afterwards finds nothing.
    const replay = await sso.callback({
      params: { code: 'whatever', state: wrongCookie.state },
      binding: wrongCookie.binding,
      context: context(),
    });
    expect(replay.kind).toBe('refused');
    expect((await accountRow(id)).external_id).toBeNull();
  });

  it('finishes a flow once', async () => {
    const email = `once-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    const first = await signIn(email, { oid: randomUUID() });
    expect(first.outcome.kind).toBe('signed-in');
    const again = await sso.callback({
      params: { code: 'any', state: first.state },
      binding: first.binding,
      context: context(),
    });
    expect(again.kind).toBe('refused');
  });

  it('refuses a callback presented from another browser', async () => {
    const email = `ua-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    expect((await signIn(email, { oid: randomUUID(), userAgent: 'curl/8.0' })).outcome.kind).toBe(
      'refused',
    );
  });

  it('refuses a provider error without exchanging anything', async () => {
    const started = await sso.start({
      email: `e@${MS_DOMAIN}`,
      returnTo: '/',
      language: 'en',
      context: context(),
    });
    if (started.kind !== 'redirect') throw new Error(started.kind);
    const before = tokenRequests;
    const outcome = await sso.callback({
      params: { error: 'access_denied', state: new URL(started.url).searchParams.get('state')! },
      binding: started.binding,
      context: context(),
    });
    expect(outcome.kind).toBe('refused');
    expect(tokenRequests).toBe(before);
  });

  it('refuses when the provider will not redeem the code', async () => {
    const email = `code-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    // The provider sees a redirect_uri that differs from the one it issued the code for.
    const { outcome } = await signIn(email, {
      oid: randomUUID(),
      redirectUri: () => 'https://elsewhere.example/cb',
    });
    expect(outcome.kind).toBe('refused');
  });

  it('stops offering a connection the moment it is disabled, mid-flow included', async () => {
    const email = `off-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    const started = await sso.start({ email, returnTo: '/', language: 'en', context: context() });
    if (started.kind !== 'redirect') throw new Error(started.kind);
    await ssoConnectionSetEnabled(deps(), {
      organisation: org.key,
      connectionId: microsoft,
      enabled: false,
      endSessions: false,
      reference: 'TEST-1',
      apply: true,
    });
    try {
      expect(
        (await sso.start({ email, returnTo: '/', language: 'en', context: context() })).kind,
      ).toBe('not-offered');
      const outcome = await sso.callback({
        params: { code: 'c', state: new URL(started.url).searchParams.get('state')! },
        binding: started.binding,
        context: context(),
      });
      expect(outcome.kind).toBe('refused');
    } finally {
      await ssoConnectionSetEnabled(deps(), {
        organisation: org.key,
        connectionId: microsoft,
        enabled: true,
        endSessions: false,
        reference: 'TEST-1',
        apply: true,
      });
    }
  });

  it('logs the reason and never an address, a code or a token', async () => {
    const email = `log-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    logged.length = 0;
    await signIn(email, { oid: randomUUID(), tamper: (c) => ({ ...c, aud: 'x' }) });
    const text = logged.join('\n');
    expect(text).toContain('ID_TOKEN_AUDIENCE_MISMATCH');
    expect(text).not.toContain(email);
    expect(text).not.toContain(CLIENT_SECRET.microsoft);
  });
});

describe('MFA after a company sign-in', () => {
  it('still challenges an enrolled account, and records both methods', async () => {
    const email = `mfa-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    const oid = randomUUID();
    const first = await signIn(email, { oid });
    if (first.outcome.kind !== 'signed-in') throw new Error(first.outcome.kind);
    const principal = await sessionMethods(first.outcome.result.access);
    const started = await mfaFlow.startEnrollment(
      { via: 'session', principal },
      { correlationId: 'c', userAgent: UA },
    );
    if (!started.ok) throw new Error(started.refusal);
    const at = Date.now();
    const confirmed = await mfaFlow.confirmEnrollment(
      { via: 'session', principal },
      totpCode(started.value.secret, at),
      { correlationId: 'c', userAgent: UA },
    );
    if (!confirmed.ok) throw new Error(confirmed.refusal);

    const second = await signIn(email, { oid });
    expect(second.outcome.kind).toBe('mfa');
    if (second.outcome.kind !== 'mfa') return;
    expect(second.outcome.challenge.kind).toBe('verify');
    const verified = await mfaFlow.verifyChallenge(
      second.outcome.challenge.token,
      { code: totpCode(started.value.secret, at + 30_000) },
      { correlationId: 'c', userAgent: UA },
    );
    if (!verified.ok) throw new Error(verified.refusal);
    const session = await sessionMethods(verified.value.access);
    expect(session.claims.amr).toEqual(['microsoft', 'totp']);
    expect(session.claims.mfa).toBe(true);
  });

  it('admits a privileged account without a factor to enrollment only', async () => {
    const email = `priv-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email, microsoft, 'operator-admin');
    const { outcome } = await signIn(email, { oid: randomUUID() });
    expect(outcome.kind).toBe('mfa');
    if (outcome.kind === 'mfa') expect(outcome.challenge.kind).toBe('enroll');
  });

  it('lets the company’s MFA stand in only when the connection says so', async () => {
    const domain = `trusting-${run}.example`;
    const trusting = (
      await ssoConnectionAdd(deps(), {
        organisation: org.key,
        provider: 'microsoft',
        directory: randomUUID(),
        domains: domain,
        trustProviderMfa: true,
        reference: 'TEST-1',
        apply: true,
      })
    ).connectionId!;
    await ssoConnectionSetEnabled(deps(), {
      organisation: org.key,
      connectionId: trusting,
      enabled: true,
      endSessions: false,
      reference: 'TEST-1',
      apply: true,
    });
    const email = `adm-${randomUUID().slice(0, 6)}@${domain}`;
    await preCreate(email, trusting, 'operator-admin');
    const { outcome } = await signIn(email, { oid: randomUUID() });
    expect(outcome.kind).toBe('signed-in');
    if (outcome.kind === 'signed-in') {
      const principal = await sessionMethods(outcome.result.access);
      expect(principal.claims.mfa).toBe(true);
      expect(principal.claims.amr).toEqual(['microsoft']);
    }
  });
});

describe('passwords and company sign-in accounts', () => {
  it('a company sign-in account has no password to sign in with', async () => {
    const email = `nopw-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    for (const password of ['', PASSWORD, 'anything']) {
      const result = await auth.login({
        identifier: email,
        password,
        organisation: org.key,
        correlationId: 'corr' as never,
        userAgent: UA,
      });
      expect(result.ok).toBe(false);
    }
  });

  it('the database refuses a company sign-in account with a password, or a local one bound to a directory', async () => {
    await expect(
      asOwner(
        org.id,
        `insert into identity_account (id, tenant_id, identifier, identifier_normalized, password_hash,
           status, identity_source, identity_provider_id, updated_at)
         values ($1, $2, 'x@y.example', 'x@y.example', 'scrypt$x', 'active', 'federated', $3, now())`,
        [randomUUID(), org.id, microsoft],
      ),
    ).rejects.toThrow(/ck_identity_account_source/);
    await expect(
      asOwner(
        org.id,
        `insert into identity_account (id, tenant_id, identifier, identifier_normalized, password_hash,
           status, identity_source, identity_provider_id, updated_at)
         values ($1, $2, 'z@y.example', 'z@y.example', 'scrypt$x', 'active', 'local', $3, now())`,
        [randomUUID(), org.id, microsoft],
      ),
    ).rejects.toThrow(/ck_identity_account_source/);
  });

  it('password reset sends nothing for a company sign-in account', async () => {
    const email = `reset-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await preCreate(email);
    const sent: unknown[] = [];
    const recovery = await buildSecurityStack(
      environmentFor({
        IDENTITY_PASSWORD_RESET: 'enabled',
        IDENTITY_EMAIL_TRANSPORT: 'outbox',
        IDENTITY_EMAIL_FROM: 'no-reply@munaxa.example',
        IDENTITY_EMAIL_OUTBOX_DIR: '/tmp',
        IDENTITY_PASSWORD_RESET_URL: `${ORIGIN}/api/auth/password/reset`,
      }),
      prisma,
    );
    try {
      await recovery.recovery.request({
        organisation: org.key,
        identifier: email,
        ipAddress: '203.0.113.10',
        correlationId: 'corr' as never,
      } as never);
      await recovery.recovery.idle();
      const tokens = await asOwner<{ n: string }>(
        org.id,
        'select count(*)::text as n from identity_reset_token where account_id = $1',
        [id],
      );
      expect(tokens[0]!.n).toBe('0');
      expect(sent).toEqual([]);
    } finally {
      await recovery.close();
    }
  });
});

describe('operator commands', () => {
  it('moves a password account to company sign-in: password gone, sessions ended, id and roles kept', async () => {
    const email = `move-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    const id = await localAccount(email);
    const before = await auth.login({
      identifier: email,
      password: PASSWORD,
      organisation: org.key,
      correlationId: 'c' as never,
      userAgent: UA,
    });
    expect(before.ok).toBe(true);
    await ssoAccountConvert(deps(), {
      organisation: org.key,
      connectionId: microsoft,
      accountId: id,
      reference: 'TEST-2',
      apply: true,
    });
    const row = await accountRow(id);
    expect(row.identity_source).toBe('federated');
    expect(row.password_hash).toBeNull();
    if (before.ok) expect((await resolvePrincipal(security, before.access)).ok).toBe(false);
    const after = await signIn(email, { oid: randomUUID() });
    expect(after.outcome.kind).toBe('signed-in');
    if (after.outcome.kind === 'signed-in') expect(after.outcome.result.claims.sub).toBe(id);
  });

  it('keeps a break-glass password account: refuses to convert the last one', async () => {
    const lone = { key: `sso-lone-${run}`, id: randomUUID() as TenantId };
    await createOrganisation(owner, lone.key, lone.id);
    const domain = `lone-${run}.example`;
    const connection = (
      await ssoConnectionAdd(deps(), {
        organisation: lone.key,
        provider: 'microsoft',
        directory: randomUUID(),
        domains: domain,
        trustProviderMfa: false,
        reference: 'TEST-3',
        apply: true,
      })
    ).connectionId!;
    const id = await localAccount(`only@${domain}`, lone.id);
    await expect(
      ssoAccountConvert(deps(), {
        organisation: lone.key,
        connectionId: connection,
        accountId: id,
        reference: 'TEST-3',
        apply: true,
      }),
    ).rejects.toThrow(/break-glass/);
  });

  it('refuses public email domains and a domain another connection already owns', async () => {
    await expect(
      ssoConnectionAdd(deps(), {
        organisation: other.key,
        provider: 'google',
        directory: 'gmail.com',
        domains: 'gmail.com',
        trustProviderMfa: false,
        reference: 'TEST-4',
        apply: true,
      }),
    ).rejects.toThrow(OperatorError);
    await expect(
      ssoConnectionAdd(deps(), {
        organisation: other.key,
        provider: 'microsoft',
        directory: randomUUID(),
        domains: MS_DOMAIN,
        trustProviderMfa: false,
        reference: 'TEST-4',
        apply: true,
      }),
    ).rejects.toThrow(/Already bound/);
  });

  it('will not act on another organisation’s connection', async () => {
    await expect(
      ssoAccountCreate(deps(), {
        organisation: other.key,
        connectionId: microsoft,
        account: `x@${MS_DOMAIN}`,
        reference: 'TEST-5',
        apply: true,
      }),
    ).rejects.toThrow(/No such connection/);
  });

  it('creates an account only in one of the connection’s domains, and only once', async () => {
    await expect(preCreate(`x@elsewhere-${run}.example`)).rejects.toThrow(
      /not a domain of this connection/,
    );
    const email = `dup-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    await expect(preCreate(email)).rejects.toThrow(/already exists/);
  });

  it('ends every bound session when a connection is disabled with --end-sessions', async () => {
    const email = `end-${randomUUID().slice(0, 6)}@${GOOGLE_DOMAIN}`;
    await preCreate(email, google);
    const { outcome } = await signIn(email, { sub: `9${Date.now()}` });
    if (outcome.kind !== 'signed-in') throw new Error(outcome.kind);
    await ssoConnectionSetEnabled(deps(), {
      organisation: org.key,
      connectionId: google,
      enabled: false,
      endSessions: true,
      reference: 'TEST-6',
      apply: true,
    });
    try {
      expect((await resolvePrincipal(security, outcome.result.access)).ok).toBe(false);
    } finally {
      await ssoConnectionSetEnabled(deps(), {
        organisation: org.key,
        connectionId: google,
        enabled: true,
        endSessions: false,
        reference: 'TEST-6',
        apply: true,
      });
    }
  });

  it('is a dry run without --apply, and parses its switches', async () => {
    const out: string[] = [];
    await runCommand({ security, prisma, out: (line) => out.push(line) }, [
      'sso-connection-add',
      '--organisation',
      other.key,
      '--provider',
      'google',
      '--directory',
      `dry-${run}.example`,
      '--domains',
      `dry-${run}.example`,
      '--trust-provider-mfa',
    ]);
    expect(out.join('\n')).toMatch(/dry run: .*trust-provider-mfa=true/);
    expect(
      await prisma.identitySsoDomain.findUnique({ where: { domain: `dry-${run}.example` } }),
    ).toBeNull();
    expect(
      parseArguments(['sso-connection-disable', '--end-sessions', '--apply']).switches,
    ).toEqual(new Set(['end-sessions', 'apply']));
  });
});

describe('the routes as a browser meets them', () => {
  const recorder = () => {
    const recorded: {
      status: number;
      redirect?: string;
      cookies: string[];
      body?: unknown;
      headers: Record<string, unknown>;
    } = { status: 200, cookies: [], headers: {} };
    const res = {
      status(code: number) {
        recorded.status = code;
        return res;
      },
      setHeader(name: string, value: unknown) {
        recorded.headers[name.toLowerCase()] = value;
        if (name.toLowerCase() === 'set-cookie') recorded.cookies = value as string[];
        return res;
      },
      getHeader(name: string) {
        return recorded.headers[name.toLowerCase()];
      },
      json(body: unknown) {
        recorded.body = body;
        return res;
      },
      type() {
        return res;
      },
      send(body: unknown) {
        recorded.body = body;
        return res;
      },
      redirect(status: number, to: string) {
        recorded.status = status;
        recorded.redirect = to;
      },
    };
    return { res: res as never, recorded };
  };
  const browser = (
    cookies: Record<string, string>,
    body: Record<string, unknown> = {},
    form = true,
  ) =>
    ({
      cookies,
      body,
      protocol: 'https',
      get: (name: string) => (name === 'host' ? 'work.test.example' : undefined),
      headers: {
        'user-agent': UA,
        'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json',
      },
      ip: '203.0.113.20',
    }) as never;

  it('start sets a Lax, host-only, HttpOnly binding cookie and 303s to the provider', async () => {
    const { res, recorded } = recorder();
    await controller.start(
      { identifier: `a@${MS_DOMAIN}`, returnTo: '/admin', lang: 'en' },
      browser({}),
      res,
    );
    expect(recorded.status).toBe(303);
    expect(recorded.redirect).toContain(`${base}/${MS_TENANT}/authorize?`);
    const cookie = recorded.cookies.find((c) => c.startsWith(`${SSO_BINDING_COOKIE}=`))!;
    expect(cookie).toMatch(/; Path=\//);
    expect(cookie).toMatch(/; Secure/);
    expect(cookie).toMatch(/; HttpOnly/);
    expect(cookie).toMatch(/; SameSite=Lax/);
    expect(cookie).not.toMatch(/Domain=/i);
  });

  it('an unknown domain goes back to the page with a message, never to a provider', async () => {
    const { res, recorded } = recorder();
    await controller.start(
      { identifier: 'a@nowhere.example', returnTo: '/x', lang: 'ar' },
      browser({}),
      res,
    );
    expect(recorded.redirect).toBe('/api/auth/sso?lang=ar&error=not-offered&returnTo=%2Fx');
    expect(recorded.cookies).toEqual([]);
  });

  it('returnTo cannot become an open redirect', async () => {
    const { res, recorded } = recorder();
    await controller.start(
      { identifier: `a@${MS_DOMAIN}`, returnTo: '//evil.example', lang: 'en' },
      browser({}),
      res,
    );
    const state = new URL(recorded.redirect!).searchParams.get('state')!;
    const cookie = recorded.cookies[0]!.split(';')[0]!.split('=')[1]!;
    const back = recorder();
    await controller.callback(
      { state, error: 'access_denied' },
      browser({ [SSO_BINDING_COOKIE]: cookie }),
      back.res,
    );
    expect(back.recorded.redirect).toBe('/api/auth/login?lang=en&error=sso&returnTo=%2F');
  });

  it('a successful callback sets the session cookies, clears the binding and returns to the page', async () => {
    const email = `route-${randomUUID().slice(0, 6)}@${MS_DOMAIN}`;
    await preCreate(email);
    const start = recorder();
    await controller.start(
      { identifier: email, returnTo: '/admin/people', lang: 'en' },
      browser({}),
      start.res,
    );
    const url = new URL(start.recorded.redirect!);
    const code = randomBytes(24).toString('base64url');
    codes.set(code, {
      provider: 'microsoft',
      clientId: MICROSOFT_CLIENT,
      redirectUri: url.searchParams.get('redirect_uri')!,
      codeChallenge: url.searchParams.get('code_challenge')!,
      claims: claimsFor('microsoft', { email, oid: randomUUID() }, url.searchParams.get('nonce')!),
    });
    const binding = decodeURIComponent(start.recorded.cookies[0]!.split(';')[0]!.split('=')[1]!);
    const back = recorder();
    await controller.callback(
      { code, state: url.searchParams.get('state')! },
      browser({ [SSO_BINDING_COOKIE]: binding }),
      back.res,
    );
    expect(back.recorded.status).toBe(303);
    expect(back.recorded.redirect).toBe('/admin/people');
    expect(back.recorded.cookies.some((c) => c.startsWith('__Host-mx_session='))).toBe(true);
    expect(back.recorded.cookies.some((c) => c.startsWith('__Secure-mx_refresh='))).toBe(true);
    expect(
      back.recorded.cookies.some(
        (c) => c.startsWith(`${SSO_BINDING_COOKIE}=;`) && c.includes('Max-Age=0'),
      ),
    ).toBe(true);
  });
});

describe('the pages', () => {
  it('offers company sign-in on the sign-in page only when it is enabled', () => {
    const on = signInPage({
      language: 'en',
      returnTo: '/a b',
      organisationRequired: false,
      companySignIn: true,
    });
    expect(on).toContain('href="/api/auth/sso?lang=en&amp;returnTo=%2Fa%20b"');
    expect(on).toContain('Sign in with Microsoft or Google');
    const off = signInPage({ language: 'en', returnTo: '/', organisationRequired: false });
    expect(off).not.toContain('/api/auth/sso');
    expect(
      signInPage({ language: 'ar', returnTo: '/', organisationRequired: false, error: 'sso' }),
    ).toContain('تعذّر');
  });

  it('the company page asks for an address and nothing else', () => {
    const page = ssoPage({ language: 'en', returnTo: '/"><script>' });
    expect(page).toContain('action="/api/auth/sso/start"');
    expect(page).not.toContain('type="password"');
    expect(page).not.toContain('<script>');
  });
});

describe('the edge', () => {
  it('counts company sign-in starts and callbacks per address', () => {
    const rule = authEdgeRules({
      loginPerIp: 300,
      loginPerIdentifier: 20,
      passwordResetPerIp: 60,
      mfaPerIp: 300,
      mfaPerSession: 10,
    }).find((r) => r.id === 'sso-per-ip')!;
    expect(
      rule.match?.({ method: 'POST', path: canonicalRoute('/api/auth/sso/start') } as never),
    ).toBe(true);
    expect(
      rule.match?.({
        method: 'GET',
        path: canonicalRoute('/api/auth/sso/callback?code=x&state=y'),
      } as never),
    ).toBe(true);
    expect(
      rule.match?.({ method: 'GET', path: canonicalRoute('/api/auth/SSO/%63allback') } as never),
    ).toBe(true);
    expect(rule.match?.({ method: 'GET', path: canonicalRoute('/api/auth/sso') } as never)).toBe(
      false,
    );
  });
});

describe('id-token verification', () => {
  it('accepts only an exact issuer spelling from the list', () => {
    const now = Math.floor(Date.now() / 1_000);
    const claims = {
      iss: 'https://accounts.google.com/',
      aud: 'a',
      sub: 's',
      nonce: 'n',
      iat: now,
      exp: now + 60,
    };
    const keys = [{ ...providerKey.publicKey.export({ format: 'jwk' }), kid: KID } as never];
    const outcome = verifyIdToken(jwt(claims), keys, {
      issuers: ['https://accounts.google.com'],
      audience: 'a',
      nonce: 'n',
      now: new Date(),
    });
    expect(outcome).toEqual({ ok: false, reason: 'ISSUER_MISMATCH' });
  });
});

describe('row-level security on the company sign-in tables', () => {
  it('hides connections without the organisation’s context, and from another organisation', async () => {
    expect(await prisma.identitySsoConnection.count()).toBe(0);
    expect(
      await prisma.withTenant(other.id, (tx) =>
        tx.identitySsoConnection.count({ where: { tenantId: org.id } }),
      ),
    ).toBe(0);
    expect(
      await prisma.withTenant(org.id, (tx) =>
        tx.identitySsoConnection.count({ where: { id: microsoft } }),
      ),
    ).toBe(1);
  });

  it('lets anyone look a domain up, but only the organisation itself add or remove one', async () => {
    expect(
      await prisma.identitySsoDomain.findUnique({ where: { domain: MS_DOMAIN } }),
    ).not.toBeNull();
    await expect(
      prisma.withTenant(other.id, (tx) =>
        tx.identitySsoDomain.create({
          data: { domain: `hijack-${run}.example`, connectionId: microsoft, tenantId: org.id },
        }),
      ),
    ).rejects.toThrow();
    // A domain row naming its own organisation but another's connection fails the composite key.
    await expect(
      prisma.withTenant(other.id, (tx) =>
        tx.identitySsoDomain.create({
          data: { domain: `hijack-${run}.example`, connectionId: microsoft, tenantId: other.id },
        }),
      ),
    ).rejects.toThrow();
    const removed = await prisma.withTenant(other.id, (tx) =>
      tx.identitySsoDomain.deleteMany({ where: { domain: MS_DOMAIN } }),
    );
    expect(removed.count).toBe(0);
    expect(
      await prisma.identitySsoDomain.findUnique({ where: { domain: MS_DOMAIN } }),
    ).not.toBeNull();
  });
});
