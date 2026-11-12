import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { TokenService } from '@munaxa/auth';
import { AsymmetricSigner, defaultPasswordHasher } from '@munaxa/crypto';
import { toCorrelationId, type SessionId, type TenantId, type UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment, type IdentityEnvironment } from '../../config/src/index.js';
import { AccountSessionsService } from '../../../apps/api/src/account/account-sessions.service.js';
import { AuthService } from '../../../apps/api/src/auth/auth.service.js';
import { resolvePrincipal } from '../../../apps/api/src/auth/principal.js';
import {
  TokenIntrospectionController,
  introspectAccessToken,
  type IntrospectionOutcome,
} from '../../../apps/api/src/auth/token-introspection.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * `GET /api/auth/introspect`, end to end against a real PostgreSQL as the restricted application
 * role, with real ES256 tokens, the real session and refresh machinery, and the real password,
 * lockdown and session-revocation services.
 *
 * The property a product relies on is narrow and absolute: **once Identity has revoked a session by
 * any route, introspection of any access token for it answers `active: false`, and nothing —
 * refresh, a replayed refresh token, a race with a refresh — makes it answer `active: true` again.**
 * Each test drives one revocation route through the service that a user or operator would use, then
 * asks the question the way Munaxa Work does.
 */

const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const PASSWORD = `Correct-Horse-${randomUUID()}`;
const NEW_PASSWORD = `Battery-Staple-${randomUUID()}`;

let outbox: string;
let environment: IdentityEnvironment;
let prisma: PrismaService;
let security: SecurityStack;
let auth: AuthService;
let sessions: AccountSessionsService;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;

const org = { key: `introspect-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
const otherOrg = { key: `introspect-b-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };

const createPerson = async (tenantId: TenantId, identifier: string): Promise<UserId> => {
  const id = randomUUID() as UserId;
  const encoded = await defaultPasswordHasher.hash(PASSWORD);
  await owner.query('begin');
  await owner.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
  await owner.query(
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, password_hash, password_algorithm,
        password_updated_at, status, token_version, mfa_enrolled, must_change_password,
        identity_source, created_at, updated_at, version)
     values ($1, $2, $3, $3, $4, $5, now(), 'active', 1, false, false, 'local', now(), now(), 1)`,
    [id, tenantId, identifier, encoded, encoded.split('$')[1] ?? 'unknown'],
  );
  await owner.query('commit');
  return id;
};

const person = async (target = org): Promise<{ id: UserId; identifier: string }> => {
  const identifier = `p-${randomUUID().slice(0, 10)}@example.test`;
  return { id: await createPerson(target.id, identifier), identifier };
};

interface SignedIn {
  readonly access: string;
  readonly refresh: string;
  readonly sessionId: SessionId;
}

const signIn = async (
  identifier: string,
  password = PASSWORD,
  target: { key: string } = org,
): Promise<SignedIn> => {
  const result = await auth.login({
    identifier,
    password,
    organisation: target.key,
    correlationId: toCorrelationId(`corr-${randomUUID()}`),
  });
  if (!result.ok) throw new Error(`sign-in failed: ${JSON.stringify(result.failure)}`);
  return {
    access: result.access,
    refresh: result.refresh,
    sessionId: result.claims.sid as SessionId,
  };
};

const refresh = (token: string) => auth.refresh({ refreshToken: token, organisation: org.key });

const introspect = (token: string | undefined): Promise<IntrospectionOutcome> =>
  introspectAccessToken(security, token);

const isActive = async (token: string): Promise<boolean> => {
  const outcome = await introspect(token);
  if (outcome.kind !== 'answered') throw new Error('introspection unavailable');
  return outcome.answer.active;
};

beforeAll(async () => {
  outbox = await mkdtemp(join(tmpdir(), 'identity-introspect-outbox-'));
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await createOrganisation(owner, org.key, org.id);
  await createOrganisation(owner, otherOrg.key, otherOrg.id);

  environment = loadEnvironment({
    NODE_ENV: 'test',
    IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
    DATABASE_URL: APPLICATION_URL,
    IDENTITY_BASE_URL: 'http://localhost:4001',
    IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
    IDENTITY_SIGNING_KID: 'identity-test-2026-11',
    IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
    CSRF_TRUSTED_ORIGINS: 'http://localhost:3001,https://id.example.test',
    IDENTITY_PASSWORD_RESET: 'enabled',
    IDENTITY_PASSWORD_RESET_URL: 'https://id.example.test/api/auth/password/reset',
    IDENTITY_EMAIL_TRANSPORT: 'outbox',
    IDENTITY_EMAIL_OUTBOX_DIR: outbox,
    IDENTITY_EMAIL_FROM: 'no-reply@example.test',
  });
  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();
  security = await buildSecurityStack(environment, prisma);
  auth = new AuthService(security, environment, prisma);
  sessions = new AccountSessionsService(security, environment);
});

afterAll(async () => {
  await security?.close();
  await prisma?.$disconnect();
  owner.release();
  await ownerPool.end();
  await rm(outbox, { recursive: true, force: true });
});

describe('a live session', () => {
  it('is active, and the answer names the token’s own subject, organisation and session only', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const outcome = await introspect(signedIn.access);
    const claims = security.tokens.verifyAccessToken(signedIn.access);

    expect(outcome).toEqual({
      kind: 'answered',
      answer: {
        active: true,
        sub: someone.id,
        tid: org.id,
        sid: signedIn.sessionId,
        exp: claims.exp,
      },
    });
    // No permission set, no roles, no token, no account record.
    expect(Object.keys((outcome as { answer: object }).answer).sort()).toEqual([
      'active',
      'exp',
      'sid',
      'sub',
      'tid',
    ]);
  });

  it('stays active across refresh, for the new token and the one it replaced', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const rotated = await refresh(signedIn.refresh);
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;
    expect(await isActive(rotated.access)).toBe(true);
    // The earlier access token belongs to the same live session; it expires on its own clock.
    expect(await isActive(signedIn.access)).toBe(true);
  });
});

describe('every revocation route ends introspection', () => {
  it('logout', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    expect(await isActive(signedIn.access)).toBe(true);

    await auth.logout({ refreshToken: signedIn.refresh, accessToken: signedIn.access });

    expect(await isActive(signedIn.access)).toBe(false);
    expect((await refresh(signedIn.refresh)).ok).toBe(false);
  });

  it('revoking one session leaves the others active', async () => {
    const someone = await person();
    const current = await signIn(someone.identifier);
    const target = await signIn(someone.identifier);

    expect((await sessions.revoke(current.access, target.sessionId, 'corr-introspect')).ok).toBe(
      true,
    );

    expect(await isActive(target.access)).toBe(false);
    expect(await isActive(current.access)).toBe(true);
    expect((await refresh(target.refresh)).ok).toBe(false);
  });

  it('revoking the other sessions keeps exactly the current one', async () => {
    const someone = await person();
    const current = await signIn(someone.identifier);
    const others = [await signIn(someone.identifier), await signIn(someone.identifier)];

    expect((await sessions.revokeOthers(current.access, 'corr-introspect')).ok).toBe(true);

    expect(await isActive(current.access)).toBe(true);
    for (const other of others) expect(await isActive(other.access)).toBe(false);
  });

  it('a password change ends every session, the one it was made from included', async () => {
    const someone = await person();
    const elsewhere = await signIn(someone.identifier);
    const here = await signIn(someone.identifier);

    const changed = await security.passwordChange.change({
      accessToken: here.access,
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      correlationId: toCorrelationId('corr-change'),
    });
    expect(changed.kind).toBe('changed');

    expect(await isActive(elsewhere.access)).toBe(false);
    expect(await isActive(here.access)).toBe(false);
    const again = await signIn(someone.identifier, NEW_PASSWORD);
    expect(await isActive(again.access)).toBe(true);
  });

  it('password recovery ends every session, through the real mailed link', async () => {
    const someone = await person();
    const before = [await signIn(someone.identifier), await signIn(someone.identifier)];

    await security.recovery.request({
      organisation: org.key,
      identifier: someone.identifier,
      ipAddress: '203.0.113.9',
      correlationId: toCorrelationId('corr-recover'),
    });
    await security.recovery.idle();
    const token = await mailedResetToken(someone.identifier);

    const completed = await security.recovery.complete({
      organisation: org.key,
      token,
      password: NEW_PASSWORD,
      correlationId: toCorrelationId('corr-recover'),
    });
    expect(completed).toEqual({ kind: 'completed' });

    for (const signedIn of before) {
      expect(await isActive(signedIn.access)).toBe(false);
      expect((await refresh(signedIn.refresh)).ok).toBe(false);
    }
  });

  it('suspected-compromise lockdown', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    await security.lockdown.suspectedCompromise(org.id, someone.id);
    expect(await isActive(signedIn.access)).toBe(false);
    expect((await refresh(signedIn.refresh)).ok).toBe(false);
  });

  it('account disablement, including before the session revocation step has run', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    // Only the first write of `disable`: the status. The session row is still live.
    await security.directory.setStatus(org.id, someone.id, 'disabled');
    expect(await isActive(signedIn.access)).toBe(false);

    const other = await person();
    const otherSignedIn = await signIn(other.identifier);
    await security.lockdown.disable(org.id, other.id);
    expect(await isActive(otherSignedIn.access)).toBe(false);
  });

  it('a token-version bump alone, as an MFA removal or an operator reset performs it', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    await security.directory.incrementTokenVersion(org.id, someone.id);
    expect(await isActive(signedIn.access)).toBe(false);
  });
});

describe('nothing brings a revoked session back', () => {
  it('a refresh after revocation is refused, and mints nothing that introspects active', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    await security.revocation.revokeSession(org.id, someone.id, signedIn.sessionId, 'logout');

    const attempt = await refresh(signedIn.refresh);
    expect(attempt.ok).toBe(false);
    expect(await isActive(signedIn.access)).toBe(false);
  });

  it('a replayed refresh token revokes the session, and both lineages’ access tokens go inactive', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const first = await refresh(signedIn.refresh);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(await isActive(first.access)).toBe(true);

    // The original refresh token again: two parties hold this lineage.
    expect((await refresh(signedIn.refresh)).ok).toBe(false);

    expect(await isActive(signedIn.access)).toBe(false);
    expect(await isActive(first.access)).toBe(false);
    expect((await refresh(first.refresh)).ok).toBe(false);
  });

  it('every access token minted while a refresh races a revocation is inactive afterwards', async () => {
    for (let round = 0; round < 5; round += 1) {
      const someone = await person();
      const current = await signIn(someone.identifier);
      const target = await signIn(someone.identifier);

      const minted: string[] = [target.access];
      let token = target.refresh;
      const rotations = (async () => {
        for (let step = 0; step < 6; step += 1) {
          const rotated = await refresh(token);
          if (!rotated.ok) return;
          minted.push(rotated.access);
          token = rotated.refresh;
        }
      })();
      const revoked = sessions.revoke(current.access, target.sessionId, 'corr-introspect');
      await Promise.all([rotations, revoked]);

      for (const access of minted) expect(await isActive(access)).toBe(false);
      expect(await isActive(current.access)).toBe(true);
    }
  });
});

describe('tokens that never stood', () => {
  it('no token, a malformed one, another key’s, a sessionless one and an expired one are inactive', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const claims = security.tokens.verifyAccessToken(signedIn.access);

    const foreignKey = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const forger = new TokenService({
      signer: new AsymmetricSigner('ES256', [
        {
          kid: 'identity-test-2026-11',
          privateKey: foreignKey.privateKey,
          publicKey: foreignKey.publicKey,
        },
      ]),
      issuer: environment.MUNAXA_TOKEN_ISSUER,
      audience: environment.MUNAXA_TOKEN_AUDIENCE,
    });
    const forged = forger.issueAccessToken({
      subject: someone.id,
      tenantId: org.id,
      tokenVersion: 1,
      sessionId: signedIn.sessionId,
    }).token;

    const sessionless = security.tokens.issueAccessToken({
      subject: someone.id,
      tenantId: org.id,
      tokenVersion: claims.ver,
    }).token;

    const expired = security.tokens.issueAccessToken({
      subject: someone.id,
      tenantId: org.id,
      tokenVersion: claims.ver,
      sessionId: signedIn.sessionId,
      ttl: -120_000 as never,
    }).token;

    for (const token of [undefined, '', 'not-a-jwt', 'a.b.c', forged, sessionless, expired]) {
      expect(await introspect(token)).toEqual({ kind: 'answered', answer: { active: false } });
    }
  });

  // Platform 2.5.0 (#100): `verifyAccessToken` refuses a signed token whose `exp` is missing or not
  // a finite number (2.4.1 compared against NaN, so it never expired), a non-numeric `iat`, and
  // reads a string `aud` as one value instead of matching it as a substring. These tokens carry
  // Identity's own valid signature and a live session, so only those claim checks can refuse them.
  it('a token with Identity’s own signature but no usable expiry, issue time or exact audience is inactive', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const claims = security.tokens.verifyAccessToken(signedIn.access);
    expect(await isActive(signedIn.access)).toBe(true);

    const ownKey = new AsymmetricSigner('ES256', [
      {
        kid: 'identity-test-2026-11',
        privateKey: signingKey.privateKey,
        publicKey: signingKey.publicKey,
      },
    ]);
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value)).toString('base64url');
    const signedWithOwnKey = (payload: Record<string, unknown>): string => {
      const header = encode({ alg: 'ES256', typ: 'JWT', kid: 'identity-test-2026-11' });
      const body = encode(payload);
      return `${header}.${body}.${ownKey.sign(`${header}.${body}`).value}`;
    };
    const withoutExpiry: Record<string, unknown> = { ...claims };
    delete withoutExpiry.exp;

    // The control: the same construction with the claims unchanged is a token Identity accepts,
    // so each refusal below is the claim check, not the construction.
    expect(await isActive(signedWithOwnKey({ ...claims }))).toBe(true);

    for (const token of [
      signedWithOwnKey(withoutExpiry),
      signedWithOwnKey({ ...claims, exp: String(claims.exp) }),
      signedWithOwnKey({ ...claims, exp: null }),
      signedWithOwnKey({ ...claims, iat: 'yesterday' }),
      signedWithOwnKey({ ...claims, aud: 'not-munaxa-work-at-all' }),
      signedWithOwnKey({ ...claims, aud: 'munaxa-workshop' }),
    ]) {
      expect(await introspect(token)).toEqual({ kind: 'answered', answer: { active: false } });
      expect((await resolvePrincipal(security, token)).ok).toBe(false);
    }
    // A string `aud` naming exactly the trusted audience is still valid (RFC 7519 §4.1.3).
    expect(await isActive(signedWithOwnKey({ ...claims, aud: 'munaxa-work' }))).toBe(true);
  });

  it('a token naming a session of another organisation, or of another person, is inactive', async () => {
    const someone = await person();
    const other = await person();
    const foreigner = await person(otherOrg);
    const mine = await signIn(someone.identifier);
    const theirs = await signIn(other.identifier);
    const abroad = await signIn(foreigner.identifier, PASSWORD, otherOrg);
    const claims = security.tokens.verifyAccessToken(mine.access);

    const pointingAtTheirs = security.tokens.issueAccessToken({
      subject: someone.id,
      tenantId: org.id,
      tokenVersion: claims.ver,
      sessionId: theirs.sessionId,
    }).token;
    const pointingAbroad = security.tokens.issueAccessToken({
      subject: someone.id,
      tenantId: org.id,
      tokenVersion: claims.ver,
      sessionId: abroad.sessionId,
    }).token;

    expect(await isActive(pointingAtTheirs)).toBe(false);
    expect(await isActive(pointingAbroad)).toBe(false);
  });
});

describe('when Identity cannot tell', () => {
  it('answers unavailable, never active and never inactive', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const broken = {
      ...security,
      directory: { findById: () => Promise.reject(new Error('connection terminated')) },
    } as never;
    expect(await introspectAccessToken(broken, signedIn.access)).toEqual({ kind: 'unavailable' });
  });
});

describe('the HTTP surface', () => {
  interface Captured {
    status: number;
    body: unknown;
    headers: Record<string, unknown>;
  }
  const fakeResponse = (): { response: never; captured: Captured } => {
    const captured: Captured = { status: 200, body: undefined, headers: {} };
    const response = {
      status(code: number) {
        captured.status = code;
        return response;
      },
      json(body: unknown) {
        captured.body = body;
        return response;
      },
      setHeader(name: string, value: unknown) {
        captured.headers[name.toLowerCase()] = value;
        return response;
      },
    };
    return { response: response as never, captured };
  };
  const logged: string[] = [];
  const logger = { error: (...args: unknown[]) => logged.push(JSON.stringify(args)) } as never;
  const withAuthorization = (value: string | undefined) =>
    ({ headers: value === undefined ? {} : { authorization: value } }) as never;

  it('reads only a Bearer header, answers no-store, and never echoes or logs the token', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const controller = new TokenIntrospectionController(security, logger);

    const live = fakeResponse();
    await controller.introspect(withAuthorization(`Bearer ${signedIn.access}`), live.response);
    expect(live.captured.status).toBe(200);
    expect(live.captured.body).toMatchObject({ active: true, sid: signedIn.sessionId });
    expect(live.captured.headers['cache-control']).toBe('no-store');
    expect(JSON.stringify(live.captured.body)).not.toContain(signedIn.access);

    for (const header of [
      undefined,
      signedIn.access,
      `Basic ${signedIn.access}`,
      `Bearer ${signedIn.access} extra`,
    ]) {
      const refused = fakeResponse();
      await controller.introspect(withAuthorization(header), refused.response);
      expect(refused.captured).toMatchObject({ status: 200, body: { active: false } });
      expect(refused.captured.headers['cache-control']).toBe('no-store');
    }

    // A cookie is not a bearer header: this route is for a product holding the token itself.
    const cookieOnly = fakeResponse();
    await controller.introspect(
      { headers: {}, cookies: { '__Host-mx_session': signedIn.access } } as never,
      cookieOnly.response,
    );
    expect(cookieOnly.captured.body).toEqual({ active: false });
  });

  it('answers 503 with Retry-After when a dependency fails, and logs no token', async () => {
    const someone = await person();
    const signedIn = await signIn(someone.identifier);
    const broken = {
      ...security,
      directory: { findById: () => Promise.reject(new Error('connection terminated')) },
    } as never;
    const controller = new TokenIntrospectionController(broken, logger);
    const answer = fakeResponse();
    await controller.introspect(withAuthorization(`Bearer ${signedIn.access}`), answer.response);
    expect(answer.captured).toMatchObject({ status: 503, body: { code: 'AUTH_UNAVAILABLE' } });
    expect(answer.captured.headers['retry-after']).toBe('5');
    expect(answer.captured.headers['cache-control']).toBe('no-store');
    expect(logged.join('\n')).not.toContain(signedIn.access);
  });
});

/** The reset token in the newest message the outbox holds for this person. */
const mailedResetToken = async (identifier: string): Promise<string> => {
  for (const file of (await readdir(outbox)).sort().reverse()) {
    const message = JSON.parse(await readFile(join(outbox, file), 'utf8')) as {
      to?: unknown;
      recipient?: unknown;
      body?: string;
    };
    if (!JSON.stringify(message).includes(identifier)) continue;
    const link = /https:\/\/\S+/.exec(message.body ?? '');
    const token = link === null ? null : new URL(link[0]).searchParams.get('token');
    if (token !== null) return token;
  }
  throw new Error('no reset link in the outbox');
};
