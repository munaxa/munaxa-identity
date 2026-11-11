import { generateKeyPairSync, randomUUID } from 'node:crypto';

import { TokenService } from '@munaxa/auth';
import { AsymmetricSigner, defaultPasswordHasher } from '@munaxa/crypto';
import type { EpochMillis, SessionId, TenantId, UserId } from '@munaxa/types';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { APPLICATION_URL, OWNER_URL, createOrganisation } from './index.js';
import { loadEnvironment, type IdentityEnvironment } from '../../config/src/index.js';
import { AccountSessionsController } from '../../../apps/api/src/account/account-sessions.controller.js';
import { AccountSessionsService } from '../../../apps/api/src/account/account-sessions.service.js';
import { resolvePrincipal } from '../../../apps/api/src/auth/principal.js';
import { AuthService } from '../../../apps/api/src/auth/auth.service.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';
import { PrismaSessionStore } from '../../../apps/api/src/persistence/session-store.adapter.js';
import { buildSecurityStack, type SecurityStack } from '../../../apps/api/src/platform/security.js';

/**
 * Session management, end to end, against a real PostgreSQL as the restricted application role.
 *
 * Nothing here is mocked below the service: sign-in is `AuthService.login` through Platform's
 * `LoginService`, sessions are rows written by `PrismaSessionStore` under row-level security, and
 * the access tokens are real ES256 JWTs from the real signer. The properties under test — that a
 * caller cannot reach another person's sessions by changing an id, that a revoked session stays
 * revoked whatever races it, that a refresh cannot bring one back — are properties of that whole
 * path, and a test of any one layer alone would pass while the path failed.
 */

const signingKey = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const baseEnvironment = (overrides: Record<string, string> = {}): IdentityEnvironment =>
  loadEnvironment({
    NODE_ENV: 'test',
    IDENTITY_SIGNING_SECRET: `test-only-pepper-${randomUUID()}`,
    DATABASE_URL: APPLICATION_URL,
    IDENTITY_BASE_URL: 'http://localhost:4001',
    IDENTITY_AUTH_AUDIENCE: 'munaxa-work',
    IDENTITY_SIGNING_KID: 'identity-test-2026-11',
    IDENTITY_SIGNING_PRIVATE_KEY: signingKey.privateKey,
    CSRF_TRUSTED_ORIGINS: 'http://localhost:3001',
    ...overrides,
  });

let environment: IdentityEnvironment;
let prisma: PrismaService;
let security: SecurityStack;
let auth: AuthService;
let sessions: AccountSessionsService;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;

/** Organisations and the people in them, created fresh for this file. */
const orgA = { key: `sessions-a-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
const orgB = { key: `sessions-b-${randomUUID().slice(0, 8)}`, id: randomUUID() as TenantId };
const PASSWORD = `Correct-Horse-${randomUUID()}`;

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

/** Run SQL as the owner inside a tenant context. FORCE RLS applies to the owner too. */
const asOwner = async <T extends pg.QueryResultRow>(
  tenantId: TenantId,
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

interface SignedIn {
  readonly access: string;
  readonly refresh: string;
  readonly sessionId: SessionId;
}

const signIn = async (
  org: { key: string },
  identifier: string,
  context: { ipAddress?: string; userAgent?: string } = {},
): Promise<SignedIn> => {
  const result = await auth.login({
    identifier,
    password: PASSWORD,
    organisation: org.key,
    correlationId: `corr-${randomUUID()}` as never,
    ...context,
  });
  if (!result.ok) throw new Error(`sign-in failed: ${JSON.stringify(result.failure)}`);
  return {
    access: result.access,
    refresh: result.refresh,
    sessionId: result.claims.sid as SessionId,
  };
};

const refresh = (org: { key: string }, token: string) =>
  auth.refresh({ refreshToken: token, organisation: org.key });

const sessionRow = async (tenantId: TenantId, id: SessionId) =>
  (
    await asOwner<{ revoked_at: Date | null; revocation_reason: string | null }>(
      tenantId,
      'select revoked_at, revocation_reason from identity_session where id = $1',
      [id],
    )
  )[0];

const liveRefreshTokens = async (tenantId: TenantId, id: SessionId): Promise<number> =>
  Number(
    (
      await asOwner<{ n: string }>(
        tenantId,
        'select count(*) as n from identity_refresh_token where session_id = $1 and revoked_at is null',
        [id],
      )
    )[0]?.n ?? 0,
  );

let alice: UserId;
let bob: UserId;
let carol: UserId; // organisation B
const ALICE = `alice-${randomUUID().slice(0, 6)}@example.test`;
const BOB = `bob-${randomUUID().slice(0, 6)}@example.test`;
const CAROL = `carol-${randomUUID().slice(0, 6)}@example.test`;

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await createOrganisation(owner, orgA.key, orgA.id);
  await createOrganisation(owner, orgB.key, orgB.id);
  alice = await createPerson(orgA.id, ALICE);
  bob = await createPerson(orgA.id, BOB);
  carol = await createPerson(orgB.id, CAROL);

  environment = baseEnvironment();
  // The restricted runtime role: NOBYPASSRLS, so every query here is held to the policies.
  prisma = new PrismaService({ DATABASE_URL: APPLICATION_URL } as never);
  await prisma.$connect();
  security = await buildSecurityStack(environment, prisma);
  auth = new AuthService(security, environment, prisma);
  sessions = new AccountSessionsService(security, environment);
});

afterAll(async () => {
  await security.close();
  await prisma.$disconnect();
  owner.release();
  await ownerPool.end();
});

describe('listing your own sessions', () => {
  it('returns only the caller’s live sessions, marking the current one', async () => {
    const laptop = await signIn(orgA, ALICE, {
      ipAddress: '203.0.113.77',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
    });
    const phone = await signIn(orgA, ALICE, {
      ipAddress: '2001:db8:abcd:12::1',
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    });
    const bobs = await signIn(orgA, BOB);

    const listed = await sessions.list(laptop.access);
    expect(listed.ok).toBe(true);
    if (!listed.ok) return;

    const ids = listed.sessions.map((session) => session.id);
    expect(ids).toContain(laptop.sessionId);
    expect(ids).toContain(phone.sessionId);
    expect(ids).not.toContain(bobs.sessionId);

    const current = listed.sessions.find((session) => session.id === laptop.sessionId);
    expect(current).toMatchObject({
      current: true,
      ipPrefix: '203.0.113.0/24',
      device: 'Firefox on Linux',
    });
    const other = listed.sessions.find((session) => session.id === phone.sessionId);
    expect(other).toMatchObject({
      current: false,
      ipPrefix: '2001:db8:abcd::/48',
      device: 'Safari on iOS',
    });
  });

  it('returns an allow-listed shape: no token version, attributes, auth methods, raw agent or full address', async () => {
    const signedIn = await signIn(orgA, ALICE, {
      ipAddress: '198.51.100.23',
      userAgent: 'Mozilla/5.0 <script>alert(1)</script> Chrome/120.0 Windows',
    });
    const listed = await sessions.list(signedIn.access);
    if (!listed.ok) throw new Error('expected a list');

    for (const session of listed.sessions) {
      expect(Object.keys(session).sort()).toEqual(
        ['createdAt', 'current', 'device', 'expiresAt', 'id', 'lastActiveAt', 'ipPrefix']
          .filter((key) => key !== 'ipPrefix' || 'ipPrefix' in session)
          .sort(),
      );
    }
    const body = JSON.stringify(listed);
    expect(body).not.toContain('198.51.100.23');
    expect(body).not.toContain('<script>');
    expect(body).not.toContain(signedIn.refresh);
    expect(body).not.toContain('tokenVersion');
    expect(body).not.toContain('authMethods');
    const mine = listed.sessions.find((session) => session.id === signedIn.sessionId);
    expect(mine?.device).toBe('Chrome on Windows');
  });

  it('omits the network entirely when the deployment policy hides it', async () => {
    const hidden = new AccountSessionsService(
      security,
      baseEnvironment({ IDENTITY_SESSION_LIST_IP: 'hidden' }),
    );
    const signedIn = await signIn(orgA, ALICE, { ipAddress: '192.0.2.10' });
    const listed = await hidden.list(signedIn.access);
    if (!listed.ok) throw new Error('expected a list');
    for (const session of listed.sessions) expect('ipPrefix' in session).toBe(false);
  });

  it('leaves out sessions past their idle or absolute deadline, and refuses their tokens', async () => {
    const idle = await signIn(orgA, ALICE);
    const absolute = await signIn(orgA, ALICE);
    const fresh = await signIn(orgA, ALICE);

    await asOwner(
      orgA.id,
      `update identity_session set idle_expires_at = now() - interval '1 second' where id = $1`,
      [idle.sessionId],
    );
    await asOwner(
      orgA.id,
      `update identity_session set absolute_expires_at = now() - interval '1 second' where id = $1`,
      [absolute.sessionId],
    );

    const listed = await sessions.list(fresh.access);
    if (!listed.ok) throw new Error('expected a list');
    const ids = listed.sessions.map((session) => session.id);
    expect(ids).not.toContain(idle.sessionId);
    expect(ids).not.toContain(absolute.sessionId);
    expect(ids).toContain(fresh.sessionId);

    expect((await sessions.list(idle.access)).ok).toBe(false);
    expect((await sessions.list(absolute.access)).ok).toBe(false);
    expect((await refresh(orgA, idle.refresh)).ok).toBe(false);
    expect((await refresh(orgA, absolute.refresh)).ok).toBe(false);
  });

  it('keeps the configured idle and absolute timeouts, unchanged', () => {
    expect(environment.MUNAXA_SESSION_IDLE_TIMEOUT).toBe(900_000);
    expect(environment.MUNAXA_SESSION_ABSOLUTE_TIMEOUT).toBe(43_200_000);
    expect(security.sessions.policy(orgA.id)).toMatchObject({
      idleTimeout: 900_000,
      absoluteTimeout: 43_200_000,
    });
  });
});

describe('who counts as the caller', () => {
  it('refuses no token, a malformed token and a token signed with another key', async () => {
    const victim = await signIn(orgA, ALICE);
    expect(await sessions.list(undefined)).toEqual({ ok: false, reason: 'unauthenticated' });
    expect(await sessions.list('not.a.jwt')).toEqual({ ok: false, reason: 'unauthenticated' });

    const other = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const forger = new TokenService({
      signer: new AsymmetricSigner('ES256', [
        { kid: 'identity-test-2026-11', privateKey: other.privateKey, publicKey: other.publicKey },
      ]),
      issuer: environment.MUNAXA_TOKEN_ISSUER,
      audience: environment.MUNAXA_TOKEN_AUDIENCE,
    });
    const forged = forger.issueAccessToken({
      subject: alice,
      tenantId: orgA.id,
      tokenVersion: 1,
      sessionId: victim.sessionId,
    }).token;
    expect((await sessions.list(forged)).ok).toBe(false);
    expect((await sessions.revoke(forged, victim.sessionId)).ok).toBe(false);
    expect(await sessionRow(orgA.id, victim.sessionId)).toMatchObject({ revoked_at: null });
  });

  it('refuses a genuine token without a session id', async () => {
    const sessionless = security.tokens.issueAccessToken({
      subject: alice,
      tenantId: orgA.id,
      tokenVersion: 1,
    }).token;
    expect((await sessions.list(sessionless)).ok).toBe(false);
  });

  it('refuses a genuine token whose subject does not own the session it names', async () => {
    const alices = await signIn(orgA, ALICE);
    const minted = security.tokens.issueAccessToken({
      subject: bob,
      tenantId: orgA.id,
      tokenVersion: 1,
      sessionId: alices.sessionId,
    }).token;
    expect((await resolvePrincipal(security, minted)).ok).toBe(false);
    expect((await sessions.revokeOthers(minted)).ok).toBe(false);
    expect(await sessionRow(orgA.id, alices.sessionId)).toMatchObject({ revoked_at: null });
  });
});

describe('revoking one session', () => {
  it('ends that session and its refresh lineage, and leaves the current one alone', async () => {
    const current = await signIn(orgA, ALICE);
    const other = await signIn(orgA, ALICE);

    expect(await sessions.revoke(current.access, other.sessionId)).toEqual({
      ok: true,
      current: false,
    });

    expect(await sessionRow(orgA.id, other.sessionId)).toMatchObject({
      revocation_reason: 'logout',
    });
    expect(await liveRefreshTokens(orgA.id, other.sessionId)).toBe(0);
    expect((await sessions.list(other.access)).ok).toBe(false);
    expect((await refresh(orgA, other.refresh)).ok).toBe(false);

    expect((await sessions.list(current.access)).ok).toBe(true);
    expect((await refresh(orgA, current.refresh)).ok).toBe(true);
  });

  it('may end the current session, which is a logout', async () => {
    const current = await signIn(orgA, ALICE);
    expect(await sessions.revoke(current.access, current.sessionId)).toEqual({
      ok: true,
      current: true,
    });
    expect((await sessions.list(current.access)).ok).toBe(false);
  });

  it('answers not-found for another person’s session, and revokes nothing', async () => {
    const alices = await signIn(orgA, ALICE);
    const bobs = await signIn(orgA, BOB);

    expect(await sessions.revoke(bobs.access, alices.sessionId)).toEqual({
      ok: false,
      reason: 'not-found',
    });
    expect(await sessionRow(orgA.id, alices.sessionId)).toMatchObject({ revoked_at: null });
    expect(await liveRefreshTokens(orgA.id, alices.sessionId)).toBeGreaterThan(0);
    expect((await sessions.list(alices.access)).ok).toBe(true);
  });

  it('answers not-found for a session in another organisation, and revokes nothing', async () => {
    const alices = await signIn(orgA, ALICE);
    const carols = await signIn(orgB, CAROL);

    expect(await sessions.revoke(carols.access, alices.sessionId)).toEqual({
      ok: false,
      reason: 'not-found',
    });
    expect(await sessionRow(orgA.id, alices.sessionId)).toMatchObject({ revoked_at: null });

    // And the store itself, asked in organisation B for a row of organisation A, sees nothing.
    expect(
      await security.revocation.revokeSession(orgB.id, alice, alices.sessionId, 'logout'),
    ).toBe(false);
    expect(await sessionRow(orgA.id, alices.sessionId)).toMatchObject({ revoked_at: null });

    const listed = await sessions.list(carols.access);
    if (!listed.ok) throw new Error('expected a list');
    expect(listed.sessions.map((session) => session.id)).not.toContain(alices.sessionId);
  });

  it('answers the same not-found for an unknown, a malformed and an already-revoked id', async () => {
    const current = await signIn(orgA, ALICE);
    const other = await signIn(orgA, ALICE);
    await sessions.revoke(current.access, other.sessionId);

    const notFound = { ok: false, reason: 'not-found' };
    expect(await sessions.revoke(current.access, `sess_${randomUUID()}`)).toEqual(notFound);
    expect(await sessions.revoke(current.access, "x' or '1'='1")).toEqual(notFound);
    expect(await sessions.revoke(current.access, other.sessionId)).toEqual(notFound);
  });

  it('is decided once when two requests revoke the same session at the same moment', async () => {
    const current = await signIn(orgA, ALICE);
    const other = await signIn(orgA, ALICE);
    const outcomes = await Promise.all(
      Array.from({ length: 8 }, () => sessions.revoke(current.access, other.sessionId)),
    );
    expect(outcomes.filter((outcome) => outcome.ok)).toHaveLength(1);
  });
});

describe('revoking every other session', () => {
  it('keeps exactly the current session and ends the rest with their lineages', async () => {
    const keep = await signIn(orgA, BOB);
    const others = [await signIn(orgA, BOB), await signIn(orgA, BOB)];
    const alices = await signIn(orgA, ALICE);

    const outcome = await sessions.revokeOthers(keep.access);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.revoked).toBeGreaterThanOrEqual(2);

    for (const gone of others) {
      expect(await sessionRow(orgA.id, gone.sessionId)).toMatchObject({
        revocation_reason: 'logout-all',
      });
      expect(await liveRefreshTokens(orgA.id, gone.sessionId)).toBe(0);
      expect((await refresh(orgA, gone.refresh)).ok).toBe(false);
    }

    const listed = await sessions.list(keep.access);
    if (!listed.ok) throw new Error('expected a list');
    expect(listed.sessions.map((session) => session.id)).toEqual([keep.sessionId]);
    expect((await refresh(orgA, keep.refresh)).ok).toBe(true);

    // Somebody else's sessions in the same organisation are untouched.
    expect(await sessionRow(orgA.id, alices.sessionId)).toMatchObject({ revoked_at: null });
  });
});

describe('refresh never restores a revoked session', () => {
  it('refuses a still-unexpired refresh token whose session was revoked', async () => {
    const signedIn = await signIn(orgA, ALICE);
    // Revoke the row alone, as an older code path or an operator would, leaving the token live.
    await asOwner(
      orgA.id,
      `update identity_session set revoked_at = now(), revocation_reason = 'admin-revoked' where id = $1`,
      [signedIn.sessionId],
    );
    expect(await liveRefreshTokens(orgA.id, signedIn.sessionId)).toBeGreaterThan(0);

    expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    // The refusal also kills the lineage, and the row stays revoked.
    expect(await liveRefreshTokens(orgA.id, signedIn.sessionId)).toBe(0);
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'admin-revoked',
    });
  });

  it('cannot un-revoke a session through a stale whole-record write', async () => {
    const signedIn = await signIn(orgA, ALICE);
    const store = new PrismaSessionStore(prisma);
    // What `SessionManager.touch` holds between its read and its write.
    const stale = await store.get(orgA.id, signedIn.sessionId);
    if (stale === undefined) throw new Error('expected a session');

    await security.revocation.revokeSession(orgA.id, alice, signedIn.sessionId, 'logout');
    await store.update({ ...stale, lastSeenAt: Date.now() });

    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'logout',
    });
    expect((await sessions.list(signedIn.access)).ok).toBe(false);
  });

  it('ends revoked under concurrent refreshes and revocation, every time', async () => {
    for (let round = 0; round < 5; round += 1) {
      const current = await signIn(orgA, ALICE);
      const target = await signIn(orgA, ALICE);

      // Rotate the target's lineage repeatedly while it is revoked, so rotation, touch and
      // revocation interleave however the scheduler likes.
      let token = target.refresh;
      const rotations = (async () => {
        for (let step = 0; step < 6; step += 1) {
          const rotated = await refresh(orgA, token);
          if (!rotated.ok) return;
          token = rotated.refresh;
        }
      })();
      const revoked = sessions.revoke(current.access, target.sessionId);
      await Promise.all([rotations, revoked]);

      expect(await sessionRow(orgA.id, target.sessionId)).not.toMatchObject({ revoked_at: null });
      // Whatever token the rotation ended up holding is refused now.
      expect((await refresh(orgA, token)).ok).toBe(false);
      expect(await liveRefreshTokens(orgA.id, target.sessionId)).toBe(0);
    }
  });

  it('revokes the session when a rotated refresh token is presented again', async () => {
    const signedIn = await signIn(orgA, ALICE);
    const first = await refresh(orgA, signedIn.refresh);
    expect(first.ok).toBe(true);

    // The original token again: two parties hold this lineage.
    expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'token-reuse',
    });
    if (first.ok) expect((await refresh(orgA, first.refresh)).ok).toBe(false);
    expect((await sessions.list(signedIn.access)).ok).toBe(false);
  });

  it('refuses every token minted before a token-version bump', async () => {
    const signedIn = await signIn(orgA, BOB);
    // What a password reset or change does to the account.
    await security.directory.incrementTokenVersion(orgA.id, bob);

    expect((await sessions.list(signedIn.access)).ok).toBe(false);
    expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'password-changed',
    });

    // A fresh sign-in at the new version works.
    const again = await signIn(orgA, BOB);
    expect((await sessions.list(again.access)).ok).toBe(true);
  });
});

describe('account-wide revocation', () => {
  it('revokes every session and lineage for a password reset', async () => {
    const first = await signIn(orgA, ALICE);
    const second = await signIn(orgA, ALICE);
    const outcome = await security.revocation.revokeAllForUser(orgA.id, alice, 'password-reset');
    expect(outcome.sessions).toBeGreaterThanOrEqual(2);
    for (const signedIn of [first, second]) {
      expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
        revocation_reason: 'password-reset',
      });
      expect(await liveRefreshTokens(orgA.id, signedIn.sessionId)).toBe(0);
      expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    }
  });

  it('keeps the named session when asked to, for an MFA change made from it', async () => {
    const keep = await signIn(orgA, ALICE);
    const gone = await signIn(orgA, ALICE);
    await security.revocation.revokeAllForUser(orgA.id, alice, 'mfa-changed', {
      except: keep.sessionId,
    });
    expect(await sessionRow(orgA.id, keep.sessionId)).toMatchObject({ revoked_at: null });
    expect(await sessionRow(orgA.id, gone.sessionId)).toMatchObject({
      revocation_reason: 'mfa-changed',
    });
    expect((await refresh(orgA, keep.refresh)).ok).toBe(true);
  });

  it('ends everything on suspected compromise, and the person can sign in again', async () => {
    const signedIn = await signIn(orgA, ALICE);
    await security.lockdown.suspectedCompromise(orgA.id, alice);
    expect((await sessions.list(signedIn.access)).ok).toBe(false);
    expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'risk-detected',
    });
    const again = await signIn(orgA, ALICE);
    expect((await sessions.list(again.access)).ok).toBe(true);
  });

  it('ends everything when the account is disabled, and sign-in is refused', async () => {
    const dave = `dave-${randomUUID().slice(0, 6)}@example.test`;
    const daveId = await createPerson(orgA.id, dave);
    const signedIn = await signIn(orgA, dave);

    await security.lockdown.disable(orgA.id, daveId);
    expect((await sessions.list(signedIn.access)).ok).toBe(false);
    expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'account-disabled',
    });
    await expect(signIn(orgA, dave)).rejects.toThrow(/sign-in failed/);
  });

  it('refuses a refresh for a disabled account even before revocation ran', async () => {
    const erin = `erin-${randomUUID().slice(0, 6)}@example.test`;
    const erinId = await createPerson(orgA.id, erin);
    const signedIn = await signIn(orgA, erin);
    // Only the status write — the first step of `disable` — and nothing after it.
    await security.directory.setStatus(orgA.id, erinId, 'disabled');
    expect((await refresh(orgA, signedIn.refresh)).ok).toBe(false);
    expect((await sessions.list(signedIn.access)).ok).toBe(false);
  });
});

describe('logout', () => {
  it('is idempotent', async () => {
    const signedIn = await signIn(orgA, ALICE);
    await auth.logout({ accessToken: signedIn.access });
    await auth.logout({ accessToken: signedIn.access });
    await auth.logout({});
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'logout',
    });
    expect(await liveRefreshTokens(orgA.id, signedIn.sessionId)).toBe(0);
  });

  it('still works with an expired access token Identity issued', async () => {
    const signedIn = await signIn(orgA, ALICE);
    const longAgo = new TokenService({
      signer: security.signing.signer,
      issuer: environment.MUNAXA_TOKEN_ISSUER,
      audience: environment.MUNAXA_TOKEN_AUDIENCE,
      clock: { now: () => (Date.now() - 3_600_000) as EpochMillis },
    });
    const expired = longAgo.issueAccessToken({
      subject: alice,
      tenantId: orgA.id,
      tokenVersion: 1,
      sessionId: signedIn.sessionId,
    }).token;
    expect(() => security.tokens.verifyAccessToken(expired)).toThrow();

    await auth.logout({ accessToken: expired });
    expect(await sessionRow(orgA.id, signedIn.sessionId)).toMatchObject({
      revocation_reason: 'logout',
    });
  });

  it('does nothing for a forged token naming somebody else’s session', async () => {
    const victim = await signIn(orgA, ALICE);
    const other = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const forged = new TokenService({
      signer: new AsymmetricSigner('ES256', [
        { kid: 'identity-test-2026-11', privateKey: other.privateKey, publicKey: other.publicKey },
      ]),
      issuer: environment.MUNAXA_TOKEN_ISSUER,
      audience: environment.MUNAXA_TOKEN_AUDIENCE,
    }).issueAccessToken({
      subject: alice,
      tenantId: orgA.id,
      tokenVersion: 1,
      sessionId: victim.sessionId,
    }).token;

    await auth.logout({ accessToken: forged });
    expect(await sessionRow(orgA.id, victim.sessionId)).toMatchObject({ revoked_at: null });
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
      getHeader(name: string) {
        return captured.headers[name.toLowerCase()];
      },
    };
    return { response: response as never, captured };
  };

  const request = (access?: string) =>
    ({ cookies: access === undefined ? {} : { '__Host-mx_session': access } }) as never;

  const silentLogger = { error: () => undefined } as never;

  it('answers 401 without a session, 404 for a foreign id, and never caches', async () => {
    const controller = new AccountSessionsController(sessions, silentLogger);
    const alices = await signIn(orgA, ALICE);
    const bobs = await signIn(orgA, BOB);

    const anonymous = fakeResponse();
    await controller.list(request(), anonymous.response);
    expect(anonymous.captured).toMatchObject({
      status: 401,
      body: { code: 'AUTH_UNAUTHENTICATED' },
    });
    expect(anonymous.captured.headers['cache-control']).toBe('no-store');

    const foreign = fakeResponse();
    await controller.revoke(alices.sessionId, request(bobs.access), foreign.response);
    expect(foreign.captured).toMatchObject({ status: 404, body: { code: 'SESSION_NOT_FOUND' } });

    const unknown = fakeResponse();
    await controller.revoke(`sess_${randomUUID()}`, request(bobs.access), unknown.response);
    // Byte-identical to the foreign answer: nothing distinguishes "not yours" from "not there".
    expect(unknown.captured.body).toEqual(foreign.captured.body);
    expect(unknown.captured.status).toBe(foreign.captured.status);
  });

  it('clears the cookies when the current session is the one revoked', async () => {
    const controller = new AccountSessionsController(sessions, silentLogger);
    const signedIn = await signIn(orgA, ALICE);
    const revoked = fakeResponse();
    await controller.revoke(signedIn.sessionId, request(signedIn.access), revoked.response);
    expect(revoked.captured).toMatchObject({ status: 200, body: { ok: true, current: true } });
    const cookies = ([] as string[]).concat(revoked.captured.headers['set-cookie'] as string[]);
    expect(cookies.some((line) => line.startsWith('__Host-mx_session=;'))).toBe(true);
    expect(cookies.some((line) => line.startsWith('__Secure-mx_refresh=;'))).toBe(true);
  });

  it('answers 503, not 500 or 401, when the database is unavailable', async () => {
    const signedIn = await signIn(orgA, ALICE);
    const broken = new AccountSessionsService(
      {
        ...security,
        directory: {
          findById: () => Promise.reject(new Error('connection terminated')),
        },
      } as never,
      environment,
    );
    const controller = new AccountSessionsController(broken, silentLogger);
    const answer = fakeResponse();
    await controller.list(request(signedIn.access), answer.response);
    expect(answer.captured).toMatchObject({ status: 503, body: { code: 'AUTH_UNAVAILABLE' } });
  });
});
