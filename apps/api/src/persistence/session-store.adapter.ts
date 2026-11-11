import type {
  SessionCreateOutcome,
  SessionLimit,
  SessionRecord,
  SessionRevocationReason,
  SessionStorePort,
} from '@munaxa/interfaces';
import type { AuthMethod, DeviceId, SessionId, TenantId, UserId } from '@munaxa/types';

import { Prisma } from '../../../../node_modules/.prisma/identity-client';
import type { PrismaService, TenantClient } from './prisma.service.js';

/**
 * Sessions.
 *
 * `createWithinLimit` is implemented rather than omitted, and that choice is the difference
 * between an exact concurrency limit and a best-effort one: without it `SessionManager` falls back
 * to a lock, and failing that to a count that a burst of parallel sign-ins can exceed. A burst of
 * parallel sign-ins is the normal input to this control, not an exotic one.
 *
 * **The serialisation is an advisory lock, not `SELECT … FOR UPDATE`, and the difference is the
 * whole control.** `FOR UPDATE` locks the rows a query *found*; it cannot lock rows that do not
 * exist yet. So on a user with no live sessions — which is every first sign-in, and every sign-in
 * after an idle period — ten concurrent attempts all read zero, all pass the check and all insert.
 * Platform's conformance suite found exactly that here: ten parallel calls against a limit of
 * three produced ten sessions. A lock keyed by (tenant, user) has nothing to do with which rows
 * exist, so the count and the insert are one critical section whether the user has ten sessions or
 * none.
 */
export class PrismaSessionStore implements SessionStorePort {
  public constructor(private readonly prisma: PrismaService) {}

  public async create(session: SessionRecord): Promise<void> {
    await this.prisma.withTenant(session.tenantId, (tx) =>
      tx.identitySession.upsert({
        where: { id: session.id },
        create: rowOf(session),
        update: rowOf(session),
      }),
    );
  }

  public async createWithinLimit(
    session: SessionRecord,
    limit: SessionLimit,
  ): Promise<SessionCreateOutcome> {
    return this.prisma.withTenant(session.tenantId, async (tx) => {
      await lockUser(tx, session.tenantId, session.userId);
      const live = await liveSessions(tx, session.tenantId, session.userId, limit.now);

      if (live.length < limit.maxConcurrent) {
        await tx.identitySession.create({ data: rowOf(session) });
        return { created: true, evicted: [] };
      }
      if (limit.onLimitReached === 'deny') {
        return { created: false, evicted: [] };
      }

      // Evict oldest first, and evict enough to leave room for exactly one more.
      const surplus = live.length - limit.maxConcurrent + 1;
      const doomed = live.slice(0, surplus);
      await tx.identitySession.updateMany({
        where: { tenantId: session.tenantId, id: { in: doomed.map((row) => row.id) } },
        data: { revokedAt: new Date(limit.now), revocationReason: 'concurrency-limit' },
      });
      await tx.identitySession.create({ data: rowOf(session) });

      return {
        created: true,
        evicted: doomed.map((row) =>
          recordOf({
            ...row,
            revokedAt: new Date(limit.now),
            revocationReason: 'concurrency-limit',
          }),
        ),
      };
    });
  }

  public async countActive(tenantId: TenantId, userId: UserId, now: number): Promise<number> {
    return this.prisma.withTenant(tenantId, (tx) =>
      tx.identitySession.count({ where: liveWhere(tenantId, userId, now) }),
    );
  }

  public async get(tenantId: TenantId, sessionId: SessionId): Promise<SessionRecord | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identitySession.findFirst({ where: { tenantId, id: sessionId } }),
    );
    return row === null ? undefined : recordOf(row);
  }

  public async listByUser(tenantId: TenantId, userId: UserId): Promise<readonly SessionRecord[]> {
    const rows = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identitySession.findMany({
        where: { tenantId, accountId: userId, revokedAt: null },
        orderBy: { lastSeenAt: 'desc' },
      }),
    );
    return rows.map(recordOf);
  }

  /**
   * A whole-record write that can never un-revoke.
   *
   * `SessionManager.touch` is validate-then-write: it reads the row, slides the idle window and
   * writes the whole record back. If a revocation commits between that read and that write, a
   * plain update writes `revoked_at = null` with the stale copy and the session is alive again —
   * the user pressed "sign out this device", got a success, and the device is still signed in.
   * Refresh does exactly this on every rotation, so the race is the ordinary case for a session in
   * active use, not an exotic one.
   *
   * So a record without `revokedAt` only updates a row that is still unrevoked, and a record with
   * one writes the revocation but never moves an existing one. Revocation is one-way in the
   * database, whatever order the writes arrive in.
   */
  public async update(session: SessionRecord): Promise<void> {
    const { revokedAt, revocationReason, ...live } = rowOf(session);
    await this.prisma.withTenant(session.tenantId, (tx) =>
      tx.identitySession.updateMany({
        where: { tenantId: session.tenantId, id: session.id, revokedAt: null },
        data: revokedAt === null ? live : { ...live, revokedAt, revocationReason },
      }),
    );
  }

  public async delete(tenantId: TenantId, sessionId: SessionId): Promise<boolean> {
    const removed = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identitySession.deleteMany({ where: { tenantId, id: sessionId } }),
    );
    return removed.count > 0;
  }

  public async deleteExpired(tenantId: TenantId, now: number): Promise<number> {
    const removed = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identitySession.deleteMany({
        where: {
          tenantId,
          OR: [
            { absoluteExpiresAt: { lt: new Date(now) } },
            { idleExpiresAt: { lt: new Date(now) } },
          ],
        },
      }),
    );
    return removed.count;
  }
}

const liveWhere = (tenantId: TenantId, userId: UserId, now: number): Record<string, unknown> => ({
  tenantId,
  accountId: userId,
  revokedAt: null,
  idleExpiresAt: { gt: new Date(now) },
  absoluteExpiresAt: { gt: new Date(now) },
});

/**
 * Serialise this user's session creation for the rest of the transaction.
 *
 * Transaction-scoped, so it is released by commit or rollback and cannot be leaked by a failure
 * path. Keyed by (tenant, user) so two different people signing in do not queue behind each other.
 */
const lockUser = async (tx: TenantClient, tenantId: TenantId, userId: UserId): Promise<void> => {
  await tx.$executeRaw`select pg_advisory_xact_lock(hashtextextended(${`${tenantId}:${userId}`}, 0))`;
};

/** The live sessions, oldest first, so eviction takes the oldest. */
const liveSessions = async (
  tx: TenantClient,
  tenantId: TenantId,
  userId: UserId,
  now: number,
): Promise<SessionRow[]> =>
  tx.$queryRaw<SessionRow[]>`
    select * from identity_session
     where tenant_id = ${tenantId}
       and account_id = ${userId}
       and revoked_at is null
       and idle_expires_at > ${new Date(now)}
       and absolute_expires_at > ${new Date(now)}
     order by created_at asc`;

interface SessionRow {
  id: string;
  tenantId: string;
  accountId: string;
  createdAt: Date;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  deviceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  authMethods: string[];
  mfaSatisfied: boolean;
  revokedAt: Date | null;
  revocationReason: string | null;
  tokenVersion: number;
  attributes: unknown;
}

const rowOf = (session: SessionRecord) => ({
  id: session.id,
  tenantId: session.tenantId,
  accountId: session.userId,
  createdAt: new Date(session.createdAt),
  lastSeenAt: new Date(session.lastSeenAt),
  idleExpiresAt: new Date(session.idleExpiresAt),
  absoluteExpiresAt: new Date(session.absoluteExpiresAt),
  deviceId: session.deviceId ?? null,
  ipAddress: session.ipAddress ?? null,
  userAgent: session.userAgent ?? null,
  authMethods: [...session.authMethods],
  mfaSatisfied: session.mfaSatisfied,
  revokedAt: session.revokedAt === undefined ? null : new Date(session.revokedAt),
  revocationReason: session.revocationReason ?? null,
  tokenVersion: session.tokenVersion,
  // `DbNull` writes SQL NULL; `JsonNull` would write the JSON value `null`, which is a
  // different thing and reads back as a present-but-null attribute set.
  attributes:
    session.attributes === undefined
      ? Prisma.DbNull
      : (session.attributes as Prisma.InputJsonValue),
});

/**
 * Raw `$queryRaw` returns snake_case columns; the Prisma model client returns camelCase. Both
 * shapes reach here, so the reader accepts either rather than the call sites remembering which.
 */
const recordOf = (row: SessionRow | Record<string, unknown>): SessionRecord => {
  const pick = <T>(camel: string, snake: string): T =>
    ((row as Record<string, unknown>)[camel] ?? (row as Record<string, unknown>)[snake]) as T;
  const at = (camel: string, snake: string): Date | null => pick<Date | null>(camel, snake) ?? null;
  const revokedAt = at('revokedAt', 'revoked_at');
  const reason = pick<string | null>('revocationReason', 'revocation_reason');
  const deviceId = pick<string | null>('deviceId', 'device_id');
  const ipAddress = pick<string | null>('ipAddress', 'ip_address');
  const userAgent = pick<string | null>('userAgent', 'user_agent');
  const attributes = pick<Record<string, unknown> | null>('attributes', 'attributes');

  return {
    id: pick<string>('id', 'id') as SessionId,
    tenantId: pick<string>('tenantId', 'tenant_id') as TenantId,
    userId: pick<string>('accountId', 'account_id') as UserId,
    createdAt: (at('createdAt', 'created_at') as Date).getTime(),
    lastSeenAt: (at('lastSeenAt', 'last_seen_at') as Date).getTime(),
    idleExpiresAt: (at('idleExpiresAt', 'idle_expires_at') as Date).getTime(),
    absoluteExpiresAt: (at('absoluteExpiresAt', 'absolute_expires_at') as Date).getTime(),
    authMethods: pick<string[]>('authMethods', 'auth_methods') as readonly AuthMethod[],
    mfaSatisfied: pick<boolean>('mfaSatisfied', 'mfa_satisfied'),
    tokenVersion: pick<number>('tokenVersion', 'token_version'),
    ...(deviceId === null ? {} : { deviceId: deviceId as DeviceId }),
    ...(ipAddress === null ? {} : { ipAddress }),
    ...(userAgent === null ? {} : { userAgent }),
    ...(revokedAt === null ? {} : { revokedAt: revokedAt.getTime() }),
    ...(reason === null || reason === undefined
      ? {}
      : { revocationReason: reason as SessionRevocationReason }),
    ...(attributes === null ? {} : { attributes }),
  };
};
