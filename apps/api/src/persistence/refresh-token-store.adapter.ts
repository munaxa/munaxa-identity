import type { RefreshTokenRecord, RefreshTokenStorePort } from '@munaxa/interfaces';
import type { DeviceId, SessionId, TenantId, TokenFamilyId, UserId } from '@munaxa/types';

import type { PrismaService } from './prisma.service.js';

/**
 * Refresh-token lineages.
 *
 * `markRotated` is the reason this class needs a careful comment. Rotation used to be written as
 * read-check-write everywhere, so two concurrent exchanges of one token both passed the check and
 * both succeeded — which is precisely the race a thief occupies, and it disables reuse detection
 * silently. The interface is explicit that returning `true` without having affected a row is a
 * security defect rather than a performance one, so the implementation is one conditional write
 * and the answer is the row count.
 *
 * The token itself is never stored. `tokenHash` is what arrives, already peppered by
 * `RefreshTokenService`, so a database dump yields nothing an attacker can present.
 */
export class PrismaRefreshTokenStore implements RefreshTokenStorePort {
  public constructor(private readonly prisma: PrismaService) {}

  public async save(record: RefreshTokenRecord): Promise<void> {
    await this.prisma.withTenant(record.tenantId, (tx) =>
      tx.identityRefreshToken.upsert({
        where: { id: record.id },
        create: rowOf(record),
        update: rowOf(record),
      }),
    );
  }

  public async findByHash(
    tenantId: TenantId,
    tokenHash: string,
  ): Promise<RefreshTokenRecord | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRefreshToken.findFirst({ where: { tenantId, tokenHash } }),
    );
    return row === null ? undefined : recordOf(row);
  }

  public async update(record: RefreshTokenRecord): Promise<void> {
    await this.prisma.withTenant(record.tenantId, (tx) =>
      tx.identityRefreshToken.updateMany({
        where: { tenantId: record.tenantId, id: record.id },
        data: rowOf(record),
      }),
    );
  }

  /**
   * Claim a token for rotation. Exactly one caller may ever receive `true` for a given token.
   *
   *     UPDATE identity_refresh_token
   *        SET rotated_at = $at, replaced_by = $replacedBy
   *      WHERE tenant_id = $tenantId AND id = $id AND rotated_at IS NULL
   *
   * `updateMany` compiles to exactly that and reports the affected-row count, so the compare and
   * the swap are one statement and there is no window between them.
   */
  public async markRotated(
    tenantId: TenantId,
    id: string,
    at: number,
    replacedBy: string,
  ): Promise<boolean> {
    const claimed = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRefreshToken.updateMany({
        where: { tenantId, id, rotatedAt: null },
        data: { rotatedAt: new Date(at), replacedBy },
      }),
    );
    return claimed.count === 1;
  }

  public async listFamily(
    tenantId: TenantId,
    familyId: TokenFamilyId,
  ): Promise<readonly RefreshTokenRecord[]> {
    const rows = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRefreshToken.findMany({
        where: { tenantId, familyId },
        orderBy: { issuedAt: 'asc' },
      }),
    );
    return rows.map(recordOf);
  }

  /** One statement, not a read followed by N writes: a partially revoked family is a live family. */
  public async revokeFamily(
    tenantId: TenantId,
    familyId: TokenFamilyId,
    at: number,
    reason: string,
  ): Promise<number> {
    const revoked = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRefreshToken.updateMany({
        where: { tenantId, familyId, revokedAt: null },
        data: { revokedAt: new Date(at), revocationReason: reason },
      }),
    );
    return revoked.count;
  }

  public async revokeForUser(
    tenantId: TenantId,
    userId: UserId,
    at: number,
    reason: string,
  ): Promise<number> {
    const revoked = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRefreshToken.updateMany({
        where: { tenantId, accountId: userId, revokedAt: null },
        data: { revokedAt: new Date(at), revocationReason: reason },
      }),
    );
    return revoked.count;
  }

  public async deleteExpired(tenantId: TenantId, now: number): Promise<number> {
    const removed = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRefreshToken.deleteMany({ where: { tenantId, expiresAt: { lt: new Date(now) } } }),
    );
    return removed.count;
  }
}

interface RefreshRow {
  id: string;
  tenantId: string;
  accountId: string;
  familyId: string;
  tokenHash: string;
  issuedAt: Date;
  expiresAt: Date;
  sessionId: string | null;
  deviceId: string | null;
  rotatedAt: Date | null;
  replacedBy: string | null;
  revokedAt: Date | null;
  revocationReason: string | null;
  tokenVersion: number;
}

const rowOf = (record: RefreshTokenRecord): Omit<RefreshRow, never> => ({
  id: record.id,
  tenantId: record.tenantId,
  accountId: record.userId,
  familyId: record.familyId,
  tokenHash: record.tokenHash,
  issuedAt: new Date(record.issuedAt),
  expiresAt: new Date(record.expiresAt),
  sessionId: record.sessionId ?? null,
  deviceId: record.deviceId ?? null,
  rotatedAt: record.rotatedAt === undefined ? null : new Date(record.rotatedAt),
  replacedBy: record.replacedBy ?? null,
  revokedAt: record.revokedAt === undefined ? null : new Date(record.revokedAt),
  revocationReason: record.revocationReason ?? null,
  tokenVersion: record.tokenVersion,
});

const recordOf = (row: RefreshRow): RefreshTokenRecord => ({
  id: row.id,
  tenantId: row.tenantId as TenantId,
  userId: row.accountId as UserId,
  familyId: row.familyId as TokenFamilyId,
  tokenHash: row.tokenHash,
  issuedAt: row.issuedAt.getTime(),
  expiresAt: row.expiresAt.getTime(),
  tokenVersion: row.tokenVersion,
  ...(row.sessionId === null ? {} : { sessionId: row.sessionId as SessionId }),
  ...(row.deviceId === null ? {} : { deviceId: row.deviceId as DeviceId }),
  ...(row.rotatedAt === null ? {} : { rotatedAt: row.rotatedAt.getTime() }),
  ...(row.replacedBy === null ? {} : { replacedBy: row.replacedBy }),
  ...(row.revokedAt === null ? {} : { revokedAt: row.revokedAt.getTime() }),
  ...(row.revocationReason === null ? {} : { revocationReason: row.revocationReason }),
});
