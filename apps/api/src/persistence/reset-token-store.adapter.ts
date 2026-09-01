import type { ResetTokenRecord, ResetTokenStorePort } from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';

import type { PrismaService } from './prisma.service.js';

/**
 * Password-reset tickets.
 *
 * `markConsumed` is a compare-and-swap for the reason the interface gives: a reset link is mailed,
 * so it is followed by mail scanners, link previewers and impatient double-clicks, all arriving at
 * once and possibly on different replicas. Reading the record, seeing `consumedAt` unset and
 * writing it back is not single use — it is single use whenever the timing happens to cooperate.
 */
export class PrismaResetTokenStore implements ResetTokenStorePort {
  public constructor(private readonly prisma: PrismaService) {}

  public async save(record: ResetTokenRecord): Promise<void> {
    await this.prisma.withTenant(record.tenantId, (tx) =>
      tx.identityResetToken.upsert({
        where: { id: record.id },
        create: rowOf(record),
        update: rowOf(record),
      }),
    );
  }

  public async findByHash(
    tenantId: TenantId,
    tokenHash: string,
  ): Promise<ResetTokenRecord | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityResetToken.findFirst({ where: { tenantId, tokenHash } }),
    );
    return row === null ? undefined : recordOf(row);
  }

  public async update(record: ResetTokenRecord): Promise<void> {
    await this.prisma.withTenant(record.tenantId, (tx) =>
      tx.identityResetToken.updateMany({
        where: { tenantId: record.tenantId, id: record.id },
        data: rowOf(record),
      }),
    );
  }

  public async markConsumed(tenantId: TenantId, id: string, at: number): Promise<boolean> {
    const claimed = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityResetToken.updateMany({
        where: { tenantId, id, consumedAt: null, revokedAt: null },
        data: { consumedAt: new Date(at) },
      }),
    );
    return claimed.count === 1;
  }

  public async revokeForUser(tenantId: TenantId, userId: UserId, at: number): Promise<number> {
    const revoked = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityResetToken.updateMany({
        where: { tenantId, accountId: userId, consumedAt: null, revokedAt: null },
        data: { revokedAt: new Date(at) },
      }),
    );
    return revoked.count;
  }
}

interface ResetRow {
  id: string;
  tenantId: string;
  accountId: string;
  tokenHash: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
  passwordHashFingerprint: string;
  requestIp: string | null;
}

const rowOf = (record: ResetTokenRecord) => ({
  id: record.id,
  tenantId: record.tenantId,
  accountId: record.userId,
  tokenHash: record.tokenHash,
  issuedAt: new Date(record.issuedAt),
  expiresAt: new Date(record.expiresAt),
  consumedAt: record.consumedAt === undefined ? null : new Date(record.consumedAt),
  revokedAt: record.revokedAt === undefined ? null : new Date(record.revokedAt),
  passwordHashFingerprint: record.passwordHashFingerprint,
  requestIp: record.requestIp ?? null,
});

const recordOf = (row: ResetRow): ResetTokenRecord => ({
  id: row.id,
  tenantId: row.tenantId as TenantId,
  userId: row.accountId as UserId,
  tokenHash: row.tokenHash,
  issuedAt: row.issuedAt.getTime(),
  expiresAt: row.expiresAt.getTime(),
  passwordHashFingerprint: row.passwordHashFingerprint,
  ...(row.consumedAt === null ? {} : { consumedAt: row.consumedAt.getTime() }),
  ...(row.revokedAt === null ? {} : { revokedAt: row.revokedAt.getTime() }),
  ...(row.requestIp === null ? {} : { requestIp: row.requestIp }),
});
