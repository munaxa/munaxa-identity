import type { AccountStatus, CredentialRecord, UserDirectoryPort } from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';

import type { PrismaService } from './prisma.service.js';

/**
 * Accounts, as Platform's `CredentialRecord` projection of them.
 *
 * One property here is a security control rather than a detail: **`findByIdentifier` must cost the
 * same whether or not the account exists.** `LoginService` verifies against a dummy hash on the
 * miss path so the *password* comparison is constant-time, but a directory that short-circuits
 * earlier — an index probe that returns in a microsecond versus a row read that does not — narrows
 * that defence back down. A single indexed lookup on `(tenant_id, identifier_normalized)` is the
 * same query shape either way, which is why the normalised column exists and why nothing here
 * branches before the query.
 */
export class PrismaUserDirectory implements UserDirectoryPort {
  public constructor(private readonly prisma: PrismaService) {}

  public async findByIdentifier(
    tenantId: TenantId,
    identifier: string,
  ): Promise<CredentialRecord | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityAccount.findFirst({
        where: { tenantId, identifierNormalized: identifier.trim().toLowerCase() },
      }),
    );
    return row === null ? undefined : credentialOf(row);
  }

  public async findById(tenantId: TenantId, userId: UserId): Promise<CredentialRecord | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityAccount.findFirst({ where: { tenantId, id: userId } }),
    );
    return row === null ? undefined : credentialOf(row);
  }

  public async updatePasswordHash(
    tenantId: TenantId,
    userId: UserId,
    passwordHash: string,
  ): Promise<void> {
    await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityAccount.updateMany({
        where: { tenantId, id: userId },
        data: {
          passwordHash,
          passwordAlgorithm: algorithmOf(passwordHash),
          passwordUpdatedAt: new Date(),
          mustChangePassword: false,
        },
      }),
    );
  }

  /**
   * Advance the token version, invalidating every token minted before now.
   *
   * `increment` rather than read-then-write: two administrators disabling an account at once must
   * not both read 3 and both write 4, leaving tokens carrying 4 valid.
   */
  public async incrementTokenVersion(tenantId: TenantId, userId: UserId): Promise<number> {
    return this.prisma.withTenant(tenantId, async (tx) => {
      const updated = await tx.identityAccount.update({
        where: { id: userId },
        data: { tokenVersion: { increment: 1 } },
        select: { tokenVersion: true },
      });
      return updated.tokenVersion;
    });
  }

  public async setStatus(tenantId: TenantId, userId: UserId, status: AccountStatus): Promise<void> {
    await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityAccount.updateMany({
        where: { tenantId, id: userId },
        data: {
          status: storedStatus(status),
          ...(status === 'disabled' ? { disabledAt: new Date() } : {}),
        },
      }),
    );
  }
}

/** The enum PostgreSQL holds cannot contain a hyphen, so one value is spelled differently there. */
const storedStatus = (
  status: AccountStatus,
): 'active' | 'disabled' | 'locked' | 'pending_verification' =>
  status === 'pending-verification' ? 'pending_verification' : status;

const platformStatus = (status: string): AccountStatus =>
  status === 'pending_verification' ? 'pending-verification' : (status as AccountStatus);

/** Encoded hashes carry their algorithm as a prefix; this records which one wrote the row. */
const algorithmOf = (encoded: string): string => encoded.split('$')[1] ?? 'unknown';

interface AccountRow {
  id: string;
  tenantId: string;
  identifier: string;
  passwordHash: string | null;
  status: string;
  tokenVersion: number;
  mfaEnrolled: boolean;
  mustChangePassword: boolean;
  passwordUpdatedAt: Date | null;
}

const credentialOf = (row: AccountRow): CredentialRecord => ({
  userId: row.id as UserId,
  tenantId: row.tenantId as TenantId,
  identifier: row.identifier,
  passwordHash: row.passwordHash,
  status: platformStatus(row.status),
  tokenVersion: row.tokenVersion,
  mfaEnrolled: row.mfaEnrolled,
  mustChangePassword: row.mustChangePassword,
  ...(row.passwordUpdatedAt === null ? {} : { passwordUpdatedAt: row.passwordUpdatedAt.getTime() }),
});
