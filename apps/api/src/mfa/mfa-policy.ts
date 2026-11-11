import type { TenantId, UserId } from '@munaxa/types';

import type { PrismaService } from '../persistence/prisma.service.js';

/**
 * Whether an account must use a second factor to sign in.
 *
 * Read from the database on every sign-in, under the account's own tenant context, so a role grant
 * that makes somebody privileged takes effect at their next sign-in rather than after a cache
 * expires. An expired assignment does not count. There is no exemption list and no per-account
 * override: the only inputs are `MFA_POLICY`, `MFA_PRIVILEGED_ROLES` and the roles the account
 * actually holds.
 */
export class MfaPolicy {
  public constructor(
    private readonly prisma: PrismaService,
    private readonly mode: 'off' | 'privileged' | 'all',
    private readonly privilegedRoles: readonly string[],
  ) {}

  public get enforcing(): boolean {
    return this.mode !== 'off';
  }

  public async requires(tenantId: TenantId, userId: UserId): Promise<boolean> {
    if (this.mode === 'off') return false;
    if (this.mode === 'all') return true;
    if (this.privilegedRoles.length === 0) return false;
    const held = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRoleAssignment.count({
        where: {
          tenantId,
          accountId: userId,
          role: { key: { in: [...this.privilegedRoles] } },
          OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
        },
      }),
    );
    return held > 0;
  }
}
