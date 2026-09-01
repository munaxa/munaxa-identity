import type { TenantId } from '@munaxa/types';

import type { PrismaService } from './prisma.service.js';

/**
 * Organisations, by slug.
 *
 * This is the one read that happens before a tenant context exists, which is why
 * `identity_tenant` is the one table without row-level security: a sign-in knows an organisation
 * slug and needs its identifier, and every Platform port method needs that identifier as its first
 * argument. The table holds no personal data and no credential — only the directory needed to
 * establish a context — so making it readable is a bounded decision rather than a hole.
 *
 * Munaxa Work solves the equivalent problem with a `security definer` function owned by a role
 * that cannot log in (its ADR-0077), because its cross-tenant read is over membership rows that
 * *are* personal data. Identity's is not, and copying that machinery here by analogy would add a
 * mechanism to protect something that does not need protecting.
 */
export class TenantDirectory {
  public constructor(private readonly prisma: PrismaService) {}

  public async idForKey(key: string): Promise<TenantId | undefined> {
    const row = await this.prisma.identityTenant.findUnique({
      where: { key: key.trim().toLowerCase() },
      select: { id: true, status: true },
    });
    return row === null || row.status !== 'active' ? undefined : (row.id as TenantId);
  }

  public async exists(tenantId: TenantId): Promise<boolean> {
    const row = await this.prisma.identityTenant.findUnique({
      where: { id: tenantId },
      select: { id: true },
    });
    return row !== null;
  }
}
