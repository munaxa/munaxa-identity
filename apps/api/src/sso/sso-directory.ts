import type { TenantId } from '@munaxa/types';

import type { PrismaService } from '../persistence/prisma.service.js';
import { domainOf, type SsoProviderKind } from './providers.js';

/**
 * Which company directory an email address signs in through.
 *
 * The domain is looked up without a tenant context, as `TenantDirectory` reads organisations, and
 * for the same reason: company sign-in starts from an address, before any organisation is known.
 * Only `identity_sso_domain` allows that read. The connection itself, with its trust settings, is
 * read inside the organisation's own row-level security context (migration
 * `20261126190000_identity_sso`).
 *
 * A connection is offered only when it is enabled **and** its organisation is active. Everything
 * else (unknown domain, disabled connection, suspended organisation) is the same `undefined`.
 */
export interface SsoConnection {
  readonly id: string;
  readonly tenantId: TenantId;
  readonly provider: SsoProviderKind;
  readonly directoryId: string;
  readonly trustProviderMfa: boolean;
  /** Every domain this connection owns, lower-cased. */
  readonly domains: readonly string[];
}

export class SsoDirectory {
  public constructor(private readonly prisma: PrismaService) {}

  public async forEmail(email: string): Promise<SsoConnection | undefined> {
    const domain = domainOf(email);
    if (domain === undefined) return undefined;
    const row = await this.prisma.identitySsoDomain.findUnique({
      where: { domain },
      select: { connectionId: true, tenantId: true },
    });
    return row === null ? undefined : this.byId(row.tenantId as TenantId, row.connectionId);
  }

  /** The connection, read as `tenantId`: another organisation's connection is not found. */
  public async byId(tenantId: TenantId, id: string): Promise<SsoConnection | undefined> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return undefined;
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identitySsoConnection.findUnique({
        where: { id },
        include: {
          domains: { select: { domain: true } },
          tenant: { select: { status: true } },
        },
      }),
    );
    if (row === null || row.tenantId !== tenantId) return undefined;
    if (!row.enabled || row.tenant.status !== 'active') return undefined;
    if (row.provider !== 'microsoft' && row.provider !== 'google') return undefined;
    return {
      id: row.id,
      tenantId: row.tenantId as TenantId,
      provider: row.provider,
      directoryId: row.directoryId,
      trustProviderMfa: row.trustProviderMfa,
      domains: row.domains.map((entry) => entry.domain),
    };
  }
}
