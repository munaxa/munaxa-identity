import { Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '../../../../node_modules/.prisma/identity-client';

/**
 * The database connection, and the only place a tenant context is established.
 *
 * Every table but `identity_tenant` carries `force row level security` with a policy that reads
 * `identity_current_tenant()`. That function reads a *transaction-local* setting, so a query
 * outside `withTenant` matches no rows — which is the safe direction, and is deliberately not
 * the same thing as a query that fails. An adapter that forgets the context returns nothing
 * rather than everything.
 *
 * Transaction-local rather than session-level, because a session-level `set_config` outlives the
 * connection checkout and would apply this organisation's context to whatever query used the
 * connection next.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  public async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  public async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  /** Run `work` in a transaction whose row-level security context is `tenantId`. */
  public withTenant<T>(tenantId: string, work: (tx: TenantClient) => Promise<T>): Promise<T> {
    return this.$transaction(async (tx) => {
      await tx.$executeRaw`select set_config('identity.tenant_id', ${tenantId}::text, true)`;
      return work(tx as unknown as TenantClient);
    });
  }
}

/** The transactional client handed to an adapter, already scoped to one organisation. */
export type TenantClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>;
