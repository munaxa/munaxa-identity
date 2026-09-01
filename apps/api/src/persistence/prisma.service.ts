import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import type { IdentityEnvironment } from '@identity/config';

import { PrismaClient } from '../../../../node_modules/.prisma/identity-client';
import { ENVIRONMENT } from '../tokens.js';

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
 *
 * **The connection string comes from the validated configuration, never from the ambient
 * environment**, and that is not a stylistic preference. Prisma resolves `env("DATABASE_URL")`
 * itself and loads a `.env` file to do it, so a client constructed without an explicit datasource
 * silently picks up whatever `DATABASE_URL` happens to be around. With secrets mounted as files —
 * `DATABASE_URL_FILE`, which is how every deployment supplies them — `DATABASE_URL` is *unset*,
 * and Prisma fills it from a development `.env` instead. The service then starts, passes its
 * readiness probe, and answers every sign-in with a generic 401 because it is looking in the wrong
 * database. That happened, in the first real staging deployment, and cost an hour: the symptom is
 * indistinguishable from a wrong password.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  public constructor(@Inject(ENVIRONMENT) environment: IdentityEnvironment) {
    super({ datasources: { db: { url: environment.DATABASE_URL } } });
  }

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
