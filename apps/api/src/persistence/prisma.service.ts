import { AsyncLocalStorage } from 'node:async_hooks';

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

  /**
   * The transaction a unit of work is running, if any. See `unitOfWork`.
   *
   * Held in async-local storage rather than passed down, because the code between the unit of
   * work and the adapters is Platform's — `PasswordResetService.complete` calls the ports itself,
   * and its signatures carry no transaction. The adapters already funnel every statement through
   * `withTenant`, so that is the one place that needs to know.
   */
  private readonly ambient = new AsyncLocalStorage<{
    readonly tenantId: string;
    readonly tx: TenantClient;
  }>();

  /**
   * Run `work` in a transaction whose row-level security context is `tenantId`.
   *
   * Inside a `unitOfWork` for the same organisation this joins that transaction instead of opening
   * its own, so a sequence of port calls commits or rolls back together. Inside a unit of work for
   * a *different* organisation it refuses: silently running one organisation's statement inside
   * another's row-level security context is the failure this whole class exists to prevent.
   */
  public withTenant<T>(tenantId: string, work: (tx: TenantClient) => Promise<T>): Promise<T> {
    const ambient = this.ambient.getStore();
    if (ambient !== undefined) {
      if (ambient.tenantId !== tenantId) {
        return Promise.reject(
          new Error('withTenant: a unit of work for one organisation cannot touch another'),
        );
      }
      return work(ambient.tx);
    }
    return this.$transaction(async (tx) => {
      await tx.$executeRaw`select set_config('identity.tenant_id', ${tenantId}::text, true)`;
      return work(tx as unknown as TenantClient);
    });
  }

  /**
   * Run `work` as one transaction: every `withTenant` it reaches, directly or through Platform,
   * commits together or not at all.
   *
   * This exists for sequences whose intermediate states are unsafe — a reset token consumed with
   * the password unchanged, or a password changed with the old sessions still valid. PostgreSQL
   * guarantees the rollback even when the process dies mid-way: an uncommitted transaction does not
   * survive its connection.
   *
   * Rules for `work`: await everything it starts (a statement issued after the callback returns
   * meets a closed transaction), and keep anything that is not this database — email, audit fan-out,
   * cache writes — outside it, after it commits.
   */
  public unitOfWork<T>(
    tenantId: string,
    work: () => Promise<T>,
    options: { readonly timeoutMs?: number } = {},
  ): Promise<T> {
    if (this.ambient.getStore() !== undefined) {
      return Promise.reject(new Error('unitOfWork: units of work do not nest'));
    }
    return this.$transaction(
      async (tx) => {
        await tx.$executeRaw`select set_config('identity.tenant_id', ${tenantId}::text, true)`;
        return this.ambient.run({ tenantId, tx: tx as unknown as TenantClient }, work);
      },
      { timeout: options.timeoutMs ?? 15_000, maxWait: 5_000 },
    );
  }

  /** Whether the caller is inside a unit of work. For assertions, not for branching. */
  public get inUnitOfWork(): boolean {
    return this.ambient.getStore() !== undefined;
  }
}

/** The transactional client handed to an adapter, already scoped to one organisation. */
export type TenantClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>;
