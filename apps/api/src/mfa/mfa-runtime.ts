import { MfaService } from '@munaxa/auth';
import type { CachePort } from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';

import { PrismaMfaEnrollmentStore } from '../persistence/mfa-enrollment-store.adapter.js';
import type { PrismaService } from '../persistence/prisma.service.js';
import type { MfaKeys } from './mfa-keys.js';

/**
 * Platform's `MfaService`, configured for Identity.
 *
 * Identity writes no TOTP: generation, verification, drift and the fleet-wide replay claim are all
 * `@munaxa/auth`. What is Identity's is the wiring, and two choices in it are security decisions:
 *
 * - **A service per account, not one per process.** `protectSecret` has no context argument, yet
 *   the envelope must be bound to the tenant, the account and the method. Binding the AAD in a
 *   closure per account does that without changing Platform. The services are cheap; nothing in
 *   them is per-process state once `replayGuard` is wired, which it always is here.
 * - **Two store views.** `enroller` writes through the `pending` view and `verifier` reads through
 *   the `active` view (see `PrismaMfaEnrollmentStore`), so starting a replacement can never switch
 *   the current factor off.
 *
 * `replayGuard` is the shared cache, so a TOTP step accepted on one replica is refused on every
 * other for its whole window. `distributed` reports it; the composition root refuses to start in
 * production unless it is true and the cache is Redis.
 */
export interface IdentityMfa {
  /** True when the replay claim is fleet-wide. */
  readonly distributed: boolean;
  /** The active view, for operations that are not `MfaService`'s: counts, rotation. */
  readonly store: PrismaMfaEnrollmentStore;
  readonly keys: MfaKeys;
  /** Verify codes and recovery codes against the account's active factor. */
  verifier(tenantId: TenantId, userId: UserId): MfaService;
  /** Begin and confirm an enrollment, which replaces the active factor only once confirmed. */
  enroller(tenantId: TenantId, userId: UserId): MfaService;
}

export interface IdentityMfaOptions {
  readonly prisma: PrismaService;
  readonly keys: MfaKeys;
  readonly replayGuard: CachePort;
  /** How long a started enrollment stays confirmable. */
  readonly pendingTtlMs: number;
  readonly recoveryCodeCount?: number;
}

export const buildIdentityMfa = (options: IdentityMfaOptions): IdentityMfa => {
  const active = new PrismaMfaEnrollmentStore(options.prisma, options.keys, {
    view: 'active',
    pendingTtlMs: options.pendingTtlMs,
  });
  const pending = active.view('pending');

  const service = (store: PrismaMfaEnrollmentStore, tenantId: TenantId, userId: UserId) =>
    new MfaService({
      store,
      replayGuard: options.replayGuard,
      protectSecret: options.keys.protector(tenantId, userId, 'totp'),
      recoveryCodeCount: options.recoveryCodeCount ?? 10,
    });

  return {
    distributed: service(active, '' as TenantId, '' as UserId).distributed,
    store: active,
    keys: options.keys,
    verifier: (tenantId, userId) => service(active, tenantId, userId),
    enroller: (tenantId, userId) => service(pending, tenantId, userId),
  };
};
