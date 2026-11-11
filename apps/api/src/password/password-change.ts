import { anonymousAuditEvent, type AuditService } from '@munaxa/audit';
import type { LoginService } from '@munaxa/auth';
import type { CachePort } from '@munaxa/interfaces';
import { RateLimiter } from '@munaxa/security';
import {
  isPlatformError,
  type CorrelationId,
  type SessionId,
  type TenantId,
  type UserId,
} from '@munaxa/types';

import type { CredentialRevocation } from '../account/credential-revocation.js';
import { resolvePrincipal } from '../auth/principal.js';
import type { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';

/**
 * Changing a password while signed in.
 *
 * Platform's `LoginService.changePassword` owns the rules: the current password must be proved
 * (the person at the keyboard may have found an unlocked laptop), the new one must pass policy and
 * the breach check, then the hash is written and the token version bumped. Identity adds the same
 * two things it adds to a reset:
 *
 * - **One transaction.** The account row is locked, then Platform's change, the revocation of
 *   every outstanding reset link, and the revocation of every session and refresh lineage all
 *   commit together or not at all (`PrismaService.unitOfWork`). A failure part-way cannot leave a
 *   new password with the old sessions still live, or an old reset link that still works.
 * - **Every session ends, including this one.** Platform's rule, and the reason is that a password
 *   change is how a victim evicts an attacker; keeping "the current session" would keep the
 *   attacker's if the attacker is the one changing it. The caller signs in again.
 *
 * Guessing the current password through this route is limited per account and per session in the
 * shared cache, failing closed if the cache is unreachable.
 */

export type ChangeOutcome =
  | { readonly kind: 'changed'; readonly revokedSessions: number }
  | { readonly kind: 'unauthenticated' }
  | { readonly kind: 'invalid-current-password' }
  | {
      readonly kind: 'password-rejected';
      readonly code: string;
      readonly violations: readonly string[];
    }
  | { readonly kind: 'rate-limited'; readonly retryAfterSeconds: number }
  | { readonly kind: 'unavailable' };

export const PASSWORD_CHANGE_RULES = [
  {
    id: 'password-change-per-account',
    dimension: 'user' as const,
    limit: 5,
    window: 15 * 60 * 1_000,
    adaptiveFactor: 2,
  },
];

export const createChangeLimiter = (cache: CachePort): RateLimiter =>
  new RateLimiter({ cache, rules: PASSWORD_CHANGE_RULES });

const MAX_PASSWORD = 1_024;

export interface PasswordChangeOptions {
  readonly security: Pick<SecurityStack, 'tokens' | 'sessions' | 'directory'>;
  readonly prisma: PrismaService;
  readonly login: Pick<LoginService, 'changePassword'>;
  readonly revocation: Pick<CredentialRevocation, 'revokeAllForUser'>;
  readonly revokeResetLinks: (tenantId: TenantId, userId: UserId) => Promise<number>;
  readonly limiter: RateLimiter;
  readonly audit: AuditService;
  readonly log?: (level: 'warn' | 'error', event: string, fields: Record<string, unknown>) => void;
}

export class PasswordChange {
  public constructor(private readonly options: PasswordChangeOptions) {}

  public async change(input: {
    readonly accessToken: string | undefined;
    readonly currentPassword: string;
    readonly newPassword: string;
    readonly correlationId: CorrelationId;
  }): Promise<ChangeOutcome> {
    const resolution = await resolvePrincipal(this.options.security, input.accessToken);
    if (!resolution.ok) return { kind: 'unauthenticated' };
    const { tenantId, userId, sessionId } = resolution.principal;

    const decision = await this.options.limiter.check({
      method: 'POST',
      path: '/auth/password/change',
      tenantId,
      userId,
      sessionId,
    });
    if (decision.degraded === true) {
      this.options.log?.('error', 'auth.password_change.limiter_unavailable', {
        correlationId: input.correlationId,
      });
      return { kind: 'unavailable' };
    }
    if (!decision.allowed) {
      return { kind: 'rate-limited', retryAfterSeconds: Math.max(1, decision.retryAfterSeconds) };
    }

    if (
      input.currentPassword.length === 0 ||
      input.currentPassword.length > MAX_PASSWORD ||
      input.newPassword.length > MAX_PASSWORD
    ) {
      return { kind: 'invalid-current-password' };
    }

    let revokedSessions = 0;
    try {
      await this.options.prisma.unitOfWork(tenantId, async () => {
        await this.options.prisma.withTenant(
          tenantId,
          (tx) =>
            tx.$queryRaw`select id from identity_account where tenant_id = ${tenantId} and id = ${userId} for update`,
        );
        await this.options.login.changePassword(
          tenantId,
          userId,
          input.currentPassword,
          input.newPassword,
        );
        await this.options.revokeResetLinks(tenantId, userId);
        revokedSessions = (
          await this.options.revocation.revokeAllForUser(tenantId, userId, 'password-changed')
        ).sessions;
      });
    } catch (error) {
      if (isPlatformError(error) && error.code === 'AUTH_INVALID_CREDENTIALS') {
        await this.audit(tenantId, userId, sessionId, input.correlationId, 'failure', {
          reason: 'current-password',
        });
        return { kind: 'invalid-current-password' };
      }
      if (
        isPlatformError(error) &&
        (error.code === 'AUTH_PASSWORD_POLICY' ||
          error.code === 'AUTH_PASSWORD_BREACHED' ||
          error.code === 'AUTH_PASSWORD_REUSED')
      ) {
        const violations =
          (error.details as { violations?: readonly string[] } | undefined)?.violations ?? [];
        return { kind: 'password-rejected', code: error.code, violations };
      }
      this.options.log?.('error', 'auth.password_change.failed', {
        correlationId: input.correlationId,
        error: error instanceof Error ? error.name : 'unknown',
      });
      return { kind: 'unavailable' };
    }

    await this.audit(tenantId, userId, sessionId, input.correlationId, 'success');
    return { kind: 'changed', revokedSessions };
  }

  private async audit(
    tenantId: TenantId,
    userId: UserId,
    sessionId: SessionId,
    correlationId: CorrelationId,
    outcome: 'success' | 'failure',
    payload?: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.options.audit
      .write(
        anonymousAuditEvent(tenantId, correlationId, {
          name: 'auth.password.changed',
          outcome,
          actor: { kind: 'user' as const, id: userId },
          payload: { sessionId, ...(payload ?? {}) },
        }),
      )
      .catch((error: unknown) => {
        this.options.log?.('error', 'auth.password_change.audit_failed', {
          error: error instanceof Error ? error.name : 'unknown',
        });
      });
  }
}
