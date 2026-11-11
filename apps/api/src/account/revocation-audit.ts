import { anonymousAuditEvent, type AuditService } from '@munaxa/audit';
import { toCorrelationId, type SecurityEventName, type TenantId, type UserId } from '@munaxa/types';
import { randomUUID } from 'node:crypto';

/**
 * The audit record of a revocation somebody asked for.
 *
 * Written *after* the revocation commits and outside its transaction, deliberately. Inside the
 * transaction a failing audit sink would roll the revocation back, which turns an unwell trail into
 * a user who cannot sign their stolen laptop out; and inside a password reset's unit of work an
 * extra write is one more statement that can fail the whole reset. So the revocation stands on its
 * own, and the record of it is awaited, reported if it fails, and never fatal — the same rule the
 * login path follows.
 *
 * The payload carries counts, the reason and the session id that was named. Never a token, a
 * refresh hash, an address or a user-agent.
 */
export interface RevocationAuditInput {
  readonly name: Extract<SecurityEventName, 'session.revoked' | 'auth.account.locked'>;
  readonly tenantId: TenantId;
  /** Who did it: the user themselves, or `system:<what>` for an automated response. */
  readonly actor: { readonly kind: 'user' | 'system'; readonly id: string };
  readonly subject: UserId;
  readonly correlationId?: string | undefined;
  readonly payload: Readonly<Record<string, string | number | boolean>>;
}

export type RevocationAuditor = (input: RevocationAuditInput) => Promise<void>;

export const revocationAuditor =
  (audit: Pick<AuditService, 'write'>): RevocationAuditor =>
  async (input) => {
    try {
      await audit.write(
        anonymousAuditEvent(input.tenantId, toCorrelationId(input.correlationId ?? randomUUID()), {
          name: input.name,
          outcome: 'success',
          actor: input.actor,
          target: { type: 'account', id: input.subject },
          payload: input.payload,
        }),
      );
    } catch (error) {
      process.stderr.write(
        `[identity] revocation audit write failed (${input.name}): ${String(error)}\n`,
      );
    }
  };
