import type { TenantId, UserId } from '@munaxa/types';

import type { Principal } from '../auth/principal.js';
import type { IdentityMfa } from './mfa-runtime.js';
import type { Reauthentication } from './reauthentication.js';

/**
 * Whether a sensitive action may proceed for this session without a fresh second factor.
 *
 * An account with an active factor has said that a password alone is not enough to act as it. A
 * stolen session cookie plus a phished password must therefore not be enough to change the
 * password either, or the attacker turns a session into the account. So such an account must have
 * reauthenticated (password plus TOTP or recovery code, `POST /api/auth/reauthenticate`) within
 * `MFA_REAUTH_WINDOW`, on this session. An account with no factor has nothing to step up to; the
 * action's own proof (the current password, for a change) is the whole check.
 *
 * Fails closed: if the account is flagged enrolled but MFA is not configured on this replica, the
 * answer is `unavailable`, never `satisfied`.
 */
export type StepUpDecision = 'satisfied' | 'required' | 'unavailable';

export type StepUpCheck = (principal: Principal) => Promise<StepUpDecision>;

export const createStepUp =
  (deps: {
    readonly mfa: IdentityMfa | undefined;
    readonly reauthentication: Pick<Reauthentication, 'isRecent'>;
    readonly flaggedEnrolled: (tenantId: TenantId, userId: UserId) => Promise<boolean>;
  }): StepUpCheck =>
  async (principal) => {
    const { tenantId, userId } = principal;
    const enrolled =
      deps.mfa === undefined
        ? await deps.flaggedEnrolled(tenantId, userId)
        : await deps.mfa.verifier(tenantId, userId).isEnrolled(tenantId, userId);
    if (!enrolled) return 'satisfied';
    if (deps.mfa === undefined) return 'unavailable';
    const recent = await deps.reauthentication.isRecent(
      tenantId,
      principal.sessionId,
      principal.session.createdAt,
    );
    return recent ? 'satisfied' : 'required';
  };
