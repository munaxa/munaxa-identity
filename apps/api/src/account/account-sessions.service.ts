import { Inject, Injectable } from '@nestjs/common';
import type { SessionId } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';

import { resolvePrincipal } from '../auth/principal.js';
import type { SecurityStack } from '../platform/security.js';
import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import { toSessionView, type SessionView } from './session-view.js';

/**
 * "Your devices": list your own sessions, sign one out, sign out every other one.
 *
 * Every operation starts from `resolvePrincipal`, so the caller is the subject of a verified access
 * token whose session is live, whose account is active and whose token version is current. The
 * tenant and the account every query runs against are taken from that principal and from nowhere
 * else — not from the path, not from a body, not from a header — so there is no parameter a
 * caller can change to reach somebody else's sessions. The only identifier a caller supplies is a
 * session id, and that is matched against their own account inside the revoking statement.
 *
 * Listing and revoking need no recent re-authentication. Seeing your own devices and ending them
 * is the response to a suspected compromise, and gating it behind a password prompt would gate it
 * behind the credential the attacker may have changed.
 */
export type Unauthenticated = { readonly ok: false; readonly reason: 'unauthenticated' };

export type ListOutcome = Unauthenticated | { readonly ok: true; readonly sessions: SessionView[] };

export type RevokeOutcome =
  | Unauthenticated
  | { readonly ok: false; readonly reason: 'not-found' }
  | { readonly ok: true; readonly current: boolean };

export type RevokeOthersOutcome = Unauthenticated | { readonly ok: true; readonly revoked: number };

const UNAUTHENTICATED: Unauthenticated = { ok: false, reason: 'unauthenticated' };

/** Platform's ids are `sess_…`; anything outside this shape cannot name a session and is refused unread. */
const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

@Injectable()
export class AccountSessionsService {
  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
  ) {}

  public async list(accessToken: string | undefined): Promise<ListOutcome> {
    const resolved = await resolvePrincipal(this.security, accessToken);
    if (!resolved.ok) return UNAUTHENTICATED;
    const { principal } = resolved;

    // `listActive` drops revoked rows and rows past either deadline, so an expired session is not
    // offered as something to sign out of — it already is signed out.
    const sessions = await this.security.sessions.listActive(principal.tenantId, principal.userId);
    return {
      ok: true,
      sessions: sessions
        // Belt and braces: the store already filters by account, and this is the line that would
        // catch an adapter that one day did not.
        .filter((session) => session.userId === principal.userId)
        .map((session) =>
          toSessionView(session, principal.sessionId, this.environment.IDENTITY_SESSION_LIST_IP),
        ),
    };
  }

  /**
   * Sign out one of the caller's sessions. It may be the current one, which is a logout.
   *
   * "Not found" answers for an id that never existed, one already revoked and one that belongs to
   * somebody else, identically: telling those apart would let a caller probe for other people's
   * session ids.
   */
  public async revoke(
    accessToken: string | undefined,
    sessionId: string,
    correlationId?: string,
  ): Promise<RevokeOutcome> {
    const resolved = await resolvePrincipal(this.security, accessToken);
    if (!resolved.ok) return UNAUTHENTICATED;
    const { principal } = resolved;
    if (!SESSION_ID.test(sessionId)) return { ok: false, reason: 'not-found' };

    const revoked = await this.security.revocation.revokeSession(
      principal.tenantId,
      principal.userId,
      sessionId as SessionId,
      'logout',
    );
    if (!revoked) return { ok: false, reason: 'not-found' };
    const current = sessionId === principal.sessionId;
    await this.security.revocationAudit({
      name: 'session.revoked',
      tenantId: principal.tenantId,
      actor: { kind: 'user', id: principal.userId },
      subject: principal.userId,
      correlationId,
      payload: { reason: 'logout', scope: 'one', sessionId, current },
    });
    return { ok: true, current };
  }

  /** Sign out every session but the one making the request. */
  public async revokeOthers(
    accessToken: string | undefined,
    correlationId?: string,
  ): Promise<RevokeOthersOutcome> {
    const resolved = await resolvePrincipal(this.security, accessToken);
    if (!resolved.ok) return UNAUTHENTICATED;
    const { principal } = resolved;

    const outcome = await this.security.revocation.revokeOtherSessions(
      principal.tenantId,
      principal.userId,
      principal.sessionId,
      'logout-all',
    );
    await this.security.revocationAudit({
      name: 'session.revoked',
      tenantId: principal.tenantId,
      actor: { kind: 'user', id: principal.userId },
      subject: principal.userId,
      correlationId,
      payload: {
        reason: 'logout-all',
        scope: 'others',
        keptSessionId: principal.sessionId,
        sessions: outcome.sessions,
        refreshTokens: outcome.refreshTokens,
      },
    });
    return { ok: true, revoked: outcome.sessions };
  }
}
