import type { SessionRevocationReason } from '@munaxa/interfaces';
import type { SessionId, TenantId, UserId } from '@munaxa/types';

import type { PrismaService, TenantClient } from '../persistence/prisma.service.js';

/**
 * Ending sessions, and the refresh lineages that would otherwise bring them back.
 *
 * A session in Identity is two server-side objects: the `identity_session` row every
 * authenticated request consults, and the refresh tokens bound to it by `session_id`. Revoking
 * only the row is enough to make the *next* refresh fail — `AuthService.refresh` re-validates the
 * session — but it leaves live refresh tokens in the table that a later bug, or a later reader
 * that forgets the session check, would honour. Revoking only the tokens leaves an access token
 * whose `sid` still validates. So every method here revokes both, in one transaction, and a
 * partial revocation cannot be observed.
 *
 * **Ownership is in the `WHERE` clause, not in a prior read.** `revokeSession` matches on
 * tenant, session id *and* account id together: a caller who substitutes another person's session
 * id revokes nothing and gets the same answer as for an id that never existed. A read-then-check
 * would be the same rule with a window in it.
 *
 * Revocation is one-way. Nothing here, and nothing in `PrismaSessionStore.update`, writes
 * `revoked_at = null`: a revoked row stays revoked whatever else races it.
 *
 * Every write goes through `PrismaService.withTenant`, so it runs under row-level security as the
 * restricted role, and joins an enclosing unit of work for the same tenant when one is open — a
 * password reset can claim its ticket, change the password, bump the token version and call
 * `revokeAllForUser` and have all of it commit or none of it. Nothing here fires work it does not
 * await, for the same reason: inside a unit of work a stray promise would hit a closed transaction.
 */
export interface RevocationOutcome {
  /** Session rows moved from live to revoked by this call. */
  readonly sessions: number;
  /** Refresh tokens moved from live to revoked by this call. */
  readonly refreshTokens: number;
}

export class CredentialRevocation {
  public constructor(
    private readonly prisma: PrismaService,
    private readonly clock: () => number = Date.now,
  ) {}

  /**
   * Revoke one of a user's own sessions. Returns whether a live session was revoked.
   *
   * `false` covers "not found", "already revoked" and "belongs to somebody else" alike, and the
   * caller must not distinguish them.
   */
  public async revokeSession(
    tenantId: TenantId,
    userId: UserId,
    sessionId: SessionId,
    reason: SessionRevocationReason,
  ): Promise<boolean> {
    const at = new Date(this.clock());
    return this.prisma.withTenant(tenantId, async (tx) => {
      const sessions = await tx.identitySession.updateMany({
        where: { tenantId, id: sessionId, accountId: userId, revokedAt: null },
        data: { revokedAt: at, revocationReason: reason },
      });
      // The lineage goes even when the row was already revoked: an earlier revocation that
      // predates this code left its tokens live, and finishing that job is always safe. The
      // account id is in this filter too, so a foreign session id matches nothing here either.
      await revokeTokensOfSessions(tx, tenantId, userId, [sessionId], at, reason);
      return sessions.count > 0;
    });
  }

  /** Revoke every session of the user except `keep`. "Sign out my other devices." */
  public async revokeOtherSessions(
    tenantId: TenantId,
    userId: UserId,
    keep: SessionId,
    reason: SessionRevocationReason = 'logout-all',
  ): Promise<RevocationOutcome> {
    return this.revokeAllForUser(tenantId, userId, reason, { except: keep });
  }

  /**
   * Revoke every session and every refresh token the user holds, optionally keeping one session
   * and the lineage bound to it.
   *
   * Without `except` this is the password-reset, account-disabled and suspected-compromise
   * response: nothing the user was signed in with survives, including the session that asked.
   */
  public async revokeAllForUser(
    tenantId: TenantId,
    userId: UserId,
    reason: SessionRevocationReason,
    options: { readonly except?: SessionId } = {},
  ): Promise<RevocationOutcome> {
    const at = new Date(this.clock());
    const keep = options.except;
    return this.prisma.withTenant(tenantId, async (tx) => {
      const sessions = await tx.identitySession.updateMany({
        where: {
          tenantId,
          accountId: userId,
          revokedAt: null,
          ...(keep === undefined ? {} : { id: { not: keep } }),
        },
        data: { revokedAt: at, revocationReason: reason },
      });
      const refreshTokens = await tx.identityRefreshToken.updateMany({
        where: {
          tenantId,
          accountId: userId,
          revokedAt: null,
          // A token with no session is bound to nothing the user can keep, so it never survives.
          // `NOT (session_id = keep)` alone would keep it: SQL's three-valued logic makes the
          // comparison NULL, and NOT NULL is not true.
          ...(keep === undefined
            ? {}
            : { OR: [{ sessionId: null }, { sessionId: { not: keep } }] }),
        },
        data: { revokedAt: at, revocationReason: reason },
      });
      return { sessions: sessions.count, refreshTokens: refreshTokens.count };
    });
  }

  /**
   * Revoke the session a refresh lineage belongs to, and the lineage.
   *
   * The reuse-detection response. Platform revokes the family when a rotated token is presented
   * again; the session row that family was keeping alive has to go with it, or the access token
   * still in the thief's hands keeps validating until it expires — and every protected Identity
   * route would keep answering it.
   */
  public async revokeSessionOfFamily(
    tenantId: TenantId,
    userId: UserId,
    sessionId: SessionId | undefined,
    reason: SessionRevocationReason,
  ): Promise<void> {
    if (sessionId === undefined) return;
    await this.revokeSession(tenantId, userId, sessionId, reason);
  }
}

const revokeTokensOfSessions = async (
  tx: TenantClient,
  tenantId: TenantId,
  userId: UserId,
  sessionIds: readonly SessionId[],
  at: Date,
  reason: string,
): Promise<number> => {
  const revoked = await tx.identityRefreshToken.updateMany({
    where: {
      tenantId,
      accountId: userId,
      sessionId: { in: [...sessionIds] },
      revokedAt: null,
    },
    data: { revokedAt: at, revocationReason: reason },
  });
  return revoked.count;
};

/**
 * The two account-wide responses that are not a user signing their own devices out.
 *
 * Both end with nothing the user was signed in with still working, and both get there by steps
 * that each fail safe on their own, in an order where a crash between any two leaves the account
 * *more* locked than before rather than less:
 *
 * 1. `disable` sets the status first. From that write on, `resolvePrincipal` and every refresh
 *    refuse the account, whatever happens next.
 * 2. The token version is bumped, so every access token and refresh lineage minted before it is
 *    stale — including any the revocation below does not reach because it was written concurrently.
 * 3. Every session and every refresh token is revoked, so the session list and the database agree
 *    with what the version bump already decided.
 *
 * Neither is exposed over HTTP by this repository: there is no administration API yet, and these
 * are what one — or an operator script, or a risk engine — calls.
 */
export class AccountLockdown {
  public constructor(
    private readonly directory: {
      setStatus(tenantId: TenantId, userId: UserId, status: 'disabled'): Promise<void>;
      incrementTokenVersion(tenantId: TenantId, userId: UserId): Promise<number>;
    },
    private readonly revocation: CredentialRevocation,
  ) {}

  /** Disable the account and end everything it was signed in with. */
  public async disable(tenantId: TenantId, userId: UserId): Promise<RevocationOutcome> {
    await this.directory.setStatus(tenantId, userId, 'disabled');
    await this.directory.incrementTokenVersion(tenantId, userId);
    return this.revocation.revokeAllForUser(tenantId, userId, 'account-disabled');
  }

  /**
   * Treat the account as compromised: every credential issued so far is ended, the account stays
   * usable, and the user signs in again with whatever credential they still control.
   */
  public async suspectedCompromise(tenantId: TenantId, userId: UserId): Promise<RevocationOutcome> {
    await this.directory.incrementTokenVersion(tenantId, userId);
    return this.revocation.revokeAllForUser(tenantId, userId, 'risk-detected');
  }
}
