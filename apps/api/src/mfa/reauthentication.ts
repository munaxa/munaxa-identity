import type { CachePort } from '@munaxa/interfaces';
import { cacheKey, type SessionId, type TenantId } from '@munaxa/types';

/**
 * Recent reauthentication, per session.
 *
 * Enrolling, replacing or removing a second factor, and regenerating recovery codes, each need
 * proof that the person at the keyboard is the account holder *now* — not merely that a session
 * cookie exists. A successful `POST /api/auth/reauthenticate` (the password, plus a code when MFA is
 * enrolled) records a marker for the session in the shared cache with a TTL of `MFA_REAUTH_WINDOW`.
 * A session created by a full sign-in within the window counts too, so enrolling straight after
 * signing in does not ask for the password twice.
 *
 * The marker is keyed by session, so it dies with the session's revocation in effect (the
 * principal check fails first) and cannot be carried to another device.
 */
export class Reauthentication {
  public constructor(
    private readonly cache: CachePort,
    private readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  public async record(tenantId: TenantId, sessionId: SessionId): Promise<void> {
    await this.cache.set(this.#key(tenantId, sessionId), this.now(), { ttl: this.windowMs });
  }

  public async isRecent(
    tenantId: TenantId,
    sessionId: SessionId,
    sessionCreatedAt: number,
  ): Promise<boolean> {
    if (this.now() - sessionCreatedAt < this.windowMs) return true;
    const at = await this.cache.get<number>(this.#key(tenantId, sessionId));
    return at !== undefined && this.now() - at < this.windowMs;
  }

  /** Spend the marker, so one reauthentication authorises one sensitive change. */
  public async clear(tenantId: TenantId, sessionId: SessionId): Promise<void> {
    await this.cache.delete(this.#key(tenantId, sessionId));
  }

  #key(tenantId: TenantId, sessionId: SessionId): string {
    return cacheKey('auth', 'reauth', tenantId, sessionId);
  }
}
