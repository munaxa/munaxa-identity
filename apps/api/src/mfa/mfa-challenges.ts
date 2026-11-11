import { secureToken, sha256Hex } from '@munaxa/crypto';
import type { CachePort } from '@munaxa/interfaces';
import { cacheKey, type TenantId, type UserId } from '@munaxa/types';

/**
 * The pending second-factor challenge: what exists between "the password was right" and "a session
 * exists".
 *
 * Two kinds, one mechanism:
 *
 * - `verify` — the account has MFA; the holder may present a TOTP or a recovery code.
 * - `enroll` — policy requires MFA and the account has none; the holder may only start and confirm
 *   an enrollment. Nothing else in the service reads this cookie.
 *
 * Properties, each deliberate:
 *
 * - **Opaque and random.** 256 bits from `@munaxa/crypto` `secureToken`. It is not a JWT, carries no
 *   claim, and no verifier anywhere accepts it as an access token: `resolvePrincipal` reads only the
 *   session cookie and only a signed JWT.
 * - **Hashed at rest.** Redis holds the challenge under `sha256(token)`; a keyspace dump yields no
 *   presentable token.
 * - **Shared.** It lives in the shared Redis, so any replica can complete it, and exactly one can:
 *   completion is a `DEL` that returns whether it removed the key, which Redis decides once.
 * - **Bound.** It records the tenant, the account, the account's token version at the time and a
 *   digest of the user agent; completion re-checks all of them, so a challenge copied to another
 *   browser, or outlived by a password change, is refused.
 * - **Bounded.** A TTL, and an attempt counter reserved with `INCR` before each answer is checked,
 *   so concurrent answers cannot exceed the limit; at it, the challenge is dead.
 */
export type ChallengeKind = 'verify' | 'enroll';

export interface ChallengeRecord {
  readonly v: 1;
  readonly kind: ChallengeKind;
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly tokenVersion: number;
  readonly userAgentDigest: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface IssuedChallenge {
  /** The value for the cookie. Returned once, never stored. */
  readonly token: string;
  readonly record: ChallengeRecord;
}

export interface ChallengeOptions {
  readonly verifyTtlMs: number;
  readonly enrollTtlMs: number;
  readonly maxAttempts: number;
  readonly now?: () => number;
}

export const userAgentDigest = (userAgent: string | undefined): string =>
  sha256Hex(`ua:${userAgent ?? ''}`).slice(0, 32);

/** A string that is not a token this store minted is refused before it reaches Redis. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{40,64}$/;

export class MfaChallenges {
  readonly #now: () => number;

  public constructor(
    private readonly cache: CachePort,
    private readonly options: ChallengeOptions,
  ) {
    this.#now = options.now ?? Date.now;
  }

  public ttlOf(kind: ChallengeKind): number {
    return kind === 'verify' ? this.options.verifyTtlMs : this.options.enrollTtlMs;
  }

  public async issue(input: {
    readonly kind: ChallengeKind;
    readonly tenantId: TenantId;
    readonly userId: UserId;
    readonly tokenVersion: number;
    readonly userAgent?: string | undefined;
  }): Promise<IssuedChallenge> {
    const token = secureToken(32);
    const now = this.#now();
    const ttl = this.ttlOf(input.kind);
    const record: ChallengeRecord = {
      v: 1,
      kind: input.kind,
      tenantId: input.tenantId,
      userId: input.userId,
      tokenVersion: input.tokenVersion,
      userAgentDigest: userAgentDigest(input.userAgent),
      createdAt: now,
      expiresAt: now + ttl,
    };
    await this.cache.set(this.#key(token), record, { ttl });
    return { token, record };
  }

  /**
   * Look a challenge up without spending it. `undefined` for anything that is not a live challenge
   * of the expected kind presented from the browser it was issued to.
   */
  public async peek(
    token: string | undefined,
    kind: ChallengeKind,
    userAgent: string | undefined,
  ): Promise<ChallengeRecord | undefined> {
    if (token === undefined || !TOKEN_SHAPE.test(token)) return undefined;
    const record = await this.cache.get<ChallengeRecord>(this.#key(token));
    if (record?.v !== 1 || record.kind !== kind) return undefined;
    if (this.#now() >= record.expiresAt) return undefined;
    if (record.userAgentDigest !== userAgentDigest(userAgent)) return undefined;
    return record;
  }

  /**
   * Reserve one attempt **before** the answer is checked.
   *
   * `INCR` first, then verify: Redis serialises the increments, so however many answers arrive at
   * once, across however many replicas, at most `maxAttempts` of them are ever checked against the
   * factor. Checking a counter and incrementing it after a wrong answer would let every concurrent
   * request through the check. Returns the attempt number, or `undefined` once the budget is spent,
   * in which case the challenge is dead and the answer must not be checked at all.
   */
  public async reserveAttempt(
    token: string,
    record: ChallengeRecord,
  ): Promise<{ readonly attempt: number; readonly last: boolean } | undefined> {
    const attempt = await this.cache.increment(this.#attemptsKey(token), 1, {
      ttl: Math.max(1, record.expiresAt - this.#now()),
    });
    // Over the limit: refused, unchecked. The challenge record is left for its TTL rather than
    // deleted, because an attempt reserved within the limit may be a correct answer still being
    // redeemed; `exhausted` and every later reservation already treat a spent budget as dead.
    if (attempt > this.options.maxAttempts) return undefined;
    return { attempt, last: attempt >= this.options.maxAttempts };
  }

  /** Whether the attempt budget is already spent (a fast refusal before any other work). */
  public async exhausted(token: string): Promise<boolean> {
    const attempts = (await this.cache.get<number>(this.#attemptsKey(token))) ?? 0;
    return attempts >= this.options.maxAttempts;
  }

  /** Spend the challenge. Exactly one caller across the fleet gets `true`. */
  public async consume(token: string): Promise<boolean> {
    // The attempt counter is left to its TTL: deleting it would hand requests already past `peek`
    // a fresh budget.
    return this.cache.delete(this.#key(token));
  }

  #key(token: string): string {
    return cacheKey('mfa', 'challenge', sha256Hex(token));
  }

  #attemptsKey(token: string): string {
    return cacheKey('mfa', 'challenge-attempts', sha256Hex(token));
  }
}

/**
 * Wrong second-factor answers per account, across challenges and reauthentications.
 *
 * A challenge's own limit bounds one challenge; this bounds the account, so somebody holding the
 * password cannot mint challenge after challenge and keep guessing. Keyed by tenant and account.
 */
export class MfaFailureCounter {
  public constructor(
    private readonly cache: CachePort,
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  public async locked(tenantId: TenantId, userId: UserId): Promise<boolean> {
    return ((await this.cache.get<number>(this.#key(tenantId, userId))) ?? 0) >= this.max;
  }

  /**
   * Reserve one second-factor check for the account **before** it runs (`INCR` first, as for a
   * challenge). `undefined` means the account is locked and the answer must not be checked. A
   * correct answer clears the counter; a wrong one leaves its reservation counted as the failure.
   */
  public async reserve(
    tenantId: TenantId,
    userId: UserId,
  ): Promise<{ readonly count: number; readonly last: boolean } | undefined> {
    const count = await this.cache.increment(this.#key(tenantId, userId), 1, {
      ttl: this.windowMs,
    });
    if (count > this.max) return undefined;
    return { count, last: count >= this.max };
  }

  public async clear(tenantId: TenantId, userId: UserId): Promise<void> {
    await this.cache.delete(this.#key(tenantId, userId));
  }

  #key(tenantId: TenantId, userId: UserId): string {
    return cacheKey('mfa', 'failures', tenantId, userId);
  }
}
