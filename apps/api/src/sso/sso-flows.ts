import { secureToken, sha256Hex } from '@munaxa/crypto';
import type { CachePort } from '@munaxa/interfaces';
import { cacheKey, type TenantId } from '@munaxa/types';

import { constantTimeEquals } from './id-token.js';
import type { SsoProviderKind } from './providers.js';

/**
 * A company sign-in in progress: what exists between "send the browser to Microsoft or Google" and
 * "the browser came back with a code".
 *
 * The same discipline as the MFA challenge (`mfa-challenges.ts`), for the same reasons:
 *
 * - **Server-side, under a digest.** The record lives in the shared cache keyed by `sha256(state)`,
 *   so any replica can finish the flow and a keyspace dump yields no presentable `state`.
 * - **Single use.** Completion is a `DEL` that reports whether it removed the key, which the cache
 *   decides once across the fleet. A replayed callback finds nothing.
 * - **Bound to the browser that started it.** `state` alone stops a forged callback, but not *login
 *   CSRF*: an attacker starts a flow, signs in as themselves at the provider, and hands the callback
 *   URL to a victim, who is then signed in to Munaxa as the attacker. So starting also sets a random
 *   `__Host-mx_sso` cookie whose digest the record holds; the callback must present it. Also bound
 *   to a digest of the user agent, as the MFA challenge is.
 * - **Short.** `IDENTITY_SSO_FLOW_TTL`, ten minutes by default.
 *
 * The PKCE verifier and the nonce are held in the clear because they must be sent and compared;
 * neither is useful without the provider's one-time code, which never touches the cache.
 */
export interface FlowRecord {
  readonly v: 1;
  readonly connectionId: string;
  readonly tenantId: TenantId;
  readonly provider: SsoProviderKind;
  readonly nonce: string;
  readonly codeVerifier: string;
  readonly bindingDigest: string;
  readonly userAgentDigest: string;
  /** The callback URL sent with the authorization request; the token request must repeat it. */
  readonly redirectUri: string;
  readonly returnTo: string;
  readonly language: 'en' | 'ar';
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface StartedFlow {
  readonly state: string;
  readonly nonce: string;
  readonly codeVerifier: string;
  /** The value for the `__Host-mx_sso` cookie. Returned once, never stored. */
  readonly binding: string;
}

const userAgentDigest = (userAgent: string | undefined): string =>
  sha256Hex(`sso-ua:${userAgent ?? ''}`).slice(0, 32);

/** Anything that is not a value this store minted is refused before it reaches the cache. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;

export class SsoFlows {
  public constructor(
    private readonly cache: CachePort,
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  public get ttlSeconds(): number {
    return Math.ceil(this.ttlMs / 1_000);
  }

  public async start(input: {
    readonly connectionId: string;
    readonly tenantId: TenantId;
    readonly provider: SsoProviderKind;
    readonly redirectUri: string;
    readonly returnTo: string;
    readonly language: 'en' | 'ar';
    readonly userAgent: string | undefined;
  }): Promise<StartedFlow> {
    const state = secureToken(32);
    const nonce = secureToken(32);
    const codeVerifier = secureToken(48);
    const binding = secureToken(32);
    const now = this.now();
    const record: FlowRecord = {
      v: 1,
      connectionId: input.connectionId,
      tenantId: input.tenantId,
      provider: input.provider,
      nonce,
      codeVerifier,
      bindingDigest: sha256Hex(binding),
      userAgentDigest: userAgentDigest(input.userAgent),
      redirectUri: input.redirectUri,
      returnTo: input.returnTo,
      language: input.language,
      createdAt: now,
      expiresAt: now + this.ttlMs,
    };
    await this.cache.set(this.#key(state), record, { ttl: this.ttlMs });
    return { state, nonce, codeVerifier, binding };
  }

  /**
   * Spend the flow `state` names, if the presenting browser is the one that started it.
   *
   * Consumed **before** the binding is compared, deliberately: a callback that arrives with the
   * wrong cookie is an attack on this flow, and the flow ends rather than waiting for a better guess.
   */
  public async complete(
    state: string | undefined,
    binding: string | undefined,
    userAgent: string | undefined,
  ): Promise<
    | { readonly ok: true; readonly record: FlowRecord }
    | { readonly ok: false; readonly reason: string }
  > {
    if (state === undefined || !TOKEN_SHAPE.test(state))
      return { ok: false, reason: 'STATE_MALFORMED' };
    const key = this.#key(state);
    const record = await this.cache.get<FlowRecord>(key);
    if (record?.v !== 1) return { ok: false, reason: 'STATE_UNKNOWN' };
    if (!(await this.cache.delete(key))) return { ok: false, reason: 'STATE_SPENT' };
    if (this.now() >= record.expiresAt) return { ok: false, reason: 'STATE_EXPIRED' };
    if (binding === undefined || !TOKEN_SHAPE.test(binding)) {
      return { ok: false, reason: 'BINDING_MISSING' };
    }
    if (!constantTimeEquals(sha256Hex(binding), record.bindingDigest)) {
      return { ok: false, reason: 'BINDING_MISMATCH' };
    }
    if (record.userAgentDigest !== userAgentDigest(userAgent)) {
      return { ok: false, reason: 'USER_AGENT_MISMATCH' };
    }
    return { ok: true, record };
  }

  #key(state: string): string {
    return cacheKey('sso', 'flow', sha256Hex(state));
  }
}
