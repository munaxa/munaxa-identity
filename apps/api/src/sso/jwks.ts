import type { Jwk } from './id-token.js';

/**
 * Providers' published signing keys, fetched over TLS and held in memory.
 *
 * Keys are cached for an hour, the order of magnitude both providers rotate on with plenty of
 * overlap. A token naming a `kid` the cache does not hold triggers **one** refetch, and at most one
 * per minute per key set: rotation is picked up at once, and a stream of tokens with invented key
 * ids cannot turn this service into a request amplifier pointed at Microsoft or Google.
 *
 * A fetch failure is a refusal of that sign-in, never a fallback to an unverified token. Cached keys
 * that are past their hour are still used while a refetch fails, because the alternative (no company
 * sign-in at all during a provider blip) is worse and the keys were genuine when fetched.
 */

export type FetchLike = (
  url: string,
  init: {
    readonly method?: string;
    readonly headers?: Record<string, string>;
    readonly body?: string;
    readonly signal?: AbortSignal;
  },
) => Promise<{ readonly ok: boolean; readonly status: number; text(): Promise<string> }>;

const KEYS_TTL_MS = 60 * 60 * 1_000;
const REFETCH_FLOOR_MS = 60 * 1_000;
const FETCH_TIMEOUT_MS = 10_000;
/** A JWKS is a few kilobytes; anything far larger is not one. */
const MAX_JWKS_BYTES = 256 * 1_024;

interface Entry {
  readonly keys: readonly Jwk[];
  readonly fetchedAt: number;
}

export class JwksCache {
  readonly #entries = new Map<string, Entry>();
  readonly #lastAttempt = new Map<string, number>();
  readonly #inflight = new Map<string, Promise<readonly Jwk[] | undefined>>();

  public constructor(
    private readonly fetcher: FetchLike = fetch as unknown as FetchLike,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * The keys to verify a token with. `kid` is the token header's, when it has one; an unknown one
   * may trigger the single bounded refetch described above.
   */
  public async keysFor(uri: string, kid: string | undefined): Promise<readonly Jwk[] | undefined> {
    const entry = this.#entries.get(uri);
    const fresh = entry !== undefined && this.now() - entry.fetchedAt < KEYS_TTL_MS;
    const known = kid === undefined || entry?.keys.some((key) => key.kid === kid) === true;
    if (fresh && known) return entry.keys;

    const last = this.#lastAttempt.get(uri);
    if (entry !== undefined && last !== undefined && this.now() - last < REFETCH_FLOOR_MS) {
      return entry.keys;
    }
    const fetched = await this.#refresh(uri);
    return fetched ?? entry?.keys;
  }

  #refresh(uri: string): Promise<readonly Jwk[] | undefined> {
    const running = this.#inflight.get(uri);
    if (running !== undefined) return running;
    this.#lastAttempt.set(uri, this.now());
    const attempt = this.#fetch(uri).finally(() => this.#inflight.delete(uri));
    this.#inflight.set(uri, attempt);
    return attempt;
  }

  async #fetch(uri: string): Promise<readonly Jwk[] | undefined> {
    try {
      const response = await this.fetcher(uri, {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!response.ok) return undefined;
      const body = await response.text();
      if (body.length > MAX_JWKS_BYTES) return undefined;
      const parsed = JSON.parse(body) as { keys?: unknown };
      if (!Array.isArray(parsed.keys)) return undefined;
      const keys = parsed.keys.filter(
        (key): key is Jwk =>
          typeof key === 'object' &&
          key !== null &&
          typeof (key as { kty?: unknown }).kty === 'string' &&
          // An encryption key is not a signing key, whatever else it matches.
          (key as { use?: unknown }).use !== 'enc',
      );
      this.#entries.set(uri, { keys, fetchedAt: this.now() });
      return keys;
    } catch {
      return undefined;
    }
  }
}
