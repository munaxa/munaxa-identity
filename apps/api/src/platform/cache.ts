import { MemoryCache, RedisCache, type RedisLike } from '@munaxa/cache';
import type { CachePort } from '@munaxa/interfaces';
import Redis from 'ioredis';

/**
 * The cache, and what it costs to go without one.
 *
 * Three things run on this port and each degrades differently when it is per-process: login
 * lockout counters stop being a limit (each replica counts separately), the permission cache stops
 * being coherent (a revoked role stays live on replicas that did not evict it), and the rate
 * limiter becomes advisory. That is why the configuration refuses an empty `REDIS_URL` in
 * production rather than falling back quietly. A single-process development run is a different
 * case, and `MemoryCache` is correct there.
 *
 * **`ioredis` rather than `node-redis`, and the reason is not preference.** `RedisLike` is declared
 * with ioredis's shape — variadic `set(key, value, 'PX', ms)`, `incrby`, `pexpire`, `pttl`.
 * node-redis v4 takes an options object and spells those methods `incrBy`, `pExpire`, `pTTL`, so it
 * satisfies the interface structurally in only the parts that happen to match: `set` accepts the
 * extra arguments and *ignores* them. The observable result is a cache that never expires and
 * counters that never increment — the permission TTL and the login lockout both silently off, with
 * nothing failing. This was found by measuring a revocation that never took effect, not by reading
 * the code, which is the whole argument for the measurement.
 */
export interface CacheHandle {
  readonly cache: CachePort;
  readonly kind: 'redis' | 'memory';
  /**
   * Whether the cache is actually reachable *now*, for readiness to ask.
   *
   * Not the same question as `kind`. A handle opened against Redis keeps saying `redis` after the
   * server goes away, and the three things above degrade the moment it does: with the cache down,
   * sign-in fails — closed, which is right — but a readiness probe that only touches the database
   * keeps answering 200, so the load balancer goes on sending every sign-in to a replica that
   * refuses all of them. The probe has to ask the cache the same question it asks the database.
   */
  reachable(): Promise<boolean>;
  close(): Promise<void>;
}

/** How long one cache command may take before it counts as a failure. */
export const REDIS_COMMAND_TIMEOUT_MS = 2_000;

export const openCache = async (redisUrl: string): Promise<CacheHandle> => {
  if (redisUrl.trim() === '') {
    // An in-process cache is reachable exactly as long as the process is.
    return {
      cache: new MemoryCache(),
      kind: 'memory',
      reachable: () => Promise.resolve(true),
      close: () => Promise.resolve(),
    };
  }
  // `commandTimeout` turns a hung store (connection open, no answer) into an error within two
  // seconds, which every consumer already treats as unavailable: sign-in, reset and MFA refuse,
  // the credential-route edge limits refuse with 503. Without it a hang holds each request open.
  const client = new Redis(redisUrl, {
    lazyConnect: true,
    maxRetriesPerRequest: 3,
    commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
  });
  await client.connect();

  return {
    cache: new RedisCache(client as unknown as RedisLike, { keyPrefix: 'identity:' }),
    kind: 'redis',
    reachable: async () => {
      try {
        return (await client.ping()) === 'PONG';
      } catch {
        return false;
      }
    },
    close: async () => {
      await client.quit();
    },
  };
};
