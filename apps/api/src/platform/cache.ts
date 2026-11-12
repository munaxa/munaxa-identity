import { MemoryCache, RedisCache, type RedisLike } from '@munaxa/cache';
import type { CachePort } from '@munaxa/interfaces';
import type { ConnectionOptions } from 'node:tls';

import Redis, { type RedisOptions } from 'ioredis';

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

/** The client class, for the integration tests' arranging clients (packages/testing has no ioredis). */
export { Redis };

/** How long one cache command may take before it counts as a failure. */
export const REDIS_COMMAND_TIMEOUT_MS = 2_000;

/**
 * Whether an error is a write refused by a replica.
 *
 * ElastiCache's primary endpoint is a DNS name. After a failover it points at the promoted node,
 * but a connection opened before the failover is still open to the old primary, which is now a
 * replica and answers every write with `READONLY You can't write against a read only replica`.
 * Without a reconnect those writes keep failing until the connection happens to drop: every
 * lockout increment, challenge and replay marker refused (closed, so safe, but sign-in is down).
 */
export const isReadOnlyReplicaError = (error: Error): boolean =>
  typeof error?.message === 'string' && error.message.startsWith('READONLY');

/**
 * Options for the ioredis client, exported for the tests that prove them.
 *
 * - `reconnectOnError` returns 1 on `READONLY`: the refused command fails to its caller (closed, as
 *   any store error), and the connection is dropped and reopened, so the next command reaches
 *   whatever the DNS name now resolves to, the new primary. It never resends (2 would): a resent
 *   command outlives the caller's timeout, and while the endpoint still names a replica ioredis
 *   resends without limit and applies the write late, after the caller was told it failed. The
 *   platform never retries a cache write, and neither does this. Any other error is unchanged.
 * - `rediss://` turns TLS on with certificate and host-name verification (Node's defaults, stated
 *   here so nothing can switch them off), TLS 1.2 or later. `tls.ca` exists for the integration
 *   tests' own CA; production passes nothing and Node's trust store verifies ElastiCache.
 */
export const redisClientOptions = (
  redisUrl: string,
  testing: { readonly ca?: ConnectionOptions['ca'] } = {},
): RedisOptions => {
  const parsed = new URL(redisUrl);
  const options: RedisOptions = {
    lazyConnect: true,
    maxRetriesPerRequest: 3,
    commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
    reconnectOnError: (error) => (isReadOnlyReplicaError(error) ? 1 : false),
  };
  if (parsed.protocol === 'rediss:') {
    options.tls = {
      servername: parsed.hostname.replace(/^\[(.*)\]$/, '$1'),
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      ...(testing.ca === undefined ? {} : { ca: testing.ca }),
    };
  }
  return options;
};

export const openCache = async (
  redisUrl: string,
  testing: { readonly ca?: ConnectionOptions['ca'] } = {},
): Promise<CacheHandle> => {
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
  // Production's URL rules (rediss:// for a network host, a password) are in @identity/config.
  const url = redisUrl.trim();
  const client = new Redis(url, redisClientOptions(url, testing));
  await client.connect();

  return {
    cache: new RedisCache(client as unknown as RedisLike, { keyPrefix: 'identity:' }),
    kind: 'redis',
    // A replica answers PING too, and refuses every write: reachable means connected to a primary.
    // ROLE is in Valkey's @admin/@dangerous categories: an ElastiCache RBAC access string without
    // them would keep readiness false (closed), see docs/production-readiness.md.
    reachable: async () => {
      try {
        const role = (await client.call('ROLE')) as unknown;
        return Array.isArray(role) && role[0] === 'master';
      } catch {
        return false;
      }
    },
    close: async () => {
      await client.quit();
    },
  };
};
