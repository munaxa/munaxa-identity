import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer, connect, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type * as CacheModule from '../../../apps/api/src/platform/cache.js';

/**
 * The connection to Identity's security-state store, against real servers.
 *
 * Production runs every Identity task on one ElastiCache for Valkey over TLS with an AUTH token;
 * this suite proves the client side of that without AWS:
 *
 * - **Failover.** A replication pair behind a TCP proxy that stands in for the primary endpoint's
 *   DNS name. The pair is switched (the replica promoted, the old primary demoted), the proxy is
 *   pointed at the new primary, and the connection that was open before the switch is still open to
 *   the old primary, which now answers writes with `READONLY`. Identity's client reconnects and the
 *   write lands; a client without the option keeps failing, which shows the test exercises it.
 * - **TLS.** A TLS-only server with `requirepass` and its own CA: `rediss://` with the CA works; the
 *   wrong CA, the wrong host name, plaintext, or the wrong password do not, and each of those leaves
 *   the handle unreachable rather than quietly falling back.
 * - **Fail closed.** The store going away makes `reachable()` false and writes reject; it coming back
 *   makes both work again without a restart.
 *
 * It starts its own `redis-server` processes on free ports. Without the binary it is skipped, unless
 * `CACHE_CONNECTION_TEST_REQUIRE_SERVER=1` (CI) makes that a failure.
 */

const DIST = new URL('../../../apps/api/dist/', import.meta.url);
if (!existsSync(new URL('platform/cache.js', DIST))) {
  throw new Error('apps/api/dist is missing: run `pnpm build` before the integration tests.');
}
const compiled = createRequire(import.meta.url);
const { openCache, redisClientOptions, isReadOnlyReplicaError, Redis } = compiled(
  new URL('platform/cache.js', DIST).pathname,
) as typeof CacheModule;
type Redis = InstanceType<typeof CacheModule.Redis>;

const REDIS_SERVER = process.env.REDIS_SERVER_BIN ?? 'redis-server';
const haveServer = (() => {
  try {
    execFileSync(REDIS_SERVER, ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();
if (!haveServer && process.env.CACHE_CONNECTION_TEST_REQUIRE_SERVER === '1') {
  throw new Error(`${REDIS_SERVER} is required for the cache connection tests (CI installs it).`);
}

const work = mkdtempSync(path.join(tmpdir(), 'identity-cache-'));
const servers: ChildProcess[] = [];
/** A minute: the counters below need an expiry like every Identity key. */
const TTL = { ttl: 60_000 } as unknown as Parameters<
  CacheModule.CacheHandle['cache']['increment']
>[2];
/** Generated per run; never a real token. */
const PASSWORD = randomBytes(24).toString('base64url');

const freePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => resolve(typeof address === 'object' && address ? address.port : 0));
    });
  });

const waitFor = async (check: () => Promise<boolean>, what: string, ms = 10_000): Promise<void> => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await check().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${what}`);
};

const startServer = async (args: string[]): Promise<ChildProcess> => {
  const child = spawn(
    REDIS_SERVER,
    ['--save', '', '--appendonly', 'no', '--bind', '127.0.0.1', ...args],
    { stdio: 'ignore' },
  );
  servers.push(child);
  return child;
};

/** A plain client used to arrange the servers (never the client under test). */
const admin = (port: number): Redis =>
  new Redis({
    host: '127.0.0.1',
    port,
    password: PASSWORD,
    lazyConnect: true,
    maxRetriesPerRequest: 1,
  });

/** Whether the replica at `port` has a live link to its primary. */
const linkUp = async (port: number): Promise<boolean> => {
  const c = admin(port);
  try {
    await c.connect();
    return (await c.info('replication')).includes('master_link_status:up');
  } finally {
    c.disconnect();
  }
};

const ping = async (port: number): Promise<boolean> => {
  const c = admin(port);
  try {
    await c.connect();
    return (await c.ping()) === 'PONG';
  } finally {
    c.disconnect();
  }
};

/**
 * The primary endpoint: a TCP proxy whose target can be switched. Connections keep the target
 * they were opened with, exactly as a DNS change leaves open connections where they are.
 */
interface Endpoint {
  readonly port: number;
  target: number;
  close(): Promise<void>;
}
const startEndpoint = async (target: number): Promise<Endpoint> => {
  const sockets = new Set<Socket>();
  const endpoint = { port: 0, target, close: async () => undefined } as Endpoint;
  const server: Server = createServer((client) => {
    const upstream = connect(endpoint.target, '127.0.0.1');
    sockets.add(client);
    sockets.add(upstream);
    client.pipe(upstream).pipe(client);
    const end = (): void => {
      client.destroy();
      upstream.destroy();
    };
    client.on('error', end).on('close', end);
    upstream.on('error', end).on('close', end);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  (endpoint as { port: number }).port = typeof address === 'object' && address ? address.port : 0;
  endpoint.close = () =>
    new Promise((resolve) => {
      for (const s of sockets) s.destroy();
      server.close(() => resolve());
    });
  return endpoint;
};

afterAll(() => {
  for (const s of servers) s.kill('SIGKILL');
  rmSync(work, { recursive: true, force: true });
});

describe.skipIf(!haveServer)('the cache connection after a failover', () => {
  let a: number;
  let b: number;
  let endpoint: Endpoint;

  beforeAll(async () => {
    a = await freePort();
    b = await freePort();
    // Both nodes need the password for their own clients and for replication.
    const auth = ['--requirepass', PASSWORD, '--masterauth', PASSWORD];
    await startServer(['--port', String(a), ...auth]);
    await startServer(['--port', String(b), ...auth]);
    await waitFor(() => ping(a), 'node a');
    await waitFor(() => ping(b), 'node b');
    const nodeB = admin(b);
    await nodeB.connect();
    await nodeB.replicaof('127.0.0.1', a);
    nodeB.disconnect();
    await waitFor(() => linkUp(b), 'b to replicate a');
    endpoint = await startEndpoint(a);
  });

  afterAll(async () => {
    await endpoint?.close();
  });

  /** Promote b, demote a, point the endpoint at b: what ElastiCache's failover does. */
  const failover = async (from: number, to: number): Promise<void> => {
    const promoted = admin(to);
    const demoted = admin(from);
    await promoted.connect();
    await demoted.connect();
    await promoted.replicaof('NO', 'ONE');
    await demoted.replicaof('127.0.0.1', to);
    promoted.disconnect();
    demoted.disconnect();
    endpoint.target = to;
    await waitFor(() => linkUp(from), 'the demoted node to follow the new primary');
  };

  it('recognises only READONLY as a replica refusal', () => {
    expect(
      isReadOnlyReplicaError(new Error("READONLY You can't write against a read only replica.")),
    ).toBe(true);
    expect(isReadOnlyReplicaError(new Error('NOAUTH Authentication required.'))).toBe(false);
    expect(
      isReadOnlyReplicaError(new Error('OOM command not allowed when used memory > maxmemory')),
    ).toBe(false);
    expect(isReadOnlyReplicaError(new Error('Command timed out'))).toBe(false);
  });

  it('reconnects on READONLY and applies the write once on the new primary', async () => {
    const url = `redis://:${PASSWORD}@127.0.0.1:${String(endpoint.port)}`;
    const handle = await openCache(url);
    // A control client without reconnectOnError, opened the same way before the failover.
    const control = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
    await control.connect();
    try {
      const key = `failover-${randomBytes(4).toString('hex')}`;
      expect(await handle.cache.increment(key, 1, TTL)).toBe(1);
      // Let the replica acknowledge it (a planned ElastiCache failover also waits for the replica).
      const primary = admin(a);
      await primary.connect();
      expect(await primary.wait(1, 5_000)).toBe(1);
      primary.disconnect();

      await failover(a, b);

      // The connection opened before the switch is still on the old primary, now a replica.
      await expect(control.incr(`identity:${key}`)).rejects.toThrow(/READONLY/);

      // Identity's client: the write that hit READONLY is resent after the reconnect, once.
      expect(await handle.cache.increment(key, 1, TTL)).toBe(2);
      expect(await handle.reachable()).toBe(true);

      // And the state is on the new primary, where every other task now reads it.
      const direct = admin(b);
      await direct.connect();
      expect(await direct.get(`identity:${key}`)).toBe('2');
      expect(await direct.pttl(`identity:${key}`)).toBeGreaterThan(0);
      direct.disconnect();
    } finally {
      control.disconnect();
      await handle.close();
      await failover(b, a);
    }
  });

  it('fails closed while the store is gone and recovers without a restart', async () => {
    const port = await freePort();
    const child = await startServer(['--port', String(port), '--requirepass', PASSWORD]);
    await waitFor(() => ping(port), 'the store');
    const handle = await openCache(`redis://:${PASSWORD}@127.0.0.1:${String(port)}`);
    try {
      expect(await handle.reachable()).toBe(true);
      child.kill('SIGKILL');
      await waitFor(async () => !(await handle.reachable()), 'the handle to notice');
      await expect(handle.cache.increment('gone', 1, TTL)).rejects.toThrow();

      await startServer(['--port', String(port), '--requirepass', PASSWORD]);
      await waitFor(() => handle.reachable(), 'the handle to reconnect', 20_000);
      expect(await handle.cache.increment('back', 1, TTL)).toBe(1);
    } finally {
      await handle.close().catch(() => undefined);
    }
  });

  it('refuses a wrong password rather than running unauthenticated', async () => {
    const wrong = `redis://:${randomBytes(24).toString('base64url')}@127.0.0.1:${String(a)}`;
    // ioredis reports the refused AUTH as a closed connection; either way no handle exists.
    await expect(openCache(wrong)).rejects.toThrow();
  });
});

describe.skipIf(!haveServer)('the cache connection over TLS', () => {
  let port: number;
  let ca: Buffer;
  let otherCa: Buffer;

  const openssl = (...args: string[]): void => {
    execFileSync('openssl', args, { cwd: work, stdio: 'ignore' });
  };

  beforeAll(async () => {
    // A throwaway CA and a server certificate for `localhost`, generated for this run only.
    writeFileSync(
      path.join(work, 'server.ext'),
      'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n',
    );
    openssl(
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      'ca.key',
      '-out',
      'ca.pem',
      '-days',
      '1',
      '-subj',
      '/CN=identity-test-ca',
    );
    openssl(
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      'server.key',
      '-out',
      'server.csr',
      '-subj',
      '/CN=localhost',
    );
    openssl(
      'x509',
      '-req',
      '-in',
      'server.csr',
      '-CA',
      'ca.pem',
      '-CAkey',
      'ca.key',
      '-CAcreateserial',
      '-out',
      'server.pem',
      '-days',
      '1',
      '-extfile',
      'server.ext',
    );
    openssl(
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      'other.key',
      '-out',
      'other.pem',
      '-days',
      '1',
      '-subj',
      '/CN=another-ca',
    );
    ca = readFileSync(path.join(work, 'ca.pem'));
    otherCa = readFileSync(path.join(work, 'other.pem'));

    port = await freePort();
    // TLS only (no plaintext port), AUTH required: what transit_encryption_mode = required gives.
    await startServer([
      '--port',
      '0',
      '--tls-port',
      String(port),
      '--tls-cert-file',
      path.join(work, 'server.pem'),
      '--tls-key-file',
      path.join(work, 'server.key'),
      '--tls-ca-cert-file',
      path.join(work, 'ca.pem'),
      '--tls-auth-clients',
      'no',
      '--requirepass',
      PASSWORD,
    ]);
    await waitFor(async () => {
      const c = new Redis({
        host: 'localhost',
        port,
        password: PASSWORD,
        tls: { ca, servername: 'localhost' },
        lazyConnect: true,
        maxRetriesPerRequest: 1,
      });
      try {
        await c.connect();
        return (await c.ping()) === 'PONG';
      } finally {
        c.disconnect();
      }
    }, 'the TLS store');
  });

  it('builds TLS options with verification on for rediss:// and none for redis://', () => {
    const tls = redisClientOptions('rediss://:x@cache.example.internal:6379').tls;
    expect(tls).toMatchObject({
      servername: 'cache.example.internal',
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
    });
    expect(redisClientOptions('redis://:x@127.0.0.1:6379').tls).toBeUndefined();
  });

  it('connects with rediss://, the password and the trusted CA', async () => {
    const handle = await openCache(`rediss://:${PASSWORD}@localhost:${String(port)}`, { ca });
    try {
      expect(handle.kind).toBe('redis');
      expect(await handle.reachable()).toBe(true);
      expect(await handle.cache.increment('tls', 1, TTL)).toBe(1);
      expect(await handle.cache.increment('tls', 1, TTL)).toBe(2);
    } finally {
      await handle.close();
    }
  });

  it('refuses a certificate from another CA', async () => {
    const attempt = openCache(`rediss://:${PASSWORD}@localhost:${String(port)}`, { ca: otherCa });
    await expect(attempt).rejects.toThrow();
  });

  it('refuses a certificate for another host name', async () => {
    // 127.0.0.1 is not in the certificate (DNS:localhost only).
    const attempt = openCache(`rediss://:${PASSWORD}@127.0.0.1:${String(port)}`, { ca });
    await expect(attempt).rejects.toThrow();
  });

  it('cannot talk plaintext to a TLS-only store', async () => {
    const handle = openCache(`redis://:${PASSWORD}@localhost:${String(port)}`).then(
      async (h) => {
        const ok = await Promise.race([
          h.reachable(),
          new Promise<boolean>((r) => setTimeout(() => r(false), 3_000)),
        ]);
        await h.close().catch(() => undefined);
        return ok;
      },
      () => false,
    );
    expect(await handle).toBe(false);
  });

  it('refuses the wrong password over TLS', async () => {
    const wrong = randomBytes(24).toString('base64url');
    await expect(
      openCache(`rediss://:${wrong}@localhost:${String(port)}`, { ca }),
    ).rejects.toThrow();
  });
});
