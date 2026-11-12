/**
 * Where Identity's security state lives, and how it is reached in production.
 *
 * Every lockout counter, rate-limit counter, MFA challenge and attempt counter, TOTP replay marker
 * and reauthentication marker travels over this one connection. Two deployments are approved:
 *
 * - **Testing:** a Valkey sidecar in the same task, `redis://:<password>@127.0.0.1:6379`. Loopback
 *   never leaves the task, so TLS adds nothing there.
 * - **Production:** one shared ElastiCache for Valkey for every Identity task, with TLS required and
 *   an AUTH token: `rediss://:<token>@<primary endpoint>:6379`.
 *
 * So in production a host that is not loopback must be reached over TLS (`rediss://`), and every
 * production URL must carry a password. A plaintext URL to a network host would send the AUTH token
 * and every security key in clear, and ElastiCache with TLS required would refuse it anyway — at
 * the first sign-in instead of at startup. Outside production nothing changes: a developer's
 * `redis://localhost:6379` still works.
 *
 * The problems below never quote the URL: it carries the password.
 */

/** 127.0.0.0/8, ::1 and `localhost`: the addresses that stay inside the task. */
export const isLoopbackHost = (hostname: string): boolean => {
  const host = hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1');
  if (host === 'localhost' || host === '::1') return true;
  const octets = host.split('.');
  return (
    octets.length === 4 &&
    octets[0] === '127' &&
    octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)
  );
};

export const redisUrlIssues = (
  value: string,
  production: boolean,
): { key: string; problem: string }[] => {
  if (!production || value.trim() === '') return [];

  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    return [
      {
        key: 'REDIS_URL',
        problem: 'is not a valid URL (the value is not shown: it holds a password).',
      },
    ];
  }

  const issues: { key: string; problem: string }[] = [];
  if (parsed.protocol !== 'redis:' && parsed.protocol !== 'rediss:') {
    issues.push({
      key: 'REDIS_URL',
      problem: 'must use redis:// (loopback sidecar) or rediss:// (TLS).',
    });
    return issues;
  }
  if (!isLoopbackHost(parsed.hostname) && parsed.protocol !== 'rediss:') {
    issues.push({
      key: 'REDIS_URL',
      problem:
        'must use rediss:// (TLS) in production for a host that is not loopback. Only the in-task sidecar on 127.0.0.1 may use redis://.',
    });
  }
  if (parsed.password === '') {
    issues.push({
      key: 'REDIS_URL',
      problem:
        'must carry a password (the sidecar password or the cache AUTH token) in production.',
    });
  }
  // ioredis copies query parameters into its connection options, so a query string could switch
  // TLS verification off without anything in the scheme showing it.
  if (parsed.search !== '') {
    issues.push({
      key: 'REDIS_URL',
      problem: 'must not carry connection options in a query string in production.',
    });
  }
  return issues;
};
