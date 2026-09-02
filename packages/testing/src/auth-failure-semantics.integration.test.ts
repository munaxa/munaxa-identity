import { describe, expect, it } from 'vitest';
import { PlatformError } from '@munaxa/types';

import { AuthService } from '../../../apps/api/src/auth/auth.service.js';

/**
 * What a sign-in refusal *means*, as opposed to whether it refuses.
 *
 * Both answers below are refusals — nothing here can authenticate anybody, and that is checked
 * rather than assumed. The distinction under test is the one Phase 10 measured and got wrong: with
 * Redis stopped, every sign-in answered 401, which reads as "a room full of people mistyping their
 * passwords" when the truth is "the security infrastructure is down". A 401 sends an operator
 * hunting for a credential problem that does not exist.
 *
 * The rule the implementation follows is that Platform's authentication error codes are a closed
 * vocabulary; anything outside it is the machinery underneath having failed, and is settled by
 * asking the dependencies whether they are alive rather than by matching error strings.
 */

interface Harness {
  readonly service: AuthService;
  readonly probes: { cache: number; database: number };
}

const build = (options: {
  throws: unknown;
  cacheReachable?: boolean;
  databaseReachable?: boolean;
}): Harness => {
  const probes = { cache: 0, database: 0 };
  const security = {
    tenants: { idForKey: () => Promise.resolve('tenant-1') },
    login: {
      authenticate: () => Promise.reject(options.throws),
    },
    cacheReachable: () => {
      probes.cache += 1;
      return Promise.resolve(options.cacheReachable ?? true);
    },
  } as unknown as ConstructorParameters<typeof AuthService>[0];

  const environment = {
    IDENTITY_DEFAULT_ORGANISATION: 'acme',
    SESSION_COOKIE_MAX_AGE: 900,
  } as unknown as ConstructorParameters<typeof AuthService>[1];

  const prisma = {
    $queryRaw: () => {
      probes.database += 1;
      return (options.databaseReachable ?? true)
        ? Promise.resolve([{ '?column?': 1 }])
        : Promise.reject(new Error('ECONNREFUSED'));
    },
  } as unknown as ConstructorParameters<typeof AuthService>[2];

  return { service: new AuthService(security, environment, prisma), probes };
};

const attempt = (harness: Harness) =>
  harness.service.login({
    identifier: 'someone@acme.example',
    password: 'whatever-it-does-not-matter',
    correlationId: 'corr-1' as never,
  });

describe('sign-in failure semantics', () => {
  it('answers invalid-credentials for a wrong password', async () => {
    const harness = build({
      throws: new PlatformError('refused', { code: 'AUTH_INVALID_CREDENTIALS' }),
    });
    const result = await attempt(harness);
    expect(result).toEqual({ ok: false, failure: { kind: 'invalid-credentials' } });
    // A recognised authentication outcome is not an infrastructure question, so nothing is probed.
    expect(harness.probes).toEqual({ cache: 0, database: 0 });
  });

  it('answers invalid-credentials for a disabled account, disclosing nothing extra', async () => {
    const harness = build({
      throws: new PlatformError('refused', { code: 'AUTH_ACCOUNT_DISABLED' }),
    });
    const result = await attempt(harness);
    expect(result).toEqual({ ok: false, failure: { kind: 'invalid-credentials' } });
  });

  it('still reports lockout separately', async () => {
    const harness = build({
      throws: new PlatformError('refused', { code: 'AUTH_ACCOUNT_LOCKED' }),
    });
    const result = await attempt(harness);
    expect(result).toEqual({
      ok: false,
      failure: { kind: 'rate-limited', retryAfterSeconds: 900 },
    });
  });

  it('answers dependency-unavailable when the cache is down', async () => {
    const harness = build({
      throws: Object.assign(new Error('Connection is closed.'), { code: 'ECONNREFUSED' }),
      cacheReachable: false,
    });
    const result = await attempt(harness);
    expect(result).toEqual({
      ok: false,
      failure: { kind: 'dependency-unavailable', dependency: 'cache' },
    });
    // Still a refusal: no token, no session.
    expect('access' in result).toBe(false);
  });

  it('answers dependency-unavailable when the database is down', async () => {
    const harness = build({
      throws: new Error('the connection pool is closed'),
      databaseReachable: false,
    });
    const result = await attempt(harness);
    expect(result).toEqual({
      ok: false,
      failure: { kind: 'dependency-unavailable', dependency: 'database' },
    });
  });

  it('fails closed when the error is unrecognised but every dependency is healthy', async () => {
    // The important negative. An unexplained failure inside the security stack is a refusal, not a
    // pass, and it must not be reported as a 503 either — nothing is down.
    const harness = build({ throws: new Error('something nobody has seen before') });
    const result = await attempt(harness);
    expect(result).toEqual({ ok: false, failure: { kind: 'invalid-credentials' } });
    expect(harness.probes).toEqual({ cache: 1, database: 1 });
  });

  it('never returns a token on any failure path', async () => {
    for (const throws of [
      new PlatformError('refused', { code: 'AUTH_INVALID_CREDENTIALS' }),
      new PlatformError('refused', { code: 'AUTH_ACCOUNT_LOCKED' }),
      new Error('infrastructure'),
    ]) {
      const result = await attempt(build({ throws, cacheReachable: false }));
      expect(result.ok).toBe(false);
    }
  });
});

/**
 * The Phase 12 gap, which is the Phase 11 fix left half-finished.
 *
 * `failureOf` was correct and the try that called it was too small. It wrapped the call to
 * `authenticate` alone, while `organisation()` — which must resolve a tenant before any account can
 * be looked up — and the session write afterwards both sit outside it and are both database work.
 * Measured against the running deployment: with Redis stopped a sign-in answered 503, and with
 * PostgreSQL stopped the same sign-in answered 500, because the throw never reached the classifier.
 */
describe('a failure before authentication is classified too', () => {
  const buildWithFailingTenantLookup = (options: { databaseReachable?: boolean }) => {
    const probes = { cache: 0, database: 0 };
    const security = {
      tenants: {
        idForKey: () => Promise.reject(new Error('connect ECONNREFUSED 127.0.0.1:5432')),
      },
      login: { authenticate: () => Promise.reject(new Error('never reached')) },
      cacheReachable: () => {
        probes.cache += 1;
        return Promise.resolve(true);
      },
    } as unknown as ConstructorParameters<typeof AuthService>[0];

    const environment = {
      IDENTITY_DEFAULT_ORGANISATION: 'acme',
      SESSION_COOKIE_MAX_AGE: 900,
    } as unknown as ConstructorParameters<typeof AuthService>[1];

    const prisma = {
      $queryRaw: () => {
        probes.database += 1;
        return (options.databaseReachable ?? true)
          ? Promise.resolve([{ '?column?': 1 }])
          : Promise.reject(new Error('ECONNREFUSED'));
      },
    } as unknown as ConstructorParameters<typeof AuthService>[2];

    return new AuthService(security, environment, prisma);
  };

  it('answers dependency-unavailable when the database is down', async () => {
    const service = buildWithFailingTenantLookup({ databaseReachable: false });

    const result = await service.login({
      identifier: 'someone@acme.example',
      password: 'whatever-it-does-not-matter',
      correlationId: 'corr-1' as never,
    });

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failure).toEqual({
      kind: 'dependency-unavailable',
      dependency: 'database',
    });
  });

  it('still refuses generically, never openly, when every dependency answers', async () => {
    const service = buildWithFailingTenantLookup({ databaseReachable: true });

    const result = await service.login({
      identifier: 'someone@acme.example',
      password: 'whatever-it-does-not-matter',
      correlationId: 'corr-1' as never,
    });

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failure).toEqual({ kind: 'invalid-credentials' });
  });
});
