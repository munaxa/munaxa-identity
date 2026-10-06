import 'reflect-metadata';

import { MemoryCache } from '@munaxa/cache';
import { BASELINE_RATE_LIMIT_RULES, RateLimiter } from '@munaxa/security';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import type { Request, Response } from 'express';
import type { Logger } from 'pino';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

import { AuthController } from '../src/auth/auth.controller.js';
import type { AuthService, LoginRequest, LoginResult } from '../src/auth/auth.service.js';
import type { SecurityStack } from '../src/platform/security.js';
import { EdgeMiddleware } from '../src/security/edge.middleware.js';
import { TRUSTED_PROXY_HOPS, trustLoadBalancer } from '../src/security/proxy-trust.js';
import type { IdentityEnvironment } from '@identity/config';

/**
 * Who the client was, once a load balancer stands in front of the service.
 *
 * The test client plays the ALB: the connection comes from it, and it sends `X-Forwarded-For` the
 * way the ALB does in its default `append` mode — whatever the client claimed, then the address the
 * ALB actually accepted the connection from. Everything below runs through the real edge
 * middleware, Platform's real rate limiter with its real baseline rules, and the real controller,
 * over a real socket; only the account lookup is replaced, because what is under test is the
 * address that reaches it.
 *
 * Each claim is checked twice, with the setting and without it. The second run is not ceremony: it
 * is the defect this setting exists to fix, reproduced, so a later change that loses the setting
 * fails here rather than in a staging environment where everybody shares one rate-limit bucket.
 */

const ORIGIN = 'https://work-nonprod.example';
const LOGIN = '/api/auth/login';

/** Addresses from the documentation ranges, so none of them is anybody's. */
const ALICE = '203.0.113.7';
const BOB = '203.0.113.8';
const FORGED = ['198.51.100.1', '198.51.100.2', '198.51.100.3'];

/** What the ALB sends: the client's own claim, if any, then the address it really saw. */
const forwardedBy = (client: string, claimed: readonly string[] = []): string =>
  [...claimed, client].join(', ');

interface Harness {
  readonly app: NestExpressApplication;
  /** The `ipAddress` each sign-in handed to the authentication service, in order. */
  readonly signInAddresses: (string | undefined)[];
}

const harnesses: Harness[] = [];

/**
 * The parts of `main.ts` and `AppModule` that touch the client address, assembled in the same order
 * the service assembles them: the proxy setting, then the edge, then the controller.
 */
const build = async (options: { readonly behindLoadBalancer: boolean }): Promise<Harness> => {
  const moduleRef = await Test.createTestingModule({}).compile();
  const app = moduleRef.createNestApplication<NestExpressApplication>({ logger: false });

  if (options.behindLoadBalancer) trustLoadBalancer(app);
  // Nest would add its parsers at `init`, after the plain `app.use` handlers below; in the service
  // the edge is Nest middleware and runs after them, so the order is restored here.
  app.useBodyParser('json');

  const security = {
    rateLimiter: new RateLimiter({
      cache: new MemoryCache(),
      rules: [...BASELINE_RATE_LIMIT_RULES],
    }),
    audit: { write: () => Promise.resolve() },
  } as unknown as SecurityStack;
  const environment = { MUNAXA_TRUSTED_ORIGINS: [ORIGIN] } as unknown as IdentityEnvironment;
  const edge = new EdgeMiddleware(security, environment);

  const signInAddresses: (string | undefined)[] = [];
  const auth = {
    login: (attempt: LoginRequest): Promise<LoginResult> => {
      signInAddresses.push(attempt.ipAddress);
      return Promise.resolve({ ok: false, failure: { kind: 'invalid-credentials' } });
    },
  } as unknown as AuthService;
  const controller = new AuthController(auth, { error: () => undefined } as unknown as Logger);

  app.use((req: Request, res: Response, next: () => void) => {
    void edge.use(req, res, next);
  });
  app.use('/whoami', (req: Request, res: Response) => {
    res.json({ ip: req.ip });
  });
  app.use(LOGIN, (req: Request, res: Response, next: () => void) => {
    if (req.method !== 'POST') {
      next();
      return;
    }
    void controller.login(req.body as Record<string, unknown>, req, res);
  });
  await app.init();

  const harness = { app, signInAddresses };
  harnesses.push(harness);
  return harness;
};

const whoami = async (harness: Harness, forwardedFor?: string): Promise<string> => {
  const call = request(harness.app.getHttpServer()).get('/whoami');
  const response = await (forwardedFor === undefined
    ? call
    : call.set('x-forwarded-for', forwardedFor));
  return (response.body as { ip: string }).ip;
};

const signIn = (harness: Harness, forwardedFor: string) =>
  request(harness.app.getHttpServer())
    .post(LOGIN)
    .set('origin', ORIGIN)
    .set('x-forwarded-for', forwardedFor)
    .send({ identifier: 'someone@example.invalid', password: 'not-the-password' });

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map(({ app }) => app.close()));
});

describe('the proxy setting', () => {
  it('trusts exactly one hop — the load balancer — and not every proxy', async () => {
    const { app } = await build({ behindLoadBalancer: true });

    expect(TRUSTED_PROXY_HOPS).toBe(1);
    const express = app.getHttpAdapter().getInstance() as { get(setting: string): unknown };
    expect(express.get('trust proxy')).toBe(1);
  });
});

describe('the client address behind the load balancer', () => {
  it('is the address the load balancer saw', async () => {
    const harness = await build({ behindLoadBalancer: true });

    expect(await whoami(harness, forwardedBy(ALICE))).toBe(ALICE);
  });

  it('ignores whatever the client claimed in front of it', async () => {
    const harness = await build({ behindLoadBalancer: true });

    expect(await whoami(harness, forwardedBy(ALICE, FORGED))).toBe(ALICE);
  });

  it('is the socket peer when nothing forwards — a laptop, with no proxy at all', async () => {
    const harness = await build({ behindLoadBalancer: true });

    expect(await whoami(harness)).toMatch(/^(::ffff:)?127\.0\.0\.1$|^::1$/);
  });

  it('was the load balancer for everybody without the setting — the defect', async () => {
    const harness = await build({ behindLoadBalancer: false });

    const alice = await whoami(harness, forwardedBy(ALICE));
    const bob = await whoami(harness, forwardedBy(BOB));

    expect(alice).not.toBe(ALICE);
    expect(alice).toBe(bob);
  });
});

describe('the address a sign-in records', () => {
  // The controller hands `request.ip` to the authentication service, which passes it on unchanged
  // to the login attempt's audit event and to the session it creates. So the address the service
  // receives here is the address both of those record.
  it('is the client, not the load balancer and not the client’s claim', async () => {
    const harness = await build({ behindLoadBalancer: true });

    await signIn(harness, forwardedBy(ALICE, FORGED)).expect(401);
    await signIn(harness, forwardedBy(BOB)).expect(401);

    expect(harness.signInAddresses).toEqual([ALICE, BOB]);
  });
});

describe('the per-address sign-in limit behind the load balancer', () => {
  // Platform's baseline `login-per-ip`: ten attempts per address per fifteen minutes.
  const LIMIT = 10;

  it('holds against a client that forges a new address on every attempt', async () => {
    const harness = await build({ behindLoadBalancer: true });

    for (let attempt = 0; attempt < LIMIT; attempt += 1) {
      await signIn(harness, forwardedBy(ALICE, [`198.51.100.${String(attempt + 10)}`])).expect(401);
    }
    const refused = await signIn(harness, forwardedBy(ALICE, ['198.51.100.250']));

    expect(refused.status).toBe(429);
    expect((refused.body as { code: string }).code).toBe('SECURITY_RATE_LIMITED');
    // Refused at the edge: the eleventh attempt never reached the password check.
    expect(harness.signInAddresses).toHaveLength(LIMIT);
  });

  it('is per client, so one person exhausting it does not lock out the next', async () => {
    const harness = await build({ behindLoadBalancer: true });

    for (let attempt = 0; attempt < LIMIT; attempt += 1) {
      await signIn(harness, forwardedBy(ALICE)).expect(401);
    }
    // Bob before Alice's refusal, not after. Platform widens a window after its first violation and
    // the wider window starts a fresh bucket, so the request *after* a 429 is admitted whichever
    // bucket it shared — asking then would pass with the setting removed and prove nothing.
    await signIn(harness, forwardedBy(BOB)).expect(401);
    await signIn(harness, forwardedBy(ALICE)).expect(429);
  });

  it('was one bucket shared by everybody without the setting — the defect', async () => {
    const harness = await build({ behindLoadBalancer: false });

    for (let attempt = 0; attempt < LIMIT; attempt += 1) {
      await signIn(harness, forwardedBy(ALICE)).expect(401);
    }

    await signIn(harness, forwardedBy(BOB)).expect(429);
  });
});
