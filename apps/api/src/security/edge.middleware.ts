import { Inject, Injectable, type NestMiddleware } from '@nestjs/common';
import { anonymousAuditEvent } from '@munaxa/audit';
import { securityPipeline } from '@munaxa/security';
import {
  ROOT_TENANT_ID,
  emptyResponse,
  toCorrelationId,
  type PlatformRequest,
} from '@munaxa/types';
import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import { MFA_CHALLENGE_COOKIE, SESSION_COOKIE } from '../auth/cookies.js';
import {
  INTROSPECTION_PATH,
  isIntrospection,
  normalisedPath,
} from '../auth/token-introspection.js';
import {
  canonicalRoute,
  credentialSubject,
  identifierSubject,
  isLogin,
  isMfa,
  type AuthEdgeDecision,
} from './auth-edge-limits.js';
import type { SecurityStack } from '../platform/security.js';
import type { IdentityEnvironment } from '@identity/config';

/**
 * The secure edge, in front of every authentication route.
 *
 * The order is Platform's and is fixed there rather than left to each product's framework
 * registration: headers first so they survive a later rejection, path inspection before anything
 * parses a body, rate limiting *before* authentication because the login endpoint is what gets
 * attacked and authentication is expensive by design, then origin checking, then advisory threat
 * scanning.
 *
 * Origin checking is the CSRF defence here rather than a double-submit token, and the choice is
 * deliberate. A `__Host-` cookie cannot be set or overwritten by a subdomain, `SameSite=Lax`
 * already withholds it from cross-site POSTs, and the sign-in form is served from the origin it
 * posts to. A token would be a third mechanism on the same door; a strict origin allow-list closes
 * the case `Lax` does not — a same-site subdomain — and `trustedOrigins` being empty is refused by
 * the configuration rather than quietly disabling the check.
 *
 * `CORRELATION` is set before anything else so a rejection at the edge is still traceable: a 429
 * with no correlation id is a support ticket nobody can answer.
 */
@Injectable()
export class EdgeMiddleware implements NestMiddleware {
  private readonly pipeline: ReturnType<typeof securityPipeline>;
  /**
   * Edge events precede any organisation — a rate limit fires before authentication, an origin
   * rejection before a session is resolved — so they are recorded against the platform's reserved
   * root tenant rather than against a customer who had nothing to do with them.
   */
  private readonly edgeTenant = ROOT_TENANT_ID;

  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
  ) {
    this.pipeline = securityPipeline({
      rateLimiter: security.rateLimiter,
      trustedOrigins: [...environment.MUNAXA_TRUSTED_ORIGINS],
      apiOnly: true,
      scanBodies: true,
      onEvent: (event) => {
        // Reported, never fatal. An audit sink that rejects must not take an authentication
        // service down with it — an unhandled rejection here would do exactly that, and the
        // outage would be caused by the machinery that exists to record outages.
        void this.security.audit
          .write(
            anonymousAuditEvent(this.edgeTenant, toCorrelationId(randomUUID()), {
              name: event.name,
              outcome: 'failure',
              ...(event.detail === undefined ? {} : { payload: event.detail }),
            }),
          )
          .catch((error: unknown) => {
            process.stderr.write(`[identity] edge audit write failed: ${String(error)}\n`);
          });
      },
    });
  }

  public async use(request: Request, response: Response, next: NextFunction): Promise<void> {
    const correlationId = headerOf(request, 'x-correlation-id') ?? randomUUID();
    response.setHeader('x-correlation-id', correlationId);
    (request as Request & { correlationId?: string }).correlationId = correlationId;

    const target = request.originalUrl || request.url || '/';
    const route = canonicalRoute(target);
    const platformRequest: PlatformRequest = {
      method: request.method,
      path: generalPathOf(target, route),
      headers: request.headers as Record<string, string | undefined>,
      cookies: (request as Request & { cookies?: Record<string, string> }).cookies ?? {},
      body: request.body as unknown,
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
    };

    const platformResponse = emptyResponse();
    const short = await this.pipeline(platformRequest, platformResponse);

    for (const [name, value] of Object.entries(platformResponse.headers)) {
      response.setHeader(name, value);
    }
    if (short) {
      response.status(short.status).json(short.body);
      return;
    }

    const decision = await this.authLimit(request, route);
    if (decision.kind === 'limited') {
      this.record('security.ratelimit.exceeded', {
        rule: decision.rule,
        retryAfterSeconds: decision.retryAfterSeconds,
      });
      response
        .status(429)
        .setHeader('retry-after', String(decision.retryAfterSeconds))
        .setHeader('ratelimit-limit', String(decision.limit))
        .setHeader('ratelimit-remaining', '0')
        .json({ code: 'SECURITY_RATE_LIMITED', retryAfterSeconds: decision.retryAfterSeconds });
      return;
    }
    if (decision.kind === 'unavailable') {
      // The limit on a credential route could not be read. Admitting would be an unlimited
      // guessing window for as long as the store is down, so the request is refused as an outage.
      this.record('security.ratelimit.exceeded', {
        rule: decision.rule,
        reason: 'store-unavailable',
      });
      response.status(503).setHeader('retry-after', '5').json({ code: 'AUTH_UNAVAILABLE' });
      return;
    }
    next();
  }

  /**
   * The credential-route limits, with the subject each one counts.
   *
   * Sign-in: the typed identifier, trimmed and lowercased exactly as the directory finds accounts,
   * digested (`identifierSubject`) whether or not an account exists, so the limit is not an oracle.
   * MFA: the session's `sid` when the session cookie verifies (signature and expiry, checked
   * locally, no database), else a digest of the challenge cookie; with neither, only the
   * per-address rule applies and the route itself refuses the request. Raw values never leave this
   * method — not into a key, not into a log.
   */
  private async authLimit(request: Request, route: string): Promise<AuthEdgeDecision> {
    const method = request.method;
    const login = isLogin(method, route);
    const mfa = isMfa(method, route);
    const body = request.body as Record<string, unknown> | undefined;
    // The organisation the sign-in resolves to, as `AuthService` resolves it: a missing or blank
    // field means the default, so naming the default explicitly is not a second budget.
    const typed = body?.organisation;
    const organisation =
      typeof typed === 'string' && typed.trim() !== ''
        ? typed
        : this.environment.IDENTITY_DEFAULT_ORGANISATION;
    const identifier = login ? identifierSubject(body?.identifier, organisation) : undefined;
    const credential = mfa ? this.credentialOf(request, route) : undefined;
    return this.security.authEdgeLimiter.check({
      method,
      route,
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
      ...(identifier === undefined ? {} : { identifier }),
      ...(credential === undefined ? {} : { credential }),
    });
  }

  private credentialOf(request: Request, route: string): string | undefined {
    const jar = (request as Request & { cookies?: Record<string, string> }).cookies ?? {};
    // The sign-in challenge is redeemed only with the challenge cookie; the enrolment routes accept
    // a session first, then a challenge (as the controller does); the rest take only a session.
    const challengeOnly = route === '/api/auth/mfa/verify';
    const challengeAllowed = challengeOnly || route.startsWith('/api/auth/mfa/enrollment');
    if (!challengeOnly) {
      const session = jar[SESSION_COOKIE];
      if (typeof session === 'string' && session !== '') {
        try {
          const sid = this.security.tokens.verifyAccessToken(session).sid;
          if (typeof sid === 'string' && sid !== '') return credentialSubject('session', sid);
        } catch {
          // Not a session we issued, or expired: the route refuses it; only the address counts.
        }
      }
    }
    const challenge = jar[MFA_CHALLENGE_COOKIE];
    if (challengeAllowed && typeof challenge === 'string' && challenge !== '') {
      return credentialSubject('challenge', challenge);
    }
    return undefined;
  }

  private record(name: 'security.ratelimit.exceeded', detail: Record<string, unknown>): void {
    void this.security.audit
      .write(
        anonymousAuditEvent(this.edgeTenant, toCorrelationId(randomUUID()), {
          name,
          outcome: 'failure',
          payload: detail,
        }),
      )
      .catch((error: unknown) => {
        process.stderr.write(`[identity] edge audit write failed: ${String(error)}\n`);
      });
  }
}

/**
 * The path the general rules see.
 *
 * The canonical route, except that only spellings Express itself routes to introspection (case,
 * repeated and trailing slashes; no percent-decoding) are carved out to its high address limit. A
 * percent-encoded spelling such as `/api/auth/%69ntrospect` is a 404 and stays under the browser
 * limit rather than buying 404 traffic at the product-egress rate.
 */
const generalPathOf = (target: string, route: string): string => {
  if (route !== INTROSPECTION_PATH) return route;
  const withoutHost = target.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '');
  const end = withoutHost.search(/[?#]/);
  const routed = isIntrospection(
    normalisedPath(end === -1 ? withoutHost : withoutHost.slice(0, end)),
  );
  return routed ? route : `${route}#encoded`;
};

const headerOf = (request: Request, name: string): string | undefined => {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
};
