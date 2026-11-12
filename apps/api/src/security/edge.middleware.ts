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

    const platformRequest: PlatformRequest = {
      method: request.method,
      path: fullPathOf(request),
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
    next();
  }
}

/**
 * The request's whole path, prefix included, without the query.
 *
 * Not `request.path`: Nest mounts this middleware for every route, and Express then reports the
 * path relative to that mount, which is `/` for every request. Every path-matched rule (the login,
 * password-reset, MFA and introspection limits) would silently never match.
 */
const fullPathOf = (request: Request): string => {
  const raw = request.originalUrl || request.url || '/';
  const end = raw.search(/[?#]/);
  return end === -1 ? raw : raw.slice(0, end);
};

const headerOf = (request: Request, name: string): string | undefined => {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
};
