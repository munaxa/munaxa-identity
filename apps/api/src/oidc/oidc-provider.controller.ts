import {
  Body,
  Controller,
  Get,
  Headers,
  NotFoundException,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { SESSION_COOKIE } from '../auth/cookies.js';
import { withPageCsp } from '../ui/layout.js';
import { oidcErrorPage } from '../ui/oidc-error.page.js';
import {
  OidcProviderService,
  type AuthorizeQuery,
  type OidcRequestContext,
} from './oidc-provider.service.js';

/**
 * Identity as the OpenID Connect provider for other Munaxa products (ADR-0008).
 *
 *     GET  /api/auth/oidc/.well-known/openid-configuration   discovery
 *     GET  /api/auth/oidc/jwks                               the public signing key
 *     GET  /api/auth/oidc/authorize                          browser: sign in, then back with a code
 *     POST /api/auth/oidc/token                              client: the code for an id token
 *
 * All four answer 404 unless `IDENTITY_OIDC_PROVIDER=enabled`.
 */
@Controller('auth/oidc')
export class OidcProviderController {
  public constructor(private readonly oidc: OidcProviderService) {}

  @Get('.well-known/openid-configuration')
  public discovery(@Res() response: Response): void {
    this.requireEnabled();
    response.setHeader('cache-control', 'public, max-age=300').json(this.oidc.discovery());
  }

  @Get('jwks')
  public jwks(@Res() response: Response): void {
    this.requireEnabled();
    response.setHeader('cache-control', 'public, max-age=300').json(this.oidc.jwks());
  }

  @Get('authorize')
  public async authorize(
    @Query() query: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    this.requireEnabled();
    const params: Record<string, string | undefined> = {};
    for (const key of [
      'response_type',
      'client_id',
      'redirect_uri',
      'scope',
      'state',
      'nonce',
      'code_challenge',
      'code_challenge_method',
      'prompt',
    ] as const) {
      const value = query[key];
      params[key] = typeof value === 'string' ? value : undefined;
    }
    const jar = (request as Request & { cookies?: Record<string, string> }).cookies ?? {};
    const outcome = await this.oidc.authorize(
      params as AuthorizeQuery,
      jar[SESSION_COOKIE],
      request.originalUrl,
      contextOf(request),
    );
    response.setHeader('cache-control', 'no-store');
    response.setHeader('referrer-policy', 'no-referrer');
    switch (outcome.kind) {
      case 'invalid':
        withPageCsp(response).status(400).type('html').send(oidcErrorPage());
        return;
      case 'login':
        response.redirect(
          303,
          `/api/auth/login?organisation=${encodeURIComponent(outcome.organisation)}&returnTo=${encodeURIComponent(outcome.returnTo)}`,
        );
        return;
      default:
        response.redirect(303, outcome.url);
    }
  }

  @Post('token')
  public async token(
    @Body() body: Record<string, unknown>,
    @Headers('authorization') authorization: string | undefined,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    this.requireEnabled();
    const outcome = await this.oidc.token(body ?? {}, authorization, contextOf(request));
    response.setHeader('cache-control', 'no-store').setHeader('pragma', 'no-cache');
    if (outcome.ok) {
      response.status(200).json(outcome.body);
      return;
    }
    if (outcome.status === 401) response.setHeader('www-authenticate', 'Basic realm="identity"');
    response.status(outcome.status).json({ error: outcome.error });
  }

  private requireEnabled(): void {
    if (!this.oidc.enabled) throw new NotFoundException();
  }
}

const contextOf = (request: Request): OidcRequestContext => {
  const userAgent = request.headers['user-agent'];
  return {
    ...(userAgent === undefined
      ? {}
      : { userAgent: Array.isArray(userAgent) ? userAgent[0] : userAgent }),
    ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
    correlationId: (request as Request & { correlationId?: string }).correlationId ?? randomUUID(),
  };
};
