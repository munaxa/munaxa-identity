import {
  Body,
  Controller,
  Get,
  HttpCode,
  NotFoundException,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { safeReturnTo } from '../auth/auth.controller.js';
import { issueChallengeCookie, issueCookies, setCookies } from '../auth/cookies.js';
import { ssoPage } from '../ui/sso.page.js';
import { withPageCsp } from '../ui/layout.js';
import { SsoService, type SsoRequestContext } from './sso.service.js';

/**
 * Company sign-in routes.
 *
 *     GET  /api/auth/sso            page: the work email address
 *     POST /api/auth/sso/start      form or JSON: where to send the browser
 *     GET  /api/auth/sso/callback   the provider sends the browser back here
 *
 * All three answer 404 unless `IDENTITY_SSO=enabled`, so a deployment that has not turned the
 * feature on has no new surface at all.
 *
 * The browser binding (`__Host-mx_sso`, see `sso-flows.ts`) is `SameSite=Lax` rather than Strict,
 * and that is the one cookie in this service that is: the callback is a top-level navigation that
 * starts at Microsoft or Google, and a Strict cookie is withheld from exactly that request. Lax still
 * withholds it from every cross-site subresource and POST, and the cookie authorises nothing on its
 * own: it only proves that the browser finishing a flow is the browser that started it.
 */
export const SSO_BINDING_COOKIE = '__Host-mx_sso';

@Controller('auth/sso')
export class SsoController {
  public constructor(private readonly sso: SsoService) {}

  @Get()
  public page(
    @Query('lang') language: string | undefined,
    @Query('returnTo') returnTo: string | undefined,
    @Query('error') error: string | undefined,
    @Res() response: Response,
  ): void {
    this.requireEnabled();
    withPageCsp(response)
      .status(200)
      .setHeader('cache-control', 'no-store')
      .type('html')
      .send(
        ssoPage({
          language: language === 'ar' ? 'ar' : 'en',
          returnTo: safeReturnTo(returnTo),
          error: error === 'not-offered' || error === 'unavailable' ? error : undefined,
        }),
      );
  }

  @Post('start')
  @HttpCode(200)
  public async start(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    this.requireEnabled();
    const language = body.lang === 'ar' ? 'ar' : 'en';
    const form = (request.headers['content-type'] ?? '').includes(
      'application/x-www-form-urlencoded',
    );
    const returnTo = safeReturnTo(typeof body.returnTo === 'string' ? body.returnTo : undefined);
    const outcome = await this.sso.start({
      email: typeof body.identifier === 'string' ? body.identifier : '',
      returnTo,
      language,
      context: contextOf(request),
    });
    response.setHeader('cache-control', 'no-store');

    if (outcome.kind === 'redirect') {
      setCookies(response, [
        {
          name: SSO_BINDING_COOKIE,
          value: outcome.binding,
          options: {
            path: '/',
            maxAgeSeconds: outcome.ttlSeconds,
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
          },
        },
      ]);
      if (form) {
        response.redirect(303, outcome.url);
        return;
      }
      response.json({ authorizationUrl: outcome.url });
      return;
    }

    const error = outcome.kind === 'unavailable' ? 'unavailable' : 'not-offered';
    if (outcome.kind === 'bad-origin') {
      // Not a user error and not a page a user could fix: an origin Identity does not serve.
      response.status(400).json({ code: 'SSO_ORIGIN_UNTRUSTED' });
      return;
    }
    if (form) {
      response.redirect(
        303,
        `/api/auth/sso?lang=${language}&error=${error}&returnTo=${encodeURIComponent(returnTo)}`,
      );
      return;
    }
    response
      .status(outcome.kind === 'unavailable' ? 503 : 404)
      .json({ code: outcome.kind === 'unavailable' ? 'AUTH_UNAVAILABLE' : 'SSO_NOT_OFFERED' });
  }

  @Get('callback')
  public async callback(
    @Query() query: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    this.requireEnabled();
    const params: Record<string, string | undefined> = {};
    for (const key of ['code', 'state', 'error'] as const) {
      const value = query[key];
      params[key] = typeof value === 'string' ? value : undefined;
    }
    const jar = (request as Request & { cookies?: Record<string, string> }).cookies ?? {};
    const outcome = await this.sso.callback({
      params,
      binding: jar[SSO_BINDING_COOKIE],
      context: contextOf(request),
    });

    response.setHeader('cache-control', 'no-store');
    // The binding is spent whatever happened: the flow it bound is gone.
    setCookies(response, [
      {
        name: SSO_BINDING_COOKIE,
        value: '',
        options: { path: '/', maxAgeSeconds: 0, secure: true, httpOnly: true, sameSite: 'lax' },
      },
    ]);

    const returnTo = encodeURIComponent(outcome.returnTo);
    switch (outcome.kind) {
      case 'signed-in':
        issueCookies(response, outcome.result, this.sso.sessionCookieMaxAge);
        response.redirect(303, outcome.returnTo);
        return;
      case 'mfa': {
        issueChallengeCookie(
          response,
          outcome.challenge.token,
          Math.ceil(outcome.challenge.ttlMs / 1_000),
        );
        const page = outcome.challenge.kind === 'verify' ? '/api/auth/mfa' : '/api/auth/mfa/enroll';
        response.redirect(303, `${page}?lang=${outcome.language}&returnTo=${returnTo}`);
        return;
      }
      case 'unavailable':
        response.redirect(
          303,
          `/api/auth/login?lang=${outcome.language}&error=unavailable&returnTo=${returnTo}`,
        );
        return;
      default:
        response.redirect(
          303,
          `/api/auth/login?lang=${outcome.language}&error=sso&returnTo=${returnTo}`,
        );
    }
  }

  private requireEnabled(): void {
    if (!this.sso.enabled) throw new NotFoundException();
  }
}

/**
 * The origin the browser is on, as Express sees it behind `TRUST_PROXY_HOPS` proxies. Only used
 * when it is one of `CSRF_TRUSTED_ORIGINS` (`SsoService.callbackFor`); a forged `Host` naming any
 * other origin cannot start a flow.
 */
const contextOf = (request: Request): SsoRequestContext => {
  const userAgent = request.headers['user-agent'];
  return {
    origin: `${request.protocol}://${request.get('host') ?? ''}`,
    ...(userAgent === undefined
      ? {}
      : { userAgent: Array.isArray(userAgent) ? userAgent[0] : userAgent }),
    ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
    correlationId: (request as Request & { correlationId?: string }).correlationId ?? randomUUID(),
  };
};
