import { Controller, Delete, Get, HttpCode, Inject, Param, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import type { Logger } from 'pino';

import { SESSION_COOKIE, clearSessionCookies } from '../auth/cookies.js';
import { LOGGER } from '../tokens.js';
import { AccountSessionsService } from './account-sessions.service.js';

/**
 * The session-management API.
 *
 *     GET    /api/auth/sessions                 the caller's live sessions
 *     DELETE /api/auth/sessions/:id             sign one of them out (the current one too)
 *     POST   /api/auth/sessions/revoke-others   sign out every session but this one
 *
 * Authenticated by the `__Host-mx_session` cookie and nothing else; there is no bearer-header path,
 * so the cookie's `httpOnly`, `Secure`, `SameSite=Lax` and host-only properties hold for these
 * routes too. The state-changing two are behind the same edge as sign-in — the strict origin
 * allow-list in `EdgeMiddleware` applies to every non-GET method, which is the CSRF defence for a
 * cookie-authenticated `DELETE` as much as for a `POST`.
 *
 * Every refusal to authenticate is one 401 with one code, and every "that is not a session of
 * yours" is one 404 with one code. Responses are `no-store`: a list of somebody's devices has no
 * business in a shared cache.
 */
@Controller('auth/sessions')
export class AccountSessionsController {
  public constructor(
    private readonly sessions: AccountSessionsService,
    @Inject(LOGGER) private readonly logger: Logger,
  ) {}

  @Get()
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.answer(response, async () => {
      const outcome = await this.sessions.list(cookie(request, SESSION_COOKIE));
      if (!outcome.ok) return unauthenticated(response);
      response.status(200).json({ sessions: outcome.sessions });
    });
  }

  @Post('revoke-others')
  @HttpCode(200)
  public async revokeOthers(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.answer(response, async () => {
      const outcome = await this.sessions.revokeOthers(
        cookie(request, SESSION_COOKIE),
        correlation(request),
      );
      if (!outcome.ok) return unauthenticated(response);
      response.status(200).json({ ok: true, revoked: outcome.revoked });
    });
  }

  @Delete(':id')
  public async revoke(
    @Param('id') id: string,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    await this.answer(response, async () => {
      const outcome = await this.sessions.revoke(
        cookie(request, SESSION_COOKIE),
        id,
        correlation(request),
      );
      if (!outcome.ok) {
        if (outcome.reason === 'unauthenticated') return unauthenticated(response);
        response.status(404).json({ code: 'SESSION_NOT_FOUND' });
        return;
      }
      // Signing out the session you are using is a logout, and the browser should stop presenting
      // cookies that will now be refused.
      if (outcome.current) clearSessionCookies(response);
      response.status(200).json({ ok: true, current: outcome.current });
    });
  }

  /**
   * A dependency failure is a 503, never a 500 with a stack and never a 401. The log line names
   * the event and the correlation id and nothing about the caller — no token, no session id.
   */
  private async answer(response: Response, work: () => Promise<void>): Promise<void> {
    response.setHeader('cache-control', 'no-store');
    try {
      await work();
    } catch (error) {
      this.logger.error(
        {
          event: 'auth.sessions.unavailable',
          errorName: error instanceof Error ? error.name : 'unknown',
        },
        'session management dependency unavailable',
      );
      response.status(503).setHeader('retry-after', '15').json({ code: 'AUTH_UNAVAILABLE' });
    }
  }
}

const unauthenticated = (response: Response): void => {
  response.status(401).json({ code: 'AUTH_UNAUTHENTICATED' });
};

const cookie = (request: Request, name: string): string | undefined => {
  const jar = (request as Request & { cookies?: Record<string, string> }).cookies;
  const value = jar?.[name];
  return value === undefined || value.trim() === '' ? undefined : value;
};

const correlation = (request: Request): string | undefined =>
  (request as Request & { correlationId?: string }).correlationId;
