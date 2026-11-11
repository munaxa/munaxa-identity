import { Body, Controller, HttpCode, Inject, Post, Req, Res } from '@nestjs/common';
import { toCorrelationId } from '@munaxa/types';
import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { SESSION_COOKIE, clearSessionCookies } from '../auth/cookies.js';
import type { SecurityStack } from '../platform/security.js';
import { SECURITY_STACK } from '../tokens.js';

/**
 *     POST /api/auth/password/change   { currentPassword, newPassword }
 *
 * Authenticated by the session cookie only, behind the edge's origin allow-list (the CSRF defence
 * for every state-changing route). On success every session of the account is revoked, this one
 * included, and the cookies are cleared: the caller signs in again with the new password.
 */
@Controller('auth/password')
export class PasswordChangeController {
  public constructor(@Inject(SECURITY_STACK) private readonly security: SecurityStack) {}

  @Post('change')
  @HttpCode(200)
  public async change(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    response.setHeader('cache-control', 'no-store');
    const outcome = await this.security.passwordChange.change({
      accessToken: cookie(request, SESSION_COOKIE),
      currentPassword: text(body.currentPassword),
      newPassword: text(body.newPassword),
      correlationId: toCorrelationId(
        (request as Request & { correlationId?: string }).correlationId ?? randomUUID(),
      ),
    });

    switch (outcome.kind) {
      case 'changed':
        clearSessionCookies(response);
        response.status(200).json({ ok: true, signedOut: outcome.revokedSessions });
        return;
      case 'unauthenticated':
        response.status(401).json({ code: 'AUTH_UNAUTHENTICATED' });
        return;
      case 'invalid-current-password':
        response.status(401).json({ code: 'AUTH_INVALID_CREDENTIALS' });
        return;
      case 'reauthentication-required':
        response.status(403).json({ code: 'AUTH_REAUTHENTICATION_REQUIRED' });
        return;
      case 'password-rejected':
        response.status(422).json({ code: outcome.code, violations: outcome.violations });
        return;
      case 'rate-limited':
        response
          .status(429)
          .setHeader('retry-after', String(outcome.retryAfterSeconds))
          .json({ code: 'AUTH_RATE_LIMITED', retryAfterSeconds: outcome.retryAfterSeconds });
        return;
      default:
        response.status(503).setHeader('retry-after', '15').json({ code: 'AUTH_UNAVAILABLE' });
    }
  }
}

const text = (value: unknown): string => (typeof value === 'string' ? value : '');

const cookie = (request: Request, name: string): string | undefined => {
  const jar = (request as Request & { cookies?: Record<string, string> }).cookies;
  const value = jar?.[name];
  return value === undefined || value.trim() === '' ? undefined : value;
};
