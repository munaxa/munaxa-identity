import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Inject,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import type { Logger } from 'pino';
import { randomUUID } from 'node:crypto';

import { safeReturnTo } from '../auth/auth.controller.js';
import {
  MFA_CHALLENGE_COOKIE,
  SESSION_COOKIE,
  clearChallengeCookie,
  issueCookies,
} from '../auth/cookies.js';
import { AuthService } from '../auth/auth.service.js';
import { LOGGER } from '../tokens.js';
import { mfaPage, type MfaPageOptions, type MfaPageState } from '../ui/mfa.page.js';
import {
  MfaFlowService,
  type Actor,
  type MfaRefusal,
  type RequestContext,
} from './mfa-flow.service.js';

/**
 * The MFA API.
 *
 *     GET    /api/auth/mfa                          page: enter a code (sign-in challenge)
 *     GET    /api/auth/mfa/enroll                   page: set up MFA (enrollment challenge)
 *     POST   /api/auth/mfa/verify                   redeem the sign-in challenge     [challenge]
 *     GET    /api/auth/mfa/status                   enrolled? required? codes left?  [session]
 *     POST   /api/auth/reauthenticate               password (+ code when enrolled)  [session]
 *     POST   /api/auth/mfa/enrollment               start enrollment       [session+reauth | enroll challenge]
 *     POST   /api/auth/mfa/enrollment/confirm       confirm with a code    [session+reauth | enroll challenge]
 *     POST   /api/auth/mfa/recovery-codes           regenerate the set               [session+reauth]
 *     DELETE /api/auth/mfa                          remove the factor                [session+reauth]
 *
 * The challenge cookie is read by these routes and by nothing else in the service, and the session
 * routes read only the session cookie — so a pending challenge can never stand in for a session,
 * and an `enroll` challenge reaches only the two enrollment routes. Every response is `no-store`
 * and `no-referrer`: some of them carry a secret or recovery codes, exactly once.
 *
 * Every state-changing route is behind `EdgeMiddleware`'s origin allow-list (the CSRF control for
 * cookie-authenticated requests), and the challenge cookie is additionally `SameSite=Strict`.
 */
@Controller('auth')
export class MfaController {
  public constructor(
    private readonly flow: MfaFlowService,
    private readonly auth: AuthService,
    @Inject(LOGGER) private readonly logger: Logger,
  ) {}

  @Get('mfa')
  public verifyPage(
    @Query('lang') language: string | undefined,
    @Query('returnTo') returnTo: string | undefined,
    @Query('error') error: string | undefined,
    @Res() response: Response,
  ): void {
    this.page(response, 200, {
      language: language === 'ar' ? 'ar' : 'en',
      returnTo: safeReturnTo(returnTo),
      state: { kind: 'verify' },
      error: pageError(error),
    });
  }

  @Get('mfa/enroll')
  public enrollPage(
    @Query('lang') language: string | undefined,
    @Query('returnTo') returnTo: string | undefined,
    @Query('error') error: string | undefined,
    @Res() response: Response,
  ): void {
    this.page(response, 200, {
      language: language === 'ar' ? 'ar' : 'en',
      returnTo: safeReturnTo(returnTo),
      state: { kind: 'enroll-start' },
      error: pageError(error),
    });
  }

  @Post('mfa/verify')
  @HttpCode(200)
  public async verify(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    await this.answer(request, response, async (context) => {
      const form = formTarget(request, body);
      const outcome = await this.flow.verifyChallenge(
        cookie(request, MFA_CHALLENGE_COOKIE),
        { code: optional(body.code), recoveryCode: optional(body.recoveryCode) },
        context,
      );
      if (!outcome.ok) {
        if (outcome.refusal !== 'invalid') clearChallengeCookie(response);
        if (form !== undefined) {
          response.redirect(
            303,
            `/api/auth/mfa?lang=${lang(body)}&error=${pageCode(outcome.refusal)}&returnTo=${encodeURIComponent(form)}`,
          );
          return;
        }
        refuse(response, outcome.refusal);
        return;
      }
      clearChallengeCookie(response);
      issueCookies(response, outcome.value, this.auth.sessionCookieMaxAge);
      if (form !== undefined) {
        response.redirect(303, form);
        return;
      }
      response.status(200).json({ ok: true });
    });
  }

  @Get('mfa/status')
  public async status(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.answer(request, response, async () => {
      const principal = await this.flow.principal(cookie(request, SESSION_COOKIE));
      if (principal === undefined) return refuse(response, 'unauthenticated');
      response.status(200).json(await this.flow.status(principal));
    });
  }

  @Post('reauthenticate')
  @HttpCode(200)
  public async reauthenticate(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    await this.answer(request, response, async (context) => {
      const principal = await this.flow.principal(cookie(request, SESSION_COOKIE));
      if (principal === undefined) return refuse(response, 'unauthenticated');
      const outcome = await this.flow.reauthenticate(
        principal,
        {
          password: typeof body.password === 'string' ? body.password : '',
          code: optional(body.code),
          recoveryCode: optional(body.recoveryCode),
        },
        context,
      );
      if (!outcome.ok) return refuse(response, outcome.refusal);
      response.status(200).json({ ok: true, expiresInSeconds: outcome.value.expiresInSeconds });
    });
  }

  @Post('mfa/enrollment')
  @HttpCode(200)
  public async startEnrollment(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    await this.answer(request, response, async (context) => {
      const form = formTarget(request, body);
      const actor = await this.actor(request, context);
      if (!actor.ok) return this.enrollRefused(response, body, form, actor.refusal);
      const outcome = await this.flow.startEnrollment(actor.value, context);
      if (!outcome.ok) return this.enrollRefused(response, body, form, outcome.refusal);
      if (form !== undefined) {
        this.page(response, 200, {
          language: lang(body),
          returnTo: form,
          state: { kind: 'enroll-confirm', secret: outcome.value.secret, uri: outcome.value.uri },
        });
        return;
      }
      // The secret leaves the service here, once, for the authenticator app. It is never readable
      // again: there is no route that returns a stored secret.
      response.status(200).json({ secret: outcome.value.secret, uri: outcome.value.uri });
    });
  }

  @Post('mfa/enrollment/confirm')
  @HttpCode(200)
  public async confirmEnrollment(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    await this.answer(request, response, async (context) => {
      const form = formTarget(request, body);
      const actor = await this.actor(request, context);
      if (!actor.ok) return this.enrollRefused(response, body, form, actor.refusal);
      const outcome = await this.flow.confirmEnrollment(
        actor.value,
        typeof body.code === 'string' ? body.code : '',
        context,
      );
      if (!outcome.ok) return this.enrollRefused(response, body, form, outcome.refusal);

      const { recoveryCodes, signIn } = outcome.value;
      if (actor.value.via === 'challenge') clearChallengeCookie(response);
      if (signIn !== undefined) issueCookies(response, signIn, this.auth.sessionCookieMaxAge);

      if (form !== undefined) {
        // Signed in: continue to where they were going. Not signed in (the challenge was spent
        // elsewhere): continue to sign-in. Either way the codes are on this page, once.
        const next =
          signIn !== undefined || actor.value.via === 'session'
            ? form
            : `/api/auth/login?lang=${lang(body)}&returnTo=${encodeURIComponent(form)}`;
        this.page(response, 200, {
          language: lang(body),
          returnTo: form,
          state: { kind: 'recovery-codes', codes: recoveryCodes, next },
        });
        return;
      }
      response.status(200).json({
        ok: true,
        recoveryCodes,
        signedIn: signIn !== undefined || actor.value.via === 'session',
      });
    });
  }

  @Post('mfa/recovery-codes')
  @HttpCode(200)
  public async regenerate(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.answer(request, response, async (context) => {
      const principal = await this.flow.principal(cookie(request, SESSION_COOKIE));
      if (principal === undefined) return refuse(response, 'unauthenticated');
      const outcome = await this.flow.regenerateRecoveryCodes(principal, context);
      if (!outcome.ok) return refuse(response, outcome.refusal);
      response.status(200).json({ recoveryCodes: outcome.value.recoveryCodes });
    });
  }

  @Delete('mfa')
  public async remove(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.answer(request, response, async (context) => {
      const principal = await this.flow.principal(cookie(request, SESSION_COOKIE));
      if (principal === undefined) return refuse(response, 'unauthenticated');
      const outcome = await this.flow.remove(principal, context);
      if (!outcome.ok) return refuse(response, outcome.refusal);
      response.status(200).json({ ok: true });
    });
  }

  // -----------------------------------------------------------------------------------------------

  /**
   * Who may enrol: a signed-in session, or an `enroll` challenge. The session is preferred when
   * both are present — a signed-in person is enrolling deliberately — and a `verify` challenge is
   * never accepted here.
   */
  private async actor(
    request: Request,
    context: RequestContext,
  ): Promise<{ ok: true; value: Actor } | { ok: false; refusal: MfaRefusal }> {
    const principal = await this.flow.principal(cookie(request, SESSION_COOKIE));
    if (principal !== undefined) return { ok: true, value: { via: 'session', principal } };
    const token = cookie(request, MFA_CHALLENGE_COOKIE);
    if (token === undefined) return { ok: false, refusal: 'unauthenticated' };
    const found = await this.flow.challenge(token, 'enroll', context);
    if (!found.ok) return { ok: false, refusal: found.refusal };
    return { ok: true, value: { via: 'challenge', token, record: found.value } };
  }

  private enrollRefused(
    response: Response,
    body: Record<string, unknown>,
    form: string | undefined,
    refusal: MfaRefusal,
  ): void {
    if (refusal === 'expired' || refusal === 'locked') clearChallengeCookie(response);
    if (form !== undefined) {
      response.redirect(
        303,
        `/api/auth/mfa/enroll?lang=${lang(body)}&error=${pageCode(refusal)}&returnTo=${encodeURIComponent(form)}`,
      );
      return;
    }
    refuse(response, refusal);
  }

  private page(response: Response, status: number, options: MfaPageOptions): void {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('referrer-policy', 'no-referrer');
    response.status(status).type('html').send(mfaPage(options));
  }

  /**
   * `no-store` and `no-referrer` on everything; a dependency failure is a 503 that names nothing
   * about the caller. The log line never carries a code, a secret, a recovery code or a cookie.
   */
  private async answer(
    request: Request,
    response: Response,
    work: (context: RequestContext) => Promise<void>,
  ): Promise<void> {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('referrer-policy', 'no-referrer');
    const context: RequestContext = {
      correlationId:
        (request as Request & { correlationId?: string }).correlationId ?? randomUUID(),
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
      ...(userAgent(request) === undefined ? {} : { userAgent: userAgent(request) }),
    };
    try {
      await work(context);
    } catch (error) {
      this.logger.error(
        {
          event: 'auth.mfa.unavailable',
          errorName: error instanceof Error ? error.name : 'unknown',
          correlationId: context.correlationId,
        },
        'mfa dependency unavailable',
      );
      if (!response.headersSent) {
        response.status(503).setHeader('retry-after', '15').json({ code: 'AUTH_UNAVAILABLE' });
      }
    }
  }
}

const STATUS: Record<MfaRefusal, [number, string]> = {
  unauthenticated: [401, 'AUTH_UNAUTHENTICATED'],
  expired: [401, 'AUTH_MFA_CHALLENGE_EXPIRED'],
  invalid: [401, 'AUTH_MFA_INVALID'],
  locked: [429, 'AUTH_RATE_LIMITED'],
  'reauth-required': [403, 'AUTH_REAUTHENTICATION_REQUIRED'],
  'not-enrolled': [409, 'AUTH_MFA_NOT_ENROLLED'],
  'already-enrolled': [409, 'AUTH_MFA_ALREADY_ENROLLED'],
  'required-by-policy': [403, 'AUTH_MFA_REQUIRED_BY_POLICY'],
  unavailable: [503, 'AUTH_UNAVAILABLE'],
};

const refuse = (response: Response, refusal: MfaRefusal): void => {
  const [status, code] = STATUS[refusal];
  if (status === 429) response.setHeader('retry-after', '900');
  if (status === 503) response.setHeader('retry-after', '15');
  response.status(status).json({ code });
};

const pageCode = (refusal: MfaRefusal): string =>
  refusal === 'invalid' || refusal === 'locked' || refusal === 'unavailable' ? refusal : 'expired';

const pageError = (value: string | undefined): MfaPageOptions['error'] =>
  value === 'invalid' || value === 'expired' || value === 'locked' || value === 'unavailable'
    ? value
    : undefined;

const lang = (body: Record<string, unknown>): 'en' | 'ar' => (body.lang === 'ar' ? 'ar' : 'en');

const optional = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() !== '' ? value : undefined;

const cookie = (request: Request, name: string): string | undefined => {
  const jar = (request as Request & { cookies?: Record<string, string> }).cookies;
  const value = jar?.[name];
  return value === undefined || value.trim() === '' ? undefined : value;
};

const userAgent = (request: Request): string | undefined => {
  const value = request.headers['user-agent'];
  return Array.isArray(value) ? value[0] : value;
};

const formTarget = (request: Request, body: Record<string, unknown>): string | undefined => {
  const type = request.headers['content-type'] ?? '';
  return type.includes('application/x-www-form-urlencoded')
    ? safeReturnTo(typeof body.returnTo === 'string' ? body.returnTo : undefined)
    : undefined;
};

export type { MfaPageState };
