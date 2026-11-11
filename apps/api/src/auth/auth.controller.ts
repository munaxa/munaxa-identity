import { Body, Controller, Get, HttpCode, Inject, Post, Query, Req, Res } from '@nestjs/common';
import type { Logger } from 'pino';
import { toCorrelationId } from '@munaxa/types';
import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { LOGGER } from '../tokens.js';
import { signInPage } from '../ui/sign-in.page.js';
import { AuthService, type LoginFailure } from './auth.service.js';
import {
  REFRESH_COOKIE,
  SESSION_COOKIE,
  clearSessionCookies,
  issueChallengeCookie,
  issueCookies,
} from './cookies.js';

/**
 * The authentication API.
 *
 * Every route here is reachable without a credential, because they are how a caller *obtains* one;
 * requiring a token to sign in would be circular, and requiring a valid one to sign out would mean
 * logout stops working exactly when somebody most wants it to.
 *
 * Nothing on this controller returns a token in a body. The access token exists in one place a
 * browser can hold it — an `httpOnly` cookie — and returning it as JSON would put it somewhere
 * client JavaScript can read, which is the whole thing the cookie design avoids.
 */
@Controller('auth')
export class AuthController {
  public constructor(
    private readonly auth: AuthService,
    @Inject(LOGGER) private readonly logger: Logger,
  ) {}

  /**
   * Record an infrastructure refusal where an operator will see it.
   *
   * The caller is told only `AUTH_UNAVAILABLE`; which dependency failed goes here, in a structured
   * field, alongside the correlation id that ties it to the request. No identifier and no password
   * — the whole point of a 503 is that the credential was never examined.
   */
  private noteUnavailable(request: Request, failure: LoginFailure): void {
    if (failure.kind !== 'dependency-unavailable') return;
    this.logger.error(
      {
        event: 'auth.dependency_unavailable',
        dependency: failure.dependency,
        correlationId: correlation(request),
      },
      'authentication dependency unavailable',
    );
  }

  /**
   * The sign-in page.
   *
   * Served by the service that owns the credential, so the password goes from the form straight to
   * the only process that can check it. Under the staging topology this and the portal share one
   * public origin, which is what lets the `__Host-` cookie the response sets be readable by the
   * portal at all — and what keeps Munaxa Work from ever handling a password.
   */
  @Get('login')
  public signIn(
    @Query('lang') language: string | undefined,
    @Query('returnTo') returnTo: string | undefined,
    @Query('error') error: string | undefined,
    @Res() response: Response,
  ): void {
    response
      .status(200)
      .type('html')
      .send(
        signInPage({
          language: language === 'ar' ? 'ar' : 'en',
          returnTo: safeReturnTo(returnTo),
          error: knownError(error),
          organisationRequired: !this.auth.hasDefaultOrganisation,
        }),
      );
  }

  @Post('login')
  @HttpCode(200)
  public async login(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const result = await this.auth.login({
      identifier: text(body.identifier),
      password: text(body.password),
      organisation: optional(body.organisation),
      correlationId: toCorrelationId(correlation(request)),
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
      ...(userAgent(request) === undefined ? {} : { userAgent: userAgent(request) }),
    });

    const form = wantsHtml(request, body);

    if (!result.ok) {
      this.noteUnavailable(request, result.failure);
      const challenge =
        result.failure.kind === 'mfa-required' ? result.failure.challenge : undefined;
      if (challenge !== undefined) {
        // The password was right. No session exists yet: only a short-lived challenge cookie the
        // MFA routes can redeem.
        issueChallengeCookie(response, challenge.token, Math.ceil(challenge.ttlMs / 1_000));
        response.setHeader('cache-control', 'no-store');
        if (form !== undefined) {
          const language = typeof body.lang === 'string' && body.lang === 'ar' ? 'ar' : 'en';
          const page = challenge.kind === 'verify' ? '/api/auth/mfa' : '/api/auth/mfa/enroll';
          response.redirect(303, `${page}?lang=${language}&returnTo=${encodeURIComponent(form)}`);
          return;
        }
        response.status(401).json({
          code: challenge.kind === 'verify' ? 'AUTH_MFA_REQUIRED' : 'AUTH_MFA_ENROLLMENT_REQUIRED',
          expiresInSeconds: Math.ceil(challenge.ttlMs / 1_000),
        });
        return;
      }
      if (form !== undefined) {
        // A form post gets a page, not JSON. The reason is carried as a coarse code — the four the
        // page can render — never as a message, and never distinguishing a wrong password from an
        // address that does not exist.
        const language = typeof body.lang === 'string' && body.lang === 'ar' ? 'ar' : 'en';
        response.redirect(
          303,
          `/api/auth/login?lang=${language}&error=${reasonCode(result.failure)}&returnTo=${encodeURIComponent(form)}`,
        );
        return;
      }
      refuse(response, result.failure);
      return;
    }
    issueCookies(response, result, this.auth.sessionCookieMaxAge);

    if (form !== undefined) {
      response.redirect(303, form);
      return;
    }
    response.json({ ok: true });
  }

  @Post('refresh')
  @HttpCode(200)
  public async refresh(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const token = cookie(request, REFRESH_COOKIE);
    if (token === undefined) {
      refuse(response, { kind: 'invalid-credentials' });
      return;
    }
    const result = await this.auth.refresh({
      refreshToken: token,
      // A refresh may name a different organisation: the session spans organisations, the access
      // token does not, and switching is what makes a person who belongs to two usable.
      organisation: optional(body.organisation),
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
      ...(userAgent(request) === undefined ? {} : { userAgent: userAgent(request) }),
    });

    if (!result.ok) {
      this.noteUnavailable(request, result.failure);
      // A failed refresh clears the cookies. Leaving them would send the browser back with the
      // same dead credential on every navigation.
      clearSessionCookies(response);
      refuse(response, result.failure);
      return;
    }
    issueCookies(response, result, this.auth.sessionCookieMaxAge);
    response.json({ ok: true });
  }

  @Post('logout')
  @HttpCode(200)
  public async logout(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.auth.logout({
      refreshToken: cookie(request, REFRESH_COOKIE),
      accessToken: cookie(request, SESSION_COOKIE),
    });
    clearSessionCookies(response);
    // Always 200, including for a caller who was never signed in: "you are signed out" is true
    // either way, and an error would leave a browser holding cookies it cannot clear.
    response.json({ ok: true });
  }

  /**
   * What the sign-in UI needs to render a header, and nothing else.
   *
   * No token, no permission set, no account record: a page that knows the subject and when the
   * session ends can show "signed in as" and schedule a refresh, and anything more would be a
   * second place a token or a grant list exists.
   */
  @Get('session')
  public async session(@Req() request: Request): Promise<Record<string, unknown>> {
    return this.auth.session(cookie(request, SESSION_COOKIE));
  }
}

/** The status and body for each refusal. Everything credential-shaped answers identically. */
const refuse = (response: Response, failure: LoginFailure): void => {
  switch (failure.kind) {
    case 'rate-limited':
      response
        .status(429)
        .setHeader('retry-after', String(failure.retryAfterSeconds))
        .json({ code: 'AUTH_RATE_LIMITED', retryAfterSeconds: failure.retryAfterSeconds });
      return;
    case 'mfa-required':
      response.status(401).json({ code: 'AUTH_MFA_REQUIRED' });
      return;
    case 'password-change-required':
      response.status(401).json({ code: 'AUTH_PASSWORD_POLICY' });
      return;
    case 'dependency-unavailable':
      // 503 and a Retry-After, because this is not the caller's fault and a client that retries in
      // a moment is doing the right thing. The body names no dependency: which piece of our
      // machinery is unwell is an operational detail, and the log line carries it instead.
      response.status(503).setHeader('retry-after', '15').json({ code: 'AUTH_UNAVAILABLE' });
      return;
    default:
      // `unknown-organisation` lands here too. Telling a stranger which organisations exist is a
      // disclosure, and telling them one exists but the password was wrong is two.
      response.status(401).json({ code: 'AUTH_INVALID_CREDENTIALS' });
  }
};

const text = (value: unknown): string => (typeof value === 'string' ? value : '');
const optional = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() !== '' ? value : undefined;

const cookie = (request: Request, name: string): string | undefined => {
  const jar = (request as Request & { cookies?: Record<string, string> }).cookies;
  const value = jar?.[name];
  return value === undefined || value.trim() === '' ? undefined : value;
};

const correlation = (request: Request): string =>
  (request as Request & { correlationId?: string }).correlationId ?? randomUUID();

const userAgent = (request: Request): string | undefined => {
  const value = request.headers['user-agent'];
  return Array.isArray(value) ? value[0] : value;
};

/** The four reasons the sign-in page can render. Everything credential-shaped is `invalid`. */
const reasonCode = (failure: LoginFailure): string => {
  switch (failure.kind) {
    case 'rate-limited':
      return 'locked';
    case 'mfa-required':
      return 'mfa';
    case 'password-change-required':
      return 'password-policy';
    case 'dependency-unavailable':
      return 'unavailable';
    default:
      return 'invalid';
  }
};

const knownError = (
  value: string | undefined,
): 'invalid' | 'locked' | 'mfa' | 'password-policy' | 'unavailable' | undefined =>
  value === 'invalid' ||
  value === 'locked' ||
  value === 'mfa' ||
  value === 'password-policy' ||
  value === 'unavailable'
    ? value
    : undefined;

/**
 * Where to send a browser after signing in.
 *
 * Only a path within the shared public origin is honoured. An absolute URL, or anything beginning
 * `//`, would make the sign-in page an open redirect — a phishing landing spot on a URL that
 * genuinely starts with our own domain, reached through the one page users are trained to trust.
 *
 * A backslash anywhere is refused too. Browsers (WHATWG URL parsing) treat `\` as `/` in an http(s)
 * URL, so `/\evil.example` is the scheme-relative `//evil.example` in disguise, and Express sends
 * it in `Location` unencoded. Control characters are refused because browsers strip tab and newline
 * before parsing, which turns `/<TAB>/evil.example` into `//evil.example` the same way.
 */
export const safeReturnTo = (requested: string | undefined): string =>
  requested !== undefined &&
  requested.startsWith('/') &&
  !requested.startsWith('//') &&
  !requested.includes('\\') &&
  !/[\u0000-\u001f\u007f]/.test(requested)
    ? requested
    : '/';

/**
 * The destination for a form post, or `undefined` for an API caller.
 *
 * Decided from the request rather than from a query parameter: a browser posting a form sends
 * `application/x-www-form-urlencoded`, and an API client sends JSON. Nothing else distinguishes
 * them, and nothing else needs to.
 */
const wantsHtml = (request: Request, body: Record<string, unknown>): string | undefined => {
  const type = request.headers['content-type'] ?? '';
  return type.includes('application/x-www-form-urlencoded')
    ? safeReturnTo(typeof body.returnTo === 'string' ? body.returnTo : undefined)
    : undefined;
};
