import { Body, Controller, Get, HttpCode, Inject, Post, Query, Req, Res } from '@nestjs/common';
import { toCorrelationId } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';
import type { Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

import { clearSessionCookies } from '../auth/cookies.js';
import type { SecurityStack } from '../platform/security.js';
import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import {
  donePage,
  forgotPage,
  invalidLinkPage,
  resetPage,
  unavailablePage,
  type ForgotNotice,
  type Language,
} from '../ui/password-recovery.page.js';
import type { PasswordRecovery } from './password-recovery.js';

/**
 * The password-recovery API and pages.
 *
 *     GET  /api/auth/password/forgot   the request form
 *     POST /api/auth/password/forgot   ask for a link            202, whatever the address
 *     GET  /api/auth/password/reset    inspect a link            never consumes it
 *     POST /api/auth/password/reset    set the new password      consumes it, atomically
 *
 * Every route answers 404 when recovery is disabled, so a disabled deployment does not advertise
 * a feature it does not have, and 503 when it is enabled but cannot deliver, so nothing is
 * written that nobody will receive.
 *
 * Nothing here logs a token, a password, an address or a URL with a query string. The request log
 * records the path only, and the edge sets `Cache-Control: no-store` and `Referrer-Policy:
 * no-referrer` on every response.
 */
@Controller('auth/password')
export class PasswordRecoveryController {
  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
  ) {}

  private get recovery(): PasswordRecovery {
    return this.security.recovery;
  }

  private get defaultOrganisation(): string {
    return this.environment.IDENTITY_DEFAULT_ORGANISATION.trim();
  }

  @Get('forgot')
  public forgotForm(
    @Query('lang') lang: string | undefined,
    @Query('sent') sent: string | undefined,
    @Query('notice') notice: string | undefined,
    @Res() response: Response,
  ): void {
    const language = languageOf(lang);
    if (this.recovery.availability === 'disabled') {
      notFound(response);
      return;
    }
    if (this.recovery.availability === 'unavailable') {
      response.status(503).type('html').send(unavailablePage(language));
      return;
    }
    response
      .status(200)
      .type('html')
      .send(
        forgotPage({
          language,
          organisationRequired: this.defaultOrganisation === '',
          notice: sent === '1' ? 'sent' : knownNotice(notice),
        }),
      );
  }

  @Post('forgot')
  @HttpCode(202)
  public async requestReset(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const form = isForm(request);
    const language = languageOf(text(body.lang));
    const outcome = await this.recovery.request({
      organisation: text(body.organisation).trim() || this.defaultOrganisation,
      identifier: text(body.identifier),
      correlationId: toCorrelationId(correlation(request)),
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
    });

    switch (outcome.kind) {
      case 'disabled':
        notFound(response);
        return;
      case 'unavailable':
        response.setHeader('retry-after', '60');
        if (form) {
          response.status(503).type('html').send(unavailablePage(language));
          return;
        }
        response.status(503).json({ code: 'AUTH_RESET_UNAVAILABLE' });
        return;
      case 'rate-limited':
        response.setHeader('retry-after', String(outcome.retryAfterSeconds));
        if (form) {
          response.redirect(303, `/api/auth/password/forgot?lang=${language}&notice=limited`);
          return;
        }
        response
          .status(429)
          .json({ code: 'AUTH_RATE_LIMITED', retryAfterSeconds: outcome.retryAfterSeconds });
        return;
      default:
        // Identical for an address with an account, one without, a disabled account and an
        // organisation that does not exist: nothing about any of them has been looked at yet.
        if (form) {
          response.redirect(303, `/api/auth/password/forgot?lang=${language}&sent=1`);
          return;
        }
        response.status(202).json({ ok: true });
    }
  }

  /** Inspect a link. Renders the form or says the link is dead; never consumes it. */
  @Get('reset')
  public async inspect(
    @Query('org') org: string | undefined,
    @Query('token') token: string | undefined,
    @Query('lang') lang: string | undefined,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const language = languageOf(lang);
    const organisation = (org ?? '').trim() || this.defaultOrganisation;
    const state = await this.recovery
      .inspect({ organisation, token: token ?? '' })
      .catch(() => 'unavailable' as const);

    const json = wantsJson(request);
    if (state === 'disabled') {
      notFound(response);
      return;
    }
    if (state === 'unavailable') {
      if (json) {
        response.status(503).json({ code: 'AUTH_RESET_UNAVAILABLE' });
        return;
      }
      response.status(503).type('html').send(unavailablePage(language));
      return;
    }
    if (json) {
      response.status(200).json({ valid: state === 'valid' });
      return;
    }
    if (state === 'invalid') {
      response.status(200).type('html').send(invalidLinkPage(language));
      return;
    }
    response
      .status(200)
      .type('html')
      .send(resetPage({ language, organisation, token: token ?? '' }));
  }

  @Post('reset')
  @HttpCode(200)
  public async complete(
    @Body() body: Record<string, unknown>,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const form = isForm(request);
    const language = languageOf(text(body.lang));
    const organisation = text(body.organisation).trim() || this.defaultOrganisation;
    const token = text(body.token);
    const password = text(body.password);

    if (form && text(body.confirm) !== password) {
      response
        .status(400)
        .type('html')
        .send(resetPage({ language, organisation, token, error: 'mismatch' }));
      return;
    }

    const outcome = await this.recovery.complete({
      organisation,
      token,
      password,
      correlationId: toCorrelationId(correlation(request)),
      ...(request.ip === undefined ? {} : { ipAddress: request.ip }),
    });

    switch (outcome.kind) {
      case 'completed':
        // Every session of this account has just been revoked, possibly including this browser's.
        // Clearing the cookies is housekeeping, not security: the server already refuses them.
        clearSessionCookies(response);
        if (form) {
          response.status(200).type('html').send(donePage(language));
          return;
        }
        response.status(200).json({ ok: true });
        return;
      case 'invalid-token':
        if (form) {
          response.status(400).type('html').send(invalidLinkPage(language));
          return;
        }
        response.status(400).json({ code: 'AUTH_RESET_TOKEN_INVALID' });
        return;
      case 'password-rejected':
        if (form) {
          response
            .status(422)
            .type('html')
            .send(
              resetPage({
                language,
                organisation,
                token,
                error: outcome.code === 'AUTH_PASSWORD_BREACHED' ? 'breached' : 'policy',
              }),
            );
          return;
        }
        response.status(422).json({ code: outcome.code, violations: outcome.violations });
        return;
      case 'disabled':
        notFound(response);
        return;
      default:
        response.setHeader('retry-after', '30');
        if (form) {
          response
            .status(503)
            .type('html')
            .send(resetPage({ language, organisation, token, error: 'unavailable' }));
          return;
        }
        response.status(503).json({ code: 'AUTH_RESET_UNAVAILABLE' });
    }
  }
}

const notFound = (response: Response): void => {
  response.status(404).json({ code: 'NOT_FOUND' });
};

const text = (value: unknown): string => (typeof value === 'string' ? value : '');

const languageOf = (value: string | undefined): Language => (value === 'ar' ? 'ar' : 'en');

const knownNotice = (value: string | undefined): ForgotNotice =>
  value === 'limited' || value === 'unavailable' ? value : undefined;

const isForm = (request: Request): boolean =>
  (request.headers['content-type'] ?? '').includes('application/x-www-form-urlencoded');

const wantsJson = (request: Request): boolean =>
  (request.headers.accept ?? '').includes('application/json');

const correlation = (request: Request): string =>
  (request as Request & { correlationId?: string }).correlationId ?? randomUUID();
