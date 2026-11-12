import { Controller, Get, Inject, Req, Res } from '@nestjs/common';
import type { CachePort } from '@munaxa/interfaces';
import { RateLimiter, type RateLimitRule } from '@munaxa/security';
import type { Request, Response } from 'express';
import type { Logger } from 'pino';

import { LOGGER, SECURITY_STACK } from '../tokens.js';
import type { SecurityStack } from '../platform/security.js';
import { resolvePrincipal } from './principal.js';

/**
 * Whether an access token Identity issued still stands, for a product that verified it locally.
 *
 *     GET /api/auth/introspect      Authorization: Bearer <access token>
 *
 * **Why it exists.** A product such as Munaxa Work verifies Identity's JWTs with public keys and no
 * round trip. That proves the token is genuine and unexpired; it cannot prove the session behind it
 * is still live, because a JWT cannot be un-issued. Logout, revoking a session, revoking the others,
 * a password reset or change, an MFA removal and an account lockdown all end in state only Identity
 * holds — a revoked session row, a bumped token version, a disabled account. Without asking, a
 * product honours a signed-out token until it expires.
 *
 * **What it decides with.** `resolvePrincipal`, the same gate every authenticated Identity route
 * goes through, and nothing else. So "active" here means exactly what it means to Identity itself:
 * a verified token with a `sid`, an active account whose current token version equals the token's,
 * and a live session row that belongs to the token's subject in the token's organisation. There is
 * one definition of a revoked session, and a product cannot disagree with it.
 *
 * **What it answers.** `{ active: true, sub, tid, sid, exp }` or `{ active: false }`, in the shape of
 * RFC 7662. The echoed identifiers let the caller check the answer is about the token it holds; it
 * already holds every one of them in the token, so nothing is disclosed. No permission set, no
 * account record, no token. Every inactive reason is the same `{ active: false }`, because which
 * check failed is not the caller's business. `Cache-Control: no-store` on every answer: a shared
 * cache that kept an "active" would bring a revoked session back.
 *
 * **Why the caller needs no credential of its own.** The bearer token is the only input and the
 * answer is about that token alone. Somebody who holds a token learns whether it still works, which
 * they could learn by using it. It is a `GET` with no side effect, so the edge's origin check (for
 * state-changing methods) does not apply, and the edge's rate limits do.
 *
 * **When Identity cannot tell.** A database or cache failure is `503` with `Retry-After`, never
 * `{ active: false }` and never `{ active: true }`. The caller must treat it as "not verified" and
 * refuse; it must not cache it, because the next answer may be a real one.
 */
@Controller('auth')
export class TokenIntrospectionController {
  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(LOGGER) private readonly logger: Logger,
  ) {}

  @Get('introspect')
  public async introspect(@Req() request: Request, @Res() response: Response): Promise<void> {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('pragma', 'no-cache');

    const outcome = await introspectAccessToken(
      this.security,
      bearerOf(request),
      this.security.introspectionLimiter,
    );
    if (outcome.kind === 'limited') {
      response
        .status(429)
        .setHeader('retry-after', String(outcome.retryAfterSeconds))
        .json({ code: 'RATE_LIMITED' });
      return;
    }
    if (outcome.kind === 'unavailable') {
      // The token is never logged: it is a live credential until it expires.
      this.logger.error(
        { event: 'auth.introspection_unavailable' },
        'token introspection dependency unavailable',
      );
      response.status(503).setHeader('retry-after', '5').json({ code: 'AUTH_UNAVAILABLE' });
      return;
    }
    response.status(200).json(outcome.answer);
  }
}

export type IntrospectionAnswer =
  | {
      readonly active: true;
      readonly sub: string;
      readonly tid: string;
      readonly sid: string;
      readonly exp: number;
    }
  | { readonly active: false };

export type IntrospectionOutcome =
  | { readonly kind: 'answered'; readonly answer: IntrospectionAnswer }
  | { readonly kind: 'limited'; readonly retryAfterSeconds: number }
  | { readonly kind: 'unavailable' };

/** True for the introspection route, however the global prefix spells the path. */
export const isIntrospection = (path: string): boolean => path.endsWith('/auth/introspect');

/**
 * Per-account limit on introspection answers, applied once the token resolves to an account.
 *
 * The edge keys introspection by caller address, and every product task behind one NAT address
 * shares that key, so the edge limit is set high (`introspect-per-ip` in `platform/security.ts`)
 * and this one contains a single account: a product asks about each live token at most once per
 * cache window (5 s for Work), so 600 a minute is fifty concurrently live tokens. Past it, that
 * account's product requests are refused and nobody else's are.
 */
export const INTROSPECTION_RULES: readonly RateLimitRule[] = [
  { id: 'introspect-per-user', dimension: 'user', limit: 600, window: 60 * 1_000 },
];

export const createIntrospectionLimiter = (cache: CachePort): RateLimiter =>
  new RateLimiter({ cache, rules: [...INTROSPECTION_RULES] });

const INACTIVE: IntrospectionOutcome = { kind: 'answered', answer: { active: false } };

/**
 * The decision, apart from HTTP so it can be tested against the real stores.
 *
 * `resolvePrincipal` answers `{ ok: false }` for every credential-shaped refusal and *throws* when a
 * dependency fails, so the two are told apart here: a refusal is `active: false`, a throw is
 * `unavailable`. Folding the throw into `active: false` would make an outage look like a mass
 * logout to the caller, and folding it into `active: true` would make it a bypass.
 */
export const introspectAccessToken = async (
  security: Pick<SecurityStack, 'tokens' | 'sessions' | 'directory'>,
  accessToken: string | undefined,
  limiter?: Pick<RateLimiter, 'check'>,
): Promise<IntrospectionOutcome> => {
  if (accessToken === undefined) return INACTIVE;
  let resolved;
  try {
    resolved = await resolvePrincipal(security, accessToken);
  } catch {
    return { kind: 'unavailable' };
  }
  if (!resolved.ok) return INACTIVE;

  const { claims, sessionId, tenantId, userId } = resolved.principal;
  if (limiter !== undefined) {
    const decision = await limiter.check({
      method: 'GET',
      path: '/api/auth/introspect',
      tenantId,
      userId,
    });
    if (!decision.allowed)
      return { kind: 'limited', retryAfterSeconds: decision.retryAfterSeconds };
  }
  return {
    kind: 'answered',
    answer: { active: true, sub: userId, tid: tenantId, sid: sessionId, exp: claims.exp },
  };
};

/** `Authorization: Bearer <token>`, case-insensitive scheme, exactly one value. Anything else is none. */
const bearerOf = (request: Request): string | undefined => {
  const raw = request.headers.authorization;
  if (typeof raw !== 'string') return undefined;
  const match = /^Bearer[ ]+([^\s]+)$/i.exec(raw.trim());
  return match?.[1];
};
