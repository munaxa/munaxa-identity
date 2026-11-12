import { Inject, Injectable } from '@nestjs/common';
import type { AccessTokenClaims } from '@munaxa/auth';
import { isPlatformError } from '@munaxa/types';
import type { AuthMethod, CorrelationId, SessionId, TenantId, UserId } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';

import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';
import { resolvePrincipal, verifiedClaimsIgnoringExpiry } from './principal.js';

/**
 * The authentication flow, end to end.
 *
 * The single most consequential line in this file is `permissions: resolved.permissions`. Platform
 * emits the `perms` claim only when the caller passes it, and Platform's own reference login
 * example does not — so a service written by copying that example issues tokens that authenticate
 * perfectly and authorize nothing, and every Munaxa Work route answers 403 while the session looks
 * healthy. It is passed on **both** the login and the refresh path: resolving only at sign-in would
 * freeze somebody's permissions for the thirty-day life of a refresh lineage.
 */

/**
 * The Platform error codes that mean "this sign-in attempt was refused", as opposed to "the sign-in
 * machinery broke". Anything not in this set is treated as infrastructure; see `failureOf`.
 */
const AUTHENTICATION_OUTCOMES: ReadonlySet<string> = new Set([
  'AUTH_INVALID_CREDENTIALS',
  'AUTH_ACCOUNT_DISABLED',
  'AUTH_MFA_INVALID',
  'AUTH_MFA_REQUIRED',
  'AUTH_PASSWORD_BREACHED',
  'AUTH_PASSWORD_POLICY',
  'AUTH_PASSWORD_REUSED',
]);

export type LoginFailure =
  | { readonly kind: 'invalid-credentials' }
  /**
   * The security infrastructure is unavailable — not the caller's credentials.
   *
   * Kept distinct from `invalid-credentials` because collapsing them tells an operator the wrong
   * thing at the worst moment: with Redis stopped every sign-in answered 401, indistinguishable
   * from a room full of people mistyping their passwords. It discloses nothing new — a stranger
   * learns the service is unwell, which the readiness probe already says out loud, and learns
   * nothing about whether any account exists.
   */
  | { readonly kind: 'dependency-unavailable'; readonly dependency: 'cache' | 'database' }
  /**
   * The password was right and a second factor is needed. `challenge` is present when MFA is
   * available: `verify` for an enrolled account, `enroll` when policy requires MFA and none is
   * enrolled. Absent, MFA is unavailable in this deployment and the sign-in is simply refused.
   */
  | {
      readonly kind: 'mfa-required';
      readonly challenge?: {
        readonly token: string;
        readonly kind: 'verify' | 'enroll';
        readonly ttlMs: number;
      };
    }
  | { readonly kind: 'password-change-required' }
  | { readonly kind: 'rate-limited'; readonly retryAfterSeconds: number }
  | { readonly kind: 'unknown-organisation' };

export type LoginResult =
  | {
      readonly ok: true;
      readonly access: string;
      readonly refresh: string;
      readonly claims: AccessTokenClaims;
    }
  | { readonly ok: false; readonly failure: LoginFailure };

export interface LoginRequest {
  readonly identifier: string;
  readonly password: string;
  readonly organisation?: string | undefined;
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
  readonly correlationId: CorrelationId;
}

export interface RefreshRequest {
  readonly refreshToken: string;
  readonly organisation?: string | undefined;
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
}

@Injectable()
export class AuthService {
  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
    private readonly prisma: PrismaService,
  ) {}

  public get sessionCookieMaxAge(): number {
    return this.environment.SESSION_COOKIE_MAX_AGE;
  }

  /** Whether the sign-in form must ask which organisation somebody belongs to. */
  public get hasDefaultOrganisation(): boolean {
    return this.environment.IDENTITY_DEFAULT_ORGANISATION.trim() !== '';
  }

  /**
   * Resolve the organisation a sign-in belongs to.
   *
   * Every Platform port method takes a tenant as its first argument, so this has to happen before
   * an account can be looked up at all. An unknown slug produces the same generic refusal as a
   * wrong password: telling a stranger which organisations exist is a disclosure, and telling them
   * that one exists but their password is wrong is two.
   */
  private async organisation(slug: string | undefined): Promise<TenantId | undefined> {
    const key = (slug ?? this.environment.IDENTITY_DEFAULT_ORGANISATION).trim();
    return key === '' ? undefined : this.security.tenants.idForKey(key);
  }

  /**
   * Sign in.
   *
   * The whole body is classified, not just the call to `authenticate`. Phase 11 taught this the
   * expensive way: the dependency probe was wrapped around the authentication call alone, so a
   * cache outage produced a clean 503 while a *database* outage escaped as an unhandled 500 —
   * from `organisation` above, which must run before any account can be looked up, and from the
   * session write below. Both are database work, and both were outside the one try that knew what
   * a dependency failure looks like.
   *
   * It still never fails open: `failureOf` returns a generic refusal when every dependency answers
   * and the error is unrecognised, so an unexplained failure anywhere in this method is a refusal.
   */
  public async login(request: LoginRequest): Promise<LoginResult> {
    try {
      return await this.attemptLogin(request);
    } catch (error) {
      return { ok: false, failure: await this.failureOf(error) };
    }
  }

  private async attemptLogin(request: LoginRequest): Promise<LoginResult> {
    const tenantId = await this.organisation(request.organisation);
    if (tenantId === undefined) {
      return { ok: false, failure: { kind: 'unknown-organisation' } };
    }

    // Trimmed here, because the directory finds the account by the trimmed, lowercased identifier
    // while Platform 2.4.1 keys the lockout by the lowercased one only: `" victim@x"` found the same
    // account under a fresh lockout counter, so every respelling handed back a full set of guesses.
    const identifier = request.identifier.trim();
    let outcome;
    try {
      outcome = await this.security.login.authenticate(identifier, request.password, {
        tenantId,
        correlationId: request.correlationId,
        ...(request.ipAddress === undefined ? {} : { ipAddress: request.ipAddress }),
        ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
      });
    } catch (error) {
      return { ok: false, failure: await this.failureOf(error) };
    }

    if (outcome.status === 'mfa-required') {
      // No session and no token yet: only a short-lived challenge the MFA routes can redeem. With
      // MFA unavailable (no key ring, development only) there is nothing to redeem it with, so the
      // sign-in is refused — never admitted without the factor.
      if (this.security.mfa === undefined) {
        return { ok: false, failure: { kind: 'mfa-required' } };
      }
      const kind = outcome.account.mfaEnrolled ? 'verify' : 'enroll';
      const issued = await this.security.mfaChallenges.issue({
        kind,
        tenantId,
        userId: outcome.account.userId,
        tokenVersion: outcome.account.tokenVersion,
        userAgent: request.userAgent,
      });
      return {
        ok: false,
        failure: {
          kind: 'mfa-required',
          challenge: {
            token: issued.token,
            kind,
            ttlMs: this.security.mfaChallenges.ttlOf(kind),
          },
        },
      };
    }
    if (outcome.status === 'password-change-required') {
      return { ok: false, failure: { kind: 'password-change-required' } };
    }

    const { account } = outcome;
    return this.completeSignIn({
      tenantId,
      userId: account.userId,
      tokenVersion: account.tokenVersion,
      authMethods: outcome.authMethods,
      mfaSatisfied: false,
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
    });
  }

  /**
   * Create the session and mint its tokens. The one place a sign-in becomes a session — after a
   * password alone (no factor required), or after `MfaFlowService` has redeemed a challenge, in
   * which case the methods actually used and `mfaSatisfied: true` are recorded on the session and
   * carried into the token's `amr` and `mfa` claims.
   */
  public async completeSignIn(input: {
    readonly tenantId: TenantId;
    readonly userId: UserId;
    readonly tokenVersion: number;
    readonly authMethods: readonly AuthMethod[];
    readonly mfaSatisfied: boolean;
    readonly ipAddress?: string | undefined;
    readonly userAgent?: string | undefined;
  }): Promise<LoginResult> {
    const session = await this.security.sessions.create({
      tenantId: input.tenantId,
      userId: input.userId,
      authMethods: input.authMethods,
      mfaSatisfied: input.mfaSatisfied,
      tokenVersion: input.tokenVersion,
      ...(input.ipAddress === undefined ? {} : { ipAddress: input.ipAddress }),
      ...(input.userAgent === undefined ? {} : { userAgent: input.userAgent }),
    });

    return this.issue(input.tenantId, input.userId, input.tokenVersion, session.id, undefined, {
      authMethods: session.authMethods,
      mfaSatisfied: session.mfaSatisfied,
    });
  }

  /** Rotate a session. Classified end to end for the same reason `login` is. */
  public async refresh(request: RefreshRequest): Promise<LoginResult> {
    try {
      return await this.attemptRefresh(request);
    } catch (error) {
      return { ok: false, failure: await this.failureOf(error) };
    }
  }

  private async attemptRefresh(request: RefreshRequest): Promise<LoginResult> {
    const tenantId = await this.organisation(request.organisation);
    if (tenantId === undefined) {
      return { ok: false, failure: { kind: 'unknown-organisation' } };
    }

    let rotation;
    try {
      // Reuse detection lives here: a token that has already been rotated revokes its whole
      // lineage inside `rotate`, and the caller sees a refusal rather than a new token.
      rotation = await this.security.refreshTokens.rotate(tenantId, request.refreshToken);
    } catch {
      return { ok: false, failure: { kind: 'invalid-credentials' } };
    }

    const { record } = rotation.issued;
    const sessionId = record.sessionId;

    // Identity binds every lineage to a session at sign-in. One without a session is a lineage no
    // user can see in their session list or sign out, so it is refused rather than honoured.
    if (sessionId === undefined) {
      await this.security.refreshTokens.revokeFamily(tenantId, record.familyId, 'admin-revoked');
      return { ok: false, failure: { kind: 'invalid-credentials' } };
    }

    // The account first, because its *current* token version is what everything else is held to.
    // A reset, a disablement or an MFA removal bumps it; a lineage minted before the bump is dead,
    // and so is the session it belonged to. Comparing the refresh record with the session — both
    // copied from the account at sign-in — would compare two copies of the old value and pass.
    const account = await this.security.directory.findById(tenantId, record.userId);
    if (
      account === undefined ||
      account.status !== 'active' ||
      account.tokenVersion !== record.tokenVersion
    ) {
      const reason =
        account !== undefined && account.status === 'active'
          ? 'password-changed'
          : 'account-disabled';
      await this.security.revocation.revokeSession(tenantId, record.userId, sessionId, reason);
      await this.security.refreshTokens.revokeFamily(tenantId, record.familyId, reason);
      return { ok: false, failure: { kind: 'invalid-credentials' } };
    }

    // The session is re-checked on every rotation. A refresh is the one moment a revoked session
    // can be caught before the access token's lifetime runs out, and rotation must never be a way
    // to bring a revoked session back: the new token in this lineage dies here on its first use.
    const validation = await this.security.sessions.validate(tenantId, sessionId, {
      tokenVersion: account.tokenVersion,
    });
    if (!validation.valid || validation.session.userId !== record.userId) {
      await this.security.refreshTokens.revokeFamily(
        tenantId,
        record.familyId,
        validation.valid ? 'token-reuse' : validation.reason,
      );
      return { ok: false, failure: { kind: 'invalid-credentials' } };
    }

    // `touch` re-reads the row, and the store writes only an unrevoked one, so a revocation that
    // committed after the check above is caught here as well and is a refusal too. What remains is
    // the gap between touch's own read and the mint below: a revocation landing inside it lets one
    // access token out, which every Identity route then refuses (`resolvePrincipal` validates the
    // session) and which no refresh can extend, because this lineage's next rotation fails above.
    const touched = await this.security.sessions.touch(tenantId, sessionId, {
      ...(request.ipAddress === undefined ? {} : { ipAddress: request.ipAddress }),
      ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
    });
    if (touched === undefined) {
      await this.security.refreshTokens.revokeFamily(tenantId, record.familyId, 'logout');
      return { ok: false, failure: { kind: 'invalid-credentials' } };
    }

    return this.issue(
      tenantId,
      account.userId,
      account.tokenVersion,
      sessionId,
      rotation.issued.token,
      // The factors are the session's, fixed at sign-in; a refresh can neither add nor drop one.
      {
        authMethods: validation.session.authMethods,
        mfaSatisfied: validation.session.mfaSatisfied,
      },
    );
  }

  /**
   * Ends the session and its refresh lineage. Never fails because a token has expired, and never
   * fails at all from the caller's point of view: signing out twice, or signing out with no
   * session, is the same success.
   *
   * The access token must be one Identity signed — its expiry is the only check relaxed (see
   * `verifiedClaimsIgnoringExpiry`). This used to read the token with `decodeUnsafe`, which meant a
   * forged token naming somebody else's `sid` signed that person out. Now nothing happens on the
   * strength of a token Identity did not issue.
   */
  public async logout(input: {
    readonly refreshToken?: string | undefined;
    readonly accessToken?: string | undefined;
  }): Promise<void> {
    const claims = verifiedClaimsIgnoringExpiry(this.security, input.accessToken);
    const tenantId = claims?.tid;

    if (tenantId !== undefined && input.refreshToken !== undefined) {
      await this.security.refreshTokens
        .revoke(tenantId, input.refreshToken, 'logout')
        .catch(() => false);
    }
    if (tenantId !== undefined && claims?.sid !== undefined) {
      // The session row and every refresh token bound to it, in one transaction.
      await this.security.revocation
        .revokeSession(tenantId, claims.sub as UserId, claims.sid as SessionId, 'logout')
        .catch(() => false);
    }
  }

  /** The minimum a signed-in browser may be told about itself. Never a token, never a permission set. */
  public async session(
    accessToken: string | undefined,
  ): Promise<
    | { readonly signedIn: false }
    | { readonly signedIn: true; readonly subject: string; readonly expiresAt: number }
  > {
    try {
      // The same gate every authenticated route uses: a revoked session, a disabled account or a
      // token minted before a version bump all read as signed out here too.
      const resolved = await resolvePrincipal(this.security, accessToken);
      if (!resolved.ok) return { signedIn: false };
      const { claims } = resolved.principal;
      return { signedIn: true, subject: claims.sub, expiresAt: claims.exp * 1_000 };
    } catch {
      return { signedIn: false };
    }
  }

  /**
   * Resolve permissions, then mint. The order is the contract.
   */
  private async issue(
    tenantId: TenantId,
    userId: UserId,
    tokenVersion: number,
    sessionId: SessionId | undefined,
    existingRefresh?: string,
    factors?: { readonly authMethods: readonly string[]; readonly mfaSatisfied: boolean },
  ): Promise<LoginResult> {
    const resolved = await this.security.resolver.resolve(tenantId, userId);

    const access = this.security.tokens.issueAccessToken({
      subject: userId,
      tenantId,
      tokenVersion,
      permissions: resolved.permissions,
      ...(sessionId === undefined ? {} : { sessionId }),
      ...(factors === undefined
        ? {}
        : { authMethods: factors.authMethods, mfaSatisfied: factors.mfaSatisfied }),
    });

    const refresh =
      existingRefresh ??
      (
        await this.security.refreshTokens.issue({
          tenantId,
          userId,
          tokenVersion,
          ...(sessionId === undefined ? {} : { sessionId }),
        })
      ).token;

    return { ok: true, access: access.token, refresh, claims: access.claims };
  }

  /**
   * Decide what a thrown sign-in error actually was.
   *
   * Platform's authentication errors are a closed vocabulary — `AUTH_INVALID_CREDENTIALS`,
   * `AUTH_ACCOUNT_DISABLED`, `AUTH_ACCOUNT_LOCKED`, the MFA and password-policy codes. Anything
   * outside it is not an authentication outcome at all; it is the machinery underneath having
   * failed. So rather than pattern-matching connection errors by message — which is guesswork that
   * rots the first time a driver rewords something — an unrecognised error is answered by *asking
   * the dependencies whether they are alive*. That is deterministic, and it costs one round trip
   * on a path that has already failed.
   *
   * It never fails open. When every dependency answers and the error is still unrecognised, the
   * caller gets the same generic refusal as a wrong password: an unexplained failure inside the
   * security stack is a refusal, not a pass.
   */
  private async failureOf(error: unknown): Promise<LoginFailure> {
    if (isPlatformError(error) && error.code === 'AUTH_ACCOUNT_LOCKED') {
      // The one refusal that is not generic, and has to be: a caller being throttled needs to know
      // to stop, and that they are being throttled reveals nothing about whether the account exists
      // — lockout is keyed by a digest of the identifier precisely so a guess at an address that
      // does not exist is throttled too.
      const retry = (error.details as { retryAfterSeconds?: number } | undefined)
        ?.retryAfterSeconds;
      return { kind: 'rate-limited', retryAfterSeconds: retry ?? 900 };
    }

    if (isPlatformError(error) && AUTHENTICATION_OUTCOMES.has(error.code)) {
      return { kind: 'invalid-credentials' };
    }

    if (!(await this.security.cacheReachable())) {
      return { kind: 'dependency-unavailable', dependency: 'cache' };
    }
    if (!(await this.databaseReachable())) {
      return { kind: 'dependency-unavailable', dependency: 'database' };
    }

    return { kind: 'invalid-credentials' };
  }

  private async databaseReachable(): Promise<boolean> {
    try {
      await this.prisma.$queryRaw`select 1`;
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Every credential failure looks the same from outside.
 *
 * A wrong password, an unknown identifier and a disabled account are one answer, because any
 * difference between them is an oracle: it tells somebody enumerating addresses which ones are
 * real. Rate limiting is the exception and has to be — a caller who is being throttled needs to
 * know to stop, and the fact that they are being throttled reveals nothing about the account.
 */
