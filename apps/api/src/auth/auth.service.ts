import { Inject, Injectable } from '@nestjs/common';
import type { AccessTokenClaims } from '@munaxa/auth';
import { isPlatformError } from '@munaxa/types';
import type { CorrelationId, SessionId, TenantId, UserId } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';

import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import type { SecurityStack } from '../platform/security.js';

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

export type LoginFailure =
  | { readonly kind: 'invalid-credentials' }
  | { readonly kind: 'mfa-required' }
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

  public async login(request: LoginRequest): Promise<LoginResult> {
    const tenantId = await this.organisation(request.organisation);
    if (tenantId === undefined) {
      return { ok: false, failure: { kind: 'unknown-organisation' } };
    }

    let outcome;
    try {
      outcome = await this.security.login.authenticate(request.identifier, request.password, {
        tenantId,
        correlationId: request.correlationId,
        ...(request.ipAddress === undefined ? {} : { ipAddress: request.ipAddress }),
        ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
      });
    } catch (error) {
      return { ok: false, failure: failureOf(error) };
    }

    if (outcome.status === 'mfa-required') {
      return { ok: false, failure: { kind: 'mfa-required' } };
    }
    if (outcome.status === 'password-change-required') {
      return { ok: false, failure: { kind: 'password-change-required' } };
    }

    const { account } = outcome;
    const session = await this.security.sessions.create({
      tenantId,
      userId: account.userId,
      authMethods: outcome.authMethods,
      mfaSatisfied: false,
      tokenVersion: account.tokenVersion,
      ...(request.ipAddress === undefined ? {} : { ipAddress: request.ipAddress }),
      ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
    });

    return this.issue(tenantId, account.userId, account.tokenVersion, session.id);
  }

  public async refresh(request: RefreshRequest): Promise<LoginResult> {
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

    // The session, the account status and the token version are all re-checked. A refresh is the
    // one moment a revoked session or a disabled account can be caught before the access token's
    // lifetime runs out, and skipping it would waste the only chance.
    if (sessionId !== undefined) {
      const validation = await this.security.sessions.validate(tenantId, sessionId, {
        tokenVersion: record.tokenVersion,
      });
      if (!validation.valid) {
        await this.security.refreshTokens.revokeFamily(
          tenantId,
          record.familyId,
          validation.reason,
        );
        return { ok: false, failure: { kind: 'invalid-credentials' } };
      }
      await this.security.sessions.touch(tenantId, sessionId, {
        ...(request.ipAddress === undefined ? {} : { ipAddress: request.ipAddress }),
        ...(request.userAgent === undefined ? {} : { userAgent: request.userAgent }),
      });
    }

    const account = await this.security.directory.findById(tenantId, record.userId);
    if (account === undefined || account.status !== 'active') {
      await this.security.refreshTokens.revokeFamily(tenantId, record.familyId, 'account-disabled');
      return { ok: false, failure: { kind: 'invalid-credentials' } };
    }

    return this.issue(
      tenantId,
      account.userId,
      account.tokenVersion,
      sessionId,
      rotation.issued.token,
    );
  }

  /** Ends the session and its refresh lineage. Never fails because a token has expired. */
  public async logout(input: {
    readonly refreshToken?: string | undefined;
    readonly accessToken?: string | undefined;
  }): Promise<void> {
    const claims =
      input.accessToken === undefined
        ? undefined
        : this.security.tokens.decodeUnsafe(input.accessToken);

    // `decodeUnsafe` is used, and the name is honest about what it is: the token may be expired,
    // forged or truncated. Nothing is *granted* on the strength of it — the worst a forged token
    // achieves here is revoking a session the forger already named, which they could do by signing
    // out normally. Requiring a valid token instead would mean logout stops working exactly when a
    // user most wants it to.
    const tenantId = claims?.tid;

    if (tenantId !== undefined && input.refreshToken !== undefined) {
      await this.security.refreshTokens
        .revoke(tenantId, input.refreshToken, 'logout')
        .catch(() => false);
    }
    if (tenantId !== undefined && claims?.sid !== undefined) {
      await this.security.sessions
        .revoke(tenantId, claims.sid as SessionId, 'logout')
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
    if (accessToken === undefined) return { signedIn: false };
    try {
      const claims = this.security.tokens.verifyAccessToken(accessToken);
      const validation =
        claims.sid === undefined
          ? undefined
          : await this.security.sessions.validate(claims.tid, claims.sid as SessionId);

      if (validation !== undefined && !validation.valid) return { signedIn: false };
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
  ): Promise<LoginResult> {
    const resolved = await this.security.resolver.resolve(tenantId, userId);

    const access = this.security.tokens.issueAccessToken({
      subject: userId,
      tenantId,
      tokenVersion,
      permissions: resolved.permissions,
      ...(sessionId === undefined ? {} : { sessionId }),
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
}

/**
 * Every credential failure looks the same from outside.
 *
 * A wrong password, an unknown identifier and a disabled account are one answer, because any
 * difference between them is an oracle: it tells somebody enumerating addresses which ones are
 * real. Rate limiting is the exception and has to be — a caller who is being throttled needs to
 * know to stop, and the fact that they are being throttled reveals nothing about the account.
 */
const failureOf = (error: unknown): LoginFailure => {
  if (isPlatformError(error) && error.code === 'AUTH_ACCOUNT_LOCKED') {
    // The one refusal that is not generic, and has to be: a caller being throttled needs to know
    // to stop, and that they are being throttled reveals nothing about whether the account exists
    // — lockout is keyed by a digest of the identifier precisely so a guess at an address that
    // does not exist is throttled too.
    const retry = (error.details as { retryAfterSeconds?: number } | undefined)?.retryAfterSeconds;
    return { kind: 'rate-limited', retryAfterSeconds: retry ?? 900 };
  }
  return { kind: 'invalid-credentials' };
};
