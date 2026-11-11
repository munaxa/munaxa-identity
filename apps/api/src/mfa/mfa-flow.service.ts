import { Inject, Injectable } from '@nestjs/common';
import { anonymousAuditEvent } from '@munaxa/audit';
import { defaultPasswordHasher, dummyPasswordHash, recoveryCode, sha256Hex } from '@munaxa/crypto';
import {
  isPlatformError,
  toCorrelationId,
  type AuthMethod,
  type SecurityEventName,
  type TenantId,
  type UserId,
} from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';

import { AuthService, type LoginResult } from '../auth/auth.service.js';
import { resolvePrincipal, type Principal } from '../auth/principal.js';
import type { SecurityStack } from '../platform/security.js';
import { ENVIRONMENT, SECURITY_STACK } from '../tokens.js';
import type { ChallengeRecord } from './mfa-challenges.js';
import type { IdentityMfa } from './mfa-runtime.js';

/**
 * The MFA flows: the sign-in challenge, enrollment, reauthentication, recovery codes, removal.
 *
 * Every TOTP and recovery-code check is Platform's `MfaService` (via `IdentityMfa`); this class
 * decides *who may ask* and *what happens after*. The rules it enforces:
 *
 * - A pending challenge is never a credential. It is redeemed here, once, and only then does
 *   `AuthService.completeSignIn` create a session — with the methods actually used and
 *   `mfaSatisfied: true`.
 * - An `enroll` challenge admits to enrollment and nothing else, and only for an account with no
 *   active factor.
 * - Enrolling through a session, replacing, removing and regenerating recovery codes all require a
 *   recent reauthentication of that session; the marker is spent by the change it authorised.
 * - Wrong answers count against the challenge and against the account; either limit ends the
 *   attempt. Nothing returned or logged ever contains a secret, a code or a token.
 */

export type Actor =
  | { readonly via: 'session'; readonly principal: Principal }
  | { readonly via: 'challenge'; readonly token: string; readonly record: ChallengeRecord };

export type MfaRefusal =
  | 'unauthenticated'
  | 'expired'
  | 'invalid'
  | 'locked'
  | 'reauth-required'
  | 'not-enrolled'
  | 'already-enrolled'
  | 'required-by-policy'
  | 'unavailable';

export type Outcome<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly refusal: MfaRefusal };

const refuse = <T>(refusal: MfaRefusal): Outcome<T> => ({ ok: false, refusal });
const ok = <T>(value: T): Outcome<T> => ({ ok: true, value });

export interface RequestContext {
  readonly userAgent?: string | undefined;
  readonly ipAddress?: string | undefined;
  readonly correlationId: string;
}

/** `abcde fghij klmno`, `ABCDEFGHIJKLMNO` and `abcde-fghij-klmno` are the same code. */
export const normaliseRecoveryCode = (input: string): string => {
  const compact = input.toUpperCase().replaceAll(/[^A-Z0-9]/g, '');
  return compact.length === 15
    ? `${compact.slice(0, 5)}-${compact.slice(5, 10)}-${compact.slice(10)}`
    : input.trim().toUpperCase();
};

/** A six-digit code, possibly typed with a space in the middle. */
const normaliseTotp = (input: string): string => input.replaceAll(/\s/g, '');

@Injectable()
export class MfaFlowService {
  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
    private readonly auth: AuthService,
  ) {}

  public get available(): boolean {
    return this.security.mfa !== undefined;
  }

  public get challengeTtlSeconds(): Record<'verify' | 'enroll', number> {
    return {
      verify: Math.ceil(this.security.mfaChallenges.ttlOf('verify') / 1_000),
      enroll: Math.ceil(this.security.mfaChallenges.ttlOf('enroll') / 1_000),
    };
  }

  // -----------------------------------------------------------------------------------------------
  // Who is asking
  // -----------------------------------------------------------------------------------------------

  public async principal(accessToken: string | undefined): Promise<Principal | undefined> {
    const resolved = await resolvePrincipal(this.security, accessToken);
    return resolved.ok ? resolved.principal : undefined;
  }

  /**
   * A live challenge of `kind`, still matching the account it was issued for. A challenge whose
   * account was disabled, or whose token version moved (a password change or reset), is destroyed.
   */
  public async challenge(
    token: string | undefined,
    kind: 'verify' | 'enroll',
    context: RequestContext,
  ): Promise<Outcome<ChallengeRecord>> {
    const record = await this.security.mfaChallenges.peek(token, kind, context.userAgent);
    if (record === undefined || token === undefined) return refuse('expired');
    if (await this.security.mfaChallenges.exhausted(token)) return refuse('expired');
    const account = await this.security.directory.findById(record.tenantId, record.userId);
    if (
      account === undefined ||
      account.status !== 'active' ||
      account.tokenVersion !== record.tokenVersion ||
      (kind === 'verify' && !account.mfaEnrolled) ||
      (kind === 'enroll' && account.mfaEnrolled)
    ) {
      await this.security.mfaChallenges.consume(token);
      return refuse('expired');
    }
    if (await this.security.mfaFailures.locked(record.tenantId, record.userId)) {
      await this.security.mfaChallenges.consume(token);
      return refuse('locked');
    }
    return ok(record);
  }

  // -----------------------------------------------------------------------------------------------
  // Sign-in: redeem a `verify` challenge
  // -----------------------------------------------------------------------------------------------

  public async verifyChallenge(
    token: string | undefined,
    answer: { readonly code?: string | undefined; readonly recoveryCode?: string | undefined },
    context: RequestContext,
  ): Promise<Outcome<Extract<LoginResult, { ok: true }>>> {
    const mfa = this.security.mfa;
    if (mfa === undefined) return refuse('unavailable');
    const found = await this.challenge(token, 'verify', context);
    if (!found.ok) return found;
    const record = found.value;
    const { tenantId, userId } = record;

    const method = await this.checkFactor(mfa, tenantId, userId, answer);
    if (method === undefined) {
      const failure = await this.failed(tenantId, userId, context, 'sign-in');
      const alive = await this.security.mfaChallenges.recordFailure(token as string, record);
      return refuse(failure === 'locked' || !alive ? 'locked' : 'invalid');
    }

    // Exactly one redemption across the fleet. A correct answer that loses this race is refused:
    // the other request already created the session.
    if (!(await this.security.mfaChallenges.consume(token as string))) return refuse('expired');
    await this.security.mfaFailures.clear(tenantId, userId);

    const signedIn = await this.auth.completeSignIn({
      tenantId,
      userId,
      tokenVersion: record.tokenVersion,
      authMethods: ['password', method],
      mfaSatisfied: true,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });
    if (!signedIn.ok) return refuse('unavailable');
    await this.audit(tenantId, userId, context, 'auth.mfa.succeeded', 'success', {
      method,
      ...(method === 'recovery-code'
        ? { recoveryCodesRemaining: await mfa.store.remainingRecoveryCodes(tenantId, userId) }
        : {}),
    });
    return ok(signedIn);
  }

  // -----------------------------------------------------------------------------------------------
  // Reauthentication
  // -----------------------------------------------------------------------------------------------

  public async reauthenticate(
    principal: Principal,
    input: {
      readonly password: string;
      readonly code?: string | undefined;
      readonly recoveryCode?: string | undefined;
    },
    context: RequestContext,
  ): Promise<Outcome<{ readonly expiresInSeconds: number }>> {
    const { tenantId, userId, sessionId } = principal;
    if (await this.security.mfaFailures.locked(tenantId, userId)) return refuse('locked');

    const account = await this.security.directory.findById(tenantId, userId);
    // The same cost whether or not the account has a password, as at sign-in.
    const encoded = account?.passwordHash ?? (await dummyPasswordHash(defaultPasswordHasher));
    const passwordOk =
      (await defaultPasswordHasher.verify(input.password, encoded)) &&
      account?.passwordHash !== null &&
      account !== undefined;

    let factorOk = true;
    if (passwordOk && account.mfaEnrolled) {
      const mfa = this.security.mfa;
      factorOk =
        mfa !== undefined && (await this.checkFactor(mfa, tenantId, userId, input)) !== undefined;
    }

    if (!passwordOk || !factorOk) {
      const failure = await this.failed(tenantId, userId, context, 'reauthentication');
      return refuse(failure === 'locked' ? 'locked' : 'invalid');
    }
    await this.security.mfaFailures.clear(tenantId, userId);
    await this.security.reauthentication.record(tenantId, sessionId);
    return ok({ expiresInSeconds: Math.floor(this.environment.MFA_REAUTH_WINDOW / 1_000) });
  }

  /** Whether `principal`'s session reauthenticated recently enough for a sensitive change. */
  public recentlyReauthenticated(principal: Principal): Promise<boolean> {
    return this.security.reauthentication.isRecent(
      principal.tenantId,
      principal.sessionId,
      principal.session.createdAt,
    );
  }

  // -----------------------------------------------------------------------------------------------
  // Enrollment
  // -----------------------------------------------------------------------------------------------

  public async startEnrollment(
    actor: Actor,
    context: RequestContext,
  ): Promise<Outcome<{ readonly secret: string; readonly uri: string }>> {
    const mfa = this.security.mfa;
    if (mfa === undefined) return refuse('unavailable');
    const { tenantId, userId } = subjectOf(actor);
    if (actor.via === 'session' && !(await this.recentlyReauthenticated(actor.principal))) {
      return refuse('reauth-required');
    }
    if (await this.security.mfaFailures.locked(tenantId, userId)) return refuse('locked');

    const account = await this.security.directory.findById(tenantId, userId);
    if (account === undefined || account.status !== 'active') return refuse('unauthenticated');

    const started = await mfa.enroller(tenantId, userId).beginTotpEnrollment(tenantId, userId, {
      issuer: this.environment.MFA_ISSUER,
      account: account.identifier,
    });
    void context;
    return ok(started);
  }

  public async confirmEnrollment(
    actor: Actor,
    code: string,
    context: RequestContext,
  ): Promise<
    Outcome<{
      readonly recoveryCodes: readonly string[];
      readonly signIn?: Extract<LoginResult, { ok: true }>;
    }>
  > {
    const mfa = this.security.mfa;
    if (mfa === undefined) return refuse('unavailable');
    const { tenantId, userId } = subjectOf(actor);
    if (actor.via === 'session' && !(await this.recentlyReauthenticated(actor.principal))) {
      return refuse('reauth-required');
    }
    if (await this.security.mfaFailures.locked(tenantId, userId)) return refuse('locked');

    const replacing = await mfa.verifier(tenantId, userId).isEnrolled(tenantId, userId);
    if (actor.via === 'challenge' && replacing) return refuse('already-enrolled');

    let recoveryCodes: readonly string[];
    try {
      recoveryCodes = await mfa
        .enroller(tenantId, userId)
        .confirmTotpEnrollment(tenantId, userId, normaliseTotp(code));
    } catch (error) {
      if (isPlatformError(error) && error.code === 'AUTH_MFA_INVALID') {
        const failure = await this.failed(tenantId, userId, context, 'enrollment');
        const alive =
          actor.via === 'challenge'
            ? await this.security.mfaChallenges.recordFailure(actor.token, actor.record)
            : true;
        return refuse(failure === 'locked' || !alive ? 'locked' : 'invalid');
      }
      throw error;
    }

    // Platform's confirmation does not claim the TOTP step it accepted. Claim it now, through the
    // active factor that confirmation just created, so the same code cannot then be presented at
    // sign-in or reauthentication within its window.
    await mfa.verifier(tenantId, userId).verifyTotpCode(tenantId, userId, normaliseTotp(code));
    await this.security.mfaFailures.clear(tenantId, userId);
    await this.audit(tenantId, userId, context, 'auth.mfa.enrolled', 'success', {
      method: 'totp',
      replaced: replacing,
    });

    if (actor.via === 'session') {
      // Every other session was established without this factor (or with the one it replaced).
      await this.security.revocation.revokeOtherSessions(
        tenantId,
        userId,
        actor.principal.sessionId,
        'mfa-changed',
      );
      await this.security.reauthentication.clear(tenantId, actor.principal.sessionId);
      return ok({ recoveryCodes });
    }

    // Enrollment during sign-in: the challenge is spent and the sign-in completes now, with both
    // factors proven. If another request already spent it, the factor stands but no session is
    // created here; the person signs in again normally.
    if (!(await this.security.mfaChallenges.consume(actor.token))) return ok({ recoveryCodes });
    const signedIn = await this.auth.completeSignIn({
      tenantId,
      userId,
      tokenVersion: actor.record.tokenVersion,
      authMethods: ['password', 'totp'],
      mfaSatisfied: true,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });
    return ok(signedIn.ok ? { recoveryCodes, signIn: signedIn } : { recoveryCodes });
  }

  // -----------------------------------------------------------------------------------------------
  // Recovery codes, removal, status
  // -----------------------------------------------------------------------------------------------

  public async regenerateRecoveryCodes(
    principal: Principal,
    context: RequestContext,
  ): Promise<Outcome<{ readonly recoveryCodes: readonly string[] }>> {
    const mfa = this.security.mfa;
    if (mfa === undefined) return refuse('unavailable');
    const { tenantId, userId } = principal;
    if (!(await this.recentlyReauthenticated(principal))) return refuse('reauth-required');
    if (!(await mfa.verifier(tenantId, userId).isEnrolled(tenantId, userId))) {
      return refuse('not-enrolled');
    }
    // Same generator and same hash as `MfaService.confirmTotpEnrollment`; Platform has no
    // regenerate method yet (ADR-0005). The store replaces the whole previous set atomically.
    const recoveryCodes = Array.from({ length: 10 }, () => recoveryCode());
    await mfa.store.saveRecoveryCodes(
      tenantId,
      userId,
      recoveryCodes.map((value) => sha256Hex(value)),
    );
    await this.security.reauthentication.clear(tenantId, principal.sessionId);
    await this.audit(tenantId, userId, context, 'auth.mfa.enrolled', 'success', {
      recoveryCodesRegenerated: true,
    });
    return ok({ recoveryCodes });
  }

  public async remove(principal: Principal, context: RequestContext): Promise<Outcome<null>> {
    const mfa = this.security.mfa;
    if (mfa === undefined) return refuse('unavailable');
    const { tenantId, userId } = principal;
    if (!(await this.recentlyReauthenticated(principal))) return refuse('reauth-required');
    if (!(await mfa.verifier(tenantId, userId).isEnrolled(tenantId, userId))) {
      return refuse('not-enrolled');
    }
    // A required factor cannot be switched off by its holder. Replacing it is the supported path;
    // a lost device goes through the operator recovery procedure (docs/runbooks/mfa.md).
    if (await this.security.mfaPolicy.requires(tenantId, userId)) {
      return refuse('required-by-policy');
    }
    await mfa.enroller(tenantId, userId).remove(tenantId, userId, 'totp');
    await mfa.verifier(tenantId, userId).remove(tenantId, userId, 'totp');
    await this.security.revocation.revokeOtherSessions(
      tenantId,
      userId,
      principal.sessionId,
      'mfa-changed',
    );
    await this.security.reauthentication.clear(tenantId, principal.sessionId);
    await this.audit(tenantId, userId, context, 'auth.mfa.removed', 'success', { method: 'totp' });
    return ok(null);
  }

  public async status(principal: Principal): Promise<{
    readonly available: boolean;
    readonly enrolled: boolean;
    readonly required: boolean;
    readonly recoveryCodesRemaining: number;
    readonly reauthenticated: boolean;
  }> {
    const { tenantId, userId } = principal;
    const mfa = this.security.mfa;
    const enrolled =
      mfa === undefined ? false : await mfa.verifier(tenantId, userId).isEnrolled(tenantId, userId);
    return {
      available: mfa !== undefined,
      enrolled,
      required: await this.security.mfaPolicy.requires(tenantId, userId),
      recoveryCodesRemaining:
        mfa === undefined || !enrolled
          ? 0
          : await mfa.store.remainingRecoveryCodes(tenantId, userId),
      reauthenticated: await this.recentlyReauthenticated(principal),
    };
  }

  // -----------------------------------------------------------------------------------------------

  /** Check a TOTP or a recovery code against the active factor. Returns the method that passed. */
  private async checkFactor(
    mfa: IdentityMfa,
    tenantId: TenantId,
    userId: UserId,
    answer: { readonly code?: string | undefined; readonly recoveryCode?: string | undefined },
  ): Promise<Extract<AuthMethod, 'totp' | 'recovery-code'> | undefined> {
    const verifier = mfa.verifier(tenantId, userId);
    if (answer.code !== undefined && answer.code.trim() !== '') {
      const code = normaliseTotp(answer.code);
      if (!/^\d{6}$/.test(code)) return undefined;
      return (await verifier.verifyTotpCode(tenantId, userId, code)) ? 'totp' : undefined;
    }
    if (answer.recoveryCode !== undefined && answer.recoveryCode.trim() !== '') {
      return (await verifier.verifyRecoveryCode(
        tenantId,
        userId,
        normaliseRecoveryCode(answer.recoveryCode),
      ))
        ? 'recovery-code'
        : undefined;
    }
    return undefined;
  }

  private async failed(
    tenantId: TenantId,
    userId: UserId,
    context: RequestContext,
    stage: 'sign-in' | 'enrollment' | 'reauthentication',
  ): Promise<'counted' | 'locked'> {
    const failures = await this.security.mfaFailures.fail(tenantId, userId);
    await this.audit(tenantId, userId, context, 'auth.mfa.failed', 'failure', { stage });
    return failures >= this.environment.MFA_ACCOUNT_MAX_FAILURES ? 'locked' : 'counted';
  }

  /** A chained audit record. Never a code, a secret or a token; reported, never fatal. */
  private async audit(
    tenantId: TenantId,
    userId: UserId,
    context: RequestContext,
    name: SecurityEventName,
    outcome: 'success' | 'failure',
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.security.audit
      .write(
        anonymousAuditEvent(tenantId, toCorrelationId(context.correlationId), {
          name,
          outcome,
          actor: { kind: 'user', id: userId },
          payload,
          ...(context.ipAddress === undefined && context.userAgent === undefined
            ? {}
            : {
                source: {
                  ...(context.ipAddress === undefined ? {} : { ipAddress: context.ipAddress }),
                  ...(context.userAgent === undefined ? {} : { userAgent: context.userAgent }),
                },
              }),
        }),
      )
      .catch((error: unknown) => {
        process.stderr.write(`[identity] mfa audit write failed: ${String(error)}\n`);
      });
  }
}

const subjectOf = (actor: Actor): { tenantId: TenantId; userId: UserId } =>
  actor.via === 'session'
    ? { tenantId: actor.principal.tenantId, userId: actor.principal.userId }
    : { tenantId: actor.record.tenantId, userId: actor.record.userId };
