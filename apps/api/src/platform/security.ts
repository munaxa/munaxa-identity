import { AuditService, anonymousAuditEvent } from '@munaxa/audit';
import {
  LoginService,
  PasswordPolicyService,
  RefreshTokenService,
  StaticBreachRegistry,
  TokenService,
} from '@munaxa/auth';
import { CacheLock } from '@munaxa/cache';
import { defaultPasswordHasher } from '@munaxa/crypto';
import { PermissionResolver } from '@munaxa/rbac';
import { RateLimiter, BASELINE_RATE_LIMIT_RULES, type RateLimitRule } from '@munaxa/security';
import { SessionManager } from '@munaxa/session';
import { toCorrelationId, type EpochMillis } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';
import type { Logger } from 'pino';

import type { CachePort } from '@munaxa/interfaces';

import { MfaChallenges, MfaFailureCounter } from '../mfa/mfa-challenges.js';
import { buildMfaKeys } from '../mfa/mfa-keys.js';
import { MfaPolicy } from '../mfa/mfa-policy.js';
import { Reauthentication } from '../mfa/reauthentication.js';
import { createStepUp } from '../mfa/step-up.js';
import { buildIdentityMfa, type IdentityMfa } from '../mfa/mfa-runtime.js';
import { AccountLockdown, CredentialRevocation } from '../account/credential-revocation.js';
import { revocationAuditor, type RevocationAuditor } from '../account/revocation-audit.js';
import { PrismaAuditRepository } from '../persistence/audit-repository.adapter.js';
import { PrismaRefreshTokenStore } from '../persistence/refresh-token-store.adapter.js';
import { PrismaResetTokenStore } from '../persistence/reset-token-store.adapter.js';
import { PrismaRoleAssignments, PrismaRoleRepository } from '../persistence/role-store.adapter.js';
import { PrismaSessionStore } from '../persistence/session-store.adapter.js';
import { PrismaUserDirectory } from '../persistence/user-directory.adapter.js';
import { TenantDirectory } from '../persistence/tenant-directory.js';
import type { PrismaService } from '../persistence/prisma.service.js';
import { emailTransportFor } from '../delivery/email.js';
import { PasswordChange, createChangeLimiter } from '../password/password-change.js';
import { PasswordRecovery, createResetLimiter } from '../password/password-recovery.js';
import { createIntrospectionLimiter, isIntrospection } from '../auth/token-introspection.js';
import { openCache, type CacheHandle } from './cache.js';
import { RoleAdministration } from './role-administration.js';
import { loadSigningKey, type SigningKey } from './signing.js';

/**
 * The composition root.
 *
 * Everything security-related in this service is a Platform class configured here; Identity writes
 * adapters and wiring and no cryptography, no password comparison and no token format of its own.
 * The rule the standards state as "no product should implement any of this again" is kept by this
 * file being the only place any of it is constructed.
 */
export interface SecurityStack {
  readonly login: LoginService;
  /** Exposed because the refresh path must re-read account status, which `LoginService` does not do. */
  readonly directory: PrismaUserDirectory;
  readonly tokens: TokenService;
  readonly refreshTokens: RefreshTokenService;
  readonly sessions: SessionManager;
  /**
   * Ends sessions together with the refresh lineages bound to them, in one transaction. The only
   * way Identity revokes a session for a user-facing reason; see `CredentialRevocation`.
   */
  readonly revocation: CredentialRevocation;
  /**
   * Platform's verifier pinned to the token's own issue time: signature, issuer and audience are
   * checked, expiry is not. For logout only — see `verifiedClaimsIgnoringExpiry`.
   */
  tokensAt(token: string): TokenService;
  /** Account disablement and the suspected-compromise response. */
  readonly lockdown: AccountLockdown;
  /** Records a user- or system-initiated revocation after it commits. Never throws. */
  readonly revocationAudit: RevocationAuditor;
  readonly resolver: PermissionResolver;
  readonly roles: RoleAdministration;
  readonly audit: AuditService;
  readonly rateLimiter: RateLimiter;
  /** The per-account limit on `GET /api/auth/introspect`; see `INTROSPECTION_RULES`. */
  readonly introspectionLimiter: RateLimiter;
  readonly tenants: TenantDirectory;
  readonly signing: SigningKey;
  readonly cacheKind: 'redis' | 'memory';
  /** Whether the cache is reachable right now. Readiness asks; see `CacheHandle.reachable`. */
  cacheReachable(): Promise<boolean>;
  readonly limitEnforcement: string;
  /** Password recovery. Its `availability` says whether the endpoints may be used at all. */
  readonly recovery: PasswordRecovery;
  /**
   * TOTP multi-factor authentication, or `undefined` when no MFA key ring is configured — which
   * the configuration allows only outside production. Absent means unavailable, never unencrypted:
   * an account already enrolled is then refused at sign-in rather than let through.
   */
  readonly mfa: IdentityMfa | undefined;
  /** Who must use a second factor (`MFA_POLICY`). */
  readonly mfaPolicy: MfaPolicy;
  /** Pending second-factor challenges, in the shared cache. */
  readonly mfaChallenges: MfaChallenges;
  /** Wrong second-factor answers per account, across challenges. */
  readonly mfaFailures: MfaFailureCounter;
  /** Recent-reauthentication markers, per session. */
  readonly reauthentication: Reauthentication;
  /** The shared cache. Exposed for the MFA flow's own keys; everything else goes through a service. */
  readonly cache: CachePort;
  /** Changing a password while signed in. */
  readonly passwordChange: PasswordChange;
  close(): Promise<void>;
}

/** How long a started TOTP enrollment stays confirmable. */
export const MFA_PENDING_ENROLLMENT_TTL_MS = 15 * 60 * 1_000;

/**
 * Refuse to run in production with replay protection that holds on one replica only.
 *
 * The configuration already requires `REDIS_URL` in production; this checks what was actually
 * built, so a future change to either cannot quietly leave MFA codes replayable across pods.
 */
export const assertMfaDistributed = (
  environment: Pick<IdentityEnvironment, 'MUNAXA_ENV'>,
  cacheKind: 'redis' | 'memory',
  mfa: IdentityMfa | undefined,
): void => {
  if (environment.MUNAXA_ENV !== 'production') return;
  if (mfa === undefined) {
    throw new Error('Refusing to start: production requires MFA (MFA_ENCRYPTION_KEYS).');
  }
  if (cacheKind !== 'redis' || !mfa.distributed) {
    throw new Error(
      'Refusing to start: production requires the MFA replay guard on the shared Redis cache.',
    );
  }
};

export const buildSecurityStack = async (
  environment: IdentityEnvironment,
  prisma: PrismaService,
  logger?: Logger,
): Promise<SecurityStack> => {
  const handle: CacheHandle = await openCache(environment.MUNAXA_REDIS_URL);
  const { cache } = handle;

  const directory = new PrismaUserDirectory(prisma);
  const sessionStore = new PrismaSessionStore(prisma);
  const refreshStore = new PrismaRefreshTokenStore(prisma);
  const roleRepository = new PrismaRoleRepository(prisma);
  const roleAssignments = new PrismaRoleAssignments(prisma);
  const auditRepository = new PrismaAuditRepository(prisma);
  const resetStore = new PrismaResetTokenStore(prisma);

  const audit = new AuditService({ repository: auditRepository });

  const mfaKeys = buildMfaKeys(
    environment.MFA_ENCRYPTION_KEYS,
    environment.MFA_ENCRYPTION_PRIMARY_KID,
  );
  const mfa =
    mfaKeys === undefined
      ? undefined
      : buildIdentityMfa({
          prisma,
          keys: mfaKeys,
          replayGuard: cache,
          pendingTtlMs: MFA_PENDING_ENROLLMENT_TTL_MS,
        });
  try {
    assertMfaDistributed(environment, handle.kind, mfa);
  } catch (error) {
    await handle.close();
    throw error;
  }

  const signing = loadSigningKey({
    algorithm: environment.IDENTITY_SIGNING_ALGORITHM,
    kid: environment.IDENTITY_SIGNING_KID,
    privateKeyPem: environment.IDENTITY_SIGNING_PRIVATE_KEY,
  });

  const tokens = new TokenService({
    signer: signing.signer,
    issuer: environment.MUNAXA_TOKEN_ISSUER,
    audience: environment.MUNAXA_TOKEN_AUDIENCE,
    accessTokenTtl: environment.MUNAXA_ACCESS_TOKEN_TTL,
  });

  const revocation = new CredentialRevocation(prisma);

  const refreshTokens = new RefreshTokenService({
    store: refreshStore,
    // A rotated token presented again means the lineage is held by two parties. Platform revokes
    // the family; the session that family kept alive goes with it, or the access token in the
    // second party's hands keeps passing every session check until it expires. Awaited, so a
    // failure here surfaces as a refused refresh rather than as a half-revoked lineage.
    onReuseDetected: (record) =>
      revocation.revokeSessionOfFamily(
        record.tenantId,
        record.userId,
        record.sessionId,
        'token-reuse',
      ),
    ttl: environment.MUNAXA_REFRESH_TOKEN_TTL,
    // The pepper is the deployment's signing secret: a stolen database cannot be used to look a
    // refresh token up without it.
    pepper: environment.MUNAXA_SIGNING_SECRET,
  });

  const sessions = new SessionManager({
    store: sessionStore,
    locks: new CacheLock(cache),
    policy: {
      idleTimeout: environment.MUNAXA_SESSION_IDLE_TIMEOUT,
      absoluteTimeout: environment.MUNAXA_SESSION_ABSOLUTE_TIMEOUT,
      maxConcurrent: environment.MUNAXA_SESSION_MAX_CONCURRENT,
    },
  });

  const policy = new PasswordPolicyService({
    policy: {
      minLength: environment.MUNAXA_PASSWORD_MIN_LENGTH,
      historyCount: environment.MUNAXA_PASSWORD_HISTORY,
      checkBreaches: environment.MUNAXA_PASSWORD_BREACH_CHECK,
    },
    ...(environment.MUNAXA_PASSWORD_BREACH_CHECK
      ? { breachRegistry: new StaticBreachRegistry() }
      : {}),
  });

  const mfaPolicy = new MfaPolicy(prisma, environment.MFA_POLICY, environment.MFA_PRIVILEGED_ROLES);

  const login = new LoginService({
    directory,
    // Consulted only for an account with no factor enrolled (an enrolled one is always challenged).
    // True means "admit to enrollment only", never "admit".
    requireMfa: (account) => mfaPolicy.requires(account.tenantId, account.userId),
    hasher: defaultPasswordHasher,
    policy,
    cache,
    maxAttempts: environment.MUNAXA_LOGIN_MAX_ATTEMPTS,
    lockoutDuration: environment.MUNAXA_LOGIN_LOCKOUT,
    onEvent: (event) => {
      // Every attempt, successful or not, becomes a chained record. The event carries an
      // identifier and never a password or a hash; nothing is added to it here.
      void audit
        .write(
          anonymousAuditEvent(
            event.tenantId,
            event.context.correlationId ?? toCorrelationId(`login-${Date.now().toString(36)}`),
            {
              name: event.name,
              outcome: event.name === 'auth.login.succeeded' ? 'success' : 'failure',
              ...(event.userId === undefined
                ? {}
                : { actor: { kind: 'user' as const, id: event.userId } }),
              ...(event.detail === undefined ? {} : { payload: event.detail }),
            },
          ),
        )
        // Reported, never fatal: a failing trail must not become a failing login.
        .catch((error: unknown) => {
          process.stderr.write(`[identity] login audit write failed: ${String(error)}\n`);
        });
    },
  });

  const resolver = new PermissionResolver({
    roles: roleRepository,
    assignments: roleAssignments,
    cache,
    onUnrepresentableGrant: (detail) => {
      // A scoped wildcard cannot be narrowed and is dropped. An operator who configured one needs
      // to know the grant did not survive resolution rather than discovering it as a denial.
      process.stderr.write(
        `[identity] dropped unrepresentable grants for ${detail.userId}: ${detail.grants.join(', ')}\n`,
      );
    },
  });

  const recovery = new PasswordRecovery({
    prisma,
    store: resetStore,
    directory,
    hasher: defaultPasswordHasher,
    policy,
    tenants: new TenantDirectory(prisma),
    // Runs inside the completion's unit of work: `CredentialRevocation` writes through
    // `withTenant`, which joins it, so the revocation commits with the password change or not at all.
    revokeCredentials: async (tenantId, userId) => {
      await revocation.revokeAllForUser(tenantId, userId, 'password-reset');
    },
    // Its own limiter, so its rules and its fail-closed handling are its own. Same shared cache.
    limiter: createResetLimiter(cache),
    audit,
    transport: emailTransportFor(environment),
    enabled: environment.IDENTITY_PASSWORD_RESET === 'enabled',
    resetUrl: environment.IDENTITY_PASSWORD_RESET_URL.trim(),
    ttl: environment.IDENTITY_PASSWORD_RESET_TTL,
    from: environment.IDENTITY_EMAIL_FROM,
    // The same pepper as refresh tokens: a stolen table cannot be used to look a link up without it.
    pepper: environment.MUNAXA_SIGNING_SECRET,
    log: (level, event, fields) => {
      if (logger === undefined) {
        process.stderr.write(`[identity] ${event} ${JSON.stringify(fields)}\n`);
        return;
      }
      logger[level]({ event, ...fields }, event);
    },
  });

  const reauthentication = new Reauthentication(cache, environment.MFA_REAUTH_WINDOW);
  const passwordChange = new PasswordChange({
    security: { tokens, sessions, directory },
    prisma,
    login,
    revocation,
    // Outstanding reset links are bound to the old password already; revoking them as well means
    // the table says so, rather than leaving rows that only fail on use.
    revokeResetLinks: (tenantId, userId) => recovery.revokeOutstanding(tenantId, userId),
    limiter: createChangeLimiter(cache),
    stepUp: createStepUp({
      mfa,
      reauthentication,
      flaggedEnrolled: async (tenantId, userId) =>
        (await directory.findById(tenantId, userId))?.mfaEnrolled === true,
    }),
    audit,
    log: (level, event, fields) => {
      if (logger === undefined) {
        process.stderr.write(`[identity] ${event} ${JSON.stringify(fields)}\n`);
        return;
      }
      logger[level]({ event, ...fields }, event);
    },
  });

  return {
    login,
    directory,
    tokens,
    refreshTokens,
    sessions,
    revocation,
    lockdown: new AccountLockdown(directory, revocation, revocationAuditor(audit)),
    revocationAudit: revocationAuditor(audit),
    tokensAt: (token: string) => {
      const issuedAt = tokens.decodeUnsafe(token)?.iat;
      return new TokenService({
        signer: signing.signer,
        issuer: environment.MUNAXA_TOKEN_ISSUER,
        audience: environment.MUNAXA_TOKEN_AUDIENCE,
        accessTokenTtl: environment.MUNAXA_ACCESS_TOKEN_TTL,
        clock: {
          now: () => ((typeof issuedAt === 'number' ? issuedAt : 0) * 1_000) as EpochMillis,
        },
      });
    },
    resolver,
    roles: new RoleAdministration(roleRepository, roleAssignments, resolver),
    audit,
    rateLimiter: new RateLimiter({ cache, rules: edgeRules() }),
    introspectionLimiter: createIntrospectionLimiter(cache),
    tenants: new TenantDirectory(prisma),
    signing,
    cacheKind: handle.kind,
    cacheReachable: () => handle.reachable(),
    limitEnforcement: sessions.limitEnforcement,
    recovery,
    mfa,
    mfaPolicy,
    mfaChallenges: new MfaChallenges(cache, {
      verifyTtlMs: environment.MFA_CHALLENGE_TTL,
      enrollTtlMs: environment.MFA_ENROLLMENT_CHALLENGE_TTL,
      maxAttempts: environment.MFA_CHALLENGE_MAX_ATTEMPTS,
    }),
    mfaFailures: new MfaFailureCounter(
      cache,
      environment.MFA_ACCOUNT_MAX_FAILURES,
      environment.MUNAXA_LOGIN_LOCKOUT,
    ),
    reauthentication,
    cache,
    passwordChange,
    close: async () => {
      await recovery.idle();
      await handle.close();
    },
  };
};

/**
 * Platform's baseline edge rules, with introspection given its own address limit.
 *
 * `api-per-ip` (300 a minute) is right for a browser and wrong for a product backend: every Work
 * task behind one NAT address shares the key, so about 25 live users would exhaust it and every
 * Work request would then be refused. Introspection is carved out of it and gets `introspect-per-ip`
 * instead, sized for a product's whole egress; one account is contained by `INTROSPECTION_RULES`.
 */
export const edgeRules = (): RateLimitRule[] =>
  BASELINE_RATE_LIMIT_RULES.flatMap((rule): RateLimitRule[] => {
    if (rule.id !== 'api-per-ip') return [rule];
    const { match } = rule;
    return [
      { ...rule, match: (target) => !isIntrospection(target.path) && (match?.(target) ?? true) },
      {
        id: 'introspect-per-ip',
        dimension: 'ip',
        limit: 12_000,
        window: 60 * 1_000,
        match: (target) => isIntrospection(target.path),
      },
    ];
  });
