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
import { RateLimiter, BASELINE_RATE_LIMIT_RULES } from '@munaxa/security';
import { SessionManager } from '@munaxa/session';
import { toCorrelationId, type EpochMillis } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';

import { AccountLockdown, CredentialRevocation } from '../account/credential-revocation.js';
import { PrismaAuditRepository } from '../persistence/audit-repository.adapter.js';
import { PrismaRefreshTokenStore } from '../persistence/refresh-token-store.adapter.js';
import { PrismaResetTokenStore } from '../persistence/reset-token-store.adapter.js';
import { PrismaRoleAssignments, PrismaRoleRepository } from '../persistence/role-store.adapter.js';
import { PrismaSessionStore } from '../persistence/session-store.adapter.js';
import { PrismaUserDirectory } from '../persistence/user-directory.adapter.js';
import { TenantDirectory } from '../persistence/tenant-directory.js';
import type { PrismaService } from '../persistence/prisma.service.js';
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
  readonly resolver: PermissionResolver;
  readonly roles: RoleAdministration;
  readonly audit: AuditService;
  readonly rateLimiter: RateLimiter;
  readonly tenants: TenantDirectory;
  readonly signing: SigningKey;
  readonly cacheKind: 'redis' | 'memory';
  /** Whether the cache is reachable right now. Readiness asks; see `CacheHandle.reachable`. */
  cacheReachable(): Promise<boolean>;
  readonly limitEnforcement: string;
  close(): Promise<void>;
}

export const buildSecurityStack = async (
  environment: IdentityEnvironment,
  prisma: PrismaService,
): Promise<SecurityStack> => {
  const handle: CacheHandle = await openCache(environment.MUNAXA_REDIS_URL);
  const { cache } = handle;

  const directory = new PrismaUserDirectory(prisma);
  const sessionStore = new PrismaSessionStore(prisma);
  const refreshStore = new PrismaRefreshTokenStore(prisma);
  const roleRepository = new PrismaRoleRepository(prisma);
  const roleAssignments = new PrismaRoleAssignments(prisma);
  const auditRepository = new PrismaAuditRepository(prisma);
  // Constructed so a reset flow has a store the day it is written, and so the platform's reset
  // conformance suite runs against a real adapter now rather than after the fact.
  void new PrismaResetTokenStore(prisma);

  const audit = new AuditService({ repository: auditRepository });

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

  const login = new LoginService({
    directory,
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

  return {
    login,
    directory,
    tokens,
    refreshTokens,
    sessions,
    revocation,
    lockdown: new AccountLockdown(directory, revocation),
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
    rateLimiter: new RateLimiter({ cache, rules: [...BASELINE_RATE_LIMIT_RULES] }),
    tenants: new TenantDirectory(prisma),
    signing,
    cacheKind: handle.kind,
    cacheReachable: () => handle.reachable(),
    limitEnforcement: sessions.limitEnforcement,
    close: () => handle.close(),
  };
};
