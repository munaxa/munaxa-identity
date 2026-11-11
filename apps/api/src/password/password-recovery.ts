import { anonymousAuditEvent, type AuditService } from '@munaxa/audit';
import {
  PasswordResetService,
  type DeliverResetInput,
  type PasswordPolicyService,
  type PasswordResetServiceOptions,
} from '@munaxa/auth';
import { prefixedId, sha256Hex, type PasswordHasher } from '@munaxa/crypto';
import type {
  NotificationMessage,
  ResetTokenStorePort,
  UserDirectoryPort,
} from '@munaxa/interfaces';
import { RateLimiter } from '@munaxa/security';
import type { CachePort } from '@munaxa/interfaces';
import {
  PlatformError,
  ROOT_TENANT_ID,
  isPlatformError,
  toCorrelationId,
  type CorrelationId,
  type SecurityEventName,
  type TenantId,
  type UserId,
} from '@munaxa/types';

import { sendEmail, type EmailTransport } from '../delivery/email.js';
import type { PrismaService } from '../persistence/prisma.service.js';

/**
 * Password recovery: Platform's `PasswordResetService`, made safe to run on a real deployment.
 *
 * Nothing here re-implements the reset rules. Token generation, hashing at rest, the single-use
 * claim, the binding to the password in force at issue time, policy and breach checks, and the
 * hashing of the new password are all Platform's, called unchanged. What Identity adds is what
 * Platform cannot know:
 *
 * 1. **Atomic completion.** Platform's `complete` claims the token, writes the password, bumps the
 *    token version, revokes the other reset tokens and then calls `onReset` — five separate port
 *    calls. On their own they can stop half-way: a crash after the claim leaves a consumed link and
 *    an unchanged password; a crash after the password write leaves the attacker's sessions alive
 *    under the new password. Here the whole call runs inside one PostgreSQL transaction
 *    (`PrismaService.unitOfWork`) that every adapter joins, together with the session and refresh
 *    revocation `onReset` performs, so it commits as one thing or not at all. The account row is
 *    locked first, so a concurrent password change cannot interleave.
 * 2. **No enumeration, including by timing.** The request endpoint answers before any account is
 *    looked up. The lookup, the token and the email happen afterwards, off the request path, so a
 *    known address and an unknown one return the same status, the same body and the same latency.
 * 3. **Delivery that fails closed.** No transport means recovery reports itself unavailable and
 *    writes nothing. A transport that refuses a message gets the token it was carrying revoked
 *    straight away, so a failed email never leaves a live credential behind.
 * 4. **Links from configuration.** The URL in the email comes from `IDENTITY_PASSWORD_RESET_URL`,
 *    never from a request header.
 * 5. **Shared abuse limits** on the request, per client address and per (organisation, identifier),
 *    in the shared cache, failing closed when that cache cannot be reached.
 */

export type RecoveryAvailability = 'available' | 'unavailable' | 'disabled';

export interface PasswordRecoveryOptions {
  readonly prisma: PrismaService;
  readonly store: ResetTokenStorePort;
  readonly directory: UserDirectoryPort;
  readonly hasher: PasswordHasher;
  readonly policy: PasswordPolicyService;
  readonly tenants: { idForKey(key: string): Promise<TenantId | undefined> };
  /** Revoke every session and refresh lineage of the user. Must only touch this database. */
  readonly revokeCredentials: (tenantId: TenantId, userId: UserId) => Promise<void>;
  readonly limiter: RateLimiter;
  readonly audit: AuditService;
  readonly transport: EmailTransport | undefined;
  readonly enabled: boolean;
  readonly resetUrl: string;
  readonly ttl: number;
  readonly from: string;
  readonly pepper: string;
  readonly productName?: string;
  /** Operational log. Called with an event name and safe fields only — never a token or address. */
  readonly log?: (
    level: 'info' | 'warn' | 'error',
    event: string,
    fields: Record<string, unknown>,
  ) => void;
  /** At most this many background request jobs at once; beyond it requests are dropped (and logged). */
  readonly maxInFlight?: number;
  /** For tests: delivery retry pacing. */
  readonly retryDelayMs?: number;
}

export type RequestOutcome =
  | { readonly kind: 'accepted' }
  | { readonly kind: 'rate-limited'; readonly retryAfterSeconds: number }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'disabled' };

export type CompleteOutcome =
  | { readonly kind: 'completed' }
  | { readonly kind: 'invalid-token' }
  | {
      readonly kind: 'password-rejected';
      readonly code: string;
      readonly violations: readonly string[];
    }
  | { readonly kind: 'unavailable' }
  | { readonly kind: 'disabled' };

/** Generous for any real address or password; small enough that nothing expensive runs on junk. */
const MAX_IDENTIFIER = 320;
const MAX_PASSWORD = 1_024;
/** `secureToken(32)` is 43 base64url characters; anything far outside that is not a token. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;
const ORGANISATION_SHAPE = /^[A-Za-z0-9._-]{1,100}$/;
const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;

export const RESET_REQUEST_RULES = [
  {
    id: 'password-forgot-per-ip',
    dimension: 'ip' as const,
    limit: 5,
    window: 60 * 60 * 1_000,
    adaptiveFactor: 2,
  },
  {
    // Keyed by a digest of (organisation, identifier) whether or not the account exists, so the
    // limit itself says nothing about which addresses are real. It also bounds how often anybody
    // can invalidate someone else's outstanding link by asking for a new one.
    id: 'password-forgot-per-identifier',
    dimension: 'user' as const,
    limit: 3,
    window: 60 * 60 * 1_000,
  },
];

/** The request limiter, on the shared cache. Its own instance, so its rules and failure handling are its own. */
export const createResetLimiter = (cache: CachePort): RateLimiter =>
  new RateLimiter({ cache, rules: RESET_REQUEST_RULES });

export class PasswordRecovery {
  readonly #options: PasswordRecoveryOptions;
  readonly #reset: PasswordResetService;
  readonly #inFlight = new Set<Promise<void>>();
  readonly #maxInFlight: number;

  public constructor(options: PasswordRecoveryOptions) {
    this.#options = options;
    this.#maxInFlight = options.maxInFlight ?? 64;
    // The shared instance inspects, completes and revokes; it never delivers. Requests get their
    // own instance in `#process`.
    this.#reset = this.#service();
  }

  public get availability(): RecoveryAvailability {
    if (!this.#options.enabled) return 'disabled';
    if (this.#options.transport === undefined || this.#options.resetUrl === '')
      return 'unavailable';
    return 'available';
  }

  /** Resolves when every background request job started so far has finished. For tests and shutdown. */
  public async idle(): Promise<void> {
    while (this.#inFlight.size > 0) await Promise.allSettled([...this.#inFlight]);
  }

  /**
   * Ask for a reset link.
   *
   * Everything that decides the response happens before any account is looked up: availability,
   * input shape, and the rate limits — which are keyed by address and by a digest of what was
   * typed, never by an account. So the response cannot depend on whether the account exists.
   */
  public async request(input: {
    readonly organisation: string;
    readonly identifier: string;
    readonly ipAddress?: string | undefined;
    readonly correlationId: CorrelationId;
  }): Promise<RequestOutcome> {
    const availability = this.availability;
    if (availability !== 'available') return { kind: availability };

    const organisation = input.organisation.trim();
    const identifier = input.identifier.trim();
    // Malformed input gets the same answer as well-formed input. It is simply not processed.
    const processable =
      ORGANISATION_SHAPE.test(organisation) &&
      identifier.length > 0 &&
      identifier.length <= MAX_IDENTIFIER;

    const decision = await this.#options.limiter.check({
      method: 'POST',
      path: '/auth/password/forgot',
      tenantId: ROOT_TENANT_ID,
      userId: sha256Hex(`${organisation.toLowerCase()}\u0000${identifier.toLowerCase()}`),
      ...(input.ipAddress === undefined ? {} : { ipAddress: input.ipAddress }),
    });
    if (decision.degraded === true) {
      // The shared counter store is unreachable. Platform's limiter allows on failure; recovery
      // does not, because an unlimited reset endpoint is a mail cannon pointed at our own users.
      this.#log('error', 'auth.password_reset.limiter_unavailable', {
        correlationId: input.correlationId,
      });
      return { kind: 'unavailable' };
    }
    if (!decision.allowed) {
      return { kind: 'rate-limited', retryAfterSeconds: Math.max(1, decision.retryAfterSeconds) };
    }

    if (processable) {
      this.#schedule(() =>
        this.#process(organisation, identifier, input.ipAddress, input.correlationId),
      );
    }
    return { kind: 'accepted' };
  }

  /**
   * Whether a link is still usable. Read-only: it never consumes, so a mail scanner or a link
   * preview that fetches the page changes nothing.
   */
  public async inspect(input: {
    readonly organisation: string;
    readonly token: string;
  }): Promise<'valid' | 'invalid' | 'unavailable' | 'disabled'> {
    const availability = this.availability;
    if (availability !== 'available') return availability;
    if (!ORGANISATION_SHAPE.test(input.organisation) || !TOKEN_SHAPE.test(input.token)) {
      return 'invalid';
    }
    const tenantId = await this.#options.tenants.idForKey(input.organisation);
    if (tenantId === undefined) return 'invalid';
    return (await this.#reset.inspect(tenantId, input.token)) === undefined ? 'invalid' : 'valid';
  }

  /**
   * Use a link to set a new password.
   *
   * One transaction: the account row lock, Platform's checks and claim, the password write, the
   * token-version bump, the revocation of every other reset token, and the revocation of every
   * session and refresh lineage. A failure anywhere — including the process dying — rolls all of
   * it back and leaves the link usable for another try.
   */
  public async complete(input: {
    readonly organisation: string;
    readonly token: string;
    readonly password: string;
    readonly ipAddress?: string | undefined;
    readonly correlationId: CorrelationId;
  }): Promise<CompleteOutcome> {
    const availability = this.availability;
    if (availability !== 'available') return { kind: availability };
    if (!ORGANISATION_SHAPE.test(input.organisation) || !TOKEN_SHAPE.test(input.token)) {
      return { kind: 'invalid-token' };
    }
    if (input.password.length === 0 || input.password.length > MAX_PASSWORD) {
      return { kind: 'password-rejected', code: 'AUTH_PASSWORD_POLICY', violations: ['length'] };
    }

    const tenantId = await this.#options.tenants.idForKey(input.organisation);
    if (tenantId === undefined) return { kind: 'invalid-token' };

    // Read-only, outside the transaction: only to learn whose row to lock. Everything is checked
    // again under the lock by Platform's `complete`.
    const ticket = await this.#reset.inspect(tenantId, input.token);
    if (ticket === undefined) {
      await this.#audit(
        tenantId,
        input.correlationId,
        'auth.password.reset.completed',
        'failure',
        undefined,
        { reason: 'token-invalid' },
      );
      return { kind: 'invalid-token' };
    }

    try {
      await this.#options.prisma.unitOfWork(tenantId, async () => {
        await this.#lockAccount(tenantId, ticket.userId);
        // Platform's `complete` checks that the account exists, not that it may be used. A link
        // issued before an administrator disabled the account must not bring it back to life.
        const account = await this.#options.directory.findById(tenantId, ticket.userId);
        if (account === undefined || account.status === 'disabled') {
          throw new PlatformError('Account cannot be recovered', {
            code: 'AUTH_RESET_TOKEN_INVALID',
          });
        }
        await this.#reset.complete(tenantId, input.token, input.password);
      });
    } catch (error) {
      if (isPlatformError(error) && error.code === 'AUTH_RESET_TOKEN_INVALID') {
        await this.#audit(
          tenantId,
          input.correlationId,
          'auth.password.reset.completed',
          'failure',
          ticket.userId,
          { reason: 'token-invalid' },
        );
        return { kind: 'invalid-token' };
      }
      if (
        isPlatformError(error) &&
        (error.code === 'AUTH_PASSWORD_POLICY' ||
          error.code === 'AUTH_PASSWORD_BREACHED' ||
          error.code === 'AUTH_PASSWORD_REUSED')
      ) {
        const violations =
          (error.details as { violations?: readonly string[] } | undefined)?.violations ?? [];
        await this.#audit(
          tenantId,
          input.correlationId,
          'auth.password.policy.rejected',
          'failure',
          ticket.userId,
          { violations: [...violations] },
        );
        return { kind: 'password-rejected', code: error.code, violations };
      }
      this.#log('error', 'auth.password_reset.complete_failed', {
        correlationId: input.correlationId,
        error: (error as Error).name,
      });
      return { kind: 'unavailable' };
    }

    await this.#audit(
      tenantId,
      input.correlationId,
      'auth.password.reset.completed',
      'success',
      ticket.userId,
    );
    this.#schedule(() => this.#notifyChanged(tenantId, ticket.userId, input.correlationId));
    return { kind: 'completed' };
  }

  /** Revoke outstanding links after a password change by any other route. Joins a unit of work. */
  public revokeOutstanding(tenantId: TenantId, userId: UserId): Promise<number> {
    return this.#reset.revokeAll(tenantId, userId);
  }

  // ---------------------------------------------------------------------------------------------

  async #process(
    organisation: string,
    identifier: string,
    ipAddress: string | undefined,
    correlationId: CorrelationId,
  ): Promise<void> {
    const tenantId = await this.#options.tenants.idForKey(organisation);
    if (tenantId === undefined) return;

    // A service per request, so the delivery callback knows which organisation the link is for and
    // who it went to. Construction is free; every rule still lives in Platform.
    let recipient: UserId | undefined;
    const reset = this.#service(async (delivery) => {
      recipient = delivery.userId;
      await this.#deliver(organisation, delivery);
    });

    try {
      await reset.request(tenantId, identifier, {
        ...(ipAddress === undefined ? {} : { ipAddress }),
      });
      if (recipient !== undefined) {
        await this.#audit(
          tenantId,
          correlationId,
          'auth.password.reset.requested',
          'success',
          recipient,
        );
      }
    } catch (error) {
      // The token Platform just saved is unreachable — its email never left. Revoke it, so a failed
      // delivery cannot leave a live credential in the table.
      if (recipient !== undefined) {
        await reset.revokeAll(tenantId, recipient).catch(() => 0);
        await this.#audit(
          tenantId,
          correlationId,
          'auth.password.reset.requested',
          'failure',
          recipient,
          { reason: 'delivery-failed' },
        );
      }
      this.#log('error', 'auth.password_reset.request_failed', {
        correlationId,
        error: (error as Error).name,
      });
    }
  }

  #service(deliver?: PasswordResetServiceOptions['deliver']): PasswordResetService {
    const options = this.#options;
    return new PasswordResetService({
      store: options.store,
      directory: options.directory,
      hasher: options.hasher,
      policy: options.policy,
      ttl: options.ttl,
      pepper: options.pepper,
      ...(deliver === undefined ? {} : { deliver }),
      onReset: (tenantId, userId) => options.revokeCredentials(tenantId, userId),
    });
  }

  async #deliver(organisation: string, input: DeliverResetInput): Promise<void> {
    const transport = this.#options.transport;
    if (transport === undefined) {
      throw new Error('no delivery transport');
    }
    if (!EMAIL.test(input.identifier)) {
      // An account whose identifier is not an address has nowhere to receive a link.
      throw new Error('identifier is not an email address');
    }

    const link = new URL(this.#options.resetUrl);
    link.searchParams.set('org', organisation);
    link.searchParams.set('token', input.token);
    const minutes = Math.max(1, Math.round((input.expiresAt - Date.now()) / 60_000));
    const product = this.#options.productName ?? 'Munaxa';

    const message: NotificationMessage = {
      id: prefixedId('mail'),
      tenantId: input.tenantId,
      channel: 'email',
      recipient: { userId: input.userId, email: input.identifier },
      subject: `Reset your ${product} password`,
      // Platform's `security.password-reset-requested` wording. No password, no code: one link.
      body:
        `Use this link within ${String(minutes)} minutes to choose a new password: ${link.toString()}\n\n` +
        'If you did not ask for this, you can ignore this message — your password has not changed.',
      templateId: 'security.password-reset-requested',
      priority: 'critical',
      metadata: { from: this.#options.from },
    };

    await sendEmail(transport, message, {
      ...(this.#options.retryDelayMs === undefined
        ? {}
        : { retryDelayMs: this.#options.retryDelayMs }),
    });
  }

  async #notifyChanged(
    tenantId: TenantId,
    userId: UserId,
    correlationId: CorrelationId,
  ): Promise<void> {
    const transport = this.#options.transport;
    if (transport === undefined) return;
    const account = await this.#options.directory.findById(tenantId, userId);
    if (account === undefined || !EMAIL.test(account.identifier)) return;
    const product = this.#options.productName ?? 'Munaxa';
    try {
      await sendEmail(
        transport,
        {
          id: prefixedId('mail'),
          tenantId,
          channel: 'email',
          recipient: { userId, email: account.identifier },
          subject: `Your ${product} password was changed`,
          body:
            `Your password was changed on ${new Date().toISOString()}, and every device was signed out. ` +
            `If this was not you, request a new reset link at ${new URL(this.#options.resetUrl).origin}/api/auth/password/forgot and contact your administrator.`,
          templateId: 'security.password-changed',
          priority: 'critical',
          metadata: { from: this.#options.from },
        },
        {
          ...(this.#options.retryDelayMs === undefined
            ? {}
            : { retryDelayMs: this.#options.retryDelayMs }),
        },
      );
    } catch (error) {
      // The password change has already happened; the notice is best effort and its failure is
      // an operational event, not a reason to undo anything.
      this.#log('warn', 'auth.password_changed.notice_failed', {
        correlationId,
        error: (error as Error).name,
      });
    }
  }

  async #lockAccount(tenantId: TenantId, userId: UserId): Promise<void> {
    await this.#options.prisma.withTenant(
      tenantId,
      (tx) =>
        tx.$queryRaw`select id from identity_account where tenant_id = ${tenantId} and id = ${userId} for update`,
    );
  }

  #schedule(job: () => Promise<void>): void {
    if (this.#inFlight.size >= this.#maxInFlight) {
      this.#log('warn', 'auth.password_reset.backlog_full', { inFlight: this.#inFlight.size });
      return;
    }
    const running: Promise<void> = job()
      .catch((error: unknown) => {
        this.#log('error', 'auth.password_reset.job_failed', { error: (error as Error).name });
      })
      .finally(() => {
        this.#inFlight.delete(running);
      });
    this.#inFlight.add(running);
  }

  async #audit(
    tenantId: TenantId,
    correlationId: CorrelationId,
    name: SecurityEventName,
    outcome: 'success' | 'failure',
    userId?: UserId,
    payload?: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.#options.audit
      .write(
        anonymousAuditEvent(tenantId, correlationId ?? toCorrelationId(prefixedId('corr')), {
          name,
          outcome,
          ...(userId === undefined ? {} : { actor: { kind: 'user' as const, id: userId } }),
          ...(payload === undefined ? {} : { payload }),
        }),
      )
      // Reported, never fatal, and never carrying the token or the address.
      .catch((error: unknown) => {
        this.#log('error', 'auth.password_reset.audit_failed', {
          event: name,
          error: (error as Error).name,
        });
      });
  }

  #log(level: 'info' | 'warn' | 'error', event: string, fields: Record<string, unknown>): void {
    this.#options.log?.(level, event, fields);
  }
}
