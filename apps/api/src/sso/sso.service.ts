import { createHash } from 'node:crypto';

import { Inject, Injectable, Optional } from '@nestjs/common';
import { anonymousAuditEvent } from '@munaxa/audit';
import { toCorrelationId, type SecurityEventName, type TenantId, type UserId } from '@munaxa/types';
import type { IdentityEnvironment } from '@identity/config';
import type { Logger } from 'pino';

import { AuthService, type LoginResult } from '../auth/auth.service.js';
import { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';
import { ENVIRONMENT, LOGGER, SECURITY_STACK, SSO_OPTIONS } from '../tokens.js';
import { verifyIdToken } from './id-token.js';
import { JwksCache, type FetchLike } from './jwks.js';
import {
  DEFAULT_PROVIDER_CATALOGUE,
  domainOf,
  personFrom,
  type ProviderCatalogue,
  type SsoProviderKind,
} from './providers.js';
import { SsoDirectory, type SsoConnection } from './sso-directory.js';
import { SsoFlows } from './sso-flows.js';

/**
 * Company sign-in: send the browser to the company's Microsoft or Google directory, and turn what
 * comes back into an ordinary Munaxa session.
 *
 * ## What a company sign-in proves, and what it does not
 *
 * It proves that the company's own directory (one Entra tenant, or one Workspace domain, pinned per
 * connection) says this person is `oid`/`sub` there and holds an address in a domain the connection
 * owns. It does **not** decide who may use Munaxa or with which roles: the account must already
 * exist in the organisation, created by an operator for this connection (`sso-account-create` or
 * `sso-account-convert`). Nobody is created on first sign-in, so a directory compromise at the
 * company reaches exactly the accounts Munaxa already decided that company's people hold.
 *
 * ## Account binding
 *
 * The first company sign-in for a pre-created account binds it to the provider's stable identifier
 * (`external_id`); every later one matches on that identifier alone, and never on the address
 * again. The address is used once, and only to find an account that an operator created for this
 * exact connection and that is not yet bound. A local (password) account is never bound by a
 * sign-in: converting one is an operator act that also removes its password.
 *
 * ## After the provider
 *
 * Exactly what a correct password leads to, with the provider as the first factor:
 * the organisation's MFA policy applies unchanged (an enrolled account is challenged, a privileged
 * one without a factor is admitted to enrollment only), unless the connection says the company's
 * own MFA stands in for Munaxa's (`trust_provider_mfa`, off by default). The session, refresh,
 * revocation and introspection are the same; the session's `amr` says `microsoft` or `google`.
 *
 * Every refusal looks the same to the browser (the sign-in page's `sso` message); the reason is
 * logged and audited.
 */

export interface SsoOptions {
  /** Where each provider lives. Tests stand up their own; production uses the default. */
  readonly catalogue: ProviderCatalogue;
  readonly fetcher: FetchLike;
  readonly now: () => number;
}

export const defaultSsoOptions = (): SsoOptions => ({
  catalogue: DEFAULT_PROVIDER_CATALOGUE,
  fetcher: fetch as unknown as FetchLike,
  now: Date.now,
});

export interface SsoRequestContext {
  /** `scheme://host` the browser is on. Must be one of `CSRF_TRUSTED_ORIGINS`. */
  readonly origin: string;
  readonly userAgent?: string | undefined;
  readonly ipAddress?: string | undefined;
  readonly correlationId: string;
}

export type StartOutcome =
  | {
      readonly kind: 'redirect';
      readonly url: string;
      /** The `__Host-mx_sso` cookie value. */
      readonly binding: string;
      readonly ttlSeconds: number;
    }
  /** No enabled connection owns this address's domain, or its provider is not configured here. */
  | { readonly kind: 'not-offered' }
  /** The request came from an origin Identity does not serve. */
  | { readonly kind: 'bad-origin' }
  | { readonly kind: 'unavailable' };

export type CallbackOutcome =
  | {
      readonly kind: 'signed-in';
      readonly result: Extract<LoginResult, { ok: true }>;
      readonly returnTo: string;
      readonly language: 'en' | 'ar';
    }
  | {
      readonly kind: 'mfa';
      readonly challenge: {
        readonly token: string;
        readonly kind: 'verify' | 'enroll';
        readonly ttlMs: number;
      };
      readonly returnTo: string;
      readonly language: 'en' | 'ar';
    }
  | { readonly kind: 'refused'; readonly returnTo: string; readonly language: 'en' | 'ar' }
  | { readonly kind: 'unavailable'; readonly returnTo: string; readonly language: 'en' | 'ar' };

type Redeemed =
  | { readonly kind: 'signed-in'; readonly result: Extract<LoginResult, { ok: true }> }
  | {
      readonly kind: 'mfa';
      readonly challenge: {
        readonly token: string;
        readonly kind: 'verify' | 'enroll';
        readonly ttlMs: number;
      };
    };

const TOKEN_TIMEOUT_MS = 10_000;
const MAX_TOKEN_RESPONSE_BYTES = 64 * 1_024;
/** The provider's `error` parameter, logged only when it has this shape (it is caller-supplied). */
const PROVIDER_ERROR = /^[a-z_]{1,64}$/;

class Refusal extends Error {
  public constructor(
    public readonly reason: string,
    public readonly tenantId?: TenantId,
    public readonly userId?: UserId,
  ) {
    super(reason);
  }
}

@Injectable()
export class SsoService {
  private readonly directory: SsoDirectory;
  private readonly flows: SsoFlows;
  private readonly jwks: JwksCache;
  private readonly options: SsoOptions;

  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
    private readonly prisma: PrismaService,
    private readonly auth: AuthService,
    @Inject(LOGGER) private readonly logger: Logger,
    @Optional() @Inject(SSO_OPTIONS) options?: SsoOptions,
  ) {
    this.options = options ?? defaultSsoOptions();
    this.directory = new SsoDirectory(prisma);
    this.flows = new SsoFlows(security.cache, environment.IDENTITY_SSO_FLOW_TTL, this.options.now);
    this.jwks = new JwksCache(this.options.fetcher, this.options.now);
  }

  /** Whether company sign-in exists on this deployment. Off means the routes answer 404. */
  public get enabled(): boolean {
    return this.environment.IDENTITY_SSO === 'enabled';
  }

  public get sessionCookieMaxAge(): number {
    return this.auth.sessionCookieMaxAge;
  }

  public get flowTtlSeconds(): number {
    return this.flows.ttlSeconds;
  }

  /** The callback URL for an origin Identity serves, or `undefined` for any other origin. */
  public callbackFor(origin: string): string | undefined {
    return this.environment.MUNAXA_TRUSTED_ORIGINS.includes(origin)
      ? `${origin}/api/auth/sso/callback`
      : undefined;
  }

  private client(
    provider: SsoProviderKind,
  ): { readonly id: string; readonly secret: string } | undefined {
    const id =
      provider === 'microsoft'
        ? this.environment.IDENTITY_SSO_MICROSOFT_CLIENT_ID
        : this.environment.IDENTITY_SSO_GOOGLE_CLIENT_ID;
    const secret =
      provider === 'microsoft'
        ? this.environment.IDENTITY_SSO_MICROSOFT_CLIENT_SECRET
        : this.environment.IDENTITY_SSO_GOOGLE_CLIENT_SECRET;
    return id.trim() === '' || secret.trim() === ''
      ? undefined
      : { id: id.trim(), secret: secret.trim() };
  }

  // -----------------------------------------------------------------------------------------------
  // Start
  // -----------------------------------------------------------------------------------------------

  public async start(input: {
    readonly email: string;
    readonly returnTo: string;
    readonly language: 'en' | 'ar';
    readonly context: SsoRequestContext;
  }): Promise<StartOutcome> {
    if (!this.enabled) return { kind: 'not-offered' };
    const redirectUri = this.callbackFor(input.context.origin);
    if (redirectUri === undefined) return { kind: 'bad-origin' };

    const email = input.email.trim().toLowerCase();
    if (domainOf(email) === undefined) return { kind: 'not-offered' };

    let connection: SsoConnection | undefined;
    try {
      connection = await this.directory.forEmail(email);
    } catch (error) {
      this.log('error', 'auth.sso.start_failed', input.context, { error: (error as Error).name });
      return { kind: 'unavailable' };
    }
    if (connection === undefined) return { kind: 'not-offered' };
    const client = this.client(connection.provider);
    if (client === undefined) return { kind: 'not-offered' };

    const endpoints = this.options.catalogue[connection.provider](connection.directoryId);
    let started;
    try {
      started = await this.flows.start({
        connectionId: connection.id,
        tenantId: connection.tenantId,
        provider: connection.provider,
        redirectUri,
        returnTo: input.returnTo,
        language: input.language,
        userAgent: input.context.userAgent,
      });
    } catch (error) {
      this.log('error', 'auth.sso.start_failed', input.context, { error: (error as Error).name });
      return { kind: 'unavailable' };
    }

    const parameters = new URLSearchParams({
      response_type: 'code',
      client_id: client.id,
      redirect_uri: redirectUri,
      scope: 'openid email profile',
      state: started.state,
      nonce: started.nonce,
      // PKCE even for a confidential client: one hash, and authorization-code interception is gone.
      code_challenge: createHash('sha256').update(started.codeVerifier).digest('base64url'),
      code_challenge_method: 'S256',
      // The query response mode: the callback is a top-level GET, which is what lets the
      // `SameSite=Lax` binding cookie come with it.
      response_mode: 'query',
      login_hint: email,
      ...endpoints.extraParameters,
    });
    return {
      kind: 'redirect',
      url: `${endpoints.authorizationEndpoint}?${parameters.toString()}`,
      binding: started.binding,
      ttlSeconds: this.flows.ttlSeconds,
    };
  }

  // -----------------------------------------------------------------------------------------------
  // Callback
  // -----------------------------------------------------------------------------------------------

  public async callback(input: {
    readonly params: Readonly<Record<string, string | undefined>>;
    readonly binding: string | undefined;
    readonly context: SsoRequestContext;
  }): Promise<CallbackOutcome> {
    const flow = await this.flows
      .complete(input.params.state, input.binding, input.context.userAgent)
      .catch(() => ({ ok: false as const, reason: 'CACHE_UNAVAILABLE' }));
    if (!flow.ok) {
      // No flow means no organisation to file the attempt under; the log has it.
      this.log('warn', 'auth.sso.callback_refused', input.context, { reason: flow.reason });
      return flow.reason === 'CACHE_UNAVAILABLE'
        ? { kind: 'unavailable', returnTo: '/', language: 'en' }
        : { kind: 'refused', returnTo: '/', language: 'en' };
    }
    const { record } = flow;
    const back = { returnTo: record.returnTo, language: record.language } as const;

    try {
      const outcome = await this.redeem(record, input.params, input.context);
      return outcome.kind === 'mfa'
        ? { kind: 'mfa', challenge: outcome.challenge, ...back }
        : { kind: 'signed-in', result: outcome.result, ...back };
    } catch (error) {
      if (error instanceof Refusal) {
        this.log('warn', 'auth.sso.callback_refused', input.context, {
          reason: error.reason,
          connectionId: record.connectionId,
        });
        await this.audit(
          record.tenantId,
          input.context,
          'auth.login.failed',
          'failure',
          error.userId,
          {
            method: record.provider,
            connectionId: record.connectionId,
            reason: error.reason,
          },
        );
        return { kind: 'refused', ...back };
      }
      this.log('error', 'auth.sso.callback_failed', input.context, {
        error: (error as Error).name,
        connectionId: record.connectionId,
      });
      return { kind: 'unavailable', ...back };
    }
  }

  private async redeem(
    record: {
      readonly connectionId: string;
      readonly tenantId: TenantId;
      readonly provider: SsoProviderKind;
      readonly nonce: string;
      readonly codeVerifier: string;
      readonly redirectUri: string;
    },
    params: Readonly<Record<string, string | undefined>>,
    context: SsoRequestContext,
  ): Promise<Redeemed> {
    if (params.error !== undefined) {
      const code = PROVIDER_ERROR.test(params.error) ? params.error : 'unrecognised';
      throw new Refusal(`PROVIDER_ERROR:${code}`, record.tenantId);
    }
    const code = params.code;
    if (code === undefined || code === '' || code.length > 4_096) {
      throw new Refusal('NO_CODE', record.tenantId);
    }

    // The connection is read again: one disabled while the person was at the provider is disabled.
    const connection = await this.directory.byId(record.tenantId, record.connectionId);
    if (connection === undefined || connection.tenantId !== record.tenantId) {
      throw new Refusal('CONNECTION_UNAVAILABLE', record.tenantId);
    }
    const client = this.client(connection.provider);
    if (client === undefined) throw new Refusal('PROVIDER_NOT_CONFIGURED', record.tenantId);
    const endpoints = this.options.catalogue[connection.provider](connection.directoryId);

    const idToken = await this.exchange(endpoints.tokenEndpoint, client, code, record);
    const kid = headerKid(idToken);
    const keys = await this.jwks.keysFor(endpoints.jwksUri, kid);
    if (keys === undefined) throw new Error('Provider signing keys unavailable');

    const verified = verifyIdToken(idToken, keys, {
      issuers: endpoints.issuers,
      audience: client.id,
      nonce: record.nonce,
      now: new Date(this.options.now()),
    });
    if (!verified.ok) throw new Refusal(`ID_TOKEN_${verified.reason}`, record.tenantId);

    const person = personFrom(connection.provider, connection.directoryId, verified.claims);
    if (!person.ok) throw new Refusal(person.reason, record.tenantId);
    const domain = domainOf(person.person.email);
    if (domain === undefined || !connection.domains.includes(domain)) {
      throw new Refusal('DOMAIN_NOT_OWNED', record.tenantId);
    }

    const account = await this.bind(connection, person.person, context);

    if (account.status !== 'active') {
      throw new Refusal('ACCOUNT_NOT_ACTIVE', connection.tenantId, account.id);
    }

    const primary = connection.provider;
    // The company's own MFA standing in for Munaxa's, when (and only when) the connection says so.
    if (!connection.trustProviderMfa) {
      const required = account.mfaEnrolled
        ? 'verify'
        : (await this.security.mfaPolicy.requires(connection.tenantId, account.id))
          ? 'enroll'
          : undefined;
      if (required !== undefined) {
        if (this.security.mfa === undefined) {
          throw new Refusal('MFA_UNAVAILABLE', connection.tenantId, account.id);
        }
        const issued = await this.security.mfaChallenges.issue({
          kind: required,
          tenantId: connection.tenantId,
          userId: account.id,
          tokenVersion: account.tokenVersion,
          primary,
          userAgent: context.userAgent,
        });
        await this.audit(
          connection.tenantId,
          context,
          'auth.mfa.challenged',
          'success',
          account.id,
          {
            method: primary,
            connectionId: connection.id,
            challenge: required,
          },
        );
        return {
          kind: 'mfa',
          challenge: {
            token: issued.token,
            kind: required,
            ttlMs: this.security.mfaChallenges.ttlOf(required),
          },
        };
      }
    }

    const signedIn = await this.auth.completeSignIn({
      tenantId: connection.tenantId,
      userId: account.id,
      tokenVersion: account.tokenVersion,
      authMethods: [primary],
      mfaSatisfied: connection.trustProviderMfa,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });
    if (!signedIn.ok) throw new Error('Session could not be created');
    await this.audit(connection.tenantId, context, 'auth.login.succeeded', 'success', account.id, {
      method: primary,
      connectionId: connection.id,
      mfaSatisfied: connection.trustProviderMfa,
    });
    return { kind: 'signed-in', result: signedIn };
  }

  /** The code for an id token, server to server, with the client secret and the PKCE verifier. */
  private async exchange(
    tokenEndpoint: string,
    client: { readonly id: string; readonly secret: string },
    code: string,
    record: {
      readonly tenantId: TenantId;
      readonly codeVerifier: string;
      readonly redirectUri: string;
    },
  ): Promise<string> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: record.redirectUri,
      client_id: client.id,
      client_secret: client.secret,
      code_verifier: record.codeVerifier,
    });
    const response = await this.options.fetcher(tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: body.toString(),
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    });
    const text = await response.text();
    if (!response.ok) {
      // A 4xx is the provider refusing this code (spent, expired, wrong verifier): a refusal. The
      // body is not logged; it can echo what it was sent.
      if (response.status >= 400 && response.status < 500) {
        throw new Refusal(`TOKEN_EXCHANGE_${response.status}`, record.tenantId);
      }
      throw new Error(`Token endpoint answered ${response.status}`);
    }
    if (text.length > MAX_TOKEN_RESPONSE_BYTES)
      throw new Refusal('TOKEN_RESPONSE_TOO_LARGE', record.tenantId);
    let payload: { id_token?: unknown };
    try {
      payload = JSON.parse(text) as { id_token?: unknown };
    } catch {
      throw new Refusal('TOKEN_RESPONSE_MALFORMED', record.tenantId);
    }
    if (typeof payload.id_token !== 'string' || payload.id_token === '') {
      throw new Refusal('NO_ID_TOKEN', record.tenantId);
    }
    return payload.id_token;
  }

  /**
   * The account this person signs in as, binding a pre-created one on first use.
   *
   * One transaction under the organisation's row-level security. The bind is a conditional update
   * (`external_id is null`), so two first sign-ins racing from two tabs bind once; the loser reads
   * the binding the winner wrote. The unique index on `(tenant, connection, external_id)` makes a
   * second account bound to the same person impossible whatever the code does.
   */
  private async bind(
    connection: SsoConnection,
    person: { readonly subject: string; readonly email: string },
    context: SsoRequestContext,
  ): Promise<{
    readonly id: UserId;
    readonly status: string;
    readonly tokenVersion: number;
    readonly mfaEnrolled: boolean;
  }> {
    const select = { id: true, status: true, tokenVersion: true, mfaEnrolled: true } as const;
    const found = await this.prisma.withTenant(connection.tenantId, async (tx) => {
      const bound = await tx.identityAccount.findFirst({
        where: {
          tenantId: connection.tenantId,
          identityProviderId: connection.id,
          externalId: person.subject,
        },
        select,
      });
      if (bound !== null) return { account: bound, linked: false };

      const waiting = await tx.identityAccount.findFirst({
        where: {
          tenantId: connection.tenantId,
          identitySource: 'federated',
          identityProviderId: connection.id,
          externalId: null,
          identifierNormalized: person.email,
        },
        select,
      });
      if (waiting === null) return undefined;
      const claimed = await tx.identityAccount.updateMany({
        where: { id: waiting.id, tenantId: connection.tenantId, externalId: null },
        data: { externalId: person.subject, updatedBy: `sso:${connection.id}` },
      });
      if (claimed.count === 1) return { account: waiting, linked: true };
      const raced = await tx.identityAccount.findFirst({
        where: {
          tenantId: connection.tenantId,
          identityProviderId: connection.id,
          externalId: person.subject,
        },
        select,
      });
      return raced === null ? undefined : { account: raced, linked: false };
    });

    if (found === undefined) throw new Refusal('NOT_PROVISIONED', connection.tenantId);
    const account = { ...found.account, id: found.account.id as UserId };
    if (found.linked) {
      await this.audit(
        connection.tenantId,
        context,
        'auth.provider.linked',
        'success',
        account.id,
        {
          method: connection.provider,
          connectionId: connection.id,
        },
      );
    }
    return account;
  }

  private async audit(
    tenantId: TenantId,
    context: SsoRequestContext,
    name: SecurityEventName,
    outcome: 'success' | 'failure',
    userId: UserId | undefined,
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.security.audit
      .write(
        anonymousAuditEvent(tenantId, toCorrelationId(context.correlationId), {
          name,
          outcome,
          ...(userId === undefined ? {} : { actor: { kind: 'user' as const, id: userId } }),
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
        process.stderr.write(`[identity] sso audit write failed: ${String(error)}\n`);
      });
  }

  /** Structured, and never an address, a code, a token or a claim value. */
  private log(
    level: 'warn' | 'error',
    event: string,
    context: SsoRequestContext,
    fields: Readonly<Record<string, unknown>>,
  ): void {
    this.logger[level]({ event, correlationId: context.correlationId, ...fields }, event);
  }
}

/** The `kid` a token's header names, read only to choose which published key to try first. */
const headerKid = (token: string): string | undefined => {
  const header = token.split('.')[0];
  if (header === undefined) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as {
      kid?: unknown;
    };
    return typeof parsed.kid === 'string' ? parsed.kid : undefined;
  } catch {
    return undefined;
  }
};
