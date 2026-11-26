import { Inject, Injectable } from '@nestjs/common';
import { createHash, createPublicKey, timingSafeEqual } from 'node:crypto';

import { parseOidcClients, type IdentityEnvironment, type OidcClient } from '@identity/config';
import { anonymousAuditEvent } from '@munaxa/audit';
import { secureToken, sha256Hex } from '@munaxa/crypto';
import {
  cacheKey,
  toCorrelationId,
  type SecurityEventName,
  type SessionId,
  type TenantId,
  type UserId,
} from '@munaxa/types';

import type { Logger } from 'pino';

import { resolvePrincipal } from '../auth/principal.js';
import type { SecurityStack } from '../platform/security.js';
import { ENVIRONMENT, LOGGER, SECURITY_STACK } from '../tokens.js';

/**
 * Identity as the OpenID Connect provider for other Munaxa products (ADR-0008).
 *
 * Authorization code flow only, for confidential clients configured on the deployment
 * (`IDENTITY_OIDC_CLIENTS`). What it guarantees, each tested in `oidc-provider.integration.test.ts`:
 *
 * - **Redirect URIs match exactly**, and an unknown client or an unregistered redirect URI is an
 *   error page here, never a redirect: that is the open-redirect every hand-rolled provider has.
 * - **Codes are single use, short-lived and bound** to the client, the redirect URI, the nonce and
 *   (when sent) a PKCE S256 challenge. Stored under `sha256(code)`, consumed with one `DEL`.
 * - **A client is bound to one organisation.** A session in another organisation gets
 *   `access_denied`, so a Docs tenant only ever receives its own organisation's people.
 * - **The person is re-checked when the code is redeemed**: the session must still be live and the
 *   account active, so a sign-out or a disablement between the two steps wins.
 * - **The id token cannot be used as an access token.** Its audience is the client id, which
 *   startup refuses to let equal any access-token audience, and it carries `typ: JWT` with an
 *   `auth_time`, `nonce` and no permissions.
 *
 * What it does not do: no implicit or hybrid flow, no refresh tokens, no userinfo endpoint, no
 * dynamic registration, no consent screen (every client is Munaxa's own product).
 */

export interface AuthorizeQuery {
  readonly response_type?: string | undefined;
  readonly client_id?: string | undefined;
  readonly redirect_uri?: string | undefined;
  readonly scope?: string | undefined;
  readonly state?: string | undefined;
  readonly nonce?: string | undefined;
  readonly code_challenge?: string | undefined;
  readonly code_challenge_method?: string | undefined;
  readonly prompt?: string | undefined;
}

export type AuthorizeOutcome =
  /** Not a request this provider may answer with a redirect: show an error page. */
  | { readonly kind: 'invalid'; readonly reason: string }
  /** No live session: sign in at Identity, then come back to this exact request. */
  | { readonly kind: 'login'; readonly returnTo: string; readonly organisation: string }
  /** Back to the client, with a code or an OAuth error. */
  | { readonly kind: 'redirect'; readonly url: string };

export type TokenOutcome =
  | { readonly ok: true; readonly body: Readonly<Record<string, unknown>> }
  | { readonly ok: false; readonly status: 400 | 401; readonly error: string };

interface CodeRecord {
  readonly v: 1;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly sessionId: SessionId;
  readonly nonce: string;
  readonly codeChallenge?: string;
  readonly email: string;
  readonly amr: readonly string[];
  readonly mfa: boolean;
  readonly authTime: number;
  readonly organisation: string;
  readonly expiresAt: number;
}

export interface OidcRequestContext {
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
  readonly correlationId: string;
}

/** Sensible bounds on what a client sends; anything else is malformed, not merely unusual. */
const OPAQUE = /^[\x21-\x7e]{8,512}$/;
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const CODE = /^[A-Za-z0-9_-]{20,128}$/;

const digest = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest();
const sameSecret = (a: string, b: string): boolean => timingSafeEqual(digest(a), digest(b));
const base64url = (value: string | Buffer): string => Buffer.from(value).toString('base64url');

@Injectable()
export class OidcProviderService {
  private readonly clients: readonly OidcClient[];

  public constructor(
    @Inject(SECURITY_STACK) private readonly security: SecurityStack,
    @Inject(ENVIRONMENT) private readonly environment: IdentityEnvironment,
    @Inject(LOGGER) private readonly logger: Logger,
  ) {
    // Startup has already refused a configuration with problems (`oidcProviderIssues`).
    this.clients = parseOidcClients(
      environment.IDENTITY_OIDC_CLIENTS,
      environment.IDENTITY_OIDC_CLIENT_SECRETS,
    ).clients;
  }

  public get enabled(): boolean {
    return this.environment.IDENTITY_OIDC_PROVIDER === 'enabled';
  }

  public get issuer(): string {
    return this.environment.MUNAXA_TOKEN_ISSUER;
  }

  private endpoint(path: string): string {
    return `${this.issuer.replace(/\/+$/, '')}/api/auth/oidc/${path}`;
  }

  public discovery(): Readonly<Record<string, unknown>> {
    return {
      issuer: this.issuer,
      authorization_endpoint: this.endpoint('authorize'),
      token_endpoint: this.endpoint('token'),
      jwks_uri: this.endpoint('jwks'),
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid', 'email', 'profile'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: [
        'iss',
        'sub',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'amr',
        'email',
        'email_verified',
        'tid',
        'org',
      ],
      authorization_response_iss_parameter_supported: true,
    };
  }

  public jwks(): { readonly keys: readonly Readonly<Record<string, unknown>>[] } {
    const jwk = createPublicKey(this.security.signing.publicKeyPem).export({ format: 'jwk' });
    return {
      keys: [{ ...jwk, kid: this.security.signing.kid, alg: 'ES256', use: 'sig' }],
    };
  }

  // -----------------------------------------------------------------------------------------------
  // Authorize
  // -----------------------------------------------------------------------------------------------

  public async authorize(
    query: AuthorizeQuery,
    sessionToken: string | undefined,
    requestPath: string,
    context: OidcRequestContext,
  ): Promise<AuthorizeOutcome> {
    const client = this.clients.find((candidate) => candidate.clientId === query.client_id);
    if (client === undefined) return { kind: 'invalid', reason: 'UNKNOWN_CLIENT' };
    const redirectUri = query.redirect_uri;
    if (redirectUri === undefined || !client.redirectUris.includes(redirectUri)) {
      return { kind: 'invalid', reason: 'REDIRECT_URI_NOT_REGISTERED' };
    }
    const state = query.state;
    const back = (params: Record<string, string>): AuthorizeOutcome => {
      const url = new URL(redirectUri);
      for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
      if (state !== undefined && OPAQUE.test(state)) url.searchParams.set('state', state);
      url.searchParams.set('iss', this.issuer);
      return { kind: 'redirect', url: url.toString() };
    };

    if (state === undefined || !OPAQUE.test(state)) {
      return back({ error: 'invalid_request', error_description: 'state is required' });
    }
    if (query.response_type !== 'code') return back({ error: 'unsupported_response_type' });
    if (!(query.scope ?? '').split(' ').includes('openid')) return back({ error: 'invalid_scope' });
    if (query.nonce === undefined || !OPAQUE.test(query.nonce)) {
      return back({ error: 'invalid_request', error_description: 'nonce is required' });
    }
    if (query.code_challenge !== undefined || query.code_challenge_method !== undefined) {
      if (
        query.code_challenge_method !== 'S256' ||
        !PKCE_CHALLENGE.test(query.code_challenge ?? '')
      ) {
        return back({ error: 'invalid_request', error_description: 'PKCE must be S256' });
      }
    }

    const resolved = await resolvePrincipal(this.security, sessionToken);
    if (!resolved.ok) {
      if (query.prompt === 'none') return back({ error: 'login_required' });
      return { kind: 'login', returnTo: requestPath, organisation: client.organisation };
    }
    const principal = resolved.principal;

    const tenantId = await this.security.tenants.idForKey(client.organisation);
    if (tenantId === undefined || tenantId !== principal.tenantId) {
      this.log('warn', 'oidc.authorize.organisation_mismatch', context, {
        client: client.clientId,
      });
      await this.audit(
        principal.tenantId,
        context,
        'auth.login.failed',
        'failure',
        principal.userId,
        {
          method: 'oidc-provider',
          client: client.clientId,
          reason: 'ORGANISATION_MISMATCH',
        },
      );
      return back({ error: 'access_denied' });
    }
    const account = await this.security.directory.findById(principal.tenantId, principal.userId);
    if (account === undefined || account.status !== 'active')
      return back({ error: 'access_denied' });

    const code = secureToken(32);
    const now = Date.now();
    const record: CodeRecord = {
      v: 1,
      clientId: client.clientId,
      redirectUri,
      tenantId: principal.tenantId,
      userId: principal.userId,
      sessionId: principal.sessionId,
      nonce: query.nonce,
      ...(query.code_challenge === undefined ? {} : { codeChallenge: query.code_challenge }),
      email: account.identifier.trim().toLowerCase(),
      amr: [...(principal.claims.amr ?? ['password'])],
      mfa: principal.claims.mfa === true,
      authTime: Math.floor(principal.session.createdAt / 1_000),
      organisation: client.organisation,
      expiresAt: now + this.environment.IDENTITY_OIDC_CODE_TTL,
    };
    await this.security.cache.set(this.key(code), record, {
      ttl: this.environment.IDENTITY_OIDC_CODE_TTL,
    });
    return back({ code });
  }

  // -----------------------------------------------------------------------------------------------
  // Token
  // -----------------------------------------------------------------------------------------------

  public async token(
    body: Readonly<Record<string, unknown>>,
    authorization: string | undefined,
    context: OidcRequestContext,
  ): Promise<TokenOutcome> {
    const field = (name: string): string | undefined =>
      typeof body[name] === 'string' ? (body[name] as string) : undefined;

    // Client authentication first, and for every grant: client_secret_basic or client_secret_post,
    // never both, never neither.
    let clientId = field('client_id');
    let secret = field('client_secret');
    if (authorization !== undefined && authorization.startsWith('Basic ')) {
      if (secret !== undefined) return { ok: false, status: 400, error: 'invalid_request' };
      const decoded = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
      const at = decoded.indexOf(':');
      if (at < 0) return { ok: false, status: 401, error: 'invalid_client' };
      // RFC 6749 §2.3.1: both halves are form-urlencoded, so `+` is a space. A malformed escape is
      // an unauthenticated client, not a server error.
      const formDecode = (value: string): string | undefined => {
        try {
          return decodeURIComponent(value.replace(/\+/g, ' '));
        } catch {
          return undefined;
        }
      };
      const basicId = formDecode(decoded.slice(0, at));
      const basicSecret = formDecode(decoded.slice(at + 1));
      if (basicId === undefined || basicSecret === undefined) {
        return { ok: false, status: 401, error: 'invalid_client' };
      }
      if (clientId !== undefined && clientId !== basicId) {
        return { ok: false, status: 400, error: 'invalid_request' };
      }
      clientId = basicId;
      secret = basicSecret;
    }
    const client = this.clients.find((candidate) => candidate.clientId === clientId);
    if (client === undefined || secret === undefined || !sameSecret(secret, client.secret)) {
      this.log('warn', 'oidc.token.client_refused', context, {});
      return { ok: false, status: 401, error: 'invalid_client' };
    }

    if (field('grant_type') !== 'authorization_code') {
      return { ok: false, status: 400, error: 'unsupported_grant_type' };
    }
    const code = field('code');
    if (code === undefined || !CODE.test(code))
      return { ok: false, status: 400, error: 'invalid_grant' };

    // Consumed before anything is compared: a code presented wrongly is spent, not retried.
    const key = this.key(code);
    const record = await this.security.cache.get<CodeRecord>(key);
    if (record?.v !== 1 || !(await this.security.cache.delete(key))) {
      return this.refuse(context, client.clientId, 'CODE_UNKNOWN');
    }
    if (Date.now() >= record.expiresAt)
      return this.refuse(context, client.clientId, 'CODE_EXPIRED');
    if (record.clientId !== client.clientId) {
      return this.refuse(context, client.clientId, 'CODE_OTHER_CLIENT');
    }
    if (field('redirect_uri') !== record.redirectUri) {
      return this.refuse(context, client.clientId, 'REDIRECT_URI_MISMATCH');
    }
    if (record.codeChallenge !== undefined) {
      const verifier = field('code_verifier');
      if (
        verifier === undefined ||
        !PKCE_VERIFIER.test(verifier) ||
        base64url(digest(verifier)) !== record.codeChallenge
      ) {
        return this.refuse(context, client.clientId, 'PKCE_MISMATCH');
      }
    } else if (field('code_verifier') !== undefined) {
      return this.refuse(context, client.clientId, 'PKCE_UNEXPECTED');
    }

    // The person again, now: a sign-out or a disablement since the code was issued wins.
    const account = await this.security.directory.findById(record.tenantId, record.userId);
    if (account === undefined || account.status !== 'active') {
      return this.refuse(context, client.clientId, 'ACCOUNT_NOT_ACTIVE');
    }
    const session = await this.security.sessions.validate(record.tenantId, record.sessionId, {
      tokenVersion: account.tokenVersion,
    });
    if (!session.valid || session.session.userId !== record.userId) {
      return this.refuse(context, client.clientId, 'SESSION_ENDED');
    }

    const now = Math.floor(Date.now() / 1_000);
    const idToken = this.sign({
      iss: this.issuer,
      sub: record.userId,
      aud: client.clientId,
      exp: now + Math.floor(this.environment.IDENTITY_OIDC_ID_TOKEN_TTL / 1_000),
      iat: now,
      nbf: now,
      auth_time: record.authTime,
      nonce: record.nonce,
      amr: record.amr,
      ...(record.mfa ? { acr: 'mfa' } : {}),
      email: record.email,
      email_verified: true,
      tid: record.tenantId,
      org: record.organisation,
    });
    await this.audit(record.tenantId, context, 'auth.token.issued', 'success', record.userId, {
      kind: 'oidc-id-token',
      client: client.clientId,
    });
    return {
      ok: true,
      body: {
        // RFC 6749 requires an access token in this response. This one is accepted nowhere: there
        // is no userinfo endpoint and no API takes it. The id token is the whole answer.
        access_token: secureToken(32),
        token_type: 'Bearer',
        expires_in: 60,
        id_token: idToken,
        scope: 'openid email profile',
      },
    };
  }

  private sign(payload: Readonly<Record<string, unknown>>): string {
    const header = base64url(
      JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: this.security.signing.kid }),
    );
    const body = base64url(JSON.stringify(payload));
    const signature = this.security.signing.signer.sign(`${header}.${body}`);
    return `${header}.${body}.${signature.value}`;
  }

  private key(code: string): string {
    return cacheKey('oidc', 'code', sha256Hex(code));
  }

  private async refuse(
    context: OidcRequestContext,
    clientId: string,
    reason: string,
  ): Promise<TokenOutcome> {
    this.log('warn', 'oidc.token.refused', context, { client: clientId, reason });
    return { ok: false, status: 400, error: 'invalid_grant' };
  }

  private async audit(
    tenantId: TenantId,
    context: OidcRequestContext,
    name: SecurityEventName,
    outcome: 'success' | 'failure',
    userId: UserId,
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.security.audit
      .write(
        anonymousAuditEvent(tenantId, toCorrelationId(context.correlationId), {
          name,
          outcome,
          actor: { kind: 'user' as const, id: userId },
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
        process.stderr.write(`[identity] oidc audit write failed: ${String(error)}\n`);
      });
  }

  /** Structured, and never a code, a secret, a token or an address. */
  private log(
    level: 'info' | 'warn',
    event: string,
    context: OidcRequestContext,
    fields: Readonly<Record<string, unknown>>,
  ): void {
    this.logger[level]({ event, correlationId: context.correlationId, ...fields }, event);
  }
}
