import type { AccessTokenClaims } from '@munaxa/auth';
import type { SessionRecord } from '@munaxa/interfaces';
import type { SessionId, TenantId, UserId } from '@munaxa/types';

import type { SecurityStack } from '../platform/security.js';

/**
 * Who is calling, established from the access-token cookie and nothing else.
 *
 * This is the single gate every authenticated Identity route goes through, and every check in it
 * is one an attacker would otherwise get to skip:
 *
 * - The token is **verified**, never decoded. `decodeUnsafe` is for logout and logging; a route
 *   that grants anything on its strength trusts whoever can type base64.
 * - The token must carry a `sid`. A sessionless token is one no user can see in their session list
 *   or revoke, so a route that accepted it would make "sign out everywhere" a promise with an
 *   exception.
 * - The session row must be live — not revoked, not past its idle or absolute deadline — and be
 *   the caller's own row in the caller's own organisation. Revocation is only real because this is
 *   consulted on every request; a JWT cannot be un-issued.
 * - The account must still be active, and its token version must still equal the token's. A
 *   password reset, an account disablement or an MFA removal bumps the version, which ends every
 *   token minted before it without having to find them.
 *
 * Every refusal is the same `{ ok: false }`. Which check failed is not the caller's business: a
 * difference between "no such session" and "somebody else's session" is an oracle.
 */
export interface Principal {
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly sessionId: SessionId;
  readonly session: SessionRecord;
  readonly claims: AccessTokenClaims;
}

export type PrincipalResolution =
  { readonly ok: true; readonly principal: Principal } | { readonly ok: false };

const REFUSED: PrincipalResolution = { ok: false };

type PrincipalStack = Pick<SecurityStack, 'tokens' | 'sessions' | 'directory'>;

export const resolvePrincipal = async (
  security: PrincipalStack,
  accessToken: string | undefined,
): Promise<PrincipalResolution> => {
  if (accessToken === undefined || accessToken === '') return REFUSED;

  let claims: AccessTokenClaims;
  try {
    claims = security.tokens.verifyAccessToken(accessToken);
  } catch {
    return REFUSED;
  }
  if (claims.sid === undefined || claims.sid === '') return REFUSED;

  const tenantId = claims.tid;
  const userId = claims.sub as UserId;
  const sessionId = claims.sid;

  // The account first: its *current* token version is the one the session must match, not the
  // version the token happens to carry. Comparing a token with itself proves nothing.
  const account = await security.directory.findById(tenantId, userId);
  if (account === undefined || account.status !== 'active') return REFUSED;
  if (account.tokenVersion !== claims.ver) return REFUSED;

  const validation = await security.sessions.validate(tenantId, sessionId, {
    tokenVersion: account.tokenVersion,
  });
  if (!validation.valid) return REFUSED;

  // The session the token names must belong to the subject the token names. A row in the same
  // organisation that belongs to somebody else is not this caller's session, however it was named.
  if (validation.session.userId !== userId || validation.session.tenantId !== tenantId) {
    return REFUSED;
  }

  return {
    ok: true,
    principal: { tenantId, userId, sessionId, session: validation.session, claims },
  };
};

/**
 * The claims of a token Identity signed, whether or not it has expired.
 *
 * For logout only, and the reason is the one `AuthController.logout` gives: signing out must keep
 * working when the fifteen-minute access token has lapsed, because that is exactly when somebody
 * closes a laptop lid and wants it to mean something. The refresh cookie cannot stand in — it is
 * path-scoped to `/api/auth/refresh` and never reaches the logout route.
 *
 * What this adds over `decodeUnsafe` is the signature, issuer and audience. A forged token naming
 * somebody else's `sid` used to be enough to revoke that person's session; now the token has to
 * be one Identity actually issued. Expiry is the only check relaxed, by verifying against the
 * token's own issue time through Platform's verifier rather than by re-implementing it.
 */
export const verifiedClaimsIgnoringExpiry = (
  security: Pick<SecurityStack, 'tokensAt'>,
  token: string | undefined,
): AccessTokenClaims | undefined => {
  if (token === undefined || token === '') return undefined;
  try {
    return security.tokensAt(token).verifyAccessToken(token);
  } catch {
    return undefined;
  }
};
