import { createPublicKey, createVerify, timingSafeEqual } from 'node:crypto';

/**
 * OpenID Connect id-token verification, from the Node standard library and nothing else.
 *
 * Ported from Munaxa Docs (`apps/api/src/modules/identity/domain/oidc.ts`, Phase 17), where it has
 * run behind Docs' own federated sign-in, so the reasoning below is that file's and the two can be
 * compared line by line. Two changes: the issuer expectation may list more than one exact spelling
 * (Google documents two; each is still compared exactly), and `digestOf`/`claimAsStrings` are not
 * carried over because nothing here uses them.
 *
 * ## Why this is not a dependency
 *
 * Identity's lockfile is resolved against a private registry, and `jose` is not in it. The trade is
 * the one Docs made: Node's `crypto` imports a JWK and verifies RS256/ES256 natively, so **there is
 * no cryptography written here**. What is written is the parsing and the *checks* (a base64url
 * split, an `alg` allow-list, issuer, audience, expiry, nonce), each a comparison a reader can check
 * by eye. SAML, which needs XML canonicalisation, is the trade nobody should make by hand, and is
 * not implemented.
 *
 * ## The four checks that are load-bearing
 *
 * 1. **`alg` is allow-listed against the key's own type.** `none` and RS256-to-HS256 confusion fail.
 * 2. **The issuer matches exactly.** Otherwise a token from any provider verifies.
 * 3. **The audience contains our client id** (and `azp` is us when there are several). Otherwise a
 *    token the provider minted for someone else's application is accepted here.
 * 4. **The nonce matches**, in constant time. Otherwise an id token from another flow replays here.
 *
 * Pure: a token, keys and expectations in; claims or a named refusal out. The refusal reason goes to
 * a log, never to the person signing in.
 */

/** The algorithms accepted, and every one of them asymmetric. */
const ALLOWED_ALGORITHMS: Readonly<Record<string, { kty: string; node: string }>> = Object.freeze({
  RS256: { kty: 'RSA', node: 'RSA-SHA256' },
  RS384: { kty: 'RSA', node: 'RSA-SHA384' },
  RS512: { kty: 'RSA', node: 'RSA-SHA512' },
  ES256: { kty: 'EC', node: 'SHA256' },
  ES384: { kty: 'EC', node: 'SHA384' },
});

export interface Jwk {
  readonly kty: string;
  readonly kid?: string;
  readonly alg?: string;
  readonly use?: string;
  readonly n?: string;
  readonly e?: string;
  readonly crv?: string;
  readonly x?: string;
  readonly y?: string;
}

export interface IdTokenExpectation {
  /** Every exact spelling of the issuer this provider uses. Compared as strings, never normalised. */
  readonly issuers: readonly string[];
  readonly audience: string;
  readonly nonce: string;
  readonly now: Date;
  /** Tolerance for a provider whose clock differs from ours. Sixty seconds is the usual figure. */
  readonly clockSkewSeconds?: number;
}

export type IdTokenClaims = Readonly<Record<string, unknown>>;

export type VerificationOutcome =
  | { readonly ok: true; readonly claims: IdTokenClaims }
  | { readonly ok: false; readonly reason: string };

/**
 * Verifies an ID token against a JWKS.
 *
 * Returns a refusal rather than throwing, so the caller decides what a failure means. Every
 * refusal names the check that failed — those strings reach a log and never a caller, for the
 * reason every authentication failure in this product is uniform to the person presenting it.
 */
export function verifyIdToken(
  token: string,
  keys: readonly Jwk[],
  expectation: IdTokenExpectation,
): VerificationOutcome {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { ok: false, reason: 'MALFORMED' };
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  const header = decodeJson(encodedHeader);
  const payload = decodeJson(encodedPayload);
  if (!header || !payload) {
    return { ok: false, reason: 'MALFORMED' };
  }

  const alg = typeof header['alg'] === 'string' ? header['alg'] : '';
  const spec = ALLOWED_ALGORITHMS[alg];
  // `none` and every symmetric algorithm fail here, because neither is in the table. This is the
  // check whose absence is the oldest JWT vulnerability there is.
  if (!spec) {
    return { ok: false, reason: 'ALGORITHM_NOT_ALLOWED' };
  }

  const kid = typeof header['kid'] === 'string' ? header['kid'] : null;
  // A `kid` narrows to one key; without one, every key of the right type is tried. Trying several
  // is not a weakness — each is a full signature verification — and it is what keeps a provider
  // that publishes an unlabelled JWKS working.
  const candidates = keys.filter(
    (key) => key.kty === spec.kty && (kid === null || key.kid === undefined || key.kid === kid),
  );
  if (candidates.length === 0) {
    return { ok: false, reason: 'NO_MATCHING_KEY' };
  }

  const signed = `${encodedHeader}.${encodedPayload}`;
  const signature = Buffer.from(encodedSignature, 'base64url');
  const verified = candidates.some((key) => verifyWith(key, spec.node, signed, signature, alg));
  if (!verified) {
    return { ok: false, reason: 'BAD_SIGNATURE' };
  }

  // The issuer, exactly. Not normalised, not trailing-slash-insensitive: OIDC Core §2 says `iss`
  // is compared as a string, and "helpfully" normalising is how one provider's issuer starts
  // matching another's.
  if (typeof payload['iss'] !== 'string' || !expectation.issuers.includes(payload['iss'])) {
    return { ok: false, reason: 'ISSUER_MISMATCH' };
  }

  // The audience. `aud` is a string or an array of them; both mean "who this token is for", and
  // omitting this check accepts a token the provider minted for somebody else's application.
  const audience = payload['aud'];
  const audiences = Array.isArray(audience) ? audience : [audience];
  if (!audiences.includes(expectation.audience)) {
    return { ok: false, reason: 'AUDIENCE_MISMATCH' };
  }
  // `azp` is required when there are several audiences, and must be us. A token listing our client
  // id among four others was not issued *to* us unless it says so.
  if (audiences.length > 1 && payload['azp'] !== expectation.audience) {
    return { ok: false, reason: 'AUTHORIZED_PARTY_MISMATCH' };
  }

  const skew = expectation.clockSkewSeconds ?? 60;
  const seconds = Math.floor(expectation.now.getTime() / 1000);
  const exp = numberClaim(payload['exp']);
  if (exp === null || seconds - skew >= exp) {
    return { ok: false, reason: 'EXPIRED' };
  }
  const nbf = numberClaim(payload['nbf']);
  if (nbf !== null && seconds + skew < nbf) {
    return { ok: false, reason: 'NOT_YET_VALID' };
  }
  const iat = numberClaim(payload['iat']);
  // An ID token issued more than a day ago is not a fresh authentication however long its expiry
  // says. Providers set `exp` generously; this bounds what "just signed in" can mean.
  if (iat === null || seconds - iat > 86_400) {
    return { ok: false, reason: 'STALE' };
  }

  // The nonce, in constant time. It is a CSRF and replay defence: without it, an ID token captured
  // from any other flow with this provider can be replayed into ours.
  const nonce = payload['nonce'];
  if (typeof nonce !== 'string' || !constantTimeEquals(nonce, expectation.nonce)) {
    return { ok: false, reason: 'NONCE_MISMATCH' };
  }

  const subject = payload['sub'];
  if (typeof subject !== 'string' || subject.length === 0) {
    return { ok: false, reason: 'NO_SUBJECT' };
  }

  return { ok: true, claims: payload };
}

/** Two secrets compared without leaking where they differ. */
export function constantTimeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function verifyWith(
  key: Jwk,
  nodeAlgorithm: string,
  signed: string,
  signature: Buffer,
  alg: string,
): boolean {
  try {
    const publicKey = createPublicKey({ key: key as never, format: 'jwk' });
    const verifier = createVerify(nodeAlgorithm);
    verifier.update(signed, 'utf8');
    verifier.end();
    // ECDSA JWS signatures are the raw `r||s` concatenation of P1363, and OpenSSL expects DER.
    // `dsaEncoding: 'ieee-p1363'` is what tells it which it is being handed — without it every
    // ES256 token fails to verify, which would look like a provider problem.
    return alg.startsWith('ES')
      ? verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
      : verifier.verify(publicKey, signature);
  } catch {
    // A malformed JWK is a refusal, not a crash: a provider rotating keys can publish one this
    // build cannot import, and the other candidates must still be tried.
    return false;
  }
}

function decodeJson(segment: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function numberClaim(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
