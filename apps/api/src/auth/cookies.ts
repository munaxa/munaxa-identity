import { SESSION_COOKIE, clearCookie, refreshCookie, sessionCookie } from '@munaxa/auth';
import type { CookieInstruction } from '@munaxa/types';
import type { Response } from 'express';

/**
 * The browser's half of the session, rendered onto an Express response.
 *
 * The cookies themselves are Platform's — `sessionCookie` and `refreshCookie` — and nothing here
 * chooses their attributes. That matters more than it looks: `httpOnly` and `secure` are not
 * parameters in Platform's builder, `sameSite` may be narrowed but never widened past `lax`, and
 * the `__Host-` prefix means the browser itself enforces `Secure`, `Path=/` and the absence of a
 * `Domain`. A subdomain therefore cannot set or overwrite the session, which is what closes the
 * cookie-injection route that session fixation relies on.
 *
 * The consequence for deployment is the one Phase 7B recorded: a `__Host-` cookie is host-only, so
 * Identity and the portal that reads it must be reachable on one public origin. That is a routing
 * decision, not an application one — the services stay separate.
 */
export { SESSION_COOKIE };

/** Where the refresh cookie is offered, and nowhere else. */
export const REFRESH_PATH = '/api/auth/refresh';

/**
 * The refresh cookie's name, which is Identity's and not Platform's — the one place this file
 * departs from `@munaxa/auth`, and it is a defect in Platform that forces it.
 *
 * `@munaxa/auth` exports `REFRESH_COOKIE = '__Host-mx_refresh'` and its own `refreshCookie` builder
 * defaults that cookie to `path: '/api/auth/refresh'`. Those two facts cannot both hold. The
 * `__Host-` prefix is not decoration: RFC 6265bis requires such a cookie to be `Secure`, carry no
 * `Domain`, and have `Path=/` **exactly**. A `__Host-` cookie on any narrower path is rejected
 * outright — not downgraded, not warned about, silently dropped.
 *
 * Measured, not reasoned about. Chromium was driven through the real sign-in form: the server sent
 * `set-cookie: __Host-mx_refresh=…; Path=/api/auth/refresh`, and the browser's cookie jar afterwards
 * contained the session cookie and nothing else. Every API-level test passed throughout, because
 * they parse `Set-Cookie` themselves and no parser enforces the prefix rules a browser does. The
 * user-visible consequence is that silent session renewal cannot work in a browser at all: when the
 * fifteen-minute access token expires the person is signed out, with no refresh token to rotate.
 *
 * `__Secure-` is the correct prefix for a path-scoped cookie: it requires `Secure` and allows any
 * path. What it does not carry is `__Host-`'s guarantee of host-only — but this cookie sets no
 * `Domain` and the serializer below cannot emit one, so it is host-only in fact; the prefix simply
 * stops enforcing it against an attacker who controls a sibling subdomain. Under ADR-0004 there is
 * one origin and no sibling to control, and keeping the path narrow — so the refresh token is never
 * sent to Munaxa Work's routes — is worth more here than a prefix the browser refuses to honour.
 *
 * Platform is frozen and this is not worked around silently: the defect is reported for its owners
 * rather than patched here, per the five laws. Widening the path to `/` would also satisfy the
 * prefix, and is the wrong trade — it would put the refresh token on every request to the shared
 * origin, including every call into another product.
 */
export const REFRESH_COOKIE = '__Secure-mx_refresh';

const serialize = (instruction: CookieInstruction): string => {
  const { name, value, options } = instruction;
  const parts = [`${name}=${encodeURIComponent(value)}`];

  if (options.path !== undefined) parts.push(`Path=${options.path}`);
  if (options.maxAgeSeconds !== undefined) parts.push(`Max-Age=${options.maxAgeSeconds}`);
  if (options.expires !== undefined) parts.push(`Expires=${options.expires.toUTCString()}`);
  // No `Domain` branch, and deliberately none: a `__Host-` cookie may not carry one, and a helper
  // that could emit it is a helper somebody eventually uses.
  if (options.secure === true) parts.push('Secure');
  if (options.httpOnly === true) parts.push('HttpOnly');
  if (options.sameSite !== undefined) {
    parts.push(`SameSite=${options.sameSite[0]?.toUpperCase()}${options.sameSite.slice(1)}`);
  }
  if (options.partitioned === true) parts.push('Partitioned');

  return parts.join('; ');
};

export const setCookies = (
  response: Response,
  instructions: readonly CookieInstruction[],
): void => {
  const existing = response.getHeader('Set-Cookie');
  const previous = existing === undefined ? [] : ([] as string[]).concat(existing as string[]);
  response.setHeader('Set-Cookie', [...previous, ...instructions.map(serialize)]);
};

export const issueCookies = (
  response: Response,
  tokens: { readonly access: string; readonly refresh: string },
  sessionMaxAge: number,
): void => {
  setCookies(response, [
    sessionCookie(tokens.access, { maxAge: sessionMaxAge }),
    // Platform's builder for the attributes, Identity's name for the reason above.
    { ...refreshCookie(tokens.refresh, { path: REFRESH_PATH }), name: REFRESH_COOKIE },
  ]);
};

export const clearSessionCookies = (response: Response): void => {
  setCookies(response, [
    clearCookie(SESSION_COOKIE, '/'),
    clearCookie(REFRESH_COOKIE, REFRESH_PATH),
  ]);
};
