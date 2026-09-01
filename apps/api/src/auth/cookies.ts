import {
  REFRESH_COOKIE,
  SESSION_COOKIE,
  clearCookie,
  refreshCookie,
  sessionCookie,
} from '@munaxa/auth';
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
export { REFRESH_COOKIE, SESSION_COOKIE };

/** Where the refresh cookie is offered, and nowhere else. */
export const REFRESH_PATH = '/api/auth/refresh';

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
    refreshCookie(tokens.refresh, { path: REFRESH_PATH }),
  ]);
};

export const clearSessionCookies = (response: Response): void => {
  setCookies(response, [
    clearCookie(SESSION_COOKIE, '/'),
    clearCookie(REFRESH_COOKIE, REFRESH_PATH),
  ]);
};
