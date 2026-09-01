# Platform defect — `__Host-mx_refresh` is rejected by every browser

**Status:** reported, worked around locally in Identity, not fixed in Platform
**Package:** `@munaxa/auth` 2.4.1, `dist/http.js`
**Found:** Phase 11, by driving Chromium through the real sign-in form

## What is wrong

`@munaxa/auth` exports the refresh cookie's name and its builder:

```js
export const REFRESH_COOKIE = '__Host-mx_refresh';

export function refreshCookie(value, options = {}) {
  return {
    name: REFRESH_COOKIE,
    value,
    options: hardenedCookie({ sameSite: 'strict', path: '/api/auth/refresh', ...options }),
  };
}
```

Those two lines contradict each other. RFC 6265bis requires a cookie whose name begins `__Host-` to
be `Secure`, to carry no `Domain`, and to have **`Path=/` exactly**. The builder's own default path
is `/api/auth/refresh`. A conforming browser does not downgrade such a cookie or warn about it — it
rejects the `Set-Cookie` header outright.

So Platform's refresh cookie, used exactly as Platform ships it, is never stored by a browser.

## How it was found, and why nothing caught it earlier

Chromium was driven through Identity's sign-in form. The server sent both cookies:

```
set-cookie: __Host-mx_session=…; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Lax
set-cookie: __Secure-mx_refresh=…; Path=/api/auth/refresh; Secure; HttpOnly; SameSite=Strict
```

— and after sign-in the browser's cookie jar held the session cookie and nothing else.

Every API-level test passed throughout, including an eighteen-check cross-product acceptance suite
that exercises refresh rotation and refresh-reuse family revocation. They pass because they read
`Set-Cookie` and send `Cookie` themselves, and no such parser enforces the prefix rules a browser
enforces. This defect is invisible to anything short of a real browser.

## What it costs

Silent session renewal cannot work in a browser. When the fifteen-minute access token expires the
person is signed out, because there is no stored refresh token to rotate. Every other authentication
property is unaffected.

## What Identity does about it

`apps/api/src/auth/cookies.ts` names the cookie `__Secure-mx_refresh` and keeps Platform's builder
for every attribute. `__Secure-` requires `Secure` and permits any path, which is the correct prefix
for a path-scoped cookie.

What that gives up is `__Host-`'s _enforcement_ of host-only. The cookie sets no `Domain` and
Identity's serializer cannot emit one, so it is host-only in fact; the prefix would only add
protection against an attacker who controls a sibling subdomain, and ADR-0004 pins the deployment to
a single origin with no sibling to control.

## The fix Platform should make, and the one it should not

Platform should rename the constant to `__Secure-mx_refresh`, keeping the narrow path.

It should **not** widen the default path to `/` to satisfy the `__Host-` prefix. That would put the
refresh token on every request to the origin — and under the shared-origin topology ADR-0004
requires, that means sending it to another product's API routes on every call. A prefix is worth
less than keeping a long-lived credential off the wire.

This is recorded rather than patched because `munaxa-platform` is frozen and because a product does
not quietly rewrite the platform it shares with four other products.
