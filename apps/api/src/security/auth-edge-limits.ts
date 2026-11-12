import { createHash } from 'node:crypto';

import type { CachePort } from '@munaxa/interfaces';
import { RateLimiter, normalizePath, type RateLimitRule } from '@munaxa/security';
import { ROOT_TENANT_ID, type Clock } from '@munaxa/types';

/**
 * The edge limits on Identity's credential routes: sign-in, password reset, second factor.
 *
 * **Route identity.** Nest mounts the edge middleware on every route, and under that mount Express
 * reports `request.path` as `/`, so a rule matched on it never fires (that was the defect). The edge
 * now matches on `canonicalRoute(request.originalUrl)`: absolute-form target, query and fragment
 * removed, percent-decoded, dot segments resolved, repeated and trailing slashes collapsed,
 * lowercased. Express routes case variants, one trailing slash, a query and an absolute-form target
 * to the handler; it answers 404 for the other spellings, which the canonical form maps onto the
 * route too, so a respelling can only be counted more, never less. Nothing a client sends in a
 * header takes part in it.
 *
 * **Why these rules are Identity's own and not Platform's baseline.** The published Platform
 * limiter (2.4.1) restarts an adaptive rule's count after each refusal and admits on a store
 * failure. These rules are non-adaptive (so the count is one stable counter per rule and subject,
 * refusals included) and each is evaluated by a limiter of its own, so a store failure is seen per
 * rule and refused (`unavailable`, 503) rather than admitted. Adopting a later Platform release
 * needs its own review: munaxa-platform#107 changes how malformed counter values and IPv6 addresses
 * are treated, and this module must be re-tested against it (it is pinned to 2.4.1 behaviour).
 *
 * **Addresses.** IPv6 clients are counted by their /64 (`addressSubject`), since one subscriber
 * normally holds a whole /64 and could otherwise rotate past every per-address limit.
 *
 * **Shared addresses.** A school or office signs in from one public address, so the per-address
 * limits are sized for a population, not for a person; what stops guessing at one account is the
 * per-account control (`login-per-identifier` here, and Platform's lockout in `LoginService`), which
 * does not depend on the address. Rules are evaluated in order and the first refusal stops: a
 * request refused for its identifier is not charged to the address, so one account being hammered
 * from inside a school cannot spend the whole school's sign-in budget.
 */

export interface AuthEdgePolicy {
  /** POST /api/auth/login per client address, per 5 minutes. */
  readonly loginPerIp: number;
  /** POST /api/auth/login per typed identifier (trimmed, lowercased), per 15 minutes. */
  readonly loginPerIdentifier: number;
  /** POST /api/auth/password/forgot and /reset per client address, per hour. */
  readonly passwordResetPerIp: number;
  /** State-changing MFA and reauthentication routes per client address, per 15 minutes. */
  readonly mfaPerIp: number;
  /** The same routes per challenge or session, per 15 minutes. */
  readonly mfaPerSession: number;
}

const MINUTE = 60 * 1_000;

export const LOGIN_ROUTE = '/api/auth/login';
export const PASSWORD_ROUTES: ReadonlySet<string> = new Set([
  '/api/auth/password/forgot',
  '/api/auth/password/reset',
]);
/** Routes that check a second factor or a password inside a session, each with its method. */
export const MFA_ROUTES: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['/api/auth/mfa/verify', new Set(['POST'])],
  ['/api/auth/reauthenticate', new Set(['POST'])],
  ['/api/auth/mfa/enrollment', new Set(['POST'])],
  ['/api/auth/mfa/enrollment/confirm', new Set(['POST'])],
  ['/api/auth/mfa/recovery-codes', new Set(['POST'])],
  ['/api/auth/mfa', new Set(['DELETE'])],
]);

/**
 * The route a request target names, folded to one spelling (see the header).
 *
 * `normalizePath` decodes once (never repeatedly), drops control characters, turns `\` into `/` and
 * resolves `.` and `..`; this removes an absolute-form scheme and host and any query or fragment
 * first, and lowercases after.
 */
export const canonicalRoute = (target: string): string => {
  let path = target;
  const absolute = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(path);
  if (absolute) path = path.slice(absolute[0].length);
  const end = path.search(/[?#]/);
  if (end !== -1) path = path.slice(0, end);
  return normalizePath(path).toLowerCase();
};

const isMethod = (method: string, expected: string): boolean => method.toUpperCase() === expected;

export const isLogin = (method: string, route: string): boolean =>
  isMethod(method, 'POST') && route === LOGIN_ROUTE;
export const isPasswordReset = (method: string, route: string): boolean =>
  isMethod(method, 'POST') && PASSWORD_ROUTES.has(route);
export const isMfa = (method: string, route: string): boolean =>
  MFA_ROUTES.get(route)?.has(method.toUpperCase()) === true;

export const authEdgeRules = (policy: AuthEdgePolicy): RateLimitRule[] => [
  // Per identifier first: a refusal here stops before the address is charged.
  {
    id: 'login-per-identifier',
    match: (target) => isLogin(target.method, target.path),
    dimension: 'user',
    limit: policy.loginPerIdentifier,
    window: 15 * MINUTE,
  },
  {
    id: 'login-per-ip',
    match: (target) => isLogin(target.method, target.path),
    dimension: 'ip',
    limit: policy.loginPerIp,
    window: 5 * MINUTE,
  },
  {
    id: 'password-reset-per-ip',
    match: (target) => isPasswordReset(target.method, target.path),
    dimension: 'ip',
    limit: policy.passwordResetPerIp,
    window: 60 * MINUTE,
  },
  {
    id: 'mfa-per-session',
    match: (target) => isMfa(target.method, target.path),
    dimension: 'session',
    limit: policy.mfaPerSession,
    window: 15 * MINUTE,
  },
  {
    id: 'mfa-per-ip',
    match: (target) => isMfa(target.method, target.path),
    dimension: 'ip',
    limit: policy.mfaPerIp,
    window: 15 * MINUTE,
  },
];

/**
 * The digest a sign-in identifier is counted under: never the address itself, in a key or a log.
 *
 * Scoped by the organisation typed with it, so somebody who knows an address cannot hold that
 * person's sign-in at 429 in every organisation by posting it with a made-up one. Both are trimmed
 * and lowercased the way the directory and the organisation lookup read them.
 */
export const identifierSubject = (
  identifier: unknown,
  organisation?: unknown,
): string | undefined => {
  if (typeof identifier !== 'string') return undefined;
  const normalised = identifier.trim().toLowerCase();
  if (normalised === '') return undefined;
  const scope = typeof organisation === 'string' ? organisation.trim().toLowerCase() : '';
  return `id:${createHash('sha256').update(`${scope}\u0000${normalised}`).digest('hex').slice(0, 32)}`;
};

/**
 * The subject an address is counted under: IPv4 as it is, IPv6 by its /64, an IPv4-mapped IPv6
 * address as the IPv4 address it maps.
 */
export const addressSubject = (address: string): string => {
  const trimmed = address.trim().toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(trimmed);
  if (mapped) return mapped[1]!;
  if (!trimmed.includes(':')) return trimmed;
  const [head = '', tail] = trimmed.split('%')[0]!.split('::');
  const left = head === '' ? [] : head.split(':');
  const right = tail === undefined || tail === '' ? [] : tail.split(':');
  const groups =
    tail === undefined
      ? left
      : [
          ...left,
          ...Array.from({ length: Math.max(0, 8 - left.length - right.length) }, () => '0'),
          ...right,
        ];
  return `${groups
    .slice(0, 4)
    .map((group) => (group === '' ? '0' : group.replace(/^0+(?=.)/, '')))
    .join(':')}::/64`;
};

/** The digest a challenge or session credential is counted under. */
export const credentialSubject = (kind: 'challenge' | 'session', value: string): string =>
  `${kind}:${createHash('sha256').update(value).digest('hex').slice(0, 32)}`;

export interface AuthEdgeRequest {
  readonly method: string;
  /** From `canonicalRoute`. */
  readonly route: string;
  readonly ipAddress?: string;
  /** From `identifierSubject`; only consulted on the sign-in route. */
  readonly identifier?: string;
  /** From `credentialSubject`; only consulted on the MFA routes. */
  readonly credential?: string;
}

export type AuthEdgeDecision =
  | { readonly kind: 'allowed' }
  | {
      readonly kind: 'limited';
      readonly rule: string;
      readonly limit: number;
      readonly retryAfterSeconds: number;
    }
  | { readonly kind: 'unavailable'; readonly rule: string };

/**
 * One limiter per rule, evaluated in order, first refusal wins.
 *
 * A Platform 2.4.1 `RateLimiter.check` with several rules reports only the decision with the fewest
 * remaining, so a store failure on one rule can be hidden behind another; with one rule per limiter
 * every `degraded` is seen, and a credential route whose limit cannot be read is refused.
 */
export class AuthEdgeLimiter {
  private readonly limiters: readonly (readonly [RateLimitRule, RateLimiter])[];

  public constructor(cache: CachePort, policy: AuthEdgePolicy, clock?: Clock) {
    this.limiters = authEdgeRules(policy).map(
      (rule) =>
        [
          rule,
          new RateLimiter({ cache, rules: [rule], ...(clock === undefined ? {} : { clock }) }),
        ] as const,
    );
  }

  public get rules(): readonly RateLimitRule[] {
    return this.limiters.map(([rule]) => rule);
  }

  public async check(request: AuthEdgeRequest): Promise<AuthEdgeDecision> {
    const target = {
      method: request.method,
      path: request.route,
      tenantId: ROOT_TENANT_ID,
      ...(request.ipAddress === undefined ? {} : { ipAddress: addressSubject(request.ipAddress) }),
      ...(request.identifier === undefined ? {} : { userId: request.identifier }),
      ...(request.credential === undefined ? {} : { sessionId: request.credential }),
    };
    for (const [rule, limiter] of this.limiters) {
      if (rule.match?.(target) !== true) continue;
      const decision = await limiter.check(target);
      if (decision.degraded === true) return { kind: 'unavailable', rule: rule.id };
      if (!decision.allowed) {
        return {
          kind: 'limited',
          rule: rule.id,
          limit: rule.limit,
          retryAfterSeconds: Math.max(1, decision.retryAfterSeconds),
        };
      }
    }
    return { kind: 'allowed' };
  }
}
