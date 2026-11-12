import { readFileSync } from 'node:fs';

import {
  PLATFORM_SCHEMA,
  boolean,
  duration,
  extendConfig,
  integer,
  list,
  oneOf,
  parseConfig,
  pickSchema,
  port,
  redactConfig,
  remapSchema,
  secret,
  string,
  url,
  type Resolved,
} from '@munaxa/config';

import { PASSWORD_RECOVERY_FIELDS, passwordRecoveryIssues } from './password-recovery.js';
import { parseMfaKeys, reusesSecret } from './mfa-keys.js';
import { redisUrlIssues } from './redis-url.js';

/**
 * Identity's environment contract.
 *
 * Two halves, deliberately. The **platform half** is `PLATFORM_SCHEMA` — session timeouts, token
 * lifetimes, password policy, lockout — taken through `pickSchema` and `remapSchema` rather than
 * restated, so the platform keeps owning what a security setting *means* while Identity owns only
 * what the variable is called. Redefining one of those fields is refused by `extendConfig`, which
 * is the point: a product quietly overriding the platform's idea of an absolute session timeout is
 * how a security setting stops meaning what its documentation says.
 *
 * The **Identity half** is what no other product can supply: where the service listens, which
 * database and cache it owns, and the asymmetric key it signs with. `PLATFORM_SCHEMA` has no field
 * for a keypair — its only signing field is the symmetric `MUNAXA_SIGNING_SECRET` — so the three
 * `IDENTITY_SIGNING_*` fields are Identity's own, and the refinements below are what stop them
 * being used to build something Munaxa Work would refuse to trust.
 */

/** The only algorithms Munaxa Work will verify. A symmetric one would hand Work the minting key. */
export const IDENTITY_SIGNING_ALGORITHMS = ['ES256'] as const;

/** Fields taken from the platform. Everything omitted is a capability Identity does not wire. */
const PLATFORM_FIELDS = pickSchema(PLATFORM_SCHEMA, [
  'MUNAXA_SIGNING_SECRET',
  'MUNAXA_ENV',
  'MUNAXA_PASSWORD_MIN_LENGTH',
  'MUNAXA_PASSWORD_HISTORY',
  'MUNAXA_PASSWORD_BREACH_CHECK',
  'MUNAXA_SESSION_IDLE_TIMEOUT',
  'MUNAXA_SESSION_ABSOLUTE_TIMEOUT',
  'MUNAXA_SESSION_MAX_CONCURRENT',
  'MUNAXA_ACCESS_TOKEN_TTL',
  'MUNAXA_REFRESH_TOKEN_TTL',
  'MUNAXA_TOKEN_ISSUER',
  'MUNAXA_TOKEN_AUDIENCE',
  'MUNAXA_LOGIN_MAX_ATTEMPTS',
  'MUNAXA_LOGIN_LOCKOUT',
  'MUNAXA_TRUSTED_ORIGINS',
  'MUNAXA_REDIS_URL',
  'MUNAXA_LOG_LEVEL',
  'MUNAXA_AUDIT_ENABLED',
]);

/**
 * The names an operator actually sets.
 *
 * `MUNAXA_TOKEN_ISSUER` is read from `IDENTITY_BASE_URL` because the issuer *is* the service's
 * public base URL — one value, and two names for it is how a deployment ends up with a token whose
 * `iss` nothing recognises.
 */
const SOURCES = remapSchema(PLATFORM_FIELDS, {
  MUNAXA_SIGNING_SECRET: { env: 'IDENTITY_SIGNING_SECRET' },
  MUNAXA_ENV: { env: 'NODE_ENV' },
  MUNAXA_SESSION_IDLE_TIMEOUT: { env: 'SESSION_IDLE_TIMEOUT' },
  MUNAXA_SESSION_ABSOLUTE_TIMEOUT: { env: 'SESSION_ABSOLUTE_TIMEOUT' },
  MUNAXA_SESSION_MAX_CONCURRENT: { env: 'SESSION_MAX_CONCURRENT' },
  MUNAXA_ACCESS_TOKEN_TTL: { env: 'ACCESS_TOKEN_TTL' },
  MUNAXA_REFRESH_TOKEN_TTL: { env: 'REFRESH_TOKEN_TTL' },
  MUNAXA_TOKEN_ISSUER: { env: 'IDENTITY_BASE_URL' },
  MUNAXA_TOKEN_AUDIENCE: { env: 'IDENTITY_AUTH_AUDIENCE' },
  MUNAXA_TRUSTED_ORIGINS: { env: 'CSRF_TRUSTED_ORIGINS' },
  MUNAXA_REDIS_URL: { env: 'REDIS_URL' },
  MUNAXA_LOG_LEVEL: { env: 'LOG_LEVEL' },
  MUNAXA_PASSWORD_MIN_LENGTH: { env: 'PASSWORD_MIN_LENGTH' },
  MUNAXA_PASSWORD_HISTORY: { env: 'PASSWORD_HISTORY' },
  MUNAXA_PASSWORD_BREACH_CHECK: { env: 'PASSWORD_BREACH_CHECK' },
  MUNAXA_LOGIN_MAX_ATTEMPTS: { env: 'LOGIN_MAX_ATTEMPTS' },
  MUNAXA_LOGIN_LOCKOUT: { env: 'LOGIN_LOCKOUT' },
  MUNAXA_AUDIT_ENABLED: { env: 'AUDIT_ENABLED' },
});

/**
 * PEM markers, assembled rather than written out.
 *
 * A literal `-----BEGIN … PRIVATE KEY-----` in the source is indistinguishable from a committed key
 * to any tool that looks for one, and CI looks for one. Composing the markers keeps that check a
 * blunt search with no allow-list — and an allow-list is how the one real key eventually gets past
 * it.
 */
const marker = (label: string): string => `-----BEGIN ${label}-----`;
const PKCS8_PRIVATE = marker('PRIVATE KEY');
const EC_PRIVATE = marker('EC PRIVATE KEY');
const PUBLIC_MARKERS = [marker('PUBLIC KEY'), marker('RSA PUBLIC KEY')];

export const IDENTITY_SCHEMA = extendConfig(
  SOURCES,
  {
    APP_NAME: string({ default: 'munaxa-identity' }),
    APP_VERSION: string({ default: '0.0.0-dev' }),
    BUILD_SHA: string({ default: 'local' }),

    HOST: string({ default: '0.0.0.0' }),
    PORT: port({ default: 4001 }),

    DATABASE_URL: string({
      description: 'Runtime connection, as the restricted NOBYPASSRLS role. Never the owner.',
    }),
    DATABASE_POOL_SIZE: integer({ default: 10, min: 1, max: 100 }),

    LOG_PRETTY: boolean({ default: false }),

    /**
     * How many proxies stand in front of the service, which is Express's `trust proxy`.
     *
     * The login rate limit counts per client address, and that address is `request.ip`. With no
     * proxy trusted, behind a load balancer it is the balancer's own address, so every client
     * shares one counter: ten sign-ins in fifteen minutes from anyone locks out everyone. `1` on
     * the shared AWS stack (the ALB). `0`, the default, trusts no `X-Forwarded-For`, which is right
     * when the service is reached directly and is the only safe value when nothing strips a
     * client's own header.
     */
    TRUST_PROXY_HOPS: integer({ default: 0, min: 0, max: 10 }),

    IDENTITY_SIGNING_ALGORITHM: oneOf(IDENTITY_SIGNING_ALGORITHMS, { default: 'ES256' }),
    IDENTITY_SIGNING_KID: string({
      minLength: 3,
      description:
        'Stable key id, written into every token header. Convention: identity-<env>-<yyyy-mm>.',
    }),
    IDENTITY_SIGNING_PRIVATE_KEY: secret({
      minLength: 100,
      description: 'PEM, PKCS#8 or SEC1. Enters through the secret mechanism and is never logged.',
    }),

    /**
     * How long a `__Host-mx_session` cookie is offered to the browser.
     *
     * Separate from `ACCESS_TOKEN_TTL` on purpose: a cookie that outlives its token leaves the
     * browser presenting a credential the API has already stopped accepting, which reads to a user
     * as a broken session rather than an expired one. The refinement below keeps them equal unless
     * somebody deliberately sets otherwise.
     */
    SESSION_COOKIE_MAX_AGE: duration({ default: 900_000 }),

    /**
     * The organisation a sign-in belongs to when the form does not name one.
     *
     * A `UserDirectoryPort` lookup takes a tenant as its first argument, so a login must know its
     * organisation before it can find an account — and a staging deployment serving one customer
     * should not make somebody type a slug they have no way of knowing. Empty means every sign-in
     * must name its organisation explicitly, which is the right default for a shared deployment.
     *
     * This is a convenience over an existing row, never a bypass: the organisation must exist, and
     * an account is still found only inside it.
     */
    IDENTITY_DEFAULT_ORGANISATION: string({ default: '' }),

    /**
     * The MFA encryption key ring: `kid=base64key[,kid=base64key…]`, 32 random bytes each.
     *
     * Dedicated to sealing TOTP secrets and keying recovery-code hashes, and checked below not to
     * be the signing private key or `IDENTITY_SIGNING_SECRET` (the refresh-token pepper) under
     * another name. Supplied as `MFA_ENCRYPTION_KEYS_FILE` like every other secret. Required in
     * production; empty in development means MFA is unavailable, never that it runs unencrypted.
     */
    MFA_ENCRYPTION_KEYS: string({ secret: true, default: '', minLength: 0 }),
    /** Which entry of `MFA_ENCRYPTION_KEYS` new secrets are sealed under. Not secret. */
    MFA_ENCRYPTION_PRIMARY_KID: string({ default: '' }),

    /**
     * Who must have a second factor to sign in.
     *
     * `off` — MFA is optional: anyone may enrol, and an enrolled account is always challenged.
     * `privileged` — accounts holding any role in `MFA_PRIVILEGED_ROLES` must use MFA; one that has
     * not enrolled is admitted only to enrolment (see ADR-0005).
     * `all` — every password account must use MFA.
     *
     * Machine identities never sign in through this form (they use client credentials or API keys
     * against the consuming product), so no policy here can force one through TOTP. There is no
     * exempt account and no bypass flag: the policy is the same for everybody it names.
     */
    MFA_POLICY: oneOf(['off', 'privileged', 'all'] as const, { default: 'off' }),
    /** Role keys whose holders count as privileged under `MFA_POLICY=privileged`. */
    MFA_PRIVILEGED_ROLES: list({ default: [] }),
    /** How long the sign-in second-factor challenge lives after the password is accepted. */
    MFA_CHALLENGE_TTL: duration({ default: 5 * 60 * 1_000 }),
    /** How long the enrolment-only challenge lives when policy requires MFA and none is enrolled. */
    MFA_ENROLLMENT_CHALLENGE_TTL: duration({ default: 10 * 60 * 1_000 }),
    /** Wrong codes accepted against one challenge before it is destroyed. */
    MFA_CHALLENGE_MAX_ATTEMPTS: integer({ default: 5, min: 1, max: 10 }),
    /** Wrong codes accepted per account, across challenges, before second-factor checks lock. */
    MFA_ACCOUNT_MAX_FAILURES: integer({ default: 10, min: 3, max: 50 }),
    /** How recent a password (plus code, when enrolled) must be for enrol, replace, remove. */
    MFA_REAUTH_WINDOW: duration({ default: 5 * 60 * 1_000 }),
    /** The issuer label an authenticator app shows next to the account. */
    MFA_ISSUER: string({ default: 'Munaxa' }),
    /**
     * What a person's session list shows about where each session came from.
     *
     * `prefix` (the default) shows the network — `203.0.113.0/24`, or the /48 of an IPv6
     * address — which is enough to recognise "that was me, at home" and is not the full address.
     * `hidden` shows nothing, for a deployment whose privacy policy does not permit even that.
     * The full address is never returned under either setting.
     */
    IDENTITY_SESSION_LIST_IP: oneOf(['hidden', 'prefix'] as const, { default: 'prefix' }),

    /**
     * Edge limits on the credential routes (`apps/api/src/security/auth-edge-limits.ts`).
     *
     * The per-address limits are shared by everybody behind one public address — a school, an
     * office, a mobile carrier — so they are sized for a population and the per-account controls
     * (`EDGE_LOGIN_PER_IDENTIFIER_LIMIT`, `LOGIN_MAX_ATTEMPTS`) are what stop guessing at one
     * account. The defaults are provisional: no production traffic exists yet to size them from.
     * Each has a floor so a typo cannot lock a whole school out. See docs/rate-limits.md.
     */
    /** Sign-in posts per client address per 5 minutes. */
    EDGE_LOGIN_PER_IP_LIMIT: integer({ default: 300, min: 30, max: 100_000 }),
    /** Sign-in posts per typed identifier (trimmed, lowercased), any address, per 15 minutes. */
    EDGE_LOGIN_PER_IDENTIFIER_LIMIT: integer({ default: 20, min: 10, max: 200 }),
    /** Password-reset request and completion posts per client address per hour. */
    EDGE_PASSWORD_RESET_PER_IP_LIMIT: integer({ default: 60, min: 10, max: 10_000 }),
    /** Second-factor and reauthentication posts per client address per 15 minutes. */
    EDGE_MFA_PER_IP_LIMIT: integer({ default: 300, min: 30, max: 100_000 }),
    /** Second-factor and reauthentication posts per challenge or session per 15 minutes. */
    EDGE_MFA_PER_SESSION_LIMIT: integer({ default: 10, min: 5, max: 100 }),
    /** Reset-link requests per client address per hour, in the recovery service itself. */
    PASSWORD_RESET_REQUESTS_PER_IP: integer({ default: 30, min: 5, max: 10_000 }),

    /** Password recovery and email delivery; see `password-recovery.ts`. */
    ...PASSWORD_RECOVERY_FIELDS,
  },
  {
    refine: (resolved) => {
      const issues: { key: string; problem: string }[] = [];
      const production = resolved.MUNAXA_ENV === 'production';

      const key = resolved.IDENTITY_SIGNING_PRIVATE_KEY.trim();
      if (PUBLIC_MARKERS.some((prefix) => key.includes(prefix))) {
        issues.push({
          key: 'IDENTITY_SIGNING_PRIVATE_KEY',
          problem:
            'is a public key. Identity signs with the private half; the public half goes to Munaxa Work.',
        });
      } else if (!key.startsWith(PKCS8_PRIVATE) && !key.startsWith(EC_PRIVATE)) {
        issues.push({
          key: 'IDENTITY_SIGNING_PRIVATE_KEY',
          problem: 'is not a PEM private key. Generate one with `pnpm keys:generate`.',
        });
      }

      if (!/^https?:\/\//.test(resolved.MUNAXA_TOKEN_ISSUER)) {
        issues.push({
          key: 'IDENTITY_BASE_URL',
          problem:
            'must be an absolute URL. It becomes the `iss` claim, which Munaxa Work compares exactly.',
        });
      }
      if (production && !resolved.MUNAXA_TOKEN_ISSUER.startsWith('https://')) {
        issues.push({ key: 'IDENTITY_BASE_URL', problem: 'must be https in production.' });
      }
      if (resolved.MUNAXA_TOKEN_AUDIENCE.length === 0) {
        issues.push({
          key: 'IDENTITY_AUTH_AUDIENCE',
          problem: 'must name at least one audience. Munaxa Work checks `aud` by overlap.',
        });
      }
      if (resolved.MUNAXA_TRUSTED_ORIGINS.length === 0) {
        issues.push({
          key: 'CSRF_TRUSTED_ORIGINS',
          problem:
            'must list the public origin the browser posts from. Empty means every cross-site post is accepted.',
        });
      }
      issues.push(...mfaKeyIssues(resolved, production));
      issues.push(...mfaPolicyIssues(resolved));

      if (production) {
        if (resolved.MUNAXA_REDIS_URL === '') {
          issues.push({
            key: 'REDIS_URL',
            problem:
              'is required in production. Without a shared counter store, login lockout is disabled and the permission cache diverges per replica.',
          });
        }
        issues.push(...redisUrlIssues(resolved.MUNAXA_REDIS_URL, production));
        if (resolved.LOG_PRETTY) {
          issues.push({ key: 'LOG_PRETTY', problem: 'must be false in production.' });
        }
      }
      issues.push(...passwordRecoveryIssues(resolved));
      return issues;
    },
  },
);

export type IdentityEnvironment = Resolved<typeof IDENTITY_SCHEMA.fields>;

/**
 * MFA policy that cannot be honoured is refused at startup rather than enforced into a lockout.
 *
 * Enforcement without a key ring would leave required accounts with nowhere to enrol, and a
 * privileged policy with no privileged roles enforces nothing while reading as if it did.
 */
function mfaPolicyIssues(resolved: {
  readonly MFA_POLICY: 'off' | 'privileged' | 'all';
  readonly MFA_PRIVILEGED_ROLES: readonly string[];
  readonly MFA_ENCRYPTION_KEYS: string;
  readonly MFA_CHALLENGE_TTL: number;
  readonly MFA_ENROLLMENT_CHALLENGE_TTL: number;
  readonly MFA_REAUTH_WINDOW: number;
}): { key: string; problem: string }[] {
  const issues: { key: string; problem: string }[] = [];
  if (resolved.MFA_POLICY !== 'off' && resolved.MFA_ENCRYPTION_KEYS.trim() === '') {
    issues.push({
      key: 'MFA_POLICY',
      problem: `is ${resolved.MFA_POLICY}, but MFA_ENCRYPTION_KEYS is empty: required accounts would have no way to enrol.`,
    });
  }
  if (resolved.MFA_POLICY === 'privileged' && resolved.MFA_PRIVILEGED_ROLES.length === 0) {
    issues.push({
      key: 'MFA_PRIVILEGED_ROLES',
      problem: 'must name at least one role key when MFA_POLICY=privileged.',
    });
  }
  const bounded = (key: string, value: number, min: number, max: number): void => {
    if (value < min || value > max) {
      issues.push({ key, problem: `must be between ${min / 1_000}s and ${max / 1_000}s.` });
    }
  };
  bounded('MFA_CHALLENGE_TTL', resolved.MFA_CHALLENGE_TTL, 60_000, 10 * 60_000);
  bounded(
    'MFA_ENROLLMENT_CHALLENGE_TTL',
    resolved.MFA_ENROLLMENT_CHALLENGE_TTL,
    60_000,
    15 * 60_000,
  );
  bounded('MFA_REAUTH_WINDOW', resolved.MFA_REAUTH_WINDOW, 60_000, 15 * 60_000);
  return issues;
}

/**
 * Everything that can be wrong with the MFA key ring, reported by name and never by value.
 *
 * Production requires a ring because MFA is part of the authentication contract there: a service
 * that started without one would either refuse every enrolled user or — the outcome this exists to
 * prevent — be patched to run without encryption. Development may omit it, and MFA is then simply
 * unavailable.
 */
function mfaKeyIssues(
  resolved: {
    readonly MFA_ENCRYPTION_KEYS: string;
    readonly MFA_ENCRYPTION_PRIMARY_KID: string;
    readonly MUNAXA_SIGNING_SECRET: string;
    readonly IDENTITY_SIGNING_PRIVATE_KEY: string;
  },
  production: boolean,
): { key: string; problem: string }[] {
  const issues: { key: string; problem: string }[] = [];
  const raw = resolved.MFA_ENCRYPTION_KEYS.trim();
  const primary = resolved.MFA_ENCRYPTION_PRIMARY_KID.trim();

  if (raw === '') {
    if (production) {
      issues.push({
        key: 'MFA_ENCRYPTION_KEYS',
        problem:
          'is required in production. TOTP secrets are encrypted at rest under this dedicated key ring; supply it through MFA_ENCRYPTION_KEYS_FILE.',
      });
    }
    if (primary !== '') {
      issues.push({
        key: 'MFA_ENCRYPTION_PRIMARY_KID',
        problem: 'names a key, but MFA_ENCRYPTION_KEYS is empty.',
      });
    }
    return issues;
  }

  const { entries, problems } = parseMfaKeys(raw);
  for (const problem of problems) issues.push({ key: 'MFA_ENCRYPTION_KEYS', problem });
  if (entries.length === 0 && problems.length === 0) {
    issues.push({ key: 'MFA_ENCRYPTION_KEYS', problem: 'contains no key.' });
  }
  if (primary === '') {
    issues.push({
      key: 'MFA_ENCRYPTION_PRIMARY_KID',
      problem: 'is required when MFA_ENCRYPTION_KEYS is set: it names the key new secrets use.',
    });
  } else if (entries.length > 0 && !entries.some((entry) => entry.kid === primary)) {
    issues.push({
      key: 'MFA_ENCRYPTION_PRIMARY_KID',
      problem: `names ${primary}, which is not a key in MFA_ENCRYPTION_KEYS.`,
    });
  }
  for (const entry of entries) {
    if (reusesSecret(entry.key, resolved.MUNAXA_SIGNING_SECRET)) {
      issues.push({
        key: 'MFA_ENCRYPTION_KEYS',
        problem: `key ${entry.kid} is IDENTITY_SIGNING_SECRET. The MFA key must be dedicated material.`,
      });
    }
    if (reusesSecret(entry.key, resolved.IDENTITY_SIGNING_PRIVATE_KEY)) {
      issues.push({
        key: 'MFA_ENCRYPTION_KEYS',
        problem: `key ${entry.kid} is taken from the signing private key. The MFA key must be dedicated material.`,
      });
    }
  }
  return issues;
}

/**
 * Read `NAME` from the file named by `NAME_FILE`, wherever one is set.
 *
 * This is the convention every secret manager that mounts secrets already speaks — Docker and
 * Swarm secrets, Kubernetes projected volumes, ECS and Nomad secret files. It matters because the
 * alternative is a secret in an environment variable, and an environment variable is visible to
 * `docker inspect`, to every process in the container, to a crash reporter that dumps the
 * environment, and to any log line that prints `process.env`. For a signing key that is the whole
 * compromise.
 *
 * **`NAME_FILE` wins over an ambient `NAME`, and that is the whole point.** The opposite rule
 * looks more polite and is wrong: an ambient variable is not necessarily something an operator
 * set. Prisma's client loads a `.env` file at import time to resolve its own datasource, so
 * importing it populates `process.env.DATABASE_URL` from whatever `.env` is lying about — before
 * this function runs. Under the file convention that variable is deliberately unset, so the stray
 * development value won, and the service started, passed readiness and answered every sign-in with
 * a generic 401 from the wrong database. Mounting a secret file is a deliberate act; inheriting an
 * environment variable is not.
 *
 * An unreadable file is still an error rather than a fallback, for the same reason: a deployment
 * that names a mount and does not get one must not quietly run on something else.
 */
const withSecretFiles = (
  source: Readonly<Record<string, string | undefined>>,
  read: (path: string) => string = (path) => readFileSync(path, 'utf8'),
): Readonly<Record<string, string | undefined>> => {
  const resolved: Record<string, string | undefined> = { ...source };

  for (const [key, value] of Object.entries(source)) {
    if (!key.endsWith('_FILE') || value === undefined || value.trim() === '') continue;

    const name = key.slice(0, -'_FILE'.length);

    try {
      // Trailing newlines are what an editor adds and what `echo` adds; a PEM does not mind one
      // and a connection string very much does.
      resolved[name] = read(value.trim()).replace(/\s+$/, '');
    } catch (cause) {
      throw new Error(
        `${key} names ${value}, which could not be read. A secret mount that is absent at startup ` +
          'is a service that would otherwise run without the secret it was configured to need.',
        { cause },
      );
    }
  }
  return resolved;
};

/** Parse and validate. Throws once, listing every problem, rather than one per restart. */
export const loadEnvironment = (
  source: Readonly<Record<string, string | undefined>> = process.env,
  readSecretFile?: (path: string) => string,
): IdentityEnvironment =>
  parseConfig(
    IDENTITY_SCHEMA,
    readSecretFile === undefined
      ? withSecretFiles(source)
      : withSecretFiles(source, readSecretFile),
  );

/** The rendering safe to log or serve: every field marked `secret` is replaced. */
export const describeEnvironment = (resolved: IdentityEnvironment): Record<string, unknown> =>
  redactConfig(IDENTITY_SCHEMA, resolved);
