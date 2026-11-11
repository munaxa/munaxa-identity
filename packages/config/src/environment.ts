import { readFileSync } from 'node:fs';

import {
  PLATFORM_SCHEMA,
  boolean,
  duration,
  extendConfig,
  integer,
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
     * What a person's session list shows about where each session came from.
     *
     * `prefix` (the default) shows the network — `203.0.113.0/24`, or the /48 of an IPv6
     * address — which is enough to recognise "that was me, at home" and is not the full address.
     * `hidden` shows nothing, for a deployment whose privacy policy does not permit even that.
     * The full address is never returned under either setting.
     */
    IDENTITY_SESSION_LIST_IP: oneOf(['hidden', 'prefix'] as const, { default: 'prefix' }),
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
      if (production) {
        if (resolved.MUNAXA_REDIS_URL === '') {
          issues.push({
            key: 'REDIS_URL',
            problem:
              'is required in production. Without a shared counter store, login lockout is disabled and the permission cache diverges per replica.',
          });
        }
        if (resolved.LOG_PRETTY) {
          issues.push({ key: 'LOG_PRETTY', problem: 'must be false in production.' });
        }
      }
      return issues;
    },
  },
);

export type IdentityEnvironment = Resolved<typeof IDENTITY_SCHEMA.fields>;

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
