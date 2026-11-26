import { duration, oneOf, string } from '@munaxa/config';

import { reusesSecret } from './mfa-keys.js';

/**
 * Company sign-in (OpenID Connect with Microsoft Entra ID or Google Workspace).
 *
 * Munaxa holds **one** application registration per provider. A company's administrator consents
 * to it in their own directory, and an operator records which directory and which email domains
 * belong to which organisation (`identity_sso_connection`, `identity_sso_domain`). So the
 * configuration here is small: whether the feature exists, and Munaxa's own client id and secret
 * for each provider. Nothing here names a customer.
 *
 * Off by default, and off means absent: the sign-in page shows no company button and the routes
 * answer 404, exactly as password reset does when it is disabled.
 *
 * Callback URLs are `<origin>/api/auth/sso/callback` for every origin in `CSRF_TRUSTED_ORIGINS`
 * (Identity is reached on more than one public origin, ADR-0004), and each one must be registered
 * with the provider. They are built from that list and never from a request header alone: a
 * request naming a host that is not in it cannot start a sign-in (`docs/runbooks/sso.md`).
 */

/** The longest a browser may take to come back from the provider: fifteen minutes. */
export const MAX_SSO_FLOW_TTL = 15 * 60 * 1_000;

export const SSO_FIELDS = {
  /** Whether company sign-in exists at all. `disabled` answers the routes with 404. */
  IDENTITY_SSO: oneOf(['enabled', 'disabled'] as const, { default: 'disabled' }),

  /** Munaxa's Entra application (client) id: a GUID. Not secret. Empty = Microsoft unavailable. */
  IDENTITY_SSO_MICROSOFT_CLIENT_ID: string({ default: '', minLength: 0 }),
  /** Munaxa's Entra client secret. Supplied as `IDENTITY_SSO_MICROSOFT_CLIENT_SECRET_FILE`. */
  IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: string({ secret: true, default: '', minLength: 0 }),

  /** Munaxa's Google OAuth client id (`….apps.googleusercontent.com`). Empty = Google unavailable. */
  IDENTITY_SSO_GOOGLE_CLIENT_ID: string({ default: '', minLength: 0 }),
  /** Munaxa's Google OAuth client secret. Supplied as `IDENTITY_SSO_GOOGLE_CLIENT_SECRET_FILE`. */
  IDENTITY_SSO_GOOGLE_CLIENT_SECRET: string({ secret: true, default: '', minLength: 0 }),

  /** How long a started company sign-in stays completable. Default ten minutes. */
  IDENTITY_SSO_FLOW_TTL: duration({ default: 10 * 60 * 1_000 }),
};

interface SsoView {
  readonly MUNAXA_ENV: string;
  readonly MUNAXA_TRUSTED_ORIGINS: readonly string[];
  readonly MUNAXA_SIGNING_SECRET: string;
  readonly IDENTITY_SIGNING_PRIVATE_KEY: string;
  readonly MFA_ENCRYPTION_KEYS: string;
  readonly IDENTITY_SSO: 'enabled' | 'disabled';
  readonly IDENTITY_SSO_MICROSOFT_CLIENT_ID: string;
  readonly IDENTITY_SSO_MICROSOFT_CLIENT_SECRET: string;
  readonly IDENTITY_SSO_GOOGLE_CLIENT_ID: string;
  readonly IDENTITY_SSO_GOOGLE_CLIENT_SECRET: string;
  readonly IDENTITY_SSO_FLOW_TTL: number;
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GOOGLE_CLIENT_ID = /^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/;

/** Every reason the company sign-in configuration is unusable or unsafe, in one list. */
export const ssoIssues = (resolved: SsoView): { key: string; problem: string }[] => {
  const issues: { key: string; problem: string }[] = [];
  const production = resolved.MUNAXA_ENV === 'production';

  if (
    resolved.IDENTITY_SSO_FLOW_TTL < 60_000 ||
    resolved.IDENTITY_SSO_FLOW_TTL > MAX_SSO_FLOW_TTL
  ) {
    issues.push({ key: 'IDENTITY_SSO_FLOW_TTL', problem: 'must be between 60s and 900s.' });
  }

  const microsoftId = resolved.IDENTITY_SSO_MICROSOFT_CLIENT_ID.trim();
  const microsoftSecret = resolved.IDENTITY_SSO_MICROSOFT_CLIENT_SECRET.trim();
  const googleId = resolved.IDENTITY_SSO_GOOGLE_CLIENT_ID.trim();
  const googleSecret = resolved.IDENTITY_SSO_GOOGLE_CLIENT_SECRET.trim();

  // A half-configured provider is refused whether or not the feature is on: it is a deployment that
  // believes it has something it does not.
  if ((microsoftId === '') !== (microsoftSecret === '')) {
    issues.push({
      key: 'IDENTITY_SSO_MICROSOFT_CLIENT_SECRET',
      problem: 'and IDENTITY_SSO_MICROSOFT_CLIENT_ID must be set together or not at all.',
    });
  }
  if ((googleId === '') !== (googleSecret === '')) {
    issues.push({
      key: 'IDENTITY_SSO_GOOGLE_CLIENT_SECRET',
      problem: 'and IDENTITY_SSO_GOOGLE_CLIENT_ID must be set together or not at all.',
    });
  }
  if (microsoftId !== '' && !GUID.test(microsoftId)) {
    issues.push({
      key: 'IDENTITY_SSO_MICROSOFT_CLIENT_ID',
      problem: 'must be the application (client) id from Entra: a lower-case GUID.',
    });
  }
  if (googleId !== '' && !GOOGLE_CLIENT_ID.test(googleId)) {
    issues.push({
      key: 'IDENTITY_SSO_GOOGLE_CLIENT_ID',
      problem: 'must be a Google OAuth client id ending in .apps.googleusercontent.com.',
    });
  }

  // Dedicated material, checked rather than trusted, as for the MFA key ring.
  for (const [key, value] of [
    ['IDENTITY_SSO_MICROSOFT_CLIENT_SECRET', microsoftSecret],
    ['IDENTITY_SSO_GOOGLE_CLIENT_SECRET', googleSecret],
  ] as const) {
    if (value === '') continue;
    const bytes = Buffer.from(value, 'utf8');
    if (
      reusesSecret(bytes, resolved.MUNAXA_SIGNING_SECRET) ||
      reusesSecret(bytes, resolved.IDENTITY_SIGNING_PRIVATE_KEY) ||
      resolved.MFA_ENCRYPTION_KEYS.includes(value)
    ) {
      issues.push({ key, problem: 'is another secret this service holds. It must be its own.' });
    }
  }

  if (resolved.IDENTITY_SSO === 'disabled') return issues;

  if (microsoftId === '' && googleId === '') {
    issues.push({
      key: 'IDENTITY_SSO',
      problem:
        'is enabled but neither Microsoft nor Google is configured. Set a client id and secret for at least one, or IDENTITY_SSO=disabled.',
    });
  }
  if (production) {
    const plain = resolved.MUNAXA_TRUSTED_ORIGINS.filter(
      (origin) => !origin.startsWith('https://'),
    );
    if (plain.length > 0) {
      issues.push({
        key: 'CSRF_TRUSTED_ORIGINS',
        problem: `must be https in production when company sign-in is enabled (callbacks are built from it): ${plain.join(', ')}.`,
      });
    }
  }
  return issues;
};
