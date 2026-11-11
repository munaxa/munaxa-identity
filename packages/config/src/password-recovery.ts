import { duration, oneOf, string } from '@munaxa/config';

/**
 * Password recovery and email delivery settings.
 *
 * Kept apart from `environment.ts` so the recovery contract reads in one place, and so the rules
 * that make it fail closed sit next to the fields they govern.
 *
 * **Production refuses to start with recovery enabled and no production delivery.** A reset
 * request that writes a token nobody will ever receive is worse than no reset at all: the account
 * owner is told "check your email", nothing arrives, and the only artefact is a live credential in
 * a table. So there are exactly two honest production states — recovery `disabled`, said out loud
 * in the deployment's configuration, or `enabled` with a transport that actually delivers — and
 * none in between. No transport in this repository is production-grade yet (see
 * `docs/runbooks/password-recovery.md`, "Email delivery on AWS"), so today a production deployment
 * sets `IDENTITY_PASSWORD_RESET=disabled`.
 */

/** `none` delivers nothing and makes recovery answer "unavailable"; `outbox` writes files, for development. */
export const IDENTITY_EMAIL_TRANSPORTS = ['none', 'outbox'] as const;
export type IdentityEmailTransport = (typeof IDENTITY_EMAIL_TRANSPORTS)[number];

/** Transports allowed to carry a reset link in production. Empty until a real provider adapter lands. */
export const PRODUCTION_EMAIL_TRANSPORTS: readonly IdentityEmailTransport[] = [];

/** A reset link is a bearer credential in a mailbox. One hour is the ceiling, half that the default. */
export const MAX_PASSWORD_RESET_TTL = 60 * 60 * 1_000;

export const PASSWORD_RECOVERY_FIELDS = {
  /** Whether the reset endpoints exist at all. `disabled` answers every one of them with 404. */
  IDENTITY_PASSWORD_RESET: oneOf(['enabled', 'disabled'] as const, { default: 'enabled' }),

  /**
   * The absolute URL of the reset page, exactly as the user's browser will reach it.
   *
   * The link in the email is built from this and from nothing in the request. A link built from
   * the `Host` header is the classic reset-poisoning attack: an attacker requests a reset for the
   * victim with `Host: evil.example`, and the victim's own mailbox delivers a genuine token to the
   * attacker's server the moment they click.
   */
  IDENTITY_PASSWORD_RESET_URL: string({ default: '', minLength: 0 }),

  /** Lifetime of a reset link. Default 30 minutes, at most 60. */
  IDENTITY_PASSWORD_RESET_TTL: duration({ default: 30 * 60 * 1_000 }),

  IDENTITY_EMAIL_TRANSPORT: oneOf(IDENTITY_EMAIL_TRANSPORTS, { default: 'none' }),

  /** The sender address. Required whenever a transport other than `none` is selected. */
  IDENTITY_EMAIL_FROM: string({ default: '', minLength: 0 }),

  /** Where the `outbox` transport writes one JSON file per message. Development only. */
  IDENTITY_EMAIL_OUTBOX_DIR: string({ default: '', minLength: 0 }),
};

interface RecoveryView {
  readonly MUNAXA_ENV: string;
  readonly MUNAXA_TRUSTED_ORIGINS: readonly string[];
  readonly IDENTITY_PASSWORD_RESET: 'enabled' | 'disabled';
  readonly IDENTITY_PASSWORD_RESET_URL: string;
  readonly IDENTITY_PASSWORD_RESET_TTL: number;
  readonly IDENTITY_EMAIL_TRANSPORT: IdentityEmailTransport;
  readonly IDENTITY_EMAIL_FROM: string;
  readonly IDENTITY_EMAIL_OUTBOX_DIR: string;
}

const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/;

/** Every reason the recovery configuration is unsafe, in one list. */
export const passwordRecoveryIssues = (
  resolved: RecoveryView,
): { key: string; problem: string }[] => {
  const issues: { key: string; problem: string }[] = [];
  const production = resolved.MUNAXA_ENV === 'production';
  const transport = resolved.IDENTITY_EMAIL_TRANSPORT;

  if (resolved.IDENTITY_PASSWORD_RESET_TTL < 60_000) {
    issues.push({ key: 'IDENTITY_PASSWORD_RESET_TTL', problem: 'must be at least one minute.' });
  }
  if (resolved.IDENTITY_PASSWORD_RESET_TTL > MAX_PASSWORD_RESET_TTL) {
    issues.push({
      key: 'IDENTITY_PASSWORD_RESET_TTL',
      problem:
        'must be at most one hour. A reset link is a bearer credential sitting in a mailbox.',
    });
  }

  if (transport !== 'none' && !EMAIL.test(resolved.IDENTITY_EMAIL_FROM)) {
    issues.push({
      key: 'IDENTITY_EMAIL_FROM',
      problem: 'must be an email address when a delivery transport is selected.',
    });
  }
  if (transport === 'outbox' && resolved.IDENTITY_EMAIL_OUTBOX_DIR.trim() === '') {
    issues.push({
      key: 'IDENTITY_EMAIL_OUTBOX_DIR',
      problem: 'must name a directory when IDENTITY_EMAIL_TRANSPORT=outbox.',
    });
  }
  if (production && transport === 'outbox') {
    issues.push({
      key: 'IDENTITY_EMAIL_TRANSPORT',
      problem:
        'outbox writes live reset links to local disk and is refused in production. It exists for development.',
    });
  }

  if (resolved.IDENTITY_PASSWORD_RESET === 'disabled') return issues;

  // Enabled from here on.
  if (production && !PRODUCTION_EMAIL_TRANSPORTS.includes(transport)) {
    issues.push({
      key: 'IDENTITY_PASSWORD_RESET',
      problem:
        'is enabled but no production email transport is configured, so every reset link would go nowhere. ' +
        'Set IDENTITY_PASSWORD_RESET=disabled until a delivery provider is wired (docs/runbooks/password-recovery.md).',
    });
  }

  const raw = resolved.IDENTITY_PASSWORD_RESET_URL.trim();
  if (raw === '') {
    // Only required once something could actually send a link. With transport `none` recovery is
    // already unavailable, and demanding a URL for it would only push developers towards a fake one.
    if (transport !== 'none') {
      issues.push({
        key: 'IDENTITY_PASSWORD_RESET_URL',
        problem:
          'is required when password reset is enabled: links are built from it, never from the request.',
      });
    }
    return issues;
  }

  let parsed: URL | undefined;
  try {
    parsed = new URL(raw);
  } catch {
    issues.push({ key: 'IDENTITY_PASSWORD_RESET_URL', problem: 'must be an absolute URL.' });
  }
  if (parsed !== undefined) {
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      issues.push({ key: 'IDENTITY_PASSWORD_RESET_URL', problem: 'must be http or https.' });
    }
    if (production && parsed.protocol !== 'https:') {
      issues.push({ key: 'IDENTITY_PASSWORD_RESET_URL', problem: 'must be https in production.' });
    }
    if (
      parsed.search !== '' ||
      parsed.hash !== '' ||
      parsed.username !== '' ||
      parsed.password !== ''
    ) {
      issues.push({
        key: 'IDENTITY_PASSWORD_RESET_URL',
        problem:
          'must not carry a query string, fragment or credentials; the service adds the token.',
      });
    }
    // The reset form posts back to this origin, and the edge refuses a state-changing post from an
    // origin it does not trust. A URL outside the list would send users to a form that cannot work.
    if (!resolved.MUNAXA_TRUSTED_ORIGINS.includes(parsed.origin)) {
      issues.push({
        key: 'IDENTITY_PASSWORD_RESET_URL',
        problem: `has origin ${parsed.origin}, which is not in CSRF_TRUSTED_ORIGINS; the reset form could not post.`,
      });
    }
  }
  return issues;
};
