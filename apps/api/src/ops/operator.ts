import { anonymousAuditEvent } from '@munaxa/audit';
import { toCorrelationId, type SessionId, type TenantId, type UserId } from '@munaxa/types';
import { randomUUID } from 'node:crypto';

import { revocationAuditor } from '../account/revocation-audit.js';
import type { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';

/**
 * Operator commands: the recovery and enforcement steps that have no HTTP route, on purpose.
 *
 * Identity has no administration API. These commands are what an operator runs as a one-off task
 * with the service's own configuration (the same image, task role, secrets and `identity_app`
 * connection), so they act through exactly the code the service runs: the same row-level security,
 * the same revocation, the same audit chain. Nothing here reads, prints or accepts a secret, a
 * code or a token.
 *
 * Every command is a **dry run unless `--apply` is given**, and every command that changes state
 * requires a `--reference` (a ticket or incident id) that the audit record carries. Output names
 * accounts by id only, never by identifier: an identifier is an email address, and task logs are
 * not where personal data belongs.
 */

export type Output = (line: string) => void;

export interface OperatorDeps {
  readonly security: SecurityStack;
  readonly prisma: PrismaService;
  readonly out: Output;
  readonly now?: () => Date;
}

export class OperatorError extends Error {}

/** A ticket or incident reference: short, plain, and not a place to paste personal data. */
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/;

const requireReference = (reference: string | undefined): string => {
  if (reference === undefined || !REFERENCE.test(reference)) {
    throw new OperatorError(
      '--reference is required: a ticket or incident id, 3-64 characters of letters, digits and . _ : -',
    );
  }
  return reference;
};

const tenantOf = async (
  deps: OperatorDeps,
  organisation: string | undefined,
): Promise<TenantId> => {
  if (organisation === undefined || organisation.trim() === '') {
    throw new OperatorError('--organisation is required');
  }
  const tenantId = await deps.security.tenants.idForKey(organisation.trim());
  if (tenantId === undefined) throw new OperatorError('No such organisation');
  return tenantId;
};

const operatorActor = (reference: string) => ({
  kind: 'system' as const,
  id: `operator:${reference}`,
});

// -------------------------------------------------------------------------------------------------
// mfa-reset: the lost-device procedure
// -------------------------------------------------------------------------------------------------

export interface MfaResetResult {
  readonly accountId: UserId;
  readonly enrolled: boolean;
  readonly applied: boolean;
  readonly sessionsRevoked: number;
}

/**
 * Remove an account's second factor after its owner has lost it, and end everything the account
 * was signed in with.
 *
 * What it does, in order: deletes the active and any pending TOTP enrollment and every recovery
 * code (the store keeps `mfa_enrolled` in step), bumps the token version and revokes every session
 * and refresh lineage (`AccountLockdown.suspectedCompromise`), then writes `auth.mfa.removed` with
 * the operator reference. The password is not touched.
 *
 * What it does not do is establish who is asking. That is the procedure in `docs/runbooks/mfa.md`
 * (identity verified out of band, a second operator, the ticket), and it is the whole of the
 * security of this command: a reset hands the account to whoever holds the password. When the
 * policy covers the account, the next sign-in is admitted only to enrollment.
 */
export const mfaReset = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly account?: string | undefined;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<MfaResetResult> => {
  const tenantId = await tenantOf(deps, input.organisation);
  if (input.account === undefined || input.account.trim() === '') {
    throw new OperatorError('--account is required (the sign-in identifier)');
  }
  const account = await deps.security.directory.findByIdentifier(tenantId, input.account);
  if (account === undefined) throw new OperatorError('No such account in that organisation');
  const userId = account.userId;
  const mfa = deps.security.mfa;
  const enrolled =
    mfa === undefined
      ? account.mfaEnrolled
      : await mfa.verifier(tenantId, userId).isEnrolled(tenantId, userId);

  if (!input.apply) {
    deps.out(`dry run: account ${userId} enrolled=${enrolled}; nothing changed (add --apply)`);
    return { accountId: userId, enrolled, applied: false, sessionsRevoked: 0 };
  }
  const reference = requireReference(input.reference);
  if (mfa === undefined) {
    throw new OperatorError('MFA is not configured in this environment (no MFA_ENCRYPTION_KEYS)');
  }

  await mfa.enroller(tenantId, userId).remove(tenantId, userId, 'totp');
  await mfa.verifier(tenantId, userId).remove(tenantId, userId, 'totp');
  const outcome = await deps.security.lockdown.suspectedCompromise(
    tenantId,
    userId,
    operatorActor(reference),
  );
  await deps.security.audit
    .write(
      anonymousAuditEvent(tenantId, toCorrelationId(randomUUID()), {
        name: 'auth.mfa.removed',
        outcome: 'success',
        actor: operatorActor(reference),
        target: { type: 'account', id: userId },
        payload: { method: 'totp', reason: 'operator-recovery', reference, wasEnrolled: enrolled },
      }),
    )
    .catch((error: unknown) => {
      deps.out(`warning: the audit record could not be written: ${String(error)}`);
    });
  deps.out(
    `applied: account ${userId} factor removed, ${outcome.sessions} session(s) and ` +
      `${outcome.refreshTokens} refresh token(s) revoked, reference ${reference}`,
  );
  return { accountId: userId, enrolled, applied: true, sessionsRevoked: outcome.sessions };
};

// -------------------------------------------------------------------------------------------------
// account-disable: the containment step
// -------------------------------------------------------------------------------------------------

/**
 * Disable an account and end everything it was signed in with (`AccountLockdown.disable`: status
 * `disabled`, token version bumped, every session and refresh lineage revoked, `auth.account.locked`
 * audited with the operator reference). For a suspected takeover, and for the lost-device case
 * where the password may be known to someone else and password reset is not available. A disabled
 * account cannot sign in, reset its password or be reset by `mfa-reset` into a usable state.
 */
export const accountDisable = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly account?: string | undefined;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<{
  readonly accountId: UserId;
  readonly applied: boolean;
  readonly sessions: number;
}> => {
  const tenantId = await tenantOf(deps, input.organisation);
  if (input.account === undefined || input.account.trim() === '') {
    throw new OperatorError('--account is required (the sign-in identifier)');
  }
  const account = await deps.security.directory.findByIdentifier(tenantId, input.account);
  if (account === undefined) throw new OperatorError('No such account in that organisation');
  const userId = account.userId;
  if (!input.apply) {
    deps.out(`dry run: account ${userId} status=${account.status}; nothing changed (add --apply)`);
    return { accountId: userId, applied: false, sessions: 0 };
  }
  const reference = requireReference(input.reference);
  const outcome = await deps.security.lockdown.disable(tenantId, userId, operatorActor(reference));
  deps.out(
    `applied: account ${userId} disabled, ${outcome.sessions} session(s) and ` +
      `${outcome.refreshTokens} refresh token(s) revoked, reference ${reference}`,
  );
  return { accountId: userId, applied: true, sessions: outcome.sessions };
};

// -------------------------------------------------------------------------------------------------
// sessions-revoke-unsatisfied: finish turning enforcement on
// -------------------------------------------------------------------------------------------------

export interface RevokeUnsatisfiedResult {
  readonly accounts: number;
  readonly sessions: number;
  readonly applied: boolean;
}

/**
 * End every live session that was established without a second factor, for every account the
 * configured `MFA_POLICY` covers.
 *
 * Turning enforcement on changes what the *next* sign-in requires; sessions that already exist
 * carry `mfa_satisfied = false` and stay valid until they expire. This is the step that ends them
 * (`docs/runbooks/mfa.md`, "Turning enforcement on"). It reads the policy from the environment it
 * runs with, so run it with the same `MFA_POLICY` and `MFA_PRIVILEGED_ROLES` as the service. With
 * `MFA_POLICY=off` it covers nobody and changes nothing.
 */
export const revokeUnsatisfiedSessions = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<RevokeUnsatisfiedResult> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const reference = input.apply ? requireReference(input.reference) : undefined;
  const now = (deps.now ?? (() => new Date()))();

  const live = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identitySession.findMany({
      where: {
        tenantId,
        mfaSatisfied: false,
        revokedAt: null,
        idleExpiresAt: { gt: now },
        absoluteExpiresAt: { gt: now },
      },
      select: { id: true, accountId: true },
    }),
  );
  const byAccount = new Map<UserId, SessionId[]>();
  for (const row of live) {
    const list = byAccount.get(row.accountId as UserId) ?? [];
    list.push(row.id as SessionId);
    byAccount.set(row.accountId as UserId, list);
  }

  let accounts = 0;
  let sessions = 0;
  const audit = revocationAuditor(deps.security.audit);
  for (const [userId, ids] of byAccount) {
    if (!(await deps.security.mfaPolicy.requires(tenantId, userId))) continue;
    accounts++;
    if (reference === undefined) {
      sessions += ids.length;
      continue;
    }
    let revoked = 0;
    for (const sessionId of ids) {
      if (
        await deps.security.revocation.revokeSession(tenantId, userId, sessionId, 'admin-revoked')
      ) {
        revoked++;
      }
    }
    sessions += revoked;
    await audit({
      name: 'session.revoked',
      tenantId,
      actor: operatorActor(reference),
      subject: userId,
      payload: {
        reason: 'mfa-enforcement',
        scope: 'mfa-unsatisfied',
        sessions: revoked,
        reference,
      },
    });
  }
  deps.out(
    reference === undefined
      ? `dry run: ${sessions} session(s) of ${accounts} covered account(s) would be revoked (add --apply)`
      : `applied: ${sessions} session(s) of ${accounts} covered account(s) revoked, reference ${reference}`,
  );
  return { accounts, sessions, applied: reference !== undefined };
};

// -------------------------------------------------------------------------------------------------
// mfa-reencrypt: the key-rotation step
// -------------------------------------------------------------------------------------------------

export interface ReencryptResult {
  readonly staleSecrets: number;
  readonly resealed: number;
  readonly failed: number;
  readonly recoveryCodesUnderRetiredKeys: number;
  readonly applied: boolean;
}

/**
 * Re-seal every TOTP secret in an organisation under the primary MFA key
 * (`docs/runbooks/mfa.md`, "Rotating the key"). Compare-and-swap per row, so it is safe while the
 * service runs and safe to repeat. Recovery codes cannot be re-keyed (only their HMAC is stored);
 * the count of codes still under a retired kid is reported, and that kid must stay in the ring
 * until it reaches zero. Exits with failure if any secret failed to open.
 */
export const mfaReencrypt = async (
  deps: OperatorDeps,
  input: { readonly organisation?: string | undefined; readonly apply: boolean },
): Promise<ReencryptResult> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const mfa = deps.security.mfa;
  if (mfa === undefined) {
    throw new OperatorError('MFA is not configured in this environment (no MFA_ENCRYPTION_KEYS)');
  }
  const primary = mfa.keys.primaryKid;
  const staleSecrets = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identityMfaEnrollment.count({ where: { tenantId, keyId: { not: primary } } }),
  );
  let resealed = 0;
  let failed = 0;
  if (input.apply) ({ resealed, failed } = await mfa.store.reencryptTenant(tenantId));
  const codes = await mfa.store.recoveryCodesUnderRetiredKeys(tenantId);
  deps.out(
    input.apply
      ? `applied: ${resealed} secret(s) re-sealed under ${primary}, ${failed} failed; ` +
          `${codes} unused recovery code(s) still under a retired key`
      : `dry run: ${staleSecrets} secret(s) not under ${primary}; ${codes} unused recovery ` +
          'code(s) under a retired key (add --apply)',
  );
  if (failed > 0) {
    throw new OperatorError(
      `${failed} secret(s) did not open under any configured key; nothing was changed for them`,
    );
  }
  return {
    staleSecrets,
    resealed,
    failed,
    recoveryCodesUnderRetiredKeys: codes,
    applied: input.apply,
  };
};
