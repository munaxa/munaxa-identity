import { randomUUID } from 'node:crypto';

import type { MfaEnrollment, MfaEnrollmentStorePort } from '@munaxa/interfaces';
import { PlatformError, type TenantId, type UserId } from '@munaxa/types';

import type { MfaKeys } from '../mfa/mfa-keys.js';
import type { PrismaService, TenantClient } from './prisma.service.js';

/**
 * Second factors and recovery codes, behind Platform's `MfaEnrollmentStorePort`.
 *
 * **Two views of one table.** Platform's `MfaService` finds "the" enrollment for a method by
 * listing and taking the first match, and `beginTotpEnrollment` saves an unconfirmed record over
 * whatever was there. Against a store with one row per method that would mean starting a
 * replacement switches the current factor off. So each `MfaService` is given a *view*:
 *
 * - `active` — what sign-in verifies against. Lists confirmed factors only, consumes recovery
 *   codes, records use, and removes a factor.
 * - `pending` — what enrollment writes to. Lists only unconfirmed, unexpired enrollments. Saving a
 *   *confirmed* record through it is the promotion: in one transaction the pending row becomes the
 *   active one, the factor it replaces is deleted, the previous recovery codes are deleted, and the
 *   account's `mfa_enrolled` flag is set.
 *
 * **The secret arrives sealed.** The port's contract is that it never sees a plaintext secret, and
 * the caller seals it with AAD naming the tenant, the account and the method (see `MfaKeys`). The
 * store records which key sealed it and refuses anything that is not an envelope.
 *
 * **Recovery codes are keyed.** Platform passes `sha256(code)`; the store keeps
 * `HMAC(recovery subkey, sha256(code))` and the kid it used. Consumption tries every kid the ring
 * still holds, in one conditional `UPDATE`, and only while an active factor exists.
 *
 * Every statement runs inside `withTenant`, so row-level security applies to all of it.
 */
export type MfaStoreView = 'active' | 'pending';

export interface MfaStoreOptions {
  readonly view: MfaStoreView;
  /** How long an unconfirmed enrollment may be confirmed. After it, it is as if never started. */
  readonly pendingTtlMs: number;
  readonly now?: () => number;
}

export class PrismaMfaEnrollmentStore implements MfaEnrollmentStorePort {
  readonly #now: () => number;

  public constructor(
    private readonly prisma: PrismaService,
    private readonly keys: MfaKeys,
    private readonly options: MfaStoreOptions,
  ) {
    this.#now = options.now ?? Date.now;
  }

  /** The same store, looking at the other state. */
  public view(view: MfaStoreView): PrismaMfaEnrollmentStore {
    return new PrismaMfaEnrollmentStore(this.prisma, this.keys, { ...this.options, view });
  }

  public async list(tenantId: TenantId, userId: UserId): Promise<readonly MfaEnrollment[]> {
    const rows = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityMfaEnrollment.findMany({
        where: {
          tenantId,
          accountId: userId,
          state: this.options.view,
          ...(this.options.view === 'pending'
            ? { createdAt: { gt: new Date(this.#now() - this.options.pendingTtlMs) } }
            : {}),
        },
        orderBy: { createdAt: 'asc' },
      }),
    );
    return rows.map(recordOf);
  }

  public async save(enrollment: MfaEnrollment): Promise<void> {
    const kid = this.#kidOf(enrollment.secret);

    if (this.options.view === 'pending') {
      if (enrollment.confirmedAt === undefined) {
        await this.#savePending(enrollment, kid);
      } else {
        await this.#promote(enrollment);
      }
      return;
    }

    // Through the active view a save can only re-seal an existing factor (key rotation). It never
    // creates one: a factor becomes active only by promotion from a confirmed pending enrollment.
    const updated = await this.prisma.withTenant(enrollment.tenantId, (tx) =>
      tx.identityMfaEnrollment.updateMany({
        where: {
          tenantId: enrollment.tenantId,
          accountId: enrollment.userId,
          method: enrollment.method,
          state: 'active',
        },
        data: { secretCiphertext: enrollment.secret, keyId: kid },
      }),
    );
    if (updated.count !== 1) {
      throw new PlatformError('No active factor to update', { code: 'AUTH_MFA_INVALID' });
    }
  }

  async #savePending(enrollment: MfaEnrollment, kid: string): Promise<void> {
    const data = {
      secretCiphertext: enrollment.secret,
      keyId: kid,
      label: enrollment.label ?? null,
      createdAt: new Date(enrollment.createdAt),
      confirmedAt: null,
      lastUsedAt: null,
    };
    await this.prisma.withTenant(enrollment.tenantId, (tx) =>
      tx.identityMfaEnrollment.upsert({
        where: {
          tenantId_accountId_method_state: {
            tenantId: enrollment.tenantId,
            accountId: enrollment.userId,
            method: enrollment.method,
            state: 'pending',
          },
        },
        create: {
          id: randomUUID(),
          tenantId: enrollment.tenantId,
          accountId: enrollment.userId,
          method: enrollment.method,
          state: 'pending',
          ...data,
        },
        update: data,
      }),
    );
  }

  /**
   * Make a confirmed enrollment the account's factor.
   *
   * The pending row is matched on its ciphertext as well as its owner. Between `MfaService` reading
   * the pending secret, checking the code against it and saving, a second "start enrollment" may
   * have replaced the pending row with a new secret; promoting that one would activate a secret the
   * person never proved they hold. Matching the ciphertext makes that race fail closed.
   */
  async #promote(enrollment: MfaEnrollment): Promise<void> {
    const { tenantId, userId, method } = enrollment;
    const confirmedAt = new Date(enrollment.confirmedAt ?? this.#now());
    const freshAfter = new Date(this.#now() - this.options.pendingTtlMs);

    await this.prisma.withTenant(tenantId, async (tx) => {
      const pending = await tx.identityMfaEnrollment.findFirst({
        where: {
          tenantId,
          accountId: userId,
          method,
          state: 'pending',
          secretCiphertext: enrollment.secret,
          createdAt: { gt: freshAfter },
        },
        select: { id: true },
      });
      if (pending === null) {
        throw new PlatformError('The enrollment being confirmed is no longer pending', {
          code: 'AUTH_MFA_INVALID',
        });
      }
      await tx.identityMfaEnrollment.deleteMany({
        where: { tenantId, accountId: userId, method, state: 'active' },
      });
      // A replacement must not leave the previous factor's recovery codes working.
      await tx.identityMfaRecoveryCode.deleteMany({ where: { tenantId, accountId: userId } });
      const promoted = await tx.identityMfaEnrollment.updateMany({
        where: { tenantId, id: pending.id, state: 'pending' },
        data: { state: 'active', confirmedAt },
      });
      if (promoted.count !== 1) {
        throw new PlatformError('The enrollment was confirmed concurrently', {
          code: 'AUTH_MFA_INVALID',
        });
      }
      await setEnrolledFlag(tx, tenantId, userId);
    });
  }

  public async remove(
    tenantId: TenantId,
    userId: UserId,
    method: MfaEnrollment['method'],
  ): Promise<void> {
    await this.prisma.withTenant(tenantId, async (tx) => {
      await tx.identityMfaEnrollment.deleteMany({
        where: { tenantId, accountId: userId, method, state: this.options.view },
      });
      if (this.options.view === 'pending') return;
      // With no active factor left, no recovery code may remain usable.
      const remaining = await tx.identityMfaEnrollment.count({
        where: { tenantId, accountId: userId, state: 'active' },
      });
      if (remaining === 0) {
        await tx.identityMfaRecoveryCode.deleteMany({ where: { tenantId, accountId: userId } });
      }
      await setEnrolledFlag(tx, tenantId, userId);
    });
  }

  public async markUsed(
    tenantId: TenantId,
    userId: UserId,
    method: MfaEnrollment['method'],
    at: number,
  ): Promise<void> {
    await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityMfaEnrollment.updateMany({
        where: { tenantId, accountId: userId, method, state: 'active' },
        data: { lastUsedAt: new Date(at) },
      }),
    );
  }

  /**
   * Replace the account's recovery codes with a new set.
   *
   * Replace, not add: the old set is deleted in the same transaction, so regenerating codes
   * invalidates every code previously shown. Refused when no active factor exists — recovery codes
   * are a fallback for a factor, not a factor of their own.
   */
  public async saveRecoveryCodes(
    tenantId: TenantId,
    userId: UserId,
    hashes: readonly string[],
  ): Promise<void> {
    const kid = this.keys.primaryKid;
    const createdAt = new Date(this.#now());
    await this.prisma.withTenant(tenantId, async (tx) => {
      const active = await tx.identityMfaEnrollment.count({
        where: { tenantId, accountId: userId, state: 'active' },
      });
      if (active === 0) {
        throw new PlatformError('Recovery codes need an active factor', {
          code: 'AUTH_MFA_INVALID',
        });
      }
      await tx.identityMfaRecoveryCode.deleteMany({ where: { tenantId, accountId: userId } });
      await tx.identityMfaRecoveryCode.createMany({
        data: hashes.map((hash) => ({
          id: randomUUID(),
          tenantId,
          accountId: userId,
          codeHash: this.keys.recoveryHash(kid, hash),
          keyId: kid,
          createdAt,
        })),
      });
    });
  }

  /**
   * Spend a recovery code, once.
   *
   * One conditional `UPDATE`: Postgres re-evaluates `consumed_at IS NULL` against the row it locks,
   * so of two concurrent requests presenting the same code exactly one sees a count of 1. The
   * active-factor check runs in the same transaction, so a code cannot be spent after its factor
   * was removed.
   */
  public async consumeRecoveryCode(
    tenantId: TenantId,
    userId: UserId,
    hash: string,
  ): Promise<boolean> {
    if (this.options.view !== 'active') return false;
    const candidates = this.keys.kids.map((kid) => ({
      keyId: kid,
      codeHash: this.keys.recoveryHash(kid, hash),
    }));
    return this.prisma.withTenant(tenantId, async (tx) => {
      const active = await tx.identityMfaEnrollment.count({
        where: { tenantId, accountId: userId, state: 'active' },
      });
      if (active === 0) return false;
      const consumed = await tx.identityMfaRecoveryCode.updateMany({
        where: { tenantId, accountId: userId, consumedAt: null, OR: candidates },
        data: { consumedAt: new Date(this.#now()) },
      });
      return consumed.count === 1;
    });
  }

  /** Unspent recovery codes, for "you have N codes left". Never the codes. */
  public async remainingRecoveryCodes(tenantId: TenantId, userId: UserId): Promise<number> {
    return this.prisma.withTenant(tenantId, (tx) =>
      tx.identityMfaRecoveryCode.count({
        where: { tenantId, accountId: userId, consumedAt: null },
      }),
    );
  }

  /**
   * Re-seal every secret in one organisation that is not under the primary key.
   *
   * The rotation work-horse (docs/runbooks/mfa.md). Each row is decrypted with the AAD it was
   * sealed under and re-encrypted under the primary key, and written back only if its ciphertext
   * is still the one that was read, so a concurrent replacement is never overwritten. Returns how
   * many rows were re-sealed. A row that fails to authenticate is counted in `failed`, left
   * untouched and never logged.
   */
  public async reencryptTenant(
    tenantId: TenantId,
  ): Promise<{ readonly resealed: number; readonly failed: number }> {
    const stale = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityMfaEnrollment.findMany({
        where: { tenantId, keyId: { not: this.keys.primaryKid } },
        select: { id: true, accountId: true, method: true, secretCiphertext: true },
      }),
    );
    let resealed = 0;
    let failed = 0;
    for (const row of stale) {
      let next: string;
      try {
        next = this.keys.reseal(
          row.secretCiphertext,
          tenantId,
          row.accountId as UserId,
          row.method as MfaEnrollment['method'],
        );
      } catch {
        failed++;
        continue;
      }
      const written = await this.prisma.withTenant(tenantId, (tx) =>
        tx.identityMfaEnrollment.updateMany({
          where: { tenantId, id: row.id, secretCiphertext: row.secretCiphertext },
          data: { secretCiphertext: next, keyId: this.keys.primaryKid },
        }),
      );
      resealed += written.count;
    }
    return { resealed, failed };
  }

  /** Recovery codes keyed under a kid other than the primary, which block retiring that kid. */
  public async recoveryCodesUnderRetiredKeys(tenantId: TenantId): Promise<number> {
    return this.prisma.withTenant(tenantId, (tx) =>
      tx.identityMfaRecoveryCode.count({
        where: { tenantId, consumedAt: null, keyId: { not: this.keys.primaryKid } },
      }),
    );
  }

  #kidOf(envelope: string): string {
    const kid = this.keys.kidOf(envelope);
    if (kid === undefined) {
      // Never stored, and never echoed: this is what a plaintext secret reaching the store looks like.
      throw new PlatformError('MFA secret is not sealed', { code: 'CRYPTO_VERIFICATION_FAILED' });
    }
    return kid;
  }
}

/** Keep `identity_account.mfa_enrolled` equal to "has an active factor", in the caller's transaction. */
const setEnrolledFlag = async (
  tx: TenantClient,
  tenantId: TenantId,
  userId: UserId,
): Promise<void> => {
  const active = await tx.identityMfaEnrollment.count({
    where: { tenantId, accountId: userId, state: 'active' },
  });
  await tx.identityAccount.updateMany({
    where: { tenantId, id: userId },
    data: { mfaEnrolled: active > 0 },
  });
};

interface EnrollmentRow {
  tenantId: string;
  accountId: string;
  method: string;
  secretCiphertext: string;
  label: string | null;
  createdAt: Date;
  confirmedAt: Date | null;
  lastUsedAt: Date | null;
}

const recordOf = (row: EnrollmentRow): MfaEnrollment => ({
  tenantId: row.tenantId as TenantId,
  userId: row.accountId as UserId,
  method: row.method as MfaEnrollment['method'],
  secret: row.secretCiphertext,
  createdAt: row.createdAt.getTime(),
  ...(row.label === null ? {} : { label: row.label }),
  ...(row.confirmedAt === null ? {} : { confirmedAt: row.confirmedAt.getTime() }),
  ...(row.lastUsedAt === null ? {} : { lastUsedAt: row.lastUsedAt.getTime() }),
});
