import {
  KeyRing,
  decryptToString,
  deriveKey,
  encrypt,
  envelopeKid,
  hmacSha256Hex,
} from '@munaxa/crypto';
import type { MfaEnrollment } from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';
import { parseMfaKeys } from '@identity/config';

/**
 * The MFA key material, derived once at startup.
 *
 * The configured ring is never used directly. Each configured key is the master for two subkeys,
 * derived with `@munaxa/crypto`'s HKDF under distinct purposes — one that seals TOTP secrets and
 * one that keys recovery-code hashes — so neither use can weaken the other, and neither can ever
 * coincide with a key used anywhere else in the ecosystem. Kids are preserved, so an envelope names
 * the configured entry that can open it.
 */
export interface MfaKeys {
  readonly primaryKid: string;
  /** Every kid still accepted for decryption or recovery-code lookup. Primary first. */
  readonly kids: readonly string[];
  /** Seal and open secrets for one account and method. AAD binds all three. */
  protector(tenantId: TenantId, userId: UserId, method: MfaEnrollment['method']): SecretProtector;
  /** Re-seal under the primary key, for rotation. Throws if the envelope does not authenticate. */
  reseal(
    envelope: string,
    tenantId: TenantId,
    userId: UserId,
    method: MfaEnrollment['method'],
  ): string;
  /** The keyed recovery-code hash under `kid`. */
  recoveryHash(kid: string, platformHash: string): string;
  kidOf(envelope: string): string | undefined;
}

/** Exactly the shape `MfaServiceOptions.protectSecret` takes. */
export interface SecretProtector {
  seal(value: string): string;
  open(value: string): string;
}

const SECRET_PURPOSE = 'identity:mfa:totp-secret:v1';
const RECOVERY_PURPOSE = 'identity:mfa:recovery-code:v1';

/**
 * The additional authenticated data for one secret.
 *
 * JSON rather than a delimiter, because tenant and user ids are opaque platform strings and a
 * delimiter they might contain would let two different triples produce the same AAD.
 */
export const secretAad = (
  tenantId: TenantId,
  userId: UserId,
  method: MfaEnrollment['method'],
): string => JSON.stringify(['identity-mfa-secret', 1, tenantId, userId, method]);

export const buildMfaKeys = (raw: string, primaryKid: string): MfaKeys | undefined => {
  if (raw.trim() === '') return undefined;
  const { entries, problems } = parseMfaKeys(raw);
  // The configuration has already refused these; this is a second line, not the first.
  if (problems.length > 0 || entries.length === 0) {
    throw new Error('MFA_ENCRYPTION_KEYS is invalid; the configuration should have refused it.');
  }
  const primary = entries.find((entry) => entry.kid === primaryKid);
  if (primary === undefined) {
    throw new Error('MFA_ENCRYPTION_PRIMARY_KID does not name a configured key.');
  }

  const sealing = (key: Buffer) => deriveKey(key, SECRET_PURPOSE);
  const ring = new KeyRing(
    { kid: primary.kid, key: sealing(primary.key) },
    entries
      .filter((entry) => entry !== primary)
      .map((entry) => ({ kid: entry.kid, key: sealing(entry.key) })),
  );
  const recovery = new Map(
    entries.map((entry) => [entry.kid, deriveKey(entry.key, RECOVERY_PURPOSE)]),
  );

  return {
    primaryKid: primary.kid,
    kids: [primary.kid, ...entries.filter((entry) => entry !== primary).map((entry) => entry.kid)],
    protector: (tenantId, userId, method) => {
      const aad = secretAad(tenantId, userId, method);
      return {
        seal: (value) => encrypt(ring, value, { aad }),
        open: (value) => decryptToString(ring, value, { aad }),
      };
    },
    reseal: (envelope, tenantId, userId, method) => {
      const aad = secretAad(tenantId, userId, method);
      return encrypt(ring, decryptToString(ring, envelope, { aad }), { aad });
    },
    recoveryHash: (kid, platformHash) => {
      const key = recovery.get(kid);
      if (key === undefined) throw new Error(`Unknown MFA key id ${kid}`);
      return hmacSha256Hex(key, platformHash);
    },
    kidOf: (envelope) => envelopeKid(envelope),
  };
};
