/**
 * The MFA encryption key ring, as an operator writes it.
 *
 * `MFA_ENCRYPTION_KEYS` is a comma-separated list of `kid=key` entries, where `key` is exactly 32
 * random bytes in base64url (or standard base64). `MFA_ENCRYPTION_PRIMARY_KID` names the entry new
 * secrets are sealed under; every other entry is kept only so the secrets it sealed still open.
 * That is the whole rotation model: add a new entry, make it primary, re-encrypt, then drop the
 * old entry once nothing names it. See docs/runbooks/mfa.md.
 *
 * Parsed here rather than in the API because a malformed ring is a configuration error, and the
 * configuration is where every other configuration error is reported — at startup, all at once.
 * Nothing in this file decrypts anything; it only turns text into bytes and says what is wrong.
 */

export interface MfaKeyEntry {
  readonly kid: string;
  readonly key: Buffer;
}

export interface ParsedMfaKeys {
  readonly entries: readonly MfaKeyEntry[];
  readonly problems: readonly string[];
}

/** A kid appears inside every ciphertext envelope, which is `.`-separated. */
const KID = /^[A-Za-z0-9_-]{1,64}$/;

export const parseMfaKeys = (raw: string): ParsedMfaKeys => {
  const problems: string[] = [];
  const entries: MfaKeyEntry[] = [];
  const seen = new Set<string>();

  for (const part of raw.split(',')) {
    const entry = part.trim();
    if (entry === '') continue;
    const separator = entry.indexOf('=');
    if (separator <= 0) {
      // The entry is never echoed: it may be a key with its kid missing.
      problems.push('has an entry that is not of the form kid=key.');
      continue;
    }
    const kid = entry.slice(0, separator).trim();
    const encoded = entry.slice(separator + 1).trim();
    if (!KID.test(kid)) {
      problems.push('has a key id that is not 1-64 characters of [A-Za-z0-9_-].');
      continue;
    }
    if (seen.has(kid)) {
      problems.push(`names key id ${kid} more than once.`);
      continue;
    }
    seen.add(kid);
    const key = decode(encoded);
    if (key === undefined || key.length !== 32) {
      problems.push(`key ${kid} is not 32 bytes of base64. AES-256-GCM needs exactly 32.`);
      continue;
    }
    if (key.every((byte) => byte === key[0])) {
      problems.push(`key ${kid} is a repeated byte, not random key material.`);
      continue;
    }
    entries.push({ kid, key });
  }
  return { entries, problems };
};

const decode = (value: string): Buffer | undefined => {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) return undefined;
  return Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
};

/**
 * Whether an MFA key is the same material as another secret this service holds.
 *
 * The rule the assignment states — never reuse the JWT signing key or the refresh-token pepper as
 * the MFA key — is checked, not trusted. A key is "the same" if its bytes are the other secret's
 * bytes, its base64 decoding, or appear inside it (a PEM body).
 */
export const reusesSecret = (key: Buffer, other: string): boolean => {
  const text = other.trim();
  if (text === '') return false;
  if (key.equals(Buffer.from(text, 'utf8'))) return true;
  const decoded = decode(text);
  if (decoded !== undefined && decoded.length > 0 && key.equals(decoded)) return true;
  const b64 = key.toString('base64');
  const b64url = key.toString('base64url');
  return text.includes(b64.replace(/=+$/, '')) || text.includes(b64url);
};
