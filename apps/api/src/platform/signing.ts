import { AsymmetricSigner } from '@munaxa/crypto';
import { createPublicKey } from 'node:crypto';

/**
 * The signing key, loaded once at startup.
 *
 * Deliberately *not* generated here. A service that mints its own keypair mints a new one on every
 * restart, so every token issued before the restart stops verifying and Munaxa Work's configured
 * public key becomes wrong without anybody changing it. The key is operator-generated
 * (`pnpm keys:generate`), stored in the deployment's secret store, and arrives as configuration.
 *
 * The public half is derived here rather than configured separately: two variables that must agree
 * is one variable and one opportunity to get it wrong. `publicKeyPem` is what an operator copies
 * into Munaxa Work's `PLATFORM_AUTH_PUBLIC_KEYS`.
 */
export interface SigningKey {
  readonly signer: AsymmetricSigner;
  readonly kid: string;
  readonly publicKeyPem: string;
}

export const loadSigningKey = (input: {
  readonly algorithm: 'ES256';
  readonly kid: string;
  readonly privateKeyPem: string;
}): SigningKey => {
  const privateKey = input.privateKeyPem.trim();
  const publicKeyPem = createPublicKey(privateKey)
    .export({ type: 'spki', format: 'pem' })
    .toString();
  const signer = new AsymmetricSigner(input.algorithm, [
    { kid: input.kid, privateKey, publicKey: publicKeyPem },
  ]);
  return { signer, kid: input.kid, publicKeyPem };
};
