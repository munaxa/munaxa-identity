# Deployment secrets

**Nothing in this directory is committed.** `.gitignore` excludes it, and the exclusion is the
point: every file here is material that grants something.

| File                               | What it holds                                                        | Where it comes from                              |
| ---------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------ |
| `identity_signing_private_key.pem` | The ES256 private key. Signs every access token.                     | `pnpm keys:generate`, on an operator machine     |
| `identity_signing_secret`          | Pepper for refresh-token hashes and CSRF signing. 32+ characters.    | A password manager, or `openssl rand -base64 32` |
| `identity_database_url`            | Identity's runtime connection, as the restricted `NOBYPASSRLS` role. | Provisioning                                     |
| `work_database_url`                | Munaxa Work's runtime connection, as `work_app`.                     | Provisioning                                     |

The **public** half of the signing key is not a secret and does not live here: it goes into
`PLATFORM_AUTH_PUBLIC_KEYS` in the environment, because Munaxa Work needs to verify with it and
Platform publishes no JWKS endpoint for Work to fetch it from.

If a signing key is ever exposed, the rotation runbook is `docs/runbooks/key-rotation.md` — and it
is worth reading before you need it, because the order of the steps is what stops the rotation
becoming an outage.
