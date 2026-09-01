# Runbook — rotating the signing key

The order is the whole runbook. Any other order is an outage: Munaxa Work must be able to verify the
new key **before** Identity starts using it, and must keep the old one until nothing signed with it
is still valid.

```
1  pnpm keys:generate --kid identity-staging-2026-10
2  add the new public key to Work's PLATFORM_AUTH_PUBLIC_KEYS, alongside the old one
3  deploy Work                                  ← it now verifies both
4  set IDENTITY_SIGNING_KID to the new kid and restart Identity
5  wait ≥ access-token TTL + clock skew         ← 15 min + 30 s at the defaults
6  remove the old public key from Work, and deploy
7  delete the old private key from the secret store
```

Work rejects duplicate `kid`s and refuses any private-key PEM, so step 2 fails loudly if the wrong
half is pasted.

**If a private key is exposed**, the order inverts and the cost is accepted: rotate immediately
(steps 1, 2, 3, 4), then remove the old public key at once rather than waiting out step 5. Every
session signed with the old key stops verifying and everybody signs in again. That is the correct
trade — a compromised signing key mints tokens for any account in any organisation, and fifteen
minutes of that is worse than a forced re-authentication.

Never: a key generated at boot, a key in a repository, a key in `.env.example`, or a key in a log.
CI fails on a committed PEM.
