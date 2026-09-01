# Deployment secrets

**Nothing in this directory is committed.** `.gitignore` excludes it, and the exclusion is the
point: every file here is material that grants something.

| File                               | What it holds                                                        | Where it comes from                              |
| ---------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------ |
| `identity_signing_private_key.pem` | The ES256 private key. Signs every access token.                     | `pnpm keys:generate`, on an operator machine     |
| `identity_signing_secret`          | Pepper for refresh-token hashes and CSRF signing. 32+ characters.    | A password manager, or `openssl rand -base64 32` |
| `identity_database_url`            | Identity's runtime connection, as the restricted `NOBYPASSRLS` role. | Provisioning                                     |
| `work_database_url`                | Munaxa Work's runtime connection, as `work_app`.                     | Provisioning                                     |
| `redis_password`                   | The cache password. `redis-server` reads it; nothing else needs it.  | `openssl rand -base64 24`, at provisioning       |
| `identity_redis_url`               | Identity's cache connection, with that password embedded.            | Derived from `redis_password` at provisioning    |

`redis_password` and `identity_redis_url` are separate files holding the same secret in two shapes.
That is deliberate: the server wants a bare password and a client wants a URL, and deriving one from
the other inside a container means the password passes through a shell — where it lands in argument
lists and history. Munaxa Work has no `*_FILE` convention, so its cache URL is `WORK_REDIS_URL` in
the operator's environment rather than a file here.

## File ownership matters as much as file mode

Compose (outside swarm) bind-mounts each secret with the **host's** ownership and mode, and silently
ignores the `uid`/`gid`/`mode` fields that swarm honours. Identity's container runs as a non-root
user, so a secret left `root:root 600` — the mode you would reach for first, and the right one —
produces `EACCES` on `/run/secrets/...` and a container that restart-loops before it logs anything
useful about why.

The four secrets Identity reads are therefore owned by its container user, still `600`:

```sh
chown 100:101 deploy/secrets/identity_*        # uid/gid of the `identity` user in the image
chmod 600 deploy/secrets/identity_*
```

`redis_password` stays `root:root`, because the redis image reads it as root before dropping
privileges. If either image ever changes the user it runs as, these numbers change with it.

The **public** half of the signing key is not a secret and does not live here: it goes into
`PLATFORM_AUTH_PUBLIC_KEYS` in the environment, because Munaxa Work needs to verify with it and
Platform publishes no JWKS endpoint for Work to fetch it from.

If a signing key is ever exposed, the rotation runbook is `docs/runbooks/key-rotation.md` — and it
is worth reading before you need it, because the order of the steps is what stops the rotation
becoming an outage.
