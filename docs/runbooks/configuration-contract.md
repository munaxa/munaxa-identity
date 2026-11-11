# The staging configuration contract

Everything an operator must supply to stand up shared staging, split by the only distinction that
matters operationally: **what grants something** and **what merely describes something**.

The rule the split enforces: no secret is in Git, and no secret is a Docker build argument. A build
argument is recorded in the image history and readable by anyone who can pull the image — which for
a private registry is a wider set than the people who were given the credential.

## Secrets

Never committed. Never a build `ARG`. Never an environment literal where a file will do.

| Secret                         | What it grants                                                                                      | Where it is supplied                                                                                                                                                        | Rotation                                            |
| ------------------------------ | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `IDENTITY_SIGNING_PRIVATE_KEY` | Mints access tokens for any account in any organisation. The most consequential value here.         | `deploy/secrets/identity_signing_private_key.pem`, mounted; read via `IDENTITY_SIGNING_PRIVATE_KEY_FILE`                                                                    | `key-rotation.md`. The order is the runbook.        |
| `IDENTITY_SIGNING_SECRET`      | Pepper for refresh-token hashes and CSRF signing. A stolen database is not enough without it.       | `deploy/secrets/identity_signing_secret`, mounted via `IDENTITY_SIGNING_SECRET_FILE`                                                                                        | With the signing key.                               |
| `IDENTITY_DATABASE_PASSWORD`   | Identity's runtime database access, as the `NOBYPASSRLS` role.                                      | Inside `deploy/secrets/identity_database_url`, mounted via `DATABASE_URL_FILE`                                                                                              | `secrets.md`                                        |
| `WORK_DATABASE_PASSWORD`       | Munaxa Work's runtime database access, as `work_app`.                                               | Inside `WORK_DATABASE_URL` in the operator's environment — Work has no `*_FILE` convention, and adding one would be a change to another product for this file's convenience | `secrets.md`                                        |
| `WORK_PII_MATCH_SECRET`        | Deterministic matching over personal identifiers. Leaking it makes those identifiers guessable.     | `WORK_PII_MATCH_SECRET` in the operator's environment                                                                                                                       | `secrets.md`                                        |
| `REDIS_PASSWORD`               | The cache holding lockout counters, rate limits and resolved permission sets.                       | `deploy/secrets/redis_password` for the server; the same value inside `deploy/secrets/identity_redis_url` and `WORK_REDIS_URL` for the clients                              | `secrets.md`                                        |
| `PLATFORM_PACKAGES_TOKEN`      | Reads `@munaxa/*` from GitHub Packages. **Build-time only** — it never reaches a running container. | `NODE_AUTH_TOKEN` in the shell, mounted as the BuildKit secret `npm_token`; in CI, a repository secret                                                                      | On compromise, or when the person holding it leaves |

Two of these are files owned by the container's user rather than by root — see
`deploy/secrets/README.md`. Compose bind-mounts secrets with the host's ownership and ignores the
`uid`/`mode` fields swarm honours, so `root:root 600` produces `EACCES` and a restart loop.

## Configuration

Not secret. Wrong values still break the deployment, and two of them break it silently.

| Setting                                                | Value                                     | Notes                                                                                                                                                                     |
| ------------------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUBLIC_HOST`                                          | The hostname DNS points at the front door | Operator-supplied. Never invented, and never committed.                                                                                                                   |
| `PUBLIC_ORIGIN`                                        | `https://<PUBLIC_HOST>`                   | Becomes `CSRF_TRUSTED_ORIGINS`. A mismatch turns every sign-in into a 403.                                                                                                |
| `PLATFORM_AUTH_ISSUER`                                 | `<PUBLIC_ORIGIN>/api/auth`                | Compared **character for character** against the token's `iss`. Must equal Identity's `IDENTITY_BASE_URL` exactly.                                                        |
| `PLATFORM_AUTH_AUDIENCE`                               | `munaxa-work`                             | Must equal Identity's `IDENTITY_AUTH_AUDIENCE`.                                                                                                                           |
| `PLATFORM_AUTH_ALGORITHM`                              | `ES256`                                   | Must equal `IDENTITY_SIGNING_ALGORITHM`.                                                                                                                                  |
| `PLATFORM_AUTH_PUBLIC_KEYS`                            | JSON array of `{ kid, publicKey }`        | The **public** half only. Work refuses a private-key PEM and refuses duplicate `kid`s, so a paste of the wrong half fails loudly. During a rotation this holds both keys. |
| `IDENTITY_SIGNING_KID`                                 | e.g. `identity-staging-2026-10`           | Must appear in `PLATFORM_AUTH_PUBLIC_KEYS` **before** Identity starts using it.                                                                                           |
| `IDENTITY_DEFAULT_ORGANISATION`                        | The organisation slug sign-in assumes     | Empty means the sign-in form asks.                                                                                                                                        |
| `IDENTITY_SESSION_LIST_IP`                             | What the session list shows about origin  | `prefix` (default): the /24 or /48 network only. `hidden`: nothing. The full address is never returned.                                                                   |
| `WORK_API_URL`                                         | `http://work-api:3000`                    | Server-to-server, inside the compose network. The browser never calls the API directly.                                                                                   |
| `IDENTITY_IMAGE`, `WORK_API_IMAGE`, `WORK_ADMIN_IMAGE` | A digest, or a commit-SHA tag             | Never `latest`. A tag that can move means two hosts running "the same version" and disagreeing about what that is.                                                        |

## What is checked, and what is not

Identity refuses to start on a missing or malformed secret, and `REDIS_URL` may not be empty in
production — the cache is not optional, because without it lockout counters stop being a limit and
the permission cache stops being coherent.

Nothing checks that `PLATFORM_AUTH_ISSUER` matches `IDENTITY_BASE_URL`, or that
`PLATFORM_AUTH_PUBLIC_KEYS` contains `IDENTITY_SIGNING_KID`. Both are cross-product agreements that
no single service can verify, and both fail the same way: every sign-in succeeds and every
authenticated request answers 401. If that is what you are seeing, compare those three rows first.
