# Identity on the shared AWS stack

Identity runs on the shared AWS stack in `eu-central-1` (munaxa-platform `infra/aws`, draft) as
the `identity` ECS service, with a Valkey sidecar for lockout counters, rate limits and resolved
permission sets. This page is the Identity side of it. The stack's README holds the approval gates,
the runbook and the rollback.

**Status: not deployed.** Nothing here has created an AWS resource or published an image.

## Images

`.github/workflows/publish-images-ecr.yml` builds from a tag `image/<40-hex commit SHA>` on a
commit that is on `main`, in the protected `image-release` environment, and pushes to Amazon ECR
through GitHub OIDC. No registry credential exists. It does nothing until the owner sets the
repository variable `AWS_IMAGE_PUBLISHER_ROLE_ARN`.

| ECR repository            | `apps/api/Dockerfile` target | Runs as                          |
| ------------------------- | ---------------------------- | -------------------------------- |
| `munaxa-identity/api`     | `runtime` (unchanged)        | `identity` service, port 4001    |
| `munaxa-identity/migrate` | `migrate`                    | `identity-migrate` run-only task |

`publish-images.yml` (GHCR, for Render) is unchanged until Render is retired.

## Database and migrations

The stack's `db-admin` task creates the database, the owner role `identity_owner` (the role named
`identity_mig` on Supabase) and the runtime role `identity_app`. Both are `NOSUPERUSER` and
`NOBYPASSRLS`, and their passwords come from the secret bundles.

The `migrate` image runs `prisma migrate deploy` with the owner URL from its own bundle
(`DATABASE_MIGRATION_URL`). The baseline grants `identity_app` its privileges table by table, with
`identity_audit_event` limited to `SELECT` and `INSERT`, so nothing runs after it. The Supabase
scripts in `deploy/supabase/` are not used on AWS: RDS has no PostgREST to close, and PostgreSQL's
defaults already give `PUBLIC` execute on functions and usage on types.

## Runtime configuration

The plain environment is set in the stack's `services.tf`: `NODE_ENV=production`, `PORT=4001`,
`IDENTITY_BASE_URL`, `IDENTITY_AUTH_AUDIENCE`, `IDENTITY_SIGNING_ALGORITHM=ES256`,
`IDENTITY_SIGNING_KID`, `IDENTITY_DEFAULT_ORGANISATION`, `CSRF_TRUSTED_ORIGINS` (Identity, Work
and the operator host), `LOG_PRETTY=false` and `TRUST_PROXY_HOPS=1`.

`TRUST_PROXY_HOPS=1` makes `request.ip` the address the ALB saw rather than the ALB's own. Without
it every sign-in counts against one per-IP login limit (10 in 15 minutes), so a handful of attempts
from anyone returns 429 to everyone. On the operator host, which Cloudflare proxies, the address is
the Cloudflare edge's; that host is limited to operators, so the coarser count is accepted there.

The secrets are in the bundle `<env>/identity`, which only the execution role can read:
`DATABASE_URL`, `IDENTITY_SIGNING_PRIVATE_KEY` (from `pnpm keys:generate`),
`IDENTITY_SIGNING_SECRET`, `REDIS_URL` and `REDIS_PASSWORD`.

The two rules in `deploy/RENDER.md` still hold. `PLATFORM_AUTH_ISSUER` in every consumer must
equal `IDENTITY_BASE_URL`. `IDENTITY_SIGNING_KID` must appear in the consumers' public keys before
Identity signs with it.

## Operator organisation and Control roles

Control accepts an Identity token only from one organisation (`OPERATOR_ORGANISATION_ID`), from a
subject on `OPERATOR_SUBJECT_ALLOWLIST`, and only for the `control:*` permissions the token's roles
grant. Identity seeds those roles from `artifacts/control-permissions.json`.

The steps run as the run-only task `identity-bootstrap` (shared stack): the Identity `api` image,
working directory `apps/api`, with two secret bundles injected as ECS `secrets`, so the task
definition holds only their ARNs:

| Bundle                                   | Keys                                              | Lifetime                                   |
| ---------------------------------------- | ------------------------------------------------- | ------------------------------------------ |
| `munaxa-<env>/identity-migrate`          | `DATABASE_MIGRATION_URL` (`identity_owner`)       | standing                                   |
| `munaxa-<env>/identity-bootstrap/<slug>` | `IDENTITY_OWNER_EMAIL`, `IDENTITY_OWNER_PASSWORD` | one operator, one run; delete after step 1 |

**Never pass `IDENTITY_OWNER_PASSWORD` as a container override or on the command line.** Run-task
overrides are returned in plain text by `DescribeTasks` and recorded in CloudTrail. Only the
command is overridden below, and it carries the organisation slug and a role key, nothing secret.
Outside ECS, `IDENTITY_OWNER_PASSWORD_FILE` names a file holding the password instead.

1. Write `identity-bootstrap/<slug>` for the first operator, then run
   `node scripts/bootstrap-account.mjs --organisation munaxa-group --organisation-name "Munaxa Group"`.
   It creates the operator organisation and the account and prints `organisation` and `sub`.
   **Delete the bundle's value** (or the secret) now: nothing below needs the password.
2. `node scripts/seed-control-roles.mjs --organisation munaxa-group` writes
   `control-operator-admin` (every `control:*` permission) and `control-operator-viewer` (the
   reads). It prints `OPERATOR_ORGANISATION_ID`. It is idempotent and needs no bundle but
   `identity-migrate`.
3. `node scripts/bootstrap-account.mjs --organisation munaxa-group --role control-operator-admin`
   (or `-viewer`), with `IDENTITY_OWNER_EMAIL` set to the operator but no password. The account
   exists, so only the role is assigned; a missing account is refused rather than created.
   Repeat 1 and 3 for each operator.
4. Restart the `identity` service. Role definitions are cached in process.
5. Set the platform variables `control_operator_organisation_id` (the organisation id) and
   `control_operator_subjects` (each operator's `sub`), then apply.

For step 3 the email is not secret, so the `identity-bootstrap` bundle may hold only
`IDENTITY_OWNER_EMAIL` at that point; an empty `IDENTITY_OWNER_PASSWORD` key is treated as absent.

Seed these roles in the operator organisation only, never in a customer organisation. The scripts
connect as `identity_owner` (`DIRECT_DATABASE_URL`, or `DATABASE_MIGRATION_URL` as the bundle names
it); the application role cannot create organisations or system roles.

## Open points for review

- **Audience.** `IDENTITY_AUTH_AUDIENCE=munaxa-work,munaxa-control` puts both audiences in every
  token, so a token issued for a Work sign-in is also accepted by Control's audience check. One
  audience per client would be tighter; it is a code change in Identity, left for review.
- **MFA.** `mfaSatisfied` is always false today, so Control runs with `OPERATOR_REQUIRE_MFA=false`.
  The operator host is limited to `operator_cidrs` at the load balancer until MFA exists.

## Checked locally (PostgreSQL 16, Docker)

- I created the roles with the stack's `db-bootstrap.sh`, the same way it runs on RDS. The
  `migrate` image applied the baseline as `identity_owner`, and a second run reported no pending
  migrations.
- `identity_app` cannot create objects in `public`. It can read `identity_audit_event` but cannot
  update it.
- I started the `runtime` image read-only, with all capabilities dropped, the stack's environment
  and a Valkey on localhost. `/api/auth/health/ready` returned 200 with `cache: redis`. A login with
  unknown credentials returned `401 AUTH_INVALID_CREDENTIALS` with no database error.
