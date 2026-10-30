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
