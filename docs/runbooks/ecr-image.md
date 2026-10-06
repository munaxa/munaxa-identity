# Runbook — publishing the Identity image to Amazon ECR

AWS staging runs the Identity image from **Amazon ECR**. ECS pulls it with its task execution role —
IAM, no registry password to store or rotate — and GitHub Actions pushes it by assuming an IAM role
through **GitHub OIDC**, so no AWS credential exists anywhere outside a single workflow run.

The image is the one `apps/api/Dockerfile` has always built: multi-stage, Node 22, non-root
(`identity`), `linux/amd64`, `WORKDIR /app/apps/api`, `CMD ["node", "dist/main.js"]`. Nothing about it
changes for ECR. The same image serves:

| Use                        | Command                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| The Identity ECS service   | the image's CMD — `node dist/main.js`                                                        |
| One-off migration task     | `["node", "dist/migrate.js"]`                                                                |
| One-off provisioning tasks | `["node", "scripts/bootstrap-account.mjs", …]`, `["node", "scripts/seed-work-roles.mjs", …]` |

The service never migrates; see `migrations.md`.

**Nothing in this repository creates AWS resources.** The prerequisites below are created once, by
whoever owns the AWS account (console, CLI, or the infrastructure repository when there is one).

---

## 1. AWS prerequisites (once per account)

### 1.1 GitHub's OIDC identity provider

IAM → Identity providers → OpenID Connect:

| Field        | Value                                         |
| ------------ | --------------------------------------------- |
| Provider URL | `https://token.actions.githubusercontent.com` |
| Audience     | `sts.amazonaws.com`                           |

One per account, shared by every repository that uses it. No charge.

### 1.2 The ECR repository

| Setting          | Value                          | Why                                                                                              |
| ---------------- | ------------------------------ | ------------------------------------------------------------------------------------------------ |
| Name             | `munaxa/identity-api`          | Predictable; the `munaxa/` namespace leaves room for `munaxa/work-api` and `munaxa/work-admin`   |
| Tag immutability | **Immutable**                  | A commit tag can never be repointed at different bytes                                           |
| Scan on push     | Basic scanning, on             | Free; reports OS-package CVEs per pushed image                                                   |
| Encryption       | AES-256 (the default)          | A customer-managed KMS key adds a monthly key charge and per-request cost for no staging benefit |
| Lifecycle policy | Keep the 30 most recent images | Bounds storage; 30 is the rollback horizon                                                       |

Lifecycle policy:

```json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep the 30 most recent images. Older digests can no longer be rolled back to.",
      "selection": { "tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 30 },
      "action": { "type": "expire" }
    }
  ]
}
```

### 1.3 The publishing role

An IAM role the workflow assumes, e.g. `identity-ecr-publisher`. Maximum session duration 1 hour.

**Trust policy** — only this repository's `aws-staging` GitHub environment can assume it. Replace
`<ACCOUNT_ID>`; if the GitHub organisation or repository is ever renamed, the `sub` changes with it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:munaxa/munaxa-identity:environment:aws-staging"
        }
      }
    }
  ]
}
```

Because the job declares `environment: aws-staging`, GitHub issues the token with exactly that
`sub` — no branch, tag, fork or other repository can produce it. Which refs may run in the
environment is then decided by the environment's protection rules (§2).

**Permissions policy** — log in to ECR, and push to and read back this one repository. No delete, no
other repository, nothing outside ECR.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrLogin",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "PushAndVerifyIdentityImage",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:DescribeImages"
      ],
      "Resource": "arn:aws:ecr:<REGION>:<ACCOUNT_ID>:repository/munaxa/identity-api"
    }
  ]
}
```

`ecr:GetAuthorizationToken` cannot be scoped to a repository — AWS defines it on `*` — but it only
issues a registry login; every action on images is limited by the second statement.

### 1.4 What ECS needs to pull it

The ECS **task execution role** (for the service and for the one-off tasks) needs
`ecr:GetAuthorizationToken` on `*` and `ecr:BatchCheckLayerAvailability`, `ecr:GetDownloadUrlForLayer`,
`ecr:BatchGetImage` on the repository ARN above — read only. No GHCR credential and no
`repositoryCredentials` are needed.

The network path for a task in a **private subnet** to reach ECR is either a NAT gateway or these VPC
endpoints: `com.amazonaws.<region>.ecr.api` and `…ecr.dkr` (interface), `com.amazonaws.<region>.s3`
(gateway — image layers are served from S3), `…logs` (for the `awslogs` driver), and `…secretsmanager`
for the task's secrets. This is part of the ECS network design, not of this repository; its cost is
in §7.

---

## 2. GitHub configuration

Settings → Environments → **`aws-staging`**:

| Kind                         | Name                                                                             | Value                                                   |
| ---------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Variable                     | `AWS_REGION`                                                                     | e.g. `eu-west-1`                                        |
| Variable                     | `AWS_ROLE_ARN`                                                                   | `arn:aws:iam::<ACCOUNT_ID>:role/identity-ecr-publisher` |
| Variable                     | `ECR_REPOSITORY`                                                                 | `munaxa/identity-api`                                   |
| Deployment branches and tags | Selected: tags matching `ecr/*` (and the default branch, if dispatching from it) | Who may publish                                         |
| Required reviewers           | Optional                                                                         | A person approves each publish                          |

These are **variables**, not secrets: an account ID, a region and a role ARN are identifiers, and the
role can only be assumed from this environment anyway. **No AWS secret is stored in GitHub.** The
workflow fails at once, naming what is missing, if any of the three is unset.

The build also needs read access to the `@munaxa/*` packages. The workflow uses the existing
`PLATFORM_PACKAGES_TOKEN` secret when present and otherwise the per-run `GITHUB_TOKEN`
(`packages: read`). Granting `munaxa-identity` read access on those packages (package settings →
Manage Actions access) makes the per-run token sufficient, after which the long-lived
`PLATFORM_PACKAGES_TOKEN` can be deleted.

---

## 3. Publishing

`.github/workflows/publish-ecr.yml`, deliberately triggered, never on every push:

```bash
git tag ecr/2026-10-06-staging <commit> && git push origin ecr/2026-10-06-staging
```

or Actions → **Publish image to ECR** → Run workflow, optionally naming a commit (a dispatch is only
offered once the workflow exists on the default branch; a tag works from any commit carrying it).

The workflow: assumes the role (OIDC) → logs in to ECR → if `sha-<commit>` already exists, reuses its
digest (tags are immutable, so a re-run must not push again) → otherwise builds `linux/amd64` with the
package credential as a BuildKit secret and pushes → resolves the digest → pulls it back and runs
`.github/scripts/verify-runtime-image.sh` on exactly what ECS will run.

That script checks: x86_64; the service command and directory unchanged; not root; no development
toolchain; no credential in layer history or an `.npmrc`; the generated Prisma client loads; the
migration runner, the provisioning scripts, the baseline SQL and the Work catalogue are present;
`node dist/migrate.js --help` works; and `node dist/migrate.js` with no credential exits 1 with
`migrate.failed` and starts nothing.

### Tags

| Tag                    | Example                                        | Purpose                                            |
| ---------------------- | ---------------------------------------------- | -------------------------------------------------- |
| `sha-<40-char commit>` | `sha-c62748116cd4d88c76389d7c3542479295e39dcb` | Traceability; how a re-run finds an existing image |
| `<12-char commit>`     | `c62748116cd4`                                 | Convenience in the console                         |

There is no `latest`, and **no tag is a deployment reference**.

---

## 4. The immutable reference

The run summary prints it:

```text
<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/munaxa/identity-api@sha256:<64 hex>
```

Or, for any published commit:

```bash
aws ecr describe-images --repository-name munaxa/identity-api \
  --image-ids imageTag=sha-<commit> --query 'imageDetails[0].imageDigest' --output text
```

## 5. Using it in ECS

Every task definition that runs Identity — the service and each one-off task — sets `image` to that
`repository@sha256:…` reference. Not a tag: a digest cannot move, so the service and the migration
task that ran before it are provably the same bytes.

Also set, in the task definition's environment, `BUILD_SHA` to the commit and `APP_VERSION` to the
release name. They are not baked into the image; `/api/auth/health/live` and `/ready` report them.

Order for a release (`migrations.md`, "Before deploying a new Identity version"):

1. One-off task `["node", "dist/migrate.js"]` with the new digest; continue only on exit 0.
2. Register a new service task definition revision with the same digest; update the service.

## 6. Rollback

1. Find the previous digest: the previous task definition revision already pins it
   (`aws ecs describe-task-definition --task-definition <family>:<revision>`), or
   `aws ecr describe-images` by the previous commit's `sha-` tag.
2. Update the service to the previous revision (or register a revision with the previous digest).
3. Migrations do not roll back. The runner is forward-only and refuses a build older than the
   database's applied migrations ("ahead of the build"). Rolling the _service_ back across a migration
   is safe only if that migration was backward-compatible; if not, roll forward with a fix instead.

Digests stay available for the 30 most recent images (§1.2).

---

## 7. Staging cost considerations

What **this change** requires, at staging scale (one service, a few releases a week):

| Resource                                 | Ongoing cost                                                                                                                                                                            |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ECR repository storage                   | **Negligible.** $0.10 per GB-month; the image is ~134 MB compressed, layers are shared between versions, and 30 images are typically well under 2 GB — cents to a dollar or two a month |
| ECR pulls by ECS in the same region      | **None** — same-region transfer from ECR to Fargate is free                                                                                                                             |
| Basic scan on push                       | None                                                                                                                                                                                    |
| GitHub OIDC provider, IAM role, policies | None                                                                                                                                                                                    |
| AES-256 encryption                       | None (a KMS key would add a monthly charge; not used)                                                                                                                                   |
| GitHub Actions                           | Within the organisation's Actions minutes; one build per publish                                                                                                                        |

**The meaningful hourly charges come from the network path ECS uses to reach ECR**, which this
repository does not create but every private-subnet Fargate design needs (§1.4):

| Option                                                                   | Ongoing charge                                                                                                                                  | Note                                                                                       |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Interface VPC endpoints (`ecr.api`, `ecr.dkr`, `logs`, `secretsmanager`) | **Hourly, per endpoint, per AZ**, plus per-GB processing — roughly $7 per endpoint-AZ per month at us-east-1 list prices; verify for the region | No internet egress from the tasks at all. One AZ for staging keeps it to four endpoint-AZs |
| S3 gateway endpoint                                                      | None                                                                                                                                            | Required with the interface endpoints; serves image layers                                 |
| NAT gateway                                                              | **Hourly** (roughly $33 a month at us-east-1 list prices) plus per-GB processing, per AZ                                                        | Gives the tasks general internet egress, which neither Identity nor Work needs at runtime  |

Neither is introduced by this change; choosing between them belongs to the ECS network design.
Identity and Work make no outbound calls at runtime, so the endpoint option needs no internet path
at all.
