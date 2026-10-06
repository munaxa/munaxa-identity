# Munaxa AWS staging architecture — shared, isolated and standard

**Status:** proposed · **Date:** 2026-10-06 · **Scope:** the non-production AWS environment for
Identity and Work now, with defined extension points for Docs and School.
**Governed by:** `munaxa/munaxa` ADR-0001 (Identity is Work's authentication service) and ADR-0002
(independent products, one shared foundation). Where this document and an accepted ADR disagree,
the ADR wins and the disagreement is listed in §12.

Nothing here is built. This is the design the infrastructure will be built from.

**Evidence used.**

- `munaxa/munaxa` ADR-0002 §10 (shared vs isolated infrastructure), §11 (deployment models),
  §14 (decisions D1–D7), "Decisions taken now", "Decisions deferred".
- `munaxa-docs` ADR-0022 (ECS on Fargate), ADR-0023 (`eu-central-1`), ADR-0024 (minimum-cost
  launch), ADR-0025 (SES over SMTP), and `infra/terraform/` (applied production bootstrap, core,
  data).
- `munaxa-identity` `deploy/render.yaml`, runbooks `migrations.md`, `ecr-image.md`,
  `staging-provisioning.md`, and the AWS readiness audit.
- `munaxa-work` `apps/*/Dockerfile`, `publish-images.yml`, `packages/config`.
- `munaxa-school` `render.yaml`, `apps/api/src` (outbound integrations).

**Prices** are `eu-central-1` on-demand list prices, 730 hours a month, taken from Docs ADR-0024 §4
and §3 (AWS Price List API, 2026-10-04) unless marked _estimate_. Tax excluded. Verify before
committing a budget.

---

## 1. Architecture overview

```text
                               Route 53: nonprod.munaxa.com (delegated sub-zone)
                               ACM: *.nonprod.munaxa.com (one certificate)
                                              │
Internet ──443──▶ ┌──────────────── munaxa-shared-nonprod-alb (one ALB, 2 AZs) ────────────────┐
                  │ host work.nonprod.munaxa.com                                               │
                  │   /api/auth/*  ─▶ tg identity-api   :4001                                  │
                  │   /api/v1/*    ─▶ tg work-api       :3000   (optional; no browser caller)   │
                  │   /*           ─▶ tg work-admin     :3001                                  │
                  │ host docs.nonprod.munaxa.com    (extension point, §4)                     │
                  │ host school.nonprod.munaxa.com  (extension point, §4)                     │
                  └────────────────────────────────────────────────────────────────────────────┘
VPC munaxa-shared-nonprod 10.130.0.0/16  (§3.4; clear of Docs' 10.120/16 and 10.121/16)
 ├─ public subnets  (a, b)  ALB only
 ├─ app subnets     (a, b)  ECS tasks, no public IP, no NAT
 │     identity-api ──▶ Valkey (identity)        work-admin ──Cloud Map──▶ work-api
 │     identity-api ─┐                           work-api ─┐
 │                   └──5432 TLS──▶ RDS (Work unit: databases `identity` and `work`) ◀─┘
 ├─ data subnets    (a, b)  RDS, ElastiCache — no route out at all
 └─ endpoints (AZ a only): ecr.api, ecr.dkr, logs, secretsmanager (interface) + s3 (gateway, free)

ECS cluster munaxa-shared-nonprod: one service per deployable, one task each.
GitHub ─OIDC─▶ per-product publisher role ─▶ ECR munaxa-<product>-<component> ─digest─▶ ECS
```

**The principle:** share what is _infrastructure_ and costs money per instance (VPC, ALB, cluster,
DNS, certificate, endpoints, OIDC provider). Isolate everything that holds a product's _data, identity
or authority_ (databases and roles, Redis, secrets, IAM roles, log groups, ECR repositories, GitHub
environments). That is ADR-0002 §10 applied to one environment.

---

## 2. Shared vs isolated resources

| Resource                        | Shared or per product                                           | Scope                                   | Ongoing cost                               | Cheapest form acceptable for semi-production? | In production                                                     |
| ------------------------------- | --------------------------------------------------------------- | --------------------------------------- | ------------------------------------------ | --------------------------------------------- | ----------------------------------------------------------------- |
| AWS account                     | Shared by all products' non-production                          | Per environment                         | None                                       | Yes                                           | Separate production account(s) (§10)                              |
| Region                          | Shared: `eu-central-1` (Docs ADR-0023)                          | All                                     | None                                       | Yes                                           | Same, plus a DR region (open in Docs)                             |
| VPC                             | **Shared**                                                      | Per environment                         | None by itself                             | Yes                                           | Per environment; per product only if a customer demands it        |
| Subnets / AZs                   | Shared; 2 AZs (the ALB requires two)                            | Per environment                         | None                                       | Yes                                           | 2–3 AZs, tasks spread across them                                 |
| ALB                             | **Shared**, host + path routing                                 | Per environment                         | **Hourly** ~$27.51                         | Yes                                           | Shared or per product; WAF added                                  |
| Route 53                        | Shared sub-zone `nonprod.munaxa.com`                            | Per environment                         | $0.50/zone                                 | Yes                                           | `munaxa.com` zone (ADR-0002: one zone, one subdomain per product) |
| ACM                             | Shared wildcard `*.nonprod.munaxa.com`                          | Per environment                         | None                                       | Yes                                           | Per-product certificates for `<product>.munaxa.com`               |
| ECS cluster                     | **Shared**                                                      | Per environment                         | None                                       | Yes                                           | Shared is still fine (ADR-0002 §10: compute shareable)            |
| ECS services / task definitions | **Per deployable**                                              | Per environment                         | **Hourly** (Fargate)                       | Yes: 1 task, smallest size, Spot              | ≥2 tasks, on-demand                                               |
| ECR repositories                | **Per deployable**                                              | Per account (images promoted by digest) | Storage only, cents                        | Yes                                           | Same names in the production account                              |
| GitHub OIDC provider            | Shared                                                          | Per account                             | None                                       | Yes                                           | Same                                                              |
| IAM roles                       | **Per product, per component, per environment**                 | —                                       | None                                       | Yes                                           | Same, under a production path                                     |
| Secrets Manager                 | **Per product paths and policies**; one shared public CA bundle | Per environment                         | $0.40/secret                               | Yes                                           | Same; rotation added                                              |
| CloudWatch Logs                 | **Per product log groups**, 7-day retention                     | Per environment                         | Usage, cents                               | Yes                                           | 30+ days, alarms                                                  |
| VPC endpoints                   | Shared                                                          | Per environment                         | **Hourly** per endpoint per AZ             | Yes, one AZ                                   | Every AZ in use, or NAT (§3)                                      |
| NAT gateway                     | Not used for Identity/Work                                      | —                                       | (would be hourly)                          | —                                             | When a product needs a fixed egress address                       |
| RDS PostgreSQL                  | **Per product** (Work unit: Work + Identity)                    | Per environment                         | **Hourly** ~$16.61                         | Yes: `db.t4g.micro`, Single-AZ                | Multi-AZ, larger class, 35-day backups                            |
| Redis / Valkey                  | **Per product, only where required** (Identity)                 | Per environment                         | **Hourly** (estimate ~$10.5) or $0 sidecar | Yes: one node, no replica                     | Managed, with a replica                                           |
| Cloud Map namespace             | Shared                                                          | Per environment                         | ~$0.50 + registrations                     | Yes                                           | Same                                                              |

---

## 3. Network topology

### 3.1 Outbound requirements, by product

| Product  | Internet egress needed at runtime                                                                   | Evidence                                                                            |
| -------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Identity | **None** — PostgreSQL and Redis only                                                                | Identity AWS readiness audit; `apps/api/src` makes no outbound call                 |
| Work     | **None**                                                                                            | Work AWS audit: no `fetch`/HTTP client in runtime code                              |
| Docs     | **Yes** — SMTP 587 (SES, ADR-0025), ClamAV signature downloads, OIDC federation discovery, webhooks | Docs `infra/terraform/eu-prod/core/network.tf` security-group egress; ADR-0024 §2.2 |
| School   | **Yes** — Resend email API, Firebase, WhatsApp bridge                                               | `munaxa-school/apps/api/src/communication/*`, `auth/services/firebase.service.ts`   |

All four need AWS APIs: ECR (pull), CloudWatch Logs, Secrets Manager, and S3 (ECR serves image
layers from S3).

### 3.2 Options, for Identity + Work today (three tasks)

|                                   | A. Private tasks + NAT                    | B. Private tasks + VPC endpoints, no NAT                                           | C. Public-subnet tasks + public IPv4, no NAT |
| --------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------- |
| Monthly                           | **~$41.61** + $0.052/GB (one NAT, one AZ) | **~$35.04** (4 interface endpoints × ~$8.76 in one AZ) + $0.01/GB; S3 gateway free | **~$10.95** (3 × $3.65)                      |
| Tasks reachable from the internet | No                                        | No                                                                                 | Only through security groups                 |
| Fixed egress address              | Yes                                       | No egress at all                                                                   | No                                           |
| Internet egress                   | Yes, for everything                       | **None** — and Identity/Work need none                                             | Yes                                          |
| Precedent                         | Docs Non-Production today                 | —                                                                                  | **Docs production (ADR-0024 §2.2, §3.3)**    |

_Interface endpoint price per AZ derived from Docs ADR-0025 §5 ("about $17.50 a month" for one
endpoint in two AZs)._

**Recommendation: B.** It is the cheapest option that keeps tasks in private subnets, which this
programme requires, and for Identity and Work it gives up nothing: they need no internet path, so
the absence of one is a security property, not a limitation. Put the four interface endpoints in one
AZ; tasks in the other AZ reach them across the AZ boundary.

C is ~$24 a month cheaper and is the decision Docs already accepted for its own production. It is
rejected here only because the owner has asked for private subnets; it is listed as a decision in §12.

### 3.3 When Docs or School join this VPC

They need internet egress (§3.1), which endpoints cannot provide. At that point:

- **One NAT gateway in one AZ (~$41.61) serves every product's internet and AWS API traffic**, and the
  interface endpoints can be removed (keeping B *and* adding NAT would be ~$76.65). Total network cost
  then is ~$41.61 for four products.
- Security groups keep Identity's and Work's egress limited to what they use (443 to AWS services,
  5432, 6379), so adding the NAT gives them no new reach.
- Alternatively each of those products keeps its ADR-0024 public-subnet pattern ($3.65 per task).

### 3.4 Layout

| Tier                    | AZ a  | AZ b  | Route                                       |
| ----------------------- | ----- | ----- | ------------------------------------------- |
| Public (ALB only)       | `/24` | `/24` | Internet gateway                            |
| App (ECS tasks)         | `/20` | `/20` | Local only (+ S3 gateway); NAT later (§3.3) |
| Data (RDS, ElastiCache) | `/24` | `/24` | Local only                                  |

CIDR: **not** `10.120.0.0/16` (Docs Non-Production) or `10.121.0.0/16` (Docs production). Proposed
`10.130.0.0/16`, leaving room for peering if it is ever needed. Public IP auto-assignment off
everywhere. The default VPC and default security group are used by nothing.

Security groups, one per tier per deployable, referencing each other (pattern from Docs core network):

| Group                 | Inbound                                                     | Outbound                                                              |
| --------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------- |
| `alb`                 | 443, 80 from the internet                                   | to each target's port                                                 |
| `identity-api`        | 4001 from `alb`                                             | 5432 to `rds-work-unit`, 6379 to `identity-cache`, 443 to `endpoints` |
| `work-api`            | 3000 from `work-admin` (and `alb` if `/api/v1/*` is public) | 5432 to `rds-work-unit`, 443 to `endpoints`                           |
| `work-admin`          | 3001 from `alb`                                             | 3000 to `work-api`, 443 to `endpoints`                                |
| `ops` (one-off tasks) | none                                                        | 5432 to `rds-work-unit`, 443 to `endpoints`                           |
| `rds-work-unit`       | 5432 from `identity-api`, `work-api`, `ops`                 | none                                                                  |
| `identity-cache`      | 6379 from `identity-api`                                    | none                                                                  |
| `endpoints`           | 443 from the app tier                                       | none                                                                  |

Without a NAT, the Work admin cannot reach the API through the public ALB; it calls it over Cloud Map
(§5), which is also what Work's `WORK_API_URL` expects.

---

## 4. ALB and routing

**One ALB for the environment; one hostname per product; paths only within a product.**

- **Hostnames per product** because cookies are host-only and must stay that way (ADR-0002 binding
  decision 14; Identity ADR-0004). Products never share an origin.
- **Paths within a product** because Identity's session cookie is `__Host-` and must be set on the
  origin Work's admin reads (Identity ADR-0004): the Work unit is one origin split by path.

| Priority | Host                        | Path                                                                                                      | Target group                                                                        |
| -------- | --------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| 100      | `work.nonprod.munaxa.com`   | `/api/auth/*`                                                                                             | `identity-api` (4001), health `/api/auth/health/ready`                              |
| 110      | `work.nonprod.munaxa.com`   | `/api/v1/*`                                                                                               | `work-api` (3000), health `/health/ready` — **optional**: no browser calls it today |
| 190      | `work.nonprod.munaxa.com`   | `/*`                                                                                                      | `work-admin` (3001), health `/`                                                     |
| 200–299  | `docs.nonprod.munaxa.com`   | Docs ADR-0024 §2.3: `/api/v1/preview/stream*` → docs-api, `/*` → docs-web                                 | extension point                                                                     |
| 300–399  | `school.nonprod.munaxa.com` | e.g. `/api/*` → school-api, `/*` → school-admin (same origin also removes School's CORS ordering problem) | extension point                                                                     |
| default  | —                           | —                                                                                                         | fixed 404                                                                           |

Each product owns a block of 100 rule priorities. Port 80 redirects to 443. The TLS policy is a
current AWS-recommended policy. Identity trusts exactly one proxy hop, which this ALB is.

---

## 5. ECS model

- **One cluster per environment**, `munaxa-shared-nonprod`. Clusters cost nothing; isolation is per
  service, task role and security group.
- **One service per deployable, one task each.** No autoscaling in staging.
- **Capacity provider: Fargate Spot** for every staging service and one-off task (~65% cheaper,
  _estimate_). An interruption restarts a task; nothing in staging needs more.
- **Architecture:** `X86_64` (all images are `linux/amd64`).
- **Images by digest only** (`repository@sha256:…`), never a tag. The same digest runs the service and
  its one-off tasks.
- **One-off tasks** (migrations, provisioning) run from the service image with a command override and
  the `ops` security group, under an execution role that can read only the owner secrets. No bastion,
  no ECS Exec (it would need another endpoint).
- **Service discovery:** Cloud Map private namespace `nonprod.munaxa.internal`; names
  `work-api.nonprod.munaxa.internal` etc.
- **Container health checks:** liveness. **Target group health checks:** readiness. (Identity:
  `/api/auth/health/live` and `/ready`; Work: `/health/live` and `/health/ready`.)
- **Optional cost lever:** scale services to 0 outside test windows and stop the RDS instance (up to
  7 days at a time). The ALB and endpoints keep charging.

| Deployable     | Size               | On-demand $/month | Notes                                  |
| -------------- | ------------------ | ----------------- | -------------------------------------- |
| `identity-api` | 0.25 vCPU / 0.5 GB | ~10.37            | scrypt is per sign-in, not per request |
| `work-api`     | 0.25 vCPU / 1 GB   | ~12.23            | many modules in one process            |
| `work-admin`   | 0.25 vCPU / 0.5 GB | ~10.37            | Next.js server rendering               |

Sizes are starting points; raise one only on evidence (memory, CPU throttling, latency).

---

## 6. ECR and CI/CD model

The Identity pattern (`ecr-image.md`) is the standard:

```text
tag or dispatch ─▶ GitHub environment (protection rules) ─OIDC─▶ product publisher role
  ─▶ ECR login ─▶ build linux/amd64 (BuildKit secret for @munaxa/*) ─▶ push sha-<commit>
  ─▶ digest ─▶ verify the pulled digest ─▶ ECS task definitions pin repository@sha256
```

- **One repository per deployable**, named like the existing GHCR images (§11): `munaxa-identity-api`,
  `munaxa-work-api`, `munaxa-work-admin`, `munaxa-docs-api`, `munaxa-docs-web`, `munaxa-docs-antivirus`,
  `munaxa-school-api`, `munaxa-school-admin`. Immutable tags, basic scan on push, AES-256, keep the
  last 30 images.
- **One publisher role per product repository**, trusted for that repository's GitHub environment
  only, allowed to push to that product's repositories only.
- **One GitHub environment per AWS environment** in each repository, holding `AWS_REGION`,
  `AWS_ROLE_ARN` and the repository name as variables; no AWS secret anywhere.

**Before other products adopt it:**

1. **ADR-0002 names GHCR as the registry (§10, D6).** ECR for the AWS environments needs a superseding
   ecosystem ADR in `munaxa/munaxa` (accepted ADRs are not edited). GHCR can remain the
   on-premises/dedicated-cloud distribution channel; the same digest can be pushed to both.
2. **School's admin image is not environment-neutral:** `NEXT_PUBLIC_API_URL` is compiled in at build
   time, so one digest cannot run in two environments. Fix by making the API URL same-origin
   (`/api`, §4) or runtime configuration before School adopts promote-by-digest.
3. **School uses static AWS keys for S3** (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`); on ECS this
   becomes a task role.
4. **Shared workflow:** the publish workflow and image-verification script can become a reusable
   workflow in `munaxa/munaxa` (ADR-0002 §10: shared CI templates), parameterised per image.
5. **Docs** already publishes to GHCR by digest (D6) and plans to pull with a GHCR credential; moving
   it is Docs' own decision and changes its production network rules (the GHCR egress).

---

## 7. Database model

**Each product owns its databases and roles. Databases are never merged.** ADR-0002 §10 allows the
_server_ to be shared "for cost"; the databases, roles and credentials never are.

| Product                     | Staging instance                                                                       | Databases                 | Roles                                                                              |
| --------------------------- | -------------------------------------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------- |
| Work unit (Work + Identity) | **one** `munaxa-work-nonprod-rds`, `db.t4g.micro`, Single-AZ, 20 GB gp3, PostgreSQL 16 | `work`, `identity`        | `work_mig`, `work_app`, `work_membership_resolver`; `identity_mig`, `identity_app` |
| Docs                        | its own (ADR-0002 D4; existing Non-Production instance)                                | one per tenant (ADR-0015) | Docs' own                                                                          |
| School                      | its own                                                                                | pooled, opt-in silo       | School's own                                                                       |

Why one instance for the Work unit: Work and Identity are one deployment and purchase unit (ADR-0002
binding decision 13), Identity's provisioning runbook already allows "two databases; they may share a
server", and it saves ~$16.61 a month. Isolation is unchanged: separate databases, no cross-database
access, separate owner and runtime roles, separate secrets, and both applications refuse privileged
roles at startup. A separate Identity instance remains an open decision (§12) and is the production
default if the owner prefers blast-radius separation over cost.

All instances: private data subnets, not publicly accessible, `rds.force_ssl` on, storage encrypted
(AWS-managed key), the master password managed by RDS in Secrets Manager, 7-day backup retention in
staging, deletion protection on.

**Redis:** only Identity requires it (lockout counters, rate limits, permission cache; `noeviction`).
Staging: **one ElastiCache for Valkey `cache.t4g.micro` node**, cluster mode disabled, no replica, TLS +
AUTH, `noeviction`, owned by Identity. Not shared with other products (ADR-0002: pooling Redis is
deferred). _Cost alternative (Docs ADR-0024 §2.6):_ Redis as a loopback sidecar in the Identity task,
$0 — acceptable for one task, but a restart resets lockout counters.

---

## 8. Secrets and IAM model

**Secrets Manager** — one JSON secret per _consumer_, so an execution role can read only what its task
uses. Never a shared signing key or shared credential (ADR-0002 §10).

| Secret                         | Read by                        | Keys                                                                                   |
| ------------------------------ | ------------------------------ | -------------------------------------------------------------------------------------- |
| `munaxa-identity-nonprod/app`  | identity-api execution role    | `DATABASE_URL`, `REDIS_URL`, `IDENTITY_SIGNING_PRIVATE_KEY`, `IDENTITY_SIGNING_SECRET` |
| `munaxa-identity-nonprod/ops`  | identity ops execution role    | `DIRECT_DATABASE_URL`, `IDENTITY_OWNER_PASSWORD`                                       |
| `munaxa-work-nonprod/app`      | work-api execution role        | `DATABASE_URL`, `PII_MATCH_SECRET`                                                     |
| `munaxa-work-nonprod/ops`      | work ops execution role        | migration owner URL                                                                    |
| `munaxa-shared-nonprod/rds-ca` | any ops/app role that needs it | the regional RDS CA bundle (public; ~4.6 KB)                                           |
| `rds!…` (RDS-managed master)   | nobody at runtime              | —                                                                                      |

Non-secret configuration (issuer, audience, public keys, hostnames) goes in the task definition's
environment, not in Secrets Manager.

**IAM**, all under a product path, all with a permissions boundary (Docs pattern):

| Role                                             | Trusted by                          | May                                                                                 |
| ------------------------------------------------ | ----------------------------------- | ----------------------------------------------------------------------------------- |
| `munaxa-<product>-nonprod-<component>-execution` | `ecs-tasks`                         | pull that component's repository, read that component's secret, write its log group |
| `munaxa-<product>-nonprod-<component>-task`      | `ecs-tasks`                         | only what the application calls (Identity and Work: nothing)                        |
| `munaxa-<product>-nonprod-ops-execution`         | `ecs-tasks`                         | the ops secret, the ops log group                                                   |
| `munaxa-<product>-nonprod-github-publisher`      | GitHub OIDC, one repo + environment | push to that product's repositories                                                 |
| infrastructure deployer                          | humans/CI applying infrastructure   | names and tags of this environment only                                             |

**Same-account caution:** Docs production and Docs Non-Production are both in account
`800728620253`, the Organizations management account, separated by IAM guardrails that deny anything
**named `*nonprod*` or tagged `NonProduction`** to the Docs production deployer. Every shared staging
resource must carry the `nonprod` token and `Environment=NonProduction` if it lives in that account
— or, better, live in its own account (§12).

---

## 9. Cost-minimization strategy

Identity + Work staging, Option B, `eu-central-1`:

| Item                                                   | $/month   | Kind                                                                  |
| ------------------------------------------------------ | --------- | --------------------------------------------------------------------- |
| Shared ALB (hourly + 2 public IPv4 + ~0.5 LCU)         | ~27.51    | Hourly + usage                                                        |
| Interface endpoints ×4, one AZ                         | ~35.04    | Hourly (_derived_)                                                    |
| Fargate: identity-api, work-api, work-admin, on-demand | ~32.97    | Hourly (_derived from Docs rates_)                                    |
| RDS `db.t4g.micro` Single-AZ + 20 GB (Work unit)       | ~16.61    | Hourly                                                                |
| ElastiCache Valkey `cache.t4g.micro` (Identity)        | ~10.5     | Hourly (_estimate_: Redis OSS node is $13.14; Valkey is listed lower) |
| Secrets Manager ×6                                     | ~2.40     | Fixed                                                                 |
| Route 53 sub-zone + Cloud Map namespace                | ~1.00     | Fixed                                                                 |
| CloudWatch Logs (7 days), ECR storage, S3 gateway      | ~1–2      | Usage                                                                 |
| **Total, on-demand**                                   | **≈ 128** |                                                                       |
| With Fargate Spot                                      | ≈ 107     | _estimate_                                                            |
| With Redis as a sidecar instead of Valkey              | −10.5     | owner decision                                                        |
| With Option C instead of B                             | −24       | owner decision                                                        |

What is deliberately **not** in it: NAT gateway, Multi-AZ, replicas, autoscaling, WAF, KMS
customer-managed keys, bastion, ECS Exec endpoint, SES/S3/OpenSearch/MSK (no Identity or Work
requirement), extra ALBs. Each Docs/School join adds its tasks and database; the network and ALB do
not repeat.

**Existing cost to review:** the Docs Non-Production environment already costs about **$100 a month
idle** (NAT gateway and a Multi-AZ `db.t4g.small`; Docs ADR-0024 §4). Folding Docs staging into this
design, or shrinking it, is the largest single saving available — a Docs owner decision.

---

## 10. Staging → production

| Area    | Staging (this design)                                    | Production                                                                                 |
| ------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Account | Non-production account                                   | Separate production account(s), outside the management account                             |
| AZs     | 2 (ALB minimum), endpoints in 1                          | 2–3, everything spread                                                                     |
| Tasks   | 1 per service, Spot                                      | ≥2 per service, on-demand, rolling deploys                                                 |
| Egress  | Endpoints only (B)                                       | Endpoints in every AZ, or NAT per AZ when egress or a fixed address is needed              |
| ALB     | Shared                                                   | Shared or per product; WAF                                                                 |
| RDS     | One instance for the Work unit, Single-AZ, 7-day backups | Multi-AZ, larger class, 35-day backups + AWS Backup; separate Identity instance if decided |
| Redis   | One Valkey node                                          | Replica, Multi-AZ                                                                          |
| Logs    | 7 days                                                   | 30–90 days, alarms, dashboards                                                             |
| DNS     | `<product>.nonprod.munaxa.com`                           | `<product>.munaxa.com` (ADR-0002)                                                          |
| Images  | ECR, promoted by digest                                  | Same digest, copied to the production registry                                             |
| MFA     | Not required for staging (Identity ADR-0003)             | Required before Work production                                                            |

Nothing in the application changes between them: every difference is sizing, placement or
configuration.

---

## 11. Naming conventions

Derived from what exists (Docs: `munaxa-docs-eu-prod-*`, `/munaxa-docs/eu-prod/`,
`prod.munaxa-docs.internal`, tags `Project`/`Environment`/`ManagedBy`/`Stack`; images
`munaxa-<product>-<component>` on GHCR), extended for shared resources.

**Tokens.** `<product>` ∈ `identity`, `work`, `docs`, `school`, `shared`. `<env>` ∈ `nonprod`
(staging, matching Docs' existing `nonprod` and its guardrails), `eu-prod` (production, as Docs).
`<component>` ∈ `api`, `admin`, `web`, `antivirus`, `ops`, `rds`, `cache`, …

| Kind                         | Pattern                                                                                      | Examples                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Product resource             | `munaxa-<product>-<env>-<component>`                                                         | `munaxa-work-nonprod-rds`, `munaxa-identity-nonprod-cache`          |
| Shared resource              | `munaxa-shared-<env>[-<component>]`                                                          | `munaxa-shared-nonprod` (VPC, cluster), `munaxa-shared-nonprod-alb` |
| ECR repository               | `munaxa-<product>-<component>` (= GHCR image name; account-level, not per env)               | `munaxa-identity-api`, `munaxa-work-admin`                          |
| ECS cluster                  | `munaxa-shared-<env>`                                                                        | `munaxa-shared-nonprod`                                             |
| ECS service / task family    | `munaxa-<product>-<env>-<component>`                                                         | `munaxa-identity-nonprod-api`, `munaxa-identity-nonprod-ops`        |
| Target group (32-char limit) | `<product>-<env>-<component>`                                                                | `identity-nonprod-api`                                              |
| RDS instance / database      | instance `munaxa-<product>-<env>-rds`; database = product name                               | `munaxa-work-nonprod-rds` / `identity`, `work`                      |
| Secrets                      | `munaxa-<product>-<env>/<consumer>`                                                          | `munaxa-identity-nonprod/app`                                       |
| Log groups                   | `/munaxa-<product>/<env>/<component>`, 7 days                                                | `/munaxa-identity/nonprod/api`                                      |
| IAM roles                    | path `/munaxa-<product>/<env>/`, name `munaxa-<product>-<env>-<component>-<execution\|task>` | `munaxa-work-nonprod-admin-execution`                               |
| GitHub publisher role        | `munaxa-<product>-<env>-github-publisher`                                                    | `munaxa-identity-nonprod-github-publisher`                          |
| GitHub environment           | `aws-<env>`                                                                                  | `aws-nonprod`, `aws-eu-prod`                                        |
| Cloud Map namespace          | `<env>.munaxa.internal`                                                                      | `nonprod.munaxa.internal`                                           |
| DNS                          | `<product>.nonprod.munaxa.com` / `<product>.munaxa.com`                                      | `work.nonprod.munaxa.com`                                           |
| Tags                         | `Project=Munaxa<Product>`, `Environment=NonProduction\|Production`, `ManagedBy`, `Stack`     | `Project=MunaxaIdentity`                                            |

**Already published under different names, to align (no code change):** the Identity ECR runbook uses
repository `munaxa/identity-api` and GitHub environment `aws-staging`. Under this convention they become
`munaxa-identity-api` and `aws-nonprod` — a GitHub variable, the environment name, the role's trust
`sub`, and the runbook text.

---

## 12. Open decisions and blockers

| #   | Decision                                                                                                                      | Recommendation                                                                                                   |
| --- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| 1   | **Registry:** ADR-0002 §10/D6 names GHCR; AWS deployment uses ECR                                                             | Supersede with an ecosystem ADR: ECR for AWS environments, GHCR kept for distribution                            |
| 2   | **Account:** staging in the Organizations management account (where Docs prod and Non-Production are) or a new member account | New member account for non-production (free); keeps staging out of the Docs production deployer's reach entirely |
| 3   | **Network:** B (private + endpoints, ~$35) or C (public IPv4, ~$11, Docs precedent)                                           | B, as requested; C saves ~$24 a month if the owner accepts it                                                    |
| 4   | **Identity database server:** shared with Work (separate databases) or its own instance (+~$16.61)                            | Shared for staging; revisit for production                                                                       |
| 5   | **Identity Redis:** ElastiCache Valkey (~$10.5) or loopback sidecar ($0)                                                      | Valkey: survives task restarts and is the production shape                                                       |
| 6   | **DNS:** where `munaxa.com` is hosted, and delegating `nonprod.munaxa.com`                                                    | Delegate the sub-zone to Route 53                                                                                |
| 7   | **Fargate Spot** for staging                                                                                                  | Yes                                                                                                              |
| 8   | **Docs Non-Production** (~$100 a month idle)                                                                                  | Docs owner: shrink, or move into this design                                                                     |
| 9   | School: build-time `NEXT_PUBLIC_API_URL`, static S3 keys, `app.`/`admin.munaxa.com` hostnames (ADR-0002 R2)                   | Fix before School joins (§6)                                                                                     |
| 10  | Naming alignment of the Identity artifacts (§11)                                                                              | Rename before the first AWS publish                                                                              |
| 11  | ADR-0002 §7 says Identity signs RS256; Identity uses ES256                                                                    | Correct in the superseding ADR (#1)                                                                              |

**Blockers for building this, outside this document:** Work's own AWS blockers from its readiness audit
(migration path, `work_app` grants, RDS TLS, bootstrap from the image), and decisions 1, 2 and 6.
