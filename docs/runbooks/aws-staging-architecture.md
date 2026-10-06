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

**Prices** are `eu-central-1` on-demand list prices, 730 hours a month, tax excluded. They were
re-verified on 2026-10-06 against the AWS Price List offer files for `eu-central-1` (`AmazonVPC`,
`AmazonEC2`, `AWSELB`, `AmazonECS`, `AmazonCloudWatch`, `AWSSecretsManager`, `AmazonECR`,
`AmazonRDS`, `AmazonElastiCache`, `AWSCloudMap`; publication dates 2026-09-11 to 2026-10-06) and
the AWS pricing and service documentation cited in §3.2. Anything not in the price list is marked
_estimate_.

---

## 1. Architecture overview

```text
                               Route 53: munaxa-nonprod.com (own domain, own zone, §4)
                               ACM: *.munaxa-nonprod.com (one certificate)
                                              │
Internet ──443──▶ ┌──────────────── munaxa-shared-nonprod-alb (one ALB, 2 AZs) ────────────────┐
                  │ host work.munaxa-nonprod.com                                               │
                  │   /api/auth/*  ─▶ tg identity-api   :4001                                  │
                  │   /api/v1/*    ─▶ tg work-api       :3000   (optional; no browser caller)   │
                  │   /*           ─▶ tg work-admin     :3001                                  │
                  │ host docs.munaxa-nonprod.com    (extension point, §4.8)                   │
                  │ host school.munaxa-nonprod.com  (extension point, §4.8)                   │
                  └────────────────────────────────────────────────────────────────────────────┘
VPC munaxa-shared-nonprod 10.130.0.0/16  (§3.8; clear of Docs' 10.120/16 and 10.121/16)
 ├─ public subnets  (a, b)  ALB only                          route: internet gateway
 ├─ app subnets     (a, b)  Identity + Work tasks, no public IP route: local + S3 gateway, nothing else
 │     identity-api ──▶ Valkey (identity)        work-admin ──Cloud Map──▶ work-api
 │     identity-api ─┐                           work-api ─┐
 │                   └──5432 TLS──▶ RDS (Work unit: databases `identity` and `work`) ◀─┘
 │     all app tasks ──443──▶ interface endpoints (AWS APIs) / S3 gateway (ECR layers)
 ├─ data subnets    (a, b)  RDS, ElastiCache                  route: local only
 ├─ egress subnets  (a, b)  reserved, empty — Docs/School tasks that need the internet (§3.6)
 └─ endpoints (AZ a only): ecr.api, ecr.dkr, logs, secretsmanager (interface, $8.76/month each)
                           + s3 (gateway, free); endpoint policies: this account only (§3.7)

Decision (§3): Option B — private tasks + VPC endpoints, no NAT gateway, no internet egress.
Decision (§4): non-production on its own domain munaxa-nonprod.com; production stays on munaxa.com.

Account: munaxa-nonprod (dedicated member account, §8) — not the Organizations management account.
ECS cluster munaxa-shared-nonprod: one service per deployable, one task each.
GitHub ─OIDC─▶ per-product publisher role ─▶ ECR munaxa-<product>-<component> ─digest─▶ ECS
```

**The principle:** share what is _infrastructure_ and costs money per instance (VPC, ALB, cluster,
DNS, certificate, endpoints, OIDC provider). Isolate everything that holds a product's _data, identity
or authority_ (databases and roles, Redis, secrets, IAM roles, log groups, ECR repositories, GitHub
environments). That is ADR-0002 §10 applied to one environment.

---

## 2. Shared vs isolated resources

| Resource                        | Shared or per product                                                            | Scope                                                    | Ongoing cost                                                 | Cheapest form acceptable for semi-production? | In production                                                                                |
| ------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------- | -------------------------------------------------------------------------------------------- |
| AWS account                     | **`munaxa-nonprod` member account**, shared by all products' non-production (§8) | Per environment                                          | $0                                                           | Yes                                           | Separate production member account, never the management account (§8.5)                      |
| Region                          | Shared: `eu-central-1` (Docs ADR-0023)                                           | All                                                      | None                                                         | Yes                                           | Same, plus a DR region (open in Docs)                                                        |
| VPC                             | **Shared**                                                                       | Per environment                                          | None by itself                                               | Yes                                           | Per environment; per product only if a customer demands it                                   |
| Subnets / AZs                   | Shared; 2 AZs (the ALB requires two)                                             | Per environment                                          | None                                                         | Yes                                           | 2–3 AZs, tasks spread across them                                                            |
| ALB                             | **Shared**, host + path routing                                                  | Per environment                                          | **Hourly** $19.71 + 2 public IPv4 $7.30 + LCU usage          | Yes                                           | Shared or per product; WAF added                                                             |
| Route 53                        | Shared zone for the environment's own domain, `munaxa-nonprod.com` (§4)          | Per environment                                          | $0.50/zone + $16/year domain                                 | Yes                                           | `munaxa.com` on Cloudflare (ADR-0002: one zone, one subdomain per product), DNS-only records |
| ACM                             | Shared wildcard `*.munaxa-nonprod.com`                                           | Per environment                                          | None                                                         | Yes                                           | One certificate per product hostname (§4.5)                                                  |
| ECS cluster                     | **Shared**                                                                       | Per environment                                          | None                                                         | Yes                                           | Shared is still fine (ADR-0002 §10: compute shareable)                                       |
| ECS services / task definitions | **Per deployable**                                                               | Per environment                                          | **Hourly** (Fargate)                                         | Yes: 1 task, smallest size, Spot              | ≥2 tasks, on-demand                                                                          |
| ECR repositories                | **Per deployable**                                                               | Per account (images promoted by digest)                  | Storage only, cents                                          | Yes                                           | Same names in the production account                                                         |
| GitHub OIDC provider            | Shared within the account                                                        | Per account (one in `munaxa-nonprod`, one in production) | $0                                                           | Yes                                           | Same, trusting `aws-eu-prod` only                                                            |
| IAM roles                       | **Per product, per component, per environment**                                  | —                                                        | None                                                         | Yes                                           | Same, under a production path                                                                |
| Secrets Manager                 | **Per product paths and policies**; one shared public CA bundle                  | Per environment                                          | $0.40/secret                                                 | Yes                                           | Same; rotation added                                                                         |
| CloudWatch Logs                 | **Per product log groups**, 7-day retention                                      | Per environment                                          | Usage, cents                                                 | Yes                                           | 30+ days, alarms                                                                             |
| VPC endpoints                   | **Shared** (4 interface + S3 gateway)                                            | Per environment                                          | **Hourly** $8.76 per interface endpoint per AZ; gateway free | Yes, one AZ                                   | Every AZ that runs tasks (§10)                                                               |
| NAT gateway                     | **Not used** (§3)                                                                | —                                                        | (would be $41.61 with its address)                           | —                                             | Only if a product needs internet egress or a fixed address                                   |
| RDS PostgreSQL                  | **Per product** (Work unit: Work + Identity)                                     | Per environment                                          | **Hourly** ~$16.61                                           | Yes: `db.t4g.micro`, Single-AZ                | Multi-AZ, larger class, 35-day backups                                                       |
| Redis / Valkey                  | **Per product, only where required** (Identity)                                  | Per environment                                          | **Hourly** $10.51 (Valkey `cache.t4g.micro`) or $0 sidecar   | Yes: one node, no replica                     | Managed, with a replica                                                                      |
| Cloud Map namespace             | Shared                                                                           | Per environment                                          | ~$0.50 hosted zone + $0.10 per registered instance           | Yes                                           | Same                                                                                         |

---

## 3. Network topology

**Decision (2026-10-06, resolves former open decision #3): Option B.** Identity and Work tasks
run in private subnets with no public IP and **no route to the internet**. They reach the four AWS
APIs they use through interface VPC endpoints in one AZ, and ECR image layers through the free S3
gateway endpoint. There is no NAT gateway. Network-specific cost: **$35.04 a month fixed**, plus
$0.01 per GB through the interface endpoints (cents at staging volume).

### 3.1 Outbound requirements, by product

| Product  | Internet egress needed at runtime                                                                   | Evidence                                                                            |
| -------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Identity | **None** — PostgreSQL and Redis only                                                                | Identity AWS readiness audit; `apps/api/src` makes no outbound call                 |
| Work     | **None**                                                                                            | Work AWS audit: no `fetch`/HTTP client in runtime code                              |
| Docs     | **Yes** — SMTP 587 (SES, ADR-0025), ClamAV signature downloads, OIDC federation discovery, webhooks | Docs `infra/terraform/eu-prod/core/network.tf` security-group egress; ADR-0024 §2.2 |
| School   | **Yes** — Resend email API, Firebase, WhatsApp bridge                                               | `munaxa-school/apps/api/src/communication/*`, `auth/services/firebase.service.ts`   |

All four need AWS APIs at task start and while running: ECR (`ecr.api`, `ecr.dkr`) and S3 for the
image layers, Secrets Manager for the injected secrets, and CloudWatch Logs for `awslogs`. Fargate
tasks do not need the `ecs`, `ecs-agent` or `ecs-telemetry` endpoints (AWS ECS developer guide,
"Amazon ECS interface VPC endpoints"). Neither application calls any other AWS API, and both task
roles are empty (§8).

### 3.2 Verified prices behind the decision

| Item                                        | `eu-central-1` price                               | Source                                                        |
| ------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------- |
| NAT gateway, hourly                         | $0.052/h → **$37.96/month**                        | `AmazonEC2` `EUC1-NatGateway-Hours`                           |
| NAT gateway, data processed                 | **$0.052/GB**, including traffic to AWS services   | `EUC1-NatGateway-Bytes`; AWS VPC pricing page                 |
| Interface VPC endpoint, per endpoint per AZ | $0.012/h → **$8.76/month**                         | `AmazonVPC` `EUC1-VpcEndpoint-Hours`; AWS PrivateLink pricing |
| Interface VPC endpoint, data processed      | **$0.01/GB** (first PB)                            | `EUC1-VpcEndpoint-Bytes`                                      |
| S3 gateway endpoint                         | **$0**, no hourly or processing charge             | AWS VPC pricing page                                          |
| Public IPv4 address (task, NAT, ALB alike)  | $0.005/h → **$3.65/month** per address             | `EUC1-PublicIPv4:InUseAddress`                                |
| Inter-AZ transfer                           | $0.01/GB in each direction                         | `EUC1-DataTransfer-Regional-Bytes`                            |
| ECR → Fargate, same Region                  | **$0/GB**                                          | AWS ECR pricing page                                          |
| CloudWatch Logs ingestion / storage         | $0.63/GB / $0.0324 per GB-month                    | `EUC1-DataProcessing-Bytes`, `EUC1-TimedStorage-ByteHrs`      |
| Secrets Manager                             | $0.40 per secret-month; $0.05 per 10,000 API calls | `AWSSecretsManager`                                           |

### 3.3 Cost of each option, Identity + Work (three service tasks)

|                                       | A. Private + NAT (1 AZ)             | **B. Private + endpoints (selected)** | C. Public tasks + public IPv4                 |
| ------------------------------------- | ----------------------------------- | ------------------------------------- | --------------------------------------------- |
| **Fixed, caused by this decision**    | $37.96 NAT + $3.65 address = $41.61 | 4 × $8.76 = **$35.04**                | 3 × $3.65 = $10.95 (+ cents per one-off task) |
| **Variable, caused by this decision** | $0.052/GB of logs, ECR API, secrets | $0.01/GB of logs, ECR API, secrets    | $0                                            |
| Image layers                          | $0 through the S3 gateway (add it)  | $0 through the S3 gateway             | $0 (ECR same-Region transfer is free)         |
| Per 10 GB of logs + API traffic       | $0.52                               | $0.10                                 | $0                                            |
| Scales with                           | traffic                             | number of endpoints × AZs             | number of running tasks                       |

**Not caused by this decision**, identical in every option: the ALB ($19.71 hourly + $7.30 for its
two public IPv4 addresses + LCU usage), Fargate compute, RDS, Valkey, CloudWatch Logs ingestion and
storage, Secrets Manager secrets and API calls, ECR storage, and inter-AZ traffic between tasks and
RDS or Valkey (both in one AZ).

Variable cost is immaterial at staging volume in every option: log ingestion itself costs 63× more
per GB than the endpoint processing it passes through. The choice is decided by the fixed cost and
by security: **B costs $24.09 a month ($289 a year) more than C, and $6.57 a month less than A**.

### 3.4 Security comparison

|                                      | A. Private + NAT                                    | **B. Private + endpoints**                                      | C. Public tasks                                                     |
| ------------------------------------ | --------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------- |
| Task public IP                       | No                                                  | **No**                                                          | Yes, one per task                                                   |
| Reachable from the internet          | No route in                                         | **No route in**                                                 | Only security groups stand in the way                               |
| Task security groups                 | in: from `alb`; out: data tier + 443 to `0.0.0.0/0` | **in: from `alb`; out: data tier, `endpoints`, S3 prefix list** | in: from `alb`; out: data tier + 443 to `0.0.0.0/0`                 |
| RDS and Valkey                       | Private (data subnets, no route out)                | **Private**                                                     | Private                                                             |
| ECR / Secrets Manager / Logs reached | Public endpoints through the NAT                    | **Private endpoint ENIs; layers via S3 gateway**                | Public endpoints through the internet gateway                       |
| Runtime internet egress              | Yes, HTTPS to anywhere                              | **None**                                                        | Yes, HTTPS to anywhere                                              |
| Difference from production (§10)     | Egress path production should not have              | **None in shape**; endpoints in one AZ instead of every AZ      | Public IPs and egress production should not have for these products |

Why the egress rows say "anywhere": the ECR API, CloudWatch Logs and Secrets Manager API endpoints
have no AWS-managed prefix list (only S3 and DynamoDB among the services used here have one; AWS VPC
user guide, "AWS-managed prefix lists"), so in A and C a task's security group must allow 443 to
`0.0.0.0/0` for the task to start.

What the $24.09 a month buys over C, concretely:

1. **No inbound path to a task, even after a mistake.** In C a single wrong security-group rule makes
   a task's public IP reachable. That bypasses the ALB, its TLS and its routing. It also defeats
   Identity's proxy trust: Identity trusts exactly one hop (`trust proxy` = 1), so a client
   connecting directly can choose the `X-Forwarded-For` value Identity uses as its address, and so
   evade the per-IP sign-in rate limit. In B the app subnets have no internet route; no security-group
   rule can create one.
2. **No outbound path for a compromised task.** Identity holds the token signing key and both
   applications hold database credentials. In A and C a compromised task can send them anywhere over
   HTTPS. In B it can reach only the four AWS APIs. Endpoint policies (§3.7) restrict those to this
   account, so the remaining path is closed too.
3. **Production parity.** The intended production network for Identity and Work is B (§10). Staging
   then exercises the real security groups, endpoint policies, DNS and failure modes before
   production, including an outbound call added to either codebase: it fails in staging rather than
   being discovered in a production review.

### 3.5 Accepted compromises

- **Endpoints in one AZ (AZ a).** Tasks in AZ b reach them across the AZ boundary. If AZ a fails,
  new tasks cannot start (no image pull, no secrets) and log delivery stops until it recovers; tasks
  already running keep serving through the ALB in AZ b. Accepted for staging. Production places the
  endpoints in every AZ that runs tasks.
- **No internet from inside the VPC.** No ECS Exec (it would need the `ssmmessages` endpoint,
  +$8.76), no ad-hoc outbound debugging, no pull from any registry but ECR. One-off tasks
  (migrations, provisioning) need none of these.
- **No fixed egress address.** Neither product needs one.
- **One task per service** (§5), so an endpoint or task outage is an outage; staging accepts that.

### 3.6 When Docs and School join this VPC

Option B stays the standard for Identity and Work. Docs and School need internet egress (§3.1),
which endpoints cannot provide. Each product decides its own egress when it joins; the reserved
`egress` subnet tier (§3.8) holds their internet-facing tasks, so Identity's and Work's subnets and
security groups never change.

| When                                                              | Egress for Docs/School                                         | Network cost, all four products                    |
| ----------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------- |
| Default (Docs' own production pattern, ADR-0024)                  | Public IPv4 per task in the `egress` subnets                   | $35.04 + $3.65 × their tasks (5 tasks: **$53.29**) |
| More than 11 such tasks, a fixed address, or private tasks wanted | One NAT gateway in AZ a, routed from the `egress` subnets only | $35.04 + $41.61 + $0.052/GB = **$76.65** + traffic |

**The interface endpoints stay when a NAT arrives.** Removing them would save $35.04 but would force
Identity and Work to reach ECR, Logs and Secrets Manager through the NAT. Because those services have
no prefix list, that means 443 to `0.0.0.0/0`, so Identity and Work would gain the internet egress this
decision removes. (This corrects an earlier draft of this document, which said a NAT could replace the
endpoints without widening Identity's or Work's reach.) With private DNS on the endpoints, Docs and
School tasks also use them for AWS APIs, which reduces their NAT traffic.

### 3.7 Endpoint policies and pull conditions

Endpoints without policies leave a path out: a compromised task could write to another account's
resources using that account's credentials. So:

- **S3 gateway endpoint policy:** `s3:GetObject` on `arn:aws:s3:::prod-eu-central-1-starport-layer-bucket/*`
  only (the ECR layer bucket, per the ECR user guide). When a product later needs its own buckets,
  they are added by name.
- **Interface endpoint policies (`ecr.api`, `ecr.dkr`, `logs`, `secretsmanager`):** allow only
  principals of this account (`aws:PrincipalAccount`) acting on resources of this account
  (`aws:ResourceAccount`).
- **Execution roles:** ECR pulls conditioned on `aws:sourceVpce` (the ECS developer guide's
  "Fargate tasks pulling Amazon ECR images over interface endpoints"), so a leaked execution-role
  credential cannot pull images from outside the VPC.

All of these are free.

### 3.8 Layout

| Tier                           | AZ a  | AZ b  | Route                                | Holds                                                        |
| ------------------------------ | ----- | ----- | ------------------------------------ | ------------------------------------------------------------ |
| Public                         | `/24` | `/24` | Internet gateway                     | ALB only                                                     |
| App                            | `/20` | `/20` | Local + S3 gateway only              | Identity and Work tasks, one-off tasks, endpoint ENIs (AZ a) |
| Data                           | `/24` | `/24` | Local only                           | RDS, ElastiCache                                             |
| Egress (reserved, empty today) | `/22` | `/22` | Decided when Docs/School join (§3.6) | Docs/School internet-facing tasks                            |

CIDR: **not** `10.120.0.0/16` (Docs Non-Production) or `10.121.0.0/16` (Docs production). Proposed
`10.130.0.0/16`, leaving room for peering if it is ever needed. Public IP auto-assignment off
everywhere; ECS services set `assignPublicIp: DISABLED`. The default VPC and default security group
are used by nothing. Subnets and route tables cost nothing, so the reserved tier is free.

Security groups, one per tier per deployable, referencing each other (pattern from Docs core network):

| Group                 | Inbound                                                      | Outbound                                                                                     |
| --------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `alb`                 | 443, 80 from the internet                                    | to each target's port                                                                        |
| `identity-api`        | 4001 from `alb`                                              | 5432 to `rds-work-unit`, 6379 to `identity-cache`, 443 to `endpoints` and the S3 prefix list |
| `work-api`            | 3000 from `work-admin` (and `alb` if `/api/v1/*` is public)  | 5432 to `rds-work-unit`, 443 to `endpoints` and the S3 prefix list                           |
| `work-admin`          | 3001 from `alb`                                              | 3000 to `work-api`, 443 to `endpoints` and the S3 prefix list                                |
| `ops` (one-off tasks) | none                                                         | 5432 to `rds-work-unit`, 443 to `endpoints` and the S3 prefix list                           |
| `rds-work-unit`       | 5432 from `identity-api`, `work-api`, `ops`                  | none                                                                                         |
| `identity-cache`      | 6379 from `identity-api`                                     | none                                                                                         |
| `endpoints`           | 443 from the app-tier groups (later: the egress-tier groups) | none                                                                                         |

No group anywhere has an egress rule to `0.0.0.0/0`. DNS to the VPC resolver is not filtered by
security groups and needs no rule. Without a NAT, the Work admin cannot reach the API through the
public ALB; it calls it over Cloud Map (§5), which is also what Work's `WORK_API_URL` expects.

### 3.9 Shared and isolated, in the network

- **Shared by every product in the environment:** the VPC, its subnet tiers and route tables, the
  internet gateway, the interface endpoints and S3 gateway endpoint, the ALB and its HTTPS listener,
  the wildcard certificate, the Cloud Map namespace, and (if ever added) the NAT gateway.
- **Isolated per product or deployable:** security groups, target groups and listener-rule priority
  blocks (§4), ECS services and their task ENIs, execution and task roles, endpoint access (each
  execution role reads only its own secret and repository), RDS instances with their databases, roles
  and security groups, the Valkey node, secrets, log groups and ECR repositories. A product's tasks
  can reach another product's data tier only if that product's security group names them; none does.

### 3.10 Rejected options

- **A — private tasks + NAT gateway ($41.61 + $0.052/GB).** It costs more than B and gives Identity
  and Work an HTTPS egress path to anywhere that they do not use. It becomes useful only when a
  product needs internet egress (§3.6), and then only for that product's subnets.
- **C — public-subnet tasks with public IPv4 ($10.95, Docs production's ADR-0024 pattern).** It is
  $24.09 a month cheaper. It is acceptable for Docs, which needs egress anyway and controls exposure
  with "inbound only from the ALB" security groups. It is rejected for Identity and Work because it
  makes security groups the only barrier to direct exposure, which defeats the one-hop proxy trust,
  and it opens HTTPS egress to anywhere from the service that holds the signing key, to save $24 a
  month. The owner's constraints (private subnets kept even at minimal capacity; security not
  sacrificed merely for cost) rule it out.
- **B with endpoints in both AZs ($70.08).** Redundancy staging does not need (§3.5).
- **IPv6-only tasks with an egress-only internet gateway.** Not evaluated in detail. It gives
  internet egress like A and C, ECR's interface endpoints do not serve IPv6-only tasks (AWS ECS
  developer guide), and support for every dependency over IPv6 was not verified.

---

## 4. DNS, certificates, ALB and routing

**Decision (2026-10-06, resolves former open decision #6): non-production uses its own registrable
domain, `munaxa-nonprod.com`. Production stays on `munaxa.com`.** Every product keeps one hostname
per environment, and the Work unit stays one origin split by path:

| Product   | Non-production                      | Production (ADR-0002 binding decision 15) |
| --------- | ----------------------------------- | ----------------------------------------- |
| Work unit | `https://work.munaxa-nonprod.com`   | `https://work.munaxa.com`                 |
| Docs      | `https://docs.munaxa-nonprod.com`   | `https://docs.munaxa.com`                 |
| School    | `https://school.munaxa-nonprod.com` | `https://school.munaxa.com`               |

`munaxa-nonprod.com` returned NXDOMAIN at the `.com` registry on 2026-10-06, so it appears
unregistered. The exact name is the owner's to confirm at purchase. It matches the account name
(§8), and any unrelated name works the same way, provided it is not a subdomain of `munaxa.com`.

### 4.1 Evidence

- **`munaxa.com` is hosted on Cloudflare DNS** (`rick.ns.cloudflare.com`, `bristol.ns.cloudflare.com`;
  public DNS, 2026-10-06), not Route 53.
- Production siblings already exist on it:
  - `munaxa.com`, `www.munaxa.com`, `app.munaxa.com` and `admin.munaxa.com` are Cloudflare-proxied
    (`app.`/`admin.` are School, ADR-0002 R2);
  - `docs.munaxa.com` is a DNS-only CNAME to the Docs production ALB in `eu-central-1`;
  - `work.munaxa.com` and `nonprod.munaxa.com` do not exist.
- **Identity cookies** (`apps/api/src/auth/cookies.ts`):
  - `__Host-mx_session`: `Path=/`, no `Domain`.
  - `__Secure-mx_refresh`: `Path=/api/auth/refresh`, no `Domain`. It is `__Secure-` and not `__Host-`
    because Platform's `__Host-mx_refresh` with a narrow path is dropped by browsers (measured in
    Chromium), and `Path=/` was rejected so the refresh token never reaches Work's routes.
  - The serializer cannot emit `Domain`.
- **Refresh and logout** read the cookie through `cookie-parser`/`cookie@0.7.2`, which keeps the
  **first** of several cookies with the same name (verified:
  `parse('__Secure-mx_refresh=PLANTED; __Secure-mx_refresh=REAL')` → `PLANTED`).
- **CSRF:** Identity's edge rejects state-changing requests whose `Origin` (or `Referer`) is not in
  `CSRF_TRUSTED_ORIGINS`. This is an **exact string match** (`@munaxa/security` `isTrustedOrigin`),
  and a missing `Origin` is refused. Identity ADR-0004 and the edge middleware rely on it for the
  same-site case `SameSite=Lax` leaves open.
- **Work** reads only `__Host-mx_session`, on the admin server, and forwards it as a bearer token;
  the Work API authenticates by `Authorization` header, not by cookie. Work also defines an
  unprefixed `munaxa_work_tenant` selection cookie, which nothing sets yet (`platform-session.ts`).
- ADR-0002 binding decisions 14–15: host-only cookies are mandatory; product hostnames are
  `docs.`/`work.`/`school.munaxa.com`; one `munaxa.com` zone. No repository records a
  non-production domain convention.

### 4.2 What a host on the same registrable domain can do

Here a "sibling" is any host under the same registrable domain as `work.<domain>`. Under the old plan
that includes every `*.nonprod.munaxa.com` host, as well as `www.`, `app.`, `admin.` and `docs.munaxa.com`.

| A sibling attacker who controls `evil.munaxa.com` (HTTPS) …                                                        | Host-only cookie (no prefix)                                         | `__Secure-` cookie, no `Domain` (`__Secure-mx_refresh`)           | `__Host-` cookie (`__Host-mx_session`)                      | Cookie with `Domain=munaxa.com`                           |
| ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------- |
| **Read** it                                                                                                        | No                                                                   | No                                                                | No                                                          | **Yes**, it is sent to every subdomain (Munaxa sets none) |
| **Set** a same-named cookie that `work.munaxa.com` receives (via `Domain=munaxa.com`)                              | **Yes**                                                              | **Yes** (any `Secure` cookie set from HTTPS may carry the prefix) | **No**: the browser rejects `__Host-` with a `Domain`       | Yes                                                       |
| **Overwrite** the victim's own cookie                                                                              | No (a different cookie key), but it can **shadow** it: both are sent | No, but it can **shadow** it                                      | No                                                          | Yes                                                       |
| **Order** its copy first                                                                                           | Yes: same `Path`, created earlier; or a longer matching `Path`       | Yes, with `Path=/api/auth/refresh` set before the victim's cookie | —                                                           | —                                                         |
| **Evict** it by filling the browser's per-site cookie limit, or a "cookie bomb" that makes every request too large | **Yes**                                                              | **Yes**                                                           | **Yes**: prefixes do not stop eviction or oversized headers | Yes                                                       |
| **Make the browser send it** to `work.munaxa.com` (forms, `fetch` with credentials)                                | **Yes**: same-site, so `Lax` and `Strict` cookies are attached       | **Yes**                                                           | **Yes**                                                     | Yes                                                       |
| **Read the response** of such a request                                                                            | No (no CORS; `Cross-Origin-Resource-Policy: same-origin`)            | No                                                                | No                                                          | No                                                        |

Under a separate registrable domain, `evil.munaxa-nonprod.com` cannot set any cookie for
`munaxa.com`. Its requests to `work.munaxa.com` are **cross-site**: `Lax` cookies are withheld
from cross-site POSTs and subresources. Its cookies count against a different site's limit. All
of the "Yes" rows above become "No".

**The concrete Identity exposure** (today, under any shared registrable domain): a sibling plants
`__Secure-mx_refresh=<the attacker's own valid refresh token>; Domain=munaxa.com;
Path=/api/auth/refresh` before the victim signs in. Then:

1. The browser orders that copy first, and `cookie-parser` keeps the first.
2. The victim's next refresh rotates the **attacker's** lineage.
3. The victim's browser receives a `__Host-mx_session` for the attacker's account.
4. Work then files whatever the victim enters under the attacker's account.

This is a login-CSRF and session-swap. The `Origin` check does not stop it, because the refresh
request comes from Work's own page on the correct origin. A planted garbage value instead silently
breaks renewal, a denial of service.

### 4.3 Options compared

|                                      | A. `work.nonprod.munaxa.com` + `work.munaxa.com`                                                  | **B. Separate non-production domain (selected)**                            | C. A + `__Host-mx_refresh`                                                                                             | D. Other strategies found |
| ------------------------------------ | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| Cookie scoping across environments   | Shared site: non-production can set cookies production receives                                   | **Separate sites: none**                                                    | Refresh tossing closed; other tossing (`munaxa_work_tenant`, future product cookies), eviction and cookie bombs remain | see below                 |
| `__Host-` behaviour                  | Protects the session cookie only                                                                  | Same, plus a site boundary                                                  | Protects session and refresh                                                                                           | —                         |
| `__Secure-` behaviour                | Refresh cookie can be shadowed from non-production                                                | Cannot be shadowed from non-production                                      | Not used for refresh                                                                                                   | —                         |
| `Domain` attribute                   | Any non-production host may set `Domain=munaxa.com`                                               | Impossible across environments                                              | As A                                                                                                                   | —                         |
| SameSite                             | Non-production → production is **same-site**; `Lax`/`Strict` do not separate them                 | **Cross-site**; `Lax` applies                                               | As A                                                                                                                   | —                         |
| CSRF trusted origins                 | Only the exact-origin allow-list separates environments                                           | Allow-list and SameSite                                                     | As A                                                                                                                   | —                         |
| Identity/Work same origin (ADR-0004) | Kept                                                                                              | **Kept**: one origin per environment                                        | Kept, but the refresh token travels to every Work route (`Path=/`)                                                     | —                         |
| Federation / MFA later               | A non-production host may use `munaxa.com` as a WebAuthn RP ID and can claim same-site trust      | **Separated**: separate RP ID, separate IdP registrations and redirect URIs | As A                                                                                                                   | —                         |
| Password managers                    | Match on the site and offer **production** credentials on non-production pages                    | **Do not**                                                                  | As A                                                                                                                   | —                         |
| ACM                                  | `*.nonprod.munaxa.com`, validated through a Cloudflare delegation                                 | `*.munaxa-nonprod.com`, validated in the account's own zone                 | As A                                                                                                                   | —                         |
| Route 53 / delegation                | NS records for `nonprod` in **Cloudflare**; non-production depends on the production DNS provider | **None**: the zone is the domain's own, in `munaxa-nonprod`                 | As A                                                                                                                   | —                         |
| Branding / UX                        | On-brand                                                                                          | Non-production only; testers see a clearly different domain                 | On-brand                                                                                                               | —                         |
| Operational complexity               | A delegation in Cloudflare                                                                        | One registration to renew (auto-renew)                                      | An Identity and Platform change                                                                                        | —                         |
| Cost                                 | $0.50/month zone                                                                                  | $0.50/month zone + **$16/year** domain                                      | As A                                                                                                                   | —                         |
| Environment isolation                | Weak: production trusts nothing from non-production only because of Identity's exact allow-list   | **Strong at the browser level**                                             | Partial                                                                                                                | —                         |
| Docs and School later                | Each product's cookies inherit the problem                                                        | Each product gets `<product>.munaxa-nonprod.com` with no extra work         | Each product must adopt `__Host-` everywhere                                                                           | —                         |

**D, investigated and rejected:**

- **Listing `nonprod.munaxa.com` on the Public Suffix List** would make it its own site, but listing
  is slow, effectively permanent and meant for domains that host third parties.
- **Using the ALB's `*.elb.amazonaws.com` hostname** gets no publicly trusted certificate, so the
  `Secure` and `__Host-` cookies would not work.
- **A sub-zone on Cloudflare** is A with another provider.
- No repository or ADR proposes anything else.

**Why B and not C.** C closes one attack, refresh-cookie shadowing. It leaves non-production
same-site with production, so:

- tossing of every other cookie, eviction and cookie bombs still work;
- SameSite never separates the environments;
- password managers still cross them;
- a future WebAuthn RP ID could be shared.

It also costs a principle Identity chose deliberately: the refresh token stays off Work's routes.
B removes the whole class of attacks across environments for $16 a year, needs no code change, and
keeps ADR-0004 intact. **C is still needed for production, for a different reason (§4.4).**

### 4.4 Identity implications

**Nothing in Identity changes for this decision.** Identity takes its origin from configuration,
per environment:

- non-production: `IDENTITY_BASE_URL=https://work.munaxa-nonprod.com/api/auth` and
  `CSRF_TRUSTED_ORIGINS=https://work.munaxa-nonprod.com`;
- production: the `work.munaxa.com` equivalents;
- `IDENTITY_AUTH_AUDIENCE` is set per environment.

A non-production origin must never appear in a production allow-list. Different issuers and
different signing keys mean a non-production token is never accepted by production Work.

**Still required before production — a separate Identity decision, recorded in §12 #12.** In
production, `work.munaxa.com` will share the `munaxa.com` site with `www.`, `app.`, `admin.` (School)
and `docs.munaxa.com`. Those are different products, providers and teams, and any of them can mount
the §4.2 refresh-cookie attack. Ways to close it:

| Option                                                                                                                                                                                                             | Works with `/api/auth/refresh`, rotation, logout, Work, the one origin? | Cost                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`__Host-mx_refresh` with `Path=/`**                                                                                                                                                                              | **Yes.**                                                                | The long-lived refresh token is attached to **every** request to the origin: Work admin page loads, `/api/v1/*`, every Identity route. That reverses the reason it is path-scoped (`cookies.ts`), puts a credential in Work's request stream, contrary to ADR-0001's intent, and needs Platform's builder bypassed or fixed |
| Keep `__Secure-mx_refresh` (narrow path); refuse a refresh or logout whose `Cookie` header carries the name **more than once**, and require the request's `__Host-mx_session` subject to match the refresh lineage | Yes. Rotation and logout are unchanged for a single, honest cookie      | Identity code and tests; the session cookie's lifetime must cover the refresh window, to be checked                                                                                                                                                                                                                         |
| Fix Platform's `refreshCookie` defect (`@munaxa/auth`)                                                                                                                                                             | Depends on Platform's fix                                               | Platform is frozen; the defect is already reported by Identity                                                                                                                                                                                                                                                              |

The checks for the first option:

- `__Host-` with `Path=/` is accepted by all current browsers.
- Refresh, rotation (re-set with the same attributes) and logout (`clearCookie(name, '/')`) work
  unchanged.
- Work reads only `__Host-mx_session`, so it is not affected functionally.
- Existing `__Secure-mx_refresh` cookies are orphaned on the switch, so users sign in once more
  unless Identity reads both names for one release.

**Technically possible, but not obviously the best of the three.** It is an Identity security
decision for an Identity ADR in this repository (`docs/adr/`, next to ADR-0004), before Work
production. Nothing changes here.

**Work, before production (§12 #12):** give `munaxa_work_tenant` the `__Host-` prefix (`Path=/`
suits it) so a sibling cannot toss a tenant selection. Work's admin must keep relying on
same-origin checks (Next.js server actions check `Origin` against `Host`) for any state-changing
action it adds.

### 4.5 Zones, delegation and certificates

| Environment    | Domain and zone                                                                                                                                                         | Delegation                                                                                                 | Certificate (ACM, `eu-central-1`, DNS-validated, free)                                                            |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Non-production | `munaxa-nonprod.com`, **registered and hosted in Route 53 in `munaxa-nonprod`** (one public hosted zone at the apex). Product names are alias records to the shared ALB | **None**: the registrar points at the zone's own name servers. No dependency on `munaxa.com` or Cloudflare | **One wildcard**, `*.munaxa-nonprod.com`, in `munaxa-nonprod`, covering every product                             |
| Production     | `munaxa.com`, **stays on Cloudflare**. Each product adds its own record, DNS-only (grey cloud), CNAME to its ALB, as `docs.munaxa.com` already does                     | None needed                                                                                                | **One per product hostname** (`work.munaxa.com`, …) in the production account, validated by a CNAME in Cloudflare |

Rules that follow:

- **Product records are DNS-only, never Cloudflare-proxied.** A proxy adds a second hop. Identity
  trusts exactly one (`trust proxy` = 1), so behind Cloudflare every client would appear as a
  Cloudflare edge address, and the per-IP sign-in rate limit would collapse.
- **No wildcard for production.** `*.munaxa.com` would also cover `www.`, `app.`, `admin.` and any
  future host. Per-hostname certificates keep each product's certificate its own and movable to
  another ALB or account. Non-production uses one wildcard because one account owns the whole
  domain.
- **Per-tenant subdomains** (deferred by ADR-0002, e.g. `acme.docs.…`) would need
  `*.docs.<domain>`, a separate certificate, when they arrive.
- The non-production domain is registered through Route 53 Domains in `munaxa-nonprod`. The
  Route 53 Domains API is served from `us-east-1`, so the region-lock SCP (§8.5) must exempt
  `route53domains`. Auto-renew on; registrant contact privacy on.
- A CAA record restricting issuance to Amazon on `munaxa-nonprod.com` is free and recommended.
  `munaxa.com` has none today; that is a production DNS-owner decision.

### 4.6 Cost

| Item                              | Charge                                                                                                                                     | Change against the previous plan                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| `munaxa-nonprod.com` registration | **$16 a year** (Route 53 `.com` since 2026-07-01; secondary source citing AWS's domain-pricing PDF, so re-check at purchase) ≈ $1.33/month | **New**                                                  |
| Hosted zone `munaxa-nonprod.com`  | $0.50/month                                                                                                                                | None: replaces the planned `nonprod.munaxa.com` sub-zone |
| DNS queries                       | Alias queries to an ALB are free; others $0.40 per million                                                                                 | Negligible                                               |
| ACM public certificates           | $0                                                                                                                                         | None                                                     |
| Production DNS                    | Cloudflare, as today                                                                                                                       | None                                                     |

**Net new recurring cost: about $16 a year.** No other recurring AWS cost.

### 4.7 Standard for every product

- **Hostnames:** `<product>.munaxa-nonprod.com` in non-production and `<product>.munaxa.com` in
  production. One origin per product per environment. Paths split services inside a product.
  Products never share an origin.
- **Cookies:**
  - host-only, always;
  - `__Host-` for every authentication or authority-bearing cookie whose path can be `/`;
  - never `Domain=` (ADR-0002 binding decision 14);
  - `SameSite=Lax` or stricter.
- **CSRF:** an exact-origin allow-list per environment. A non-production origin is never in a
  production list, and the reverse holds too.
- **Records:** alias (non-production) or DNS-only CNAME (production) to the environment's ALB,
  never proxied.
- **Certificates:** the non-production wildcard covers new products automatically; production gets
  one certificate per new hostname.
- **Adding Docs or School** to non-production is one alias record and one listener-rule block (§4.8).
  No zone, certificate or DNS design of its own.
- **School** moves from `app.`/`admin.munaxa.com` to `school.munaxa.com` (ADR-0002 R2, §12 #9).
- **School's default sender** `no-reply@munaxa.app` names a domain that returned NXDOMAIN on
  2026-10-06, which is a School item. Non-production mail, when a product sends any, comes from
  `munaxa-nonprod.com`, so it never affects `munaxa.com`'s SPF, DKIM, DMARC or reputation.

### 4.8 ALB routing

**One ALB for the environment; one hostname per product; paths only within a product.**

- **Hostnames per product** because cookies are host-only and must stay that way (ADR-0002 binding
  decision 14; Identity ADR-0004). Products never share an origin.
- **Paths within a product** because Identity's session cookie is `__Host-` and must be set on the
  origin Work's admin reads (Identity ADR-0004): the Work unit is one origin split by path.

| Priority | Host                        | Path                                                                                                      | Target group                                                                        |
| -------- | --------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| 100      | `work.munaxa-nonprod.com`   | `/api/auth/*`                                                                                             | `identity-api` (4001), health `/api/auth/health/ready`                              |
| 110      | `work.munaxa-nonprod.com`   | `/api/v1/*`                                                                                               | `work-api` (3000), health `/health/ready` — **optional**: no browser calls it today |
| 190      | `work.munaxa-nonprod.com`   | `/*`                                                                                                      | `work-admin` (3001), health `/`                                                     |
| 200–299  | `docs.munaxa-nonprod.com`   | Docs ADR-0024 §2.3: `/api/v1/preview/stream*` → docs-api, `/*` → docs-web                                 | extension point                                                                     |
| 300–399  | `school.munaxa-nonprod.com` | e.g. `/api/*` → school-api, `/*` → school-admin (same origin also removes School's CORS ordering problem) | extension point                                                                     |
| default  | —                           | —                                                                                                         | fixed 404                                                                           |

Each product owns a block of 100 rule priorities. Port 80 redirects to 443. The TLS policy is a
current AWS-recommended policy. Identity trusts exactly one proxy hop, which this ALB is. An
unknown `Host` gets the fixed 404, so the ALB answers only for the environment's own names.

### 4.9 ADR

The non-production domain applies to every product, and it adds to ADR-0002's production hostname
decision without changing it. It belongs in the **ecosystem ADR in `munaxa/munaxa`** already needed
for decisions #1 and #2 (§8.9), so one ADR can cover registry, accounts and domains. The Identity
refresh-cookie hardening (§4.4) is an **Identity ADR** in this repository. Neither is created here.

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

## 8. Accounts, secrets and IAM model

**Decision (2026-10-06, resolves former open decision #2): one dedicated non-production member
account, `munaxa-nonprod`, holds the whole shared non-production environment of §1 for every
product.** Workloads are not added to the Organizations management account. Production for
Identity and Work goes into a separate production member account, created when the first production
resource for them is built, never into the management account or `munaxa-nonprod`. No account per
product: ADR-0002 binding decision 10 lists "provider accounts" among the infrastructure products
share, and per-product isolation stays inside the account (§2, §3.9, §8.5).

### 8.1 Evidence

- Docs Production and Docs Non-Production both live in account `800728620253`, **the Organizations
  management account** (Docs `infra/terraform/README.md`). Applied there so far: the production
  bootstrap, `eu-prod/core` IAM roles, the production VPC and `eu-prod/data` (RDS, KMS, S3, Backup);
  `eu-prod/service` is not applied and Docs production is NOT READY. Docs Non-Production was created
  outside Terraform.
- That README records the consequence: _"The account is the AWS Organizations management account, so
  service control policies do not apply to it. Isolation is enforced entirely in IAM"_. It also
  records that _"Both administrator users keep AdministratorAccess and can bypass all of this."_
- AWS: _"SCPs don't affect users or roles in the management account"_, and _"Avoid deploying
  workloads to the organization's management account … SCPs do not apply to the management account"_
  (Organizations user guide, SCPs; best practices for the management account).
- Docs ADR-0022 requires that _"the AWS region and account structure are decided before any resource
  is provisioned"_. Docs ADR-0024 lists _"A separate production AWS account and its administrators"_
  as still open. The ecosystem ADRs set no account convention beyond decision 10.

### 8.2 Options compared

|                           | A. Keep non-production in the management account                                                         | **B. Dedicated non-production member account (selected)**                                       |
| ------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| AWS charges               | Baseline                                                                                                 | **Same**: Organizations and accounts are free (§8.3)                                            |
| Account-level isolation   | None. Non-production shares an account with Docs production and the organization's own controls          | **Full.** Separate IAM, quotas, Secrets Manager, KMS, CloudTrail, VPCs                          |
| Production safety         | IAM deny lists by name and tag only; any administrator bypasses them; SCPs cannot apply                  | **No principal in it holds any permission in production**; SCPs apply to it                     |
| IAM complexity            | Every non-production role needs the Docs-style deny lists so it cannot touch production, and the reverse | Roles need only product scoping; the environment boundary is the account                        |
| GitHub OIDC / ECR         | One OIDC provider; every trust policy must also keep environments apart                                  | One provider per account; a non-production token has nowhere in production to land (§8.4)       |
| Secrets Manager           | Production and non-production secrets in one namespace, separated by path and IAM                        | Separate by account; no cross-account policies                                                  |
| Route 53 / ACM            | Works                                                                                                    | Works; the non-production domain and zone live entirely in the account (§4, §8.6)               |
| VPC / networking          | The shared VPC beside two Docs VPCs; the Docs deployer's deny list must keep covering it                 | The shared VPC alone; `10.130.0.0/16` stays clear of Docs' ranges for any future peering        |
| CloudWatch                | Logs and alarms of both environments in one account                                                      | Per account; cross-account viewing optional and not needed now                                  |
| Cross-account complexity  | None                                                                                                     | One deliberate path, production reading images (§8.4); everything else is inside one account    |
| Billing / accountability  | Needs cost-allocation tags, which are not retroactive                                                    | **Per-account cost in Cost Explorer from day one**, with or without tags; a budget per account  |
| Future products           | Each adds more deny-list maintenance in a privileged account                                             | Each adds roles and services inside `munaxa-nonprod`; no new account                            |
| Future production         | Production in the management account forever, or a migration later                                       | Production account created once, for all products, when needed                                  |
| Operations, small company | One sign-in                                                                                              | One more account to sign in to (IAM Identity Center or the organization access role, both free) |

**Rejected: A.** It costs the same AWS bill and gives a weaker boundary. Every non-production
deploy, run several times a day from CI, would execute in the account that also holds production
Docs data and the organization's billing and policy powers, protected only by deny lists that any
administrator bypasses. AWS's own guidance is to keep workloads out of that account.

**Also rejected:**

- **An account per product (or per product and environment).** Eight or more accounts, and the
  shared VPC and ALB would need AWS RAM subnet sharing and cross-account target registration. It
  contradicts ADR-0002 decision 10 and buys nothing that per-product IAM, security groups and
  databases (§3.9) do not already give.
- **Non-production stays in the management account and production moves out.** It protects
  production equally well. But it leaves the most-changed, least-reviewed workload in the one
  account no SCP can constrain, and it still requires a production account. It is B without B's
  benefit to the management account.

### 8.3 Cost implications

| Item                                                 | Charge                                                                 | Caused by B?                    |
| ---------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------- |
| AWS Organizations, creating the member account       | **$0** (_"offered at no additional charge"_, Organizations user guide) | —                               |
| IAM roles, OIDC provider, SCPs, IAM Identity Center  | $0                                                                     | —                               |
| CloudTrail, first copy of management events to S3    | $0 (AWS CloudTrail pricing); S3 storage cents                          | Only the storage, cents         |
| Terraform state bucket                               | S3 cents; SSE-S3 free (a customer-managed KMS key would add $1/month)  | Cents                           |
| VPC, ALB, endpoints, ECS, RDS, Valkey, secrets, zone | §9                                                                     | **No**: built once either way   |
| Shared ECR images, later copied to production        | $0.10 per GB-month in the production account                           | Cents, and only with production |

**Net additional AWS cost of B: about $0 a month.** The non-production environment does not exist
yet, so nothing is duplicated. What B adds is organizational: one account to create and secure, its
root user, and one more sign-in. Consolidated billing still produces one bill, paid by the
management account.

### 8.4 IAM, GitHub OIDC and ECR in `munaxa-nonprod`

The account boundary separates environments. IAM inside the account separates products.

| Element                                     | In `munaxa-nonprod`                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GitHub OIDC provider                        | One, `token.actions.githubusercontent.com`, audience `sts.amazonaws.com`. It trusts no repository by itself; each role's trust policy does                                                                                                                                                                                                                                            |
| GitHub environment                          | `aws-nonprod` in each product repository. Its variables (`AWS_REGION`, `AWS_ROLE_ARN`, `ECR_REPOSITORY`) name roles and repositories in `munaxa-nonprod` only                                                                                                                                                                                                                         |
| Trust policy, every GitHub role             | `StringEquals` on `aud` = `sts.amazonaws.com` **and** `sub` = `repo:munaxa/munaxa-<product>:environment:aws-nonprod`. Exact match, no wildcard, one repository per role                                                                                                                                                                                                               |
| `munaxa-<product>-nonprod-github-publisher` | Push to `repository/munaxa-<product>-*` only                                                                                                                                                                                                                                                                                                                                          |
| `munaxa-<product>-nonprod-github-deployer`  | Register task definitions; update **that product's** services (`service/munaxa-shared-nonprod/munaxa-<product>-nonprod-*`); run its one-off tasks; `iam:PassRole` **only** for roles under `/munaxa-<product>/nonprod/`. Task-definition registration is not resource-scoped in ECS, so PassRole is the boundary: a product cannot start anything that runs as another product's role |
| ECR repositories                            | `munaxa-<product>-<component>` in `munaxa-nonprod`, the source of every image. Immutable tags, digests                                                                                                                                                                                                                                                                                |
| ECS execution roles                         | Per component: pull its own repositories (conditioned on `aws:sourceVpce`, §3.7), read `munaxa-<product>-nonprod/<consumer>` only, write its own log group                                                                                                                                                                                                                            |
| ECS task roles                              | Per component; Identity and Work: no permissions                                                                                                                                                                                                                                                                                                                                      |
| Shared infrastructure                       | `munaxa-shared-nonprod-infra`, the only role that changes the VPC, ALB and listener rules, endpoints, cluster and namespace. Used by whoever applies the shared stack (§12 #1 decides where it lives); no product role holds these permissions                                                                                                                                        |
| Permissions boundary                        | Every role under a product path carries `munaxa-<product>-nonprod-boundary` (Docs pattern), so a mistaken broad allow still cannot reach another product's paths                                                                                                                                                                                                                      |

So Work's deployer cannot change Identity's service, pass Identity's roles, read Identity's
secrets or push to Identity's repositories, and the reverse holds too. That remains true when Docs and School join.

**Production (future).** The production account has its own OIDC provider and its own roles. They
trust only `sub` = `repo:munaxa/munaxa-<product>:environment:aws-eu-prod`. The production ECR
repositories have the same names. **Promotion copies the same digest**: a job in the `aws-eu-prod`
environment pulls by digest from `munaxa-nonprod` and pushes to the production repository. The
manifest is unchanged (single-platform, no provenance attestation, §6), so the digest is identical.
The only cross-account permission is a repository policy in `munaxa-nonprod` that lets the
production account pull. Non-production never gets any permission in production. Production does
not run images from `munaxa-nonprod` directly, so production never depends on the non-production
account's availability or its administrators.

**Identity's existing artifacts.** `ecr-image.md` already takes the role ARN, region and repository
from GitHub environment variables, so the account choice changes no code or workflow. The role, the
repository and the OIDC provider are created in `munaxa-nonprod`, under the names already flagged
for alignment (§11, §12 #10).

### 8.5 Production separation strategy

An accidental non-production deployment cannot modify production, because every layer would have to
fail at once:

1. **Account boundary.** Non-production credentials are minted by `munaxa-nonprod`'s STS for
   `munaxa-nonprod`'s roles. No production role trusts `munaxa-nonprod`, and none trusts the
   `aws-nonprod` subject. There is no path for a non-production token to become a production one.
2. **OIDC subject pinning.** Every role names one repository and one GitHub environment exactly.
   A workflow run in `aws-nonprod` receives a token whose `sub` no production role accepts, even if
   someone pastes a production role ARN into it.
3. **GitHub environment protection.** `aws-eu-prod` requires reviewers and allows only protected
   tags or `main`. `aws-nonprod` allows only the designated branches and tags. Variables are per
   environment, so a non-production job is never even given a production ARN.
4. **Infrastructure code pins the account.** Each Terraform root (or equivalent) declares its one
   allowed account ID, as Docs' bootstrap does today (_"The provider refuses to run against any
   other"_), so a misconfigured profile fails before planning.
5. **SCPs on member accounts (free).** On the non-production account now:
   - only `eu-central-1`, apart from global services;
   - no IAM users or access keys (OIDC and roles only);
   - no `LeaveOrganization` or `CloseAccount`;
   - no stopping or deleting CloudTrail;
   - cost guardrails such as no NAT gateways (§3), no EC2 instances, and RDS and ElastiCache
     classes limited to the micro and small families.

   On the production account later: the same, without the cost caps. SCPs need the organization to
   have **all features** enabled. Verify that before relying on them.

6. **Names and tags are kept.** `nonprod` and `Environment=NonProduction` stay on every resource.
   That is defence in depth, and the Docs production deployer's deny lists keep working while Docs
   is still in the management account.
7. **The management account holds no new workloads.** Human access to member accounts goes through
   IAM Identity Center or the `OrganizationAccountAccessRole` that Organizations creates. That role
   has administrator rights and trusts the management account, so only the management account's
   administrators may assume it.

### 8.6 Route 53 and ACM in the account structure

DNS is decided in §4. For the accounts:

- The non-production domain `munaxa-nonprod.com` is registered, and its only hosted zone kept, **in
  `munaxa-nonprod`**, with the wildcard certificate. Non-production DNS has no delegation from, and
  no dependency on, `munaxa.com`, Cloudflare or any other account. A non-production pipeline holds
  no credential that can change production DNS.
- Production records stay in the `munaxa.com` zone on Cloudflare. Production certificates live in
  the production account, validated by CNAMEs added there. `munaxa-nonprod` has no access to
  Cloudflare at all.

### 8.7 Existing Docs Non-Production

Nothing moves now. Docs' resources stay where they are until Docs joins this environment, and that
is a Docs owner decision (§12 #8).

- **Resources cannot be moved between accounts.** Docs Non-Production is recreated in
  `munaxa-nonprod`, inside the shared VPC and ALB, and the old VPC, NAT gateway, RDS instance and
  ECS cluster in the management account are deleted afterwards. That ends its ~$100 a month (§9).
  It was built outside Terraform, so recreating it as code is also an improvement.
- **Test data**, if it is worth keeping: an RDS snapshot encrypted with the account's _default_ KMS
  key cannot be shared with another account (RDS user guide, "Sharing encrypted snapshots"). Copy it
  with a customer-managed key shared with `munaxa-nonprod` first, then copy it again in the target.
  Otherwise start empty.
- **The Docs production deployer's deny lists** for `*nonprod*` and the Non-Production VPC ID stay
  harmless after the move; Docs removes them at its convenience.
- **Docs production** remains in the management account. Moving it to the production account
  (Docs ADR-0024 open item 2) is a Docs decision, outside this one. It is cheapest before go-live,
  while it holds no customer data: today only bootstrap, IAM, the VPC and the data stack are applied, and the service is not.

### 8.8 Future account structure

```text
AWS Organization (all features enabled; SCPs)
│
├── Management account 800728620253 — Organizations, billing, IAM Identity Center, org CloudTrail
│     today also: Docs production and Docs Non-Production (Docs' own decisions, §8.7)
│
├── OU NonProduction ── SCP: region lock, no IAM users/keys, cost guardrails
│   └── munaxa-nonprod          ← this document; created first
│       shared: VPC munaxa-shared-nonprod, ALB, endpoints, cluster, munaxa-nonprod.com, OIDC provider
│       ├── Identity   roles, secrets, Valkey, database `identity`   ┐ one RDS instance
│       ├── Work       roles, secrets, database `work`               ┘ (Work unit, §7)
│       ├── Docs       (on joining) roles, secrets, its own RDS
│       └── School     (on joining) roles, secrets, its own RDS
│
└── OU Production ── SCP: region lock, no IAM users/keys, CloudTrail protected
    └── munaxa-prod             ← created when the first Identity/Work production resource is built
        ├── Identity, Work      (and Docs, School when their owners decide)
        └── ECR copies of the promoted digests; own OIDC provider trusting `aws-eu-prod` only
```

### 8.9 ADR

This decision changes how every product is hosted, so it belongs in an **ecosystem ADR in
`munaxa/munaxa`** before any account is created. It can be one ADR together with the registry
decision (§12 #1). It also answers the account-structure precondition of Docs ADR-0022. No ADR is
created here: ecosystem ADRs live in `munaxa/munaxa`, which is out of scope, and accepted ADRs are
superseded rather than edited.

### 8.10 Secrets Manager

One JSON secret per _consumer_, so an execution role can read only what its task uses. There is
never a shared signing key or shared credential (ADR-0002 §10). Secrets live in the account of their
environment, so production and non-production secrets never share a namespace or a key.

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

### 8.11 IAM roles

All roles sit under a product path and carry a permissions boundary (Docs pattern). The GitHub
roles are detailed in §8.4.

| Role                                             | Trusted by                          | May                                                                                 |
| ------------------------------------------------ | ----------------------------------- | ----------------------------------------------------------------------------------- |
| `munaxa-<product>-nonprod-<component>-execution` | `ecs-tasks`                         | pull that component's repository, read that component's secret, write its log group |
| `munaxa-<product>-nonprod-<component>-task`      | `ecs-tasks`                         | only what the application calls (Identity and Work: nothing)                        |
| `munaxa-<product>-nonprod-ops-execution`         | `ecs-tasks`                         | the ops secret, the ops log group                                                   |
| `munaxa-<product>-nonprod-github-publisher`      | GitHub OIDC, one repo + environment | push to that product's repositories                                                 |
| `munaxa-<product>-nonprod-github-deployer`       | GitHub OIDC, one repo + environment | deploy that product's services and one-off tasks                                    |
| `munaxa-shared-nonprod-infra`                    | the shared-infrastructure pipeline  | the shared VPC, ALB, endpoints, cluster and namespace only                          |

---

## 9. Cost-minimization strategy

Identity + Work staging, Option B (§3), `eu-central-1`, verified list prices:

| Item                                                                        | $/month        | Kind                                                       |
| --------------------------------------------------------------------------- | -------------- | ---------------------------------------------------------- |
| Shared ALB: $19.71 hourly + 2 public IPv4 × $3.65                           | 27.01          | Fixed                                                      |
| ALB LCUs ($0.008 per LCU-hour)                                              | ~0.5–3         | Usage                                                      |
| **Interface endpoints ×4, one AZ** (the network decision)                   | **35.04**      | Fixed                                                      |
| Endpoint data processing ($0.01/GB); S3 gateway                             | < 0.10; 0      | Usage                                                      |
| Fargate on-demand: identity-api 10.36, work-api 12.23, work-admin 10.36     | 32.95          | Fixed while running ($0.04656/vCPU-h, $0.00511/GB-h)       |
| RDS `db.t4g.micro` Single-AZ ($13.87) + 20 GB gp3 ($2.74) (Work unit)       | 16.61          | Fixed                                                      |
| ElastiCache Valkey `cache.t4g.micro` (Identity)                             | 10.51          | Fixed                                                      |
| Secrets Manager ×6                                                          | 2.40           | Fixed (+ $0.05 per 10,000 calls)                           |
| Route 53 zone `munaxa-nonprod.com`, Cloud Map namespace and 3 registrations | ~1.30          | Fixed                                                      |
| Domain registration `munaxa-nonprod.com` ($16/year, §4.6)                   | ~1.33          | Fixed (annual)                                             |
| CloudWatch Logs ($0.63/GB ingested, 7 days), ECR storage ($0.10/GB-month)   | ~1–3           | Usage                                                      |
| **Total, on-demand**                                                        | **≈ 128–133**  | 127.15 fixed + usage                                       |
| With Fargate Spot                                                           | ≈ −21          | _estimate_: Spot prices vary and are not in the price list |
| With Redis as a sidecar instead of Valkey                                   | −10.51         | owner decision (§12 #5)                                    |
| Rejected: Option C instead of B / Option A instead of B                     | −24.09 / +6.57 | §3.10                                                      |

What is deliberately **not** in it: NAT gateway, endpoints in a second AZ, Multi-AZ, replicas, autoscaling, WAF, KMS
customer-managed keys, bastion, ECS Exec endpoint, SES/S3/OpenSearch/MSK (no Identity or Work
requirement), extra ALBs. Each Docs/School join adds its tasks and database; the network and ALB do
not repeat.

**Existing cost to review:** the Docs Non-Production environment already costs about **$100 a month
idle** (NAT gateway and a Multi-AZ `db.t4g.small`; Docs ADR-0024 §4). Folding Docs staging into this
design, or shrinking it, is the largest single saving available — a Docs owner decision.

---

## 10. Staging → production

| Area    | Staging (this design)                                                        | Production                                                                                                                                                         |
| ------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Account | `munaxa-nonprod` member account                                              | Production member account (`munaxa-prod`), never the management account; images copied by digest (§8.4)                                                            |
| AZs     | 2 (ALB minimum), endpoints in 1                                              | 2–3, everything spread                                                                                                                                             |
| Tasks   | 1 per service, Spot                                                          | ≥2 per service, on-demand, rolling deploys                                                                                                                         |
| Egress  | Option B: private tasks, 4 interface endpoints in 1 AZ, no internet egress   | Same shape, endpoints in every AZ that runs tasks (4 × 2 AZs = $70.08); still no internet egress for Identity and Work. A NAT only for a product that needs egress |
| ALB     | Shared                                                                       | Shared or per product; WAF                                                                                                                                         |
| RDS     | One instance for the Work unit, Single-AZ, 7-day backups                     | Multi-AZ, larger class, 35-day backups + AWS Backup; separate Identity instance if decided                                                                         |
| Redis   | One Valkey node                                                              | Replica, Multi-AZ                                                                                                                                                  |
| Logs    | 7 days                                                                       | 30–90 days, alarms, dashboards                                                                                                                                     |
| DNS     | `<product>.munaxa-nonprod.com`, own domain and zone in `munaxa-nonprod` (§4) | `<product>.munaxa.com` (ADR-0002) on Cloudflare, DNS-only records, one certificate per hostname                                                                    |
| Images  | ECR, promoted by digest                                                      | Same digest, copied to the production registry                                                                                                                     |
| MFA     | Not required for staging (Identity ADR-0003)                                 | Required before Work production                                                                                                                                    |

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
| AWS account                  | `munaxa-<env-class>`, one per environment class, never per product                           | `munaxa-nonprod`, `munaxa-prod`                                     |
| Organizational unit          | `NonProduction`, `Production`                                                                | `NonProduction` holds `munaxa-nonprod`                              |
| Cloud Map namespace          | `<env>.munaxa.internal`                                                                      | `nonprod.munaxa.internal`                                           |
| DNS                          | `<product>.munaxa-nonprod.com` / `<product>.munaxa.com`                                      | `work.munaxa-nonprod.com`, `work.munaxa.com`                        |
| Authentication cookies       | host-only; `__Host-` wherever the path can be `/`; never `Domain=` (§4.7)                    | `__Host-mx_session`                                                 |
| Tags                         | `Project=Munaxa<Product>`, `Environment=NonProduction\|Production`, `ManagedBy`, `Stack`     | `Project=MunaxaIdentity`                                            |

**Already published under different names, to align (no code change):** the Identity ECR runbook uses
repository `munaxa/identity-api` and GitHub environment `aws-staging`. Under this convention they become
`munaxa-identity-api` and `aws-nonprod` — a GitHub variable, the environment name, the role's trust
`sub`, and the runbook text.

---

## 12. Open decisions and blockers

| #   | Decision                                                                                                                                                                                                                                                                                      | Recommendation                                                                            |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| 1   | **Registry:** ADR-0002 §10/D6 names GHCR; AWS deployment uses ECR                                                                                                                                                                                                                             | Supersede with an ecosystem ADR: ECR for AWS environments, GHCR kept for distribution     |
| 2   | ~~**Account:** management account or a member account~~ — **resolved 2026-10-06: dedicated member account `munaxa-nonprod`** for all products' non-production; production later in its own member account                                                                                     | Done (§8). Needs an ecosystem ADR in `munaxa/munaxa` before the account is created (§8.9) |
| 3   | ~~**Network:** A, B or C~~ — **resolved 2026-10-06: Option B** (private tasks + 4 interface endpoints in one AZ, no NAT, no internet egress; $35.04/month)                                                                                                                                    | Done (§3). C ($10.95) and A ($41.61) rejected in §3.10                                    |
| 4   | **Identity database server:** shared with Work (separate databases) or its own instance (+~$16.61)                                                                                                                                                                                            | Shared for staging; revisit for production                                                |
| 5   | **Identity Redis:** ElastiCache Valkey (~$10.5) or loopback sidecar ($0)                                                                                                                                                                                                                      | Valkey: survives task restarts and is the production shape                                |
| 6   | ~~**DNS:** where `munaxa.com` is hosted, and delegating `nonprod.munaxa.com`~~ — **resolved 2026-10-06: own non-production domain `munaxa-nonprod.com`** (Route 53 in `munaxa-nonprod`, wildcard certificate, no delegation); production stays on `munaxa.com` (Cloudflare, DNS-only records) | Done (§4). Register the domain; same ecosystem ADR as #1 and #2 (§4.9)                    |
| 7   | **Fargate Spot** for staging                                                                                                                                                                                                                                                                  | Yes                                                                                       |
| 8   | **Docs Non-Production** (~$100 a month idle)                                                                                                                                                                                                                                                  | Docs owner: shrink, or move into this design                                              |
| 9   | School: build-time `NEXT_PUBLIC_API_URL`, static S3 keys, `app.`/`admin.munaxa.com` hostnames (ADR-0002 R2)                                                                                                                                                                                   | Fix before School joins (§6)                                                              |
| 10  | Naming alignment of the Identity artifacts (§11)                                                                                                                                                                                                                                              | Rename before the first AWS publish                                                       |
| 11  | ADR-0002 §7 says Identity signs RS256; Identity uses ES256                                                                                                                                                                                                                                    | Correct in the superseding ADR (#1)                                                       |
| 12  | **Before production, not for non-production:** a same-site sibling of `work.munaxa.com` (`www.`, `app.`, `admin.`, `docs.`) can shadow `__Secure-mx_refresh` (§4.2). Options are in §4.4. Also Work's `munaxa_work_tenant` should become `__Host-`                                            | Identity ADR in this repository; Work change. Not decided here                            |

**Blockers for building this, outside this document:** Work's own AWS blockers from its readiness audit
(migration path, `work_app` grants, RDS TLS, bootstrap from the image); decisions 1 and 6; and, for
decision 2, the ecosystem ADR and the creation of `munaxa-nonprod` with its baseline SCPs (§8.5, §8.9).
