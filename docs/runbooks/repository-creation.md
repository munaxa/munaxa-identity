# Runbook — creating the GitHub repository

This repository exists locally and is complete. It is not on GitHub, and this session could not put
it there: creating a repository in the `munaxa` organisation returned

```
POST https://api.github.com/orgs/munaxa/repos: 403 Resource not accessible by integration
```

which is the GitHub App's permission set, not a transient failure. An operator with `create
repository` in the organisation performs the steps below once.

## 1 — Create it

```bash
gh repo create munaxa/munaxa-identity --private \
  --description "Munaxa Identity — the ecosystem's authentication and authorization authority."
```

**Private is the recommendation, and it is a decision worth making deliberately.** The other five
Munaxa repositories are public. This one holds the design of the service that mints every access
token in the ecosystem, and while nothing here is a secret — no key, no credential, and CI enforces
that — an attacker reading an authentication service's source has a materially easier job than one
reading a design system's. Public is one click away if that trade is judged the wrong one; the
reverse is not, because anything that was public was cloned.

## 2 — Push

The repository has one branch, `main`, matching every other Munaxa repository.

```bash
cd munaxa-identity
git remote add origin https://github.com/munaxa/munaxa-identity.git
git push -u origin main
```

If you are starting from the delivered bundle rather than a working copy:

```bash
git clone munaxa-identity.bundle munaxa-identity
cd munaxa-identity
git remote set-url origin https://github.com/munaxa/munaxa-identity.git
git push -u origin main
```

## 3 — The CI secret

CI cannot install `@munaxa/*` without it, and every job after `Install` will fail.

```bash
gh secret set PLATFORM_PACKAGES_TOKEN --repo munaxa/munaxa-identity
```

The value is a token with **`read:packages`** on the `munaxa` organisation and nothing more. It
needs no `repo` scope, no write, and no admin: CI reads packages and does nothing else with it.

Where it must never appear: a repository file, `.env.example`, the workflow YAML, a Docker `ARG`, a
Docker `ENV`, or a log. The workflow passes it only as `NODE_AUTH_TOKEN` on the two steps that
install, and the Dockerfile takes it as a BuildKit `--mount=type=secret` — an `ARG` would be
recorded in the image history and readable by anybody who can pull the image.

## 4 — Branch protection

Match whatever the other Munaxa repositories use. At minimum, require the `verify` job to pass
before merging to `main`: that job is what proves row-level security, the port conformance
properties and the cookie-size ceiling, and a merge that skips it skips those.

## 5 — Confirm

```bash
gh run list --repo munaxa/munaxa-identity --limit 1
```

CI has never run. Until that command shows a green `verify`, the workflow is reviewed and not
proven — those are different things and the report for this phase says so.
