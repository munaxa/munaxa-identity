# Artifacts consumed from other products

Files here are **generated elsewhere and copied in**. Nothing in this directory is edited by hand,
and nothing in this repository imports another product's code to produce it.

## `work-permissions.json`

Munaxa Work's complete permission vocabulary, in the cross-product `work:` grant form.

|                     |                                                                    |
| ------------------- | ------------------------------------------------------------------ |
| **Owner**           | `munaxa-work`                                                      |
| **Source of truth** | `munaxa-work/scripts/emit-permission-catalogue.mjs`                |
| **Refresh**         | run that script in a Work checkout and replace this file           |
| **Consumed by**     | `scripts/seed-work-roles.mjs`, `scripts/check-catalogue-drift.mjs` |

### Why a file and not a package

`PLATFORM_ENGINEERING_STANDARDS.md` §4 rule 3 — "Products MUST NEVER import another product" — is
absolute, so `@work/permissions` is not available to Identity at any price. A generated artifact
carries the same vocabulary with none of the coupling: Identity reads data, not code, and Work
remains free to reorganise its modules without breaking this repository's build.

### What happens when it drifts

Nothing dangerous, and that is by design. Work validates every incoming grant against its own
closed catalogue and drops anything it does not declare, with a reason. So a stale file here
produces a _denial_, never an escalation. `pnpm check:catalogue-drift` turns that quiet denial into
a loud build failure, which is the only part that needs engineering.
