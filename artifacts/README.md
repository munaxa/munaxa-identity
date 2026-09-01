# Artifacts consumed from other products

Files here are **generated elsewhere and copied in**. Nothing in this directory is edited by hand,
and nothing in this repository imports another product's code to produce it.

## `work-permissions.json`

Munaxa Work's complete permission vocabulary, in the cross-product `work:` grant form.

|                     |                                                                    |
| ------------------- | ------------------------------------------------------------------ |
| **Owner**           | `munaxa-work`                                                      |
| **Source of truth** | `munaxa-work/scripts/emit-permission-catalogue.mjs`                |
| **Refresh**         | `pnpm catalogue:refresh --from <source>` — see below               |
| **Consumed by**     | `scripts/seed-work-roles.mjs`, `scripts/check-catalogue-drift.mjs` |

### Acquiring it

The file is committed, so a clean clone of this repository builds, tests and deploys with **no
external dependency at all**. That property is deliberate and the refresh mechanism does not weaken
it.

Refreshing names its source explicitly. There is no default that reaches out to a network location,
because a silent fetch is how a build starts depending on something nobody declared — and no
assumption that a Munaxa Work checkout sits at `../munaxa-work`, because that is a machine-specific
assumption dressed up as a procedure.

```bash
pnpm catalogue:refresh --from ~/src/munaxa-work            # runs Work's own emitter there
pnpm catalogue:refresh --from https://…/work-permissions.json
pnpm catalogue:refresh --from ./downloaded.json --check    # compares without writing
```

Every source is validated before anything is written: a wildcard, a scoped grant, a malformed name
or a duplicate fails the refresh rather than entering a role. Added and removed grants are printed,
because a _removed_ grant silently drops out of every role that named it and that is the change
worth looking at.

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
