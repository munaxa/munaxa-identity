# Staging data policy

Staging is a shared environment. More than one person signs into it, and what one of them puts in
it, the others can read. That single fact decides everything below.

## The rule

**No personal data of a real person may be entered into staging.** Not a real employee's name, not
a real salary, not a real national identifier, not a real medical note, not a real photograph, not
a real bank account, not a real home address, not a real contract.

This is not a preference about tidiness. Munaxa Work holds the categories of data — pay, health,
identity documents, disciplinary records — that carry the heaviest obligations under GDPR and its
regional equivalents, and staging meets none of the conditions those obligations attach to. It has
no data-processing agreement, no retention schedule, no subject-access route, no deletion guarantee
and no breach-notification path. A real record placed here is a record outside the controls that
were promised to the person it describes.

## What staging is for

Exercising the system with data that resembles reality closely enough to find defects:

- Employees invented for the purpose, with obviously synthetic names.
- Salaries, dates and structures that are realistic in _shape_ — the payroll engine must be given
  numbers that stress it — but attached to nobody.
- Documents generated for the test, never a scan of a real passport or contract.

`node scripts/bootstrap-tenant.mjs` in Munaxa Work seeds a tenant of exactly this kind. Prefer
extending that seed over hand-entering data, because a seed is reviewable and repeatable and a
hand-entered record is neither.

## Accounts

Staging accounts are staging-only:

- A staging password is never a password used anywhere else. Not the operator's work password, not
  a password from another environment. Staging is where experimental code runs; treat every
  credential in it as one that may be observed.
- Accounts are created through `node apps/api/scripts/bootstrap-account.mjs`, which applies the same
  password policy as any other environment. There is no bypass and none should be added.
- An account belonging to someone who has left the project is disabled, not left in place.

## Retention

Staging data is **disposable and expected to be destroyed**. There is no backup promise, no
restore-on-request and no archive. The database may be reset to a clean seed at any point — during
a schema change, a rollback rehearsal, or a restore test.

The corollary matters more than the rule: **nothing may exist only in staging.** If a document, a
configuration or a test result is worth keeping, it belongs in a repository, a runbook or an issue.

## If real data reaches staging anyway

It happens — someone pastes a real spreadsheet to reproduce a bug. Treat it as an incident, not an
embarrassment:

1. Say so immediately, in the team's normal channel. The delay in reporting is what turns a mistake
   into a breach.
2. Remove the records. If the extent is not clear, reset the tenant rather than guessing at the
   edges — see `staging-provisioning.md`.
3. Rotate any credential that was entered, following `key-rotation.md` for signing keys and
   `secrets.md` for everything else.
4. Record what happened and what was removed. Whether it is notifiable is a decision for whoever
   holds data-protection responsibility, and they cannot make it without the record.

## What this policy does not cover

It does not make staging a place where production data _could_ be handled with a few more controls.
Bringing real personal data into a shared test environment is a decision with a legal basis behind
it or it is not made at all, and that decision is not an engineering one.
