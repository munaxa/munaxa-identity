# ADR-0001 — Identity owns the durable security state; Platform owns the machinery

**Status** Accepted · **Date** 2026-09-01
**Follows** [munaxa/munaxa ADR-0001](https://github.com/munaxa/munaxa/blob/main/docs/adr/0001-munaxa-identity-is-a-sixth-peer-product.md)

## Context

`@munaxa/*` implements every security mechanism this service needs — scrypt with a hasher registry,
ES256 signing over a key ring, session lifecycle with two deadlines, refresh rotation with reuse
detection, RBAC resolution with an invalidatable cache, rate limiting, CSRF, hash-chained audit.
None of it can store anything: the platform ships `Memory*` reference implementations and states as
a principle that no database driver appears in any package.

## Decision

**Identity writes adapters and wiring, and no security mechanism of its own.** Every store in
`apps/api/src/persistence` implements a Platform port. The composition root in
`apps/api/src/platform/security.ts` is the only place any Platform service is constructed.

The test for whether something belongs here: could it be wrong in a way that is _specific to this
product's data_? A `markRotated` that is not a compare-and-swap can. A password comparison cannot —
that is the same everywhere, and writing a second one is how a product ends up with a subtly worse
version of a reviewed implementation.

## Consequences

- Upgrading `@munaxa/auth` upgrades this service's cryptography. That is the intended coupling.
- The adapters carry the risk, so they carry the tests: Platform's conformance suites run against
  them in CI, and the properties they check — compare-and-swap rotation, atomic session limits,
  single-use reset — are invisible in a sequential test.
- Where a port and this product disagree, the port wins. Foreign keys were removed from three tables
  because the port treats the user id as opaque; the column types were widened for the same reason.
