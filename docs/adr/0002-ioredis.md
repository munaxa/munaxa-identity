# ADR-0002 — `ioredis`, because `RedisLike` is ioredis-shaped

**Status** Accepted · **Date** 2026-09-01

## Context

`@munaxa/cache` declares the slice of a Redis client it uses rather than depending on one, which is
what keeps the platform cloud-agnostic. The shape it declares is ioredis's:

```ts
set(key: string, value: string, ...args: readonly (string | number)[]): Promise<string | null>;
incrby(key: string, increment: number): Promise<number>;
pexpire(key: string, milliseconds: number): Promise<number>;
```

This service was first wired with `node-redis` v4, cast with `as unknown as RedisLike`. node-redis
takes an _options object_ where ioredis takes variadic arguments, and spells the other three methods
`incrBy`, `pExpire`, `pTTL`. The cast compiled. `set(key, value, 'PX', 60000)` ran, stored the
value, and **silently ignored the expiry**.

The observable result: the permission cache never expired and the lockout counters never
incremented. Both controls were off, nothing failed, and the service looked healthy. It was found by
measuring a revoked role that stayed effective past its cache TTL — `redis-cli ttl` returned `-1` —
not by reading the code, which is the whole argument for measuring.

## Decision

**`ioredis`.** Its method names and variadic signatures satisfy `RedisLike` natively, so the
structural typing means what it appears to mean.

## Consequences

- The `as unknown as RedisLike` cast remains, because `ioredis` types its returns more precisely
  than the port declares. It is now a narrowing rather than a bridge between two shapes.
- A future client change is a real decision: check every method the port names, including the
  variadic form of `set`, before swapping one in.
- The integration suite asserts the TTL is present, so the silent version of this cannot return.
