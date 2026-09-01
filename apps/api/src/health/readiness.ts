import type { PrismaService } from '../persistence/prisma.service.js';
import type { SecurityStack } from '../platform/security.js';

/**
 * The tables Identity cannot serve a single request without.
 *
 * Deliberately the *presence* of the schema rather than a Prisma migration version. Identity's
 * baseline is applied with `psql -f`, as the migration role, before any service starts — see
 * `docs/runbooks/staging-provisioning.md` — so `_prisma_migrations` does not exist in a
 * correctly-provisioned environment and a readiness probe keyed to it would fail for ever in the
 * one environment it is meant to protect. Table presence answers the question that actually
 * matters: is the schema this build expects the schema that is there?
 *
 * The list is the same one the runbook grants on, and the two should be changed together.
 */
export const REQUIRED_TABLES: readonly string[] = [
  'identity_account',
  'identity_audit_event',
  'identity_refresh_token',
  'identity_reset_token',
  'identity_role',
  'identity_role_assignment',
  'identity_session',
  'identity_tenant',
];

export type ReadinessFailure = 'database' | 'schema' | 'cache' | 'signing';

export interface ReadinessProbe {
  readonly ok: boolean;
  readonly failed?: ReadinessFailure;
  /** Present only when the schema check is what failed, so an operator sees *which* table. */
  readonly missing?: readonly string[];
}

const SIGNING_PROBE = 'munaxa-identity readiness probe';

/**
 * The minimum infrastructure contract for accepting traffic.
 *
 * Four questions, in the order in which failing one makes the next meaningless: can we reach the
 * database, is the schema the one we expect, is the cache reachable, can we actually sign. Each is
 * cheap and none touches a business row — the schema check reads `information_schema`, and the
 * signing check signs a constant string rather than a token.
 *
 * This is readiness, not liveness. A process that fails all four is still perfectly alive and
 * restarting it would fix nothing; what it must not do is receive traffic.
 */
export const probeReadiness = async (
  prisma: PrismaService,
  security: SecurityStack,
): Promise<ReadinessProbe> => {
  try {
    await prisma.$queryRaw`select 1`;
  } catch {
    return { ok: false, failed: 'database' };
  }

  let present: readonly string[];
  try {
    const rows = await prisma.$queryRaw<{ table_name: string }[]>`
      select table_name from information_schema.tables
      where table_schema = 'public' and table_type = 'BASE TABLE'`;
    present = rows.map((row) => row.table_name);
  } catch {
    return { ok: false, failed: 'database' };
  }

  const missing = REQUIRED_TABLES.filter((table) => !present.includes(table));
  if (missing.length > 0) return { ok: false, failed: 'schema', missing };

  if (!(await security.cacheReachable())) return { ok: false, failed: 'cache' };

  // Signing is validated at boot, so this is not asking whether it was configured — it is asking
  // whether the key still *works*. A signer that parsed once and cannot produce a verifiable
  // signature now would otherwise be discovered by the first person trying to sign in.
  try {
    const signature = security.signing.signer.sign(SIGNING_PROBE);
    if (!security.signing.signer.verify(SIGNING_PROBE, signature)) {
      return { ok: false, failed: 'signing' };
    }
  } catch {
    return { ok: false, failed: 'signing' };
  }

  return { ok: true };
};
