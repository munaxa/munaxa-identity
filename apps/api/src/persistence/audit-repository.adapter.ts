import type {
  AuditAppendOptions,
  AuditQuery,
  AuditRecord,
  AuditRepositoryPort,
  ChainHead,
  AuditSealer,
} from '@munaxa/interfaces';
import type { SecurityEventName, TenantId } from '@munaxa/types';

import { Prisma } from '../../../../node_modules/.prisma/identity-client';
import type { PrismaService, TenantClient } from './prisma.service.js';

/**
 * The hash-chained security trail.
 *
 * Two concurrent appends for one organisation must produce consecutive sequence numbers and a
 * chain where each `previousHash` equals its predecessor's `hash`. This adapter takes the
 * serialising route rather than the retry route: a transaction-scoped advisory lock, keyed by the
 * organisation, held for the read-seal-insert. An advisory lock rather than `SELECT … FOR UPDATE`
 * because the first append of a chain has no row to lock, and a chain that is only serialised once
 * it is non-empty is not serialised.
 *
 * `joinsTransactions` is false and the adapter throws when handed a foreign transaction, as the
 * interface requires: silently opening its own would produce an audit record for a change that was
 * then rolled back — evidence of something that never happened.
 */
export class PrismaAuditRepository implements AuditRepositoryPort {
  public readonly joinsTransactions = false;

  public constructor(private readonly prisma: PrismaService) {}

  public async write(record: AuditRecord): Promise<void> {
    await this.prisma.withTenant(record.event.tenantId, (tx) =>
      tx.identityAuditEvent.create({ data: rowOf(record) }),
    );
  }

  public async appendChained(
    tenantId: TenantId,
    seal: AuditSealer,
    options?: AuditAppendOptions,
  ): Promise<AuditRecord> {
    if (options?.transaction !== undefined) {
      throw new Error(
        'This audit repository cannot join a caller transaction (joinsTransactions is false). ' +
          'Record after commit, or refuse to proceed — do not let the append escape silently.',
      );
    }
    return this.prisma.withTenant(tenantId, async (tx) => {
      await lockChain(tx, tenantId);
      const head = await currentHead(tx, tenantId);
      const record = seal(head);
      await tx.identityAuditEvent.create({ data: rowOf(record) });
      return record;
    });
  }

  public async query(
    query: AuditQuery,
  ): Promise<{ items: readonly AuditRecord[]; nextCursor?: string }> {
    const limit = Math.min(query.limit ?? 100, 500);
    const rows = await this.prisma.withTenant(query.tenantId, (tx) =>
      tx.identityAuditEvent.findMany({
        where: {
          tenantId: query.tenantId,
          ...(query.names === undefined ? {} : { eventName: { in: [...query.names] } }),
          ...(query.from === undefined && query.to === undefined
            ? {}
            : {
                occurredAt: {
                  ...(query.from === undefined ? {} : { gte: new Date(query.from) }),
                  ...(query.to === undefined ? {} : { lte: new Date(query.to) }),
                },
              }),
          ...(query.cursor === undefined ? {} : { sequence: { gt: BigInt(query.cursor) } }),
        },
        orderBy: { sequence: 'asc' },
        take: limit,
      }),
    );
    const items = rows.map(recordOf);
    const last = rows[rows.length - 1];

    return rows.length < limit || last === undefined
      ? { items }
      : { items, nextCursor: last.sequence.toString() };
  }

  public async latest(tenantId: TenantId): Promise<AuditRecord | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityAuditEvent.findFirst({ where: { tenantId }, orderBy: { sequence: 'desc' } }),
    );
    return row === null ? undefined : recordOf(row);
  }
}

/** Serialises this organisation's chain for the rest of the transaction. */
const lockChain = async (tx: TenantClient, tenantId: TenantId): Promise<void> => {
  await tx.$executeRaw`select pg_advisory_xact_lock(hashtextextended(${tenantId}::text, 0))`;
};

const currentHead = async (tx: TenantClient, tenantId: TenantId): Promise<ChainHead | null> => {
  const row = await tx.identityAuditEvent.findFirst({
    where: { tenantId },
    orderBy: { sequence: 'desc' },
    select: { sequence: true, hash: true },
  });
  return row === null ? null : { sequence: row.sequence, hash: row.hash };
};

interface AuditRow {
  tenantId: string;
  sequence: bigint;
  id: string;
  event: unknown;
  eventName: string;
  occurredAt: Date;
  recordedAt: Date;
  previousHash: string | null;
  hash: string;
  formatVersion: number;
}

const rowOf = (record: AuditRecord) => ({
  tenantId: record.event.tenantId,
  sequence: BigInt(record.sequence),
  id: record.id,
  event: record.event as unknown as Prisma.InputJsonValue,
  eventName: record.event.name,
  occurredAt: new Date(record.event.occurredAt),
  recordedAt: new Date(record.recordedAt),
  previousHash: record.previousHash,
  hash: record.hash,
  formatVersion: record.formatVersion ?? 1,
});

const recordOf = (row: AuditRow): AuditRecord => ({
  id: row.id,
  event: row.event as AuditRecord<SecurityEventName>['event'],
  recordedAt: row.recordedAt.getTime(),
  sequence: row.sequence,
  hash: row.hash,
  previousHash: row.previousHash,
  formatVersion: row.formatVersion,
});
