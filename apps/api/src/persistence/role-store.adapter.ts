import type {
  RoleAssignment,
  RoleAssignmentPort,
  RoleDefinition,
  RoleRepositoryPort,
} from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';
import { randomUUID } from 'node:crypto';

import type { PrismaService } from './prisma.service.js';

/**
 * Role definitions.
 *
 * `remove` refuses a system role, matching the memory reference implementation's reasoning:
 * deleting one turns a working authorization check into a silent denial for everybody who held it.
 * `work-staging-operator` and its successors are system roles for exactly that reason.
 */
export class PrismaRoleRepository implements RoleRepositoryPort {
  public constructor(private readonly prisma: PrismaService) {}

  public async list(tenantId: TenantId): Promise<readonly RoleDefinition[]> {
    const rows = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRole.findMany({ where: { tenantId }, orderBy: { key: 'asc' } }),
    );
    return rows.map(definitionOf);
  }

  public async get(tenantId: TenantId, roleId: string): Promise<RoleDefinition | undefined> {
    const row = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRole.findFirst({ where: { tenantId, key: roleId } }),
    );
    return row === null ? undefined : definitionOf(row);
  }

  public async save(role: RoleDefinition): Promise<void> {
    await this.prisma.withTenant(role.tenantId, (tx) =>
      tx.identityRole.upsert({
        where: { tenantId_key: { tenantId: role.tenantId, key: role.id } },
        create: { id: randomUUID(), ...rowOf(role) },
        update: rowOf(role),
      }),
    );
  }

  public async remove(tenantId: TenantId, roleId: string): Promise<boolean> {
    return this.prisma.withTenant(tenantId, async (tx) => {
      const existing = await tx.identityRole.findFirst({ where: { tenantId, key: roleId } });
      if (existing === null || existing.system) return false;
      const removed = await tx.identityRole.deleteMany({ where: { tenantId, key: roleId } });
      return removed.count > 0;
    });
  }
}

/**
 * Role assignments.
 *
 * `scope` participates in the primary key because it participates in the assignment's identity:
 * the same role granted twice with different scopes is two grants, and an upsert that ignored it
 * would silently replace one with the other.
 *
 * Nothing here invalidates the permission cache, and that is deliberate rather than forgotten:
 * see `RoleAdministration`, which owns the pairing so no call site can perform one without the
 * other.
 */
export class PrismaRoleAssignments implements RoleAssignmentPort {
  public constructor(private readonly prisma: PrismaService) {}

  public async listForUser(tenantId: TenantId, userId: UserId): Promise<readonly RoleAssignment[]> {
    const rows = await this.prisma.withTenant(tenantId, (tx) =>
      tx.identityRoleAssignment.findMany({
        where: { tenantId, accountId: userId },
        include: { role: { select: { key: true } } },
      }),
    );
    return rows.map(assignmentOf);
  }

  public async assign(assignment: RoleAssignment): Promise<void> {
    await this.prisma.withTenant(assignment.tenantId, async (tx) => {
      const role = await tx.identityRole.findFirst({
        where: { tenantId: assignment.tenantId, key: assignment.roleId },
        select: { id: true },
      });
      if (role === null) {
        throw new Error(`No role "${assignment.roleId}" in this organisation.`);
      }
      const key = {
        tenantId: assignment.tenantId,
        accountId: assignment.userId,
        roleId: role.id,
        scope: assignment.scope ?? '',
      };
      const data = {
        assignedAt: new Date(assignment.assignedAt),
        assignedBy: assignment.assignedBy ?? null,
        expiresAt: assignment.expiresAt === undefined ? null : new Date(assignment.expiresAt),
      };
      await tx.identityRoleAssignment.upsert({
        where: { tenantId_accountId_roleId_scope: key },
        create: { ...key, ...data },
        update: data,
      });
    });
  }

  public async revoke(
    tenantId: TenantId,
    userId: UserId,
    roleId: string,
    scope?: string,
  ): Promise<boolean> {
    return this.prisma.withTenant(tenantId, async (tx) => {
      const role = await tx.identityRole.findFirst({
        where: { tenantId, key: roleId },
        select: { id: true },
      });
      if (role === null) return false;
      const removed = await tx.identityRoleAssignment.deleteMany({
        where: { tenantId, accountId: userId, roleId: role.id, scope: scope ?? '' },
      });
      return removed.count > 0;
    });
  }
}

interface RoleRow {
  tenantId: string;
  key: string;
  name: string;
  description: string | null;
  permissions: string[];
  inherits: string[];
  system: boolean;
}

/**
 * `RoleDefinition.id` is the stable key an assignment names, not the surrogate primary key.
 *
 * The row keeps a UUID for foreign keys, but Platform's identifier for a role is the thing a seed
 * script and an administrator both write — `work-staging-operator` — and translating between them
 * at the boundary is cheaper than every caller knowing both.
 */
const definitionOf = (row: RoleRow): RoleDefinition => ({
  id: row.key,
  tenantId: row.tenantId as TenantId,
  name: row.name,
  permissions: row.permissions,
  inherits: row.inherits,
  system: row.system,
  ...(row.description === null ? {} : { description: row.description }),
});

const rowOf = (role: RoleDefinition) => ({
  tenantId: role.tenantId,
  key: role.id,
  name: role.name,
  description: role.description ?? null,
  permissions: [...role.permissions],
  inherits: [...(role.inherits ?? [])],
  system: role.system ?? false,
});

interface AssignmentRow {
  tenantId: string;
  accountId: string;
  scope: string;
  assignedAt: Date;
  assignedBy: string | null;
  expiresAt: Date | null;
  role: { key: string };
}

const assignmentOf = (row: AssignmentRow): RoleAssignment => ({
  tenantId: row.tenantId as TenantId,
  userId: row.accountId as UserId,
  roleId: row.role.key,
  assignedAt: row.assignedAt.getTime(),
  ...(row.assignedBy === null ? {} : { assignedBy: row.assignedBy as UserId }),
  ...(row.expiresAt === null ? {} : { expiresAt: row.expiresAt.getTime() }),
  ...(row.scope === '' ? {} : { scope: row.scope }),
});
