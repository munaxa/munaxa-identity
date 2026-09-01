import type { PermissionResolver } from '@munaxa/rbac';
import type {
  RoleAssignment,
  RoleAssignmentPort,
  RoleDefinition,
  RoleRepositoryPort,
} from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';

/**
 * Every path that changes what somebody may do — and the cache invalidation that must accompany it.
 *
 * `PermissionResolver.invalidateUser` exists in the platform and is called by nothing in it: the
 * mutation paths live on `RoleAssignmentPort`, which the resolver does not wrap. So the pairing is
 * a convention, and a convention that must hold on every future call site is a defect waiting for
 * a busy afternoon: forget it and a revoked role stays effective for the cache TTL, silently.
 *
 * This class is the only thing in the service permitted to touch the two role ports. Nothing else
 * imports them, so there is no path that mutates a grant without invalidating the cache — the
 * invariant is structural rather than remembered.
 */
export class RoleAdministration {
  public constructor(
    private readonly roles: RoleRepositoryPort,
    private readonly assignments: RoleAssignmentPort,
    private readonly resolver: PermissionResolver,
  ) {}

  public async defineRole(role: RoleDefinition): Promise<void> {
    await this.roles.save(role);
    // The whole organisation's resolutions are stale: a role's permissions changed, and every
    // holder of it resolved from the old set.
    await this.resolver.invalidateTenant(role.tenantId);
  }

  public async removeRole(tenantId: TenantId, roleId: string): Promise<boolean> {
    const removed = await this.roles.remove(tenantId, roleId);
    if (removed) await this.resolver.invalidateTenant(tenantId);
    return removed;
  }

  public async assign(assignment: RoleAssignment): Promise<void> {
    await this.assignments.assign(assignment);
    await this.resolver.invalidateUser(assignment.tenantId, assignment.userId);
  }

  public async revoke(
    tenantId: TenantId,
    userId: UserId,
    roleId: string,
    scope?: string,
  ): Promise<boolean> {
    const revoked = await this.assignments.revoke(tenantId, userId, roleId, scope);
    // Invalidated whether or not a row was removed: a caller that got `false` because the scope
    // did not match still expects the next resolution to be honest.
    await this.resolver.invalidateUser(tenantId, userId);
    return revoked;
  }

  public listRoles(tenantId: TenantId): Promise<readonly RoleDefinition[]> {
    return Promise.resolve(this.roles.list(tenantId));
  }

  public listAssignments(tenantId: TenantId, userId: UserId): Promise<readonly RoleAssignment[]> {
    return Promise.resolve(this.assignments.listForUser(tenantId, userId));
  }
}
