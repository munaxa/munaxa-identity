import { anonymousAuditEvent } from '@munaxa/audit';
import { toCorrelationId, type SecurityEventName, type TenantId, type UserId } from '@munaxa/types';
import { randomUUID } from 'node:crypto';

import { domainOf, SSO_PROVIDERS, type SsoProviderKind } from '../sso/providers.js';
import { OperatorError, type OperatorDeps } from './operator.js';

/**
 * Operator commands for company sign-in (ADR-0006, ADR-0007).
 *
 * Configuring which directory an organisation signs in through, and which people may use it, is an
 * operator act with a ticket reference, a dry run by default and an audit record: there is no
 * administration API, and a self-service screen would need an administrator authorisation model
 * Identity does not have yet.
 *
 *     sso-connection-add      --organisation --provider microsoft|google --directory <tenant id | domain>
 *                             --domains a.com[,b.com] [--trust-provider-mfa]      (created disabled)
 *     sso-connection-enable   --organisation --connection-id
 *     sso-connection-disable  --organisation --connection-id [--end-sessions]
 *     sso-connection-list     --organisation
 *     sso-account-create      --organisation --connection-id --account <work email> [--role <key>]
 *     sso-account-convert     --organisation --connection-id (--account-id | --account)
 *
 * `sso-account-create` necessarily takes an email address: that is the account. ADR-0006 prefers ids
 * in task overrides because CloudTrail records them; for this one command the address is the input,
 * and the runbook says so (`docs/runbooks/sso.md`).
 */

const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DOMAIN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
/**
 * Domains nobody's company owns. A connection claiming one would let that directory speak for
 * every address there; Google's own consumer domains are the obvious case.
 */
const SHARED_DOMAINS: ReadonlySet<string> = new Set([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'yahoo.com',
  'icloud.com',
  'me.com',
  'proton.me',
  'protonmail.com',
  'aol.com',
]);

const requireReference = (reference: string | undefined): string => {
  if (reference === undefined || !REFERENCE.test(reference)) {
    throw new OperatorError(
      '--reference is required: a ticket or incident id, 3-64 characters of letters, digits and . _ : -',
    );
  }
  return reference;
};

const actor = (reference: string) => ({ kind: 'system' as const, id: `operator:${reference}` });

/** Microsoft's tenant for personal accounts (outlook.com, hotmail.com, live.com). */
const MICROSOFT_CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';

const tenantOf = async (
  deps: OperatorDeps,
  organisation: string | undefined,
): Promise<TenantId> => {
  if (organisation === undefined || organisation.trim() === '') {
    throw new OperatorError('--organisation is required');
  }
  const tenantId = await deps.security.tenants.idForKey(organisation.trim());
  if (tenantId === undefined) throw new OperatorError('No such organisation');
  return tenantId;
};

const connectionOf = async (deps: OperatorDeps, tenantId: TenantId, id: string | undefined) => {
  if (id === undefined || !GUID.test(id.trim().toLowerCase())) {
    throw new OperatorError(
      '--connection-id is required (a connection id from sso-connection-list)',
    );
  }
  const row = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identitySsoConnection.findUnique({
      where: { id: id.trim().toLowerCase() },
      include: { domains: { select: { domain: true } } },
    }),
  );
  // Another organisation's connection is "no such connection" here, never a cross-tenant write.
  if (row === null || row.tenantId !== tenantId) {
    throw new OperatorError('No such connection in that organisation');
  }
  return { ...row, domains: row.domains.map((entry) => entry.domain) };
};

const parseDomains = (raw: string | undefined): string[] => {
  const domains = [
    ...new Set(
      (raw ?? '')
        .split(',')
        .map((domain) => domain.trim().toLowerCase())
        .filter((domain) => domain !== ''),
    ),
  ];
  if (domains.length === 0) throw new OperatorError('--domains is required: a.com[,b.com]');
  for (const domain of domains) {
    if (!DOMAIN.test(domain)) throw new OperatorError(`Not a domain name: ${domain}`);
    if (SHARED_DOMAINS.has(domain)) {
      throw new OperatorError(
        `${domain} is a public email domain that no company owns, and cannot be bound to a connection`,
      );
    }
  }
  return domains;
};

const audit = async (
  deps: OperatorDeps,
  tenantId: TenantId,
  name: SecurityEventName,
  reference: string,
  payload: Readonly<Record<string, unknown>>,
  target?: { readonly type: string; readonly id: string },
): Promise<void> => {
  await deps.security.audit
    .write(
      anonymousAuditEvent(tenantId, toCorrelationId(randomUUID()), {
        name,
        outcome: 'success',
        actor: actor(reference),
        ...(target === undefined ? {} : { target }),
        payload: { ...payload, reference },
      }),
    )
    .catch((error: unknown) => {
      deps.out(`warning: the audit record could not be written: ${String(error)}`);
    });
};

// -------------------------------------------------------------------------------------------------
// Connections
// -------------------------------------------------------------------------------------------------

export const ssoConnectionAdd = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly provider?: string | undefined;
    readonly directory?: string | undefined;
    readonly domains?: string | undefined;
    readonly trustProviderMfa: boolean;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<{ readonly connectionId: string | undefined; readonly applied: boolean }> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const provider = (input.provider ?? '').trim().toLowerCase();
  if (!SSO_PROVIDERS.includes(provider as SsoProviderKind)) {
    throw new OperatorError('--provider must be microsoft or google');
  }
  const directory = (input.directory ?? '').trim().toLowerCase();
  if (provider === 'microsoft' && !GUID.test(directory)) {
    throw new OperatorError(
      '--directory must be the company’s Microsoft Entra tenant id (a GUID, from their Entra admin centre overview)',
    );
  }
  // The consumer tenant: every personal Microsoft account signs in through it. A connection to it
  // would let anyone with an outlook.com or hotmail.com account claim a pre-created address.
  if (provider === 'microsoft' && directory === MICROSOFT_CONSUMER_TENANT) {
    throw new OperatorError(
      '--directory is the Microsoft consumer tenant (personal accounts), not a company directory',
    );
  }
  if (provider === 'google' && !DOMAIN.test(directory)) {
    throw new OperatorError('--directory must be the company’s Google Workspace primary domain');
  }
  const domains = parseDomains(input.domains);
  if (provider === 'google' && !domains.includes(directory)) {
    throw new OperatorError('--domains must include the Workspace domain given as --directory');
  }
  const taken = await deps.prisma.identitySsoDomain.findMany({
    where: { domain: { in: domains } },
    select: { domain: true },
  });
  if (taken.length > 0) {
    throw new OperatorError(
      `Already bound to a connection: ${taken.map((row) => row.domain).join(', ')}. A domain signs in through one directory only.`,
    );
  }

  if (!input.apply) {
    deps.out(
      `dry run: would add a disabled ${provider} connection for ${domains.length} domain(s), ` +
        `trust-provider-mfa=${input.trustProviderMfa}; nothing changed (add --apply)`,
    );
    return { connectionId: undefined, applied: false };
  }
  const reference = requireReference(input.reference);
  const id = randomUUID();
  await deps.prisma.withTenant(tenantId, async (tx) => {
    await tx.identitySsoConnection.create({
      data: {
        id,
        tenantId,
        provider,
        directoryId: directory,
        enabled: false,
        trustProviderMfa: input.trustProviderMfa,
        createdBy: `operator:${reference}`,
        updatedBy: `operator:${reference}`,
      },
    });
    await tx.identitySsoDomain.createMany({
      data: domains.map((domain) => ({ domain, connectionId: id, tenantId })),
    });
  });
  await audit(deps, tenantId, 'security.policy.changed', reference, {
    change: 'sso-connection-added',
    connectionId: id,
    provider,
    domains,
    trustProviderMfa: input.trustProviderMfa,
  });
  deps.out(
    `applied: ${provider} connection ${id} added (disabled) for ${domains.join(', ')}, reference ${reference}. ` +
      'Pre-create accounts, then sso-connection-enable.',
  );
  return { connectionId: id, applied: true };
};

export const ssoConnectionSetEnabled = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly connectionId?: string | undefined;
    readonly enabled: boolean;
    /** Disabling only: also end every session of every account bound to the connection. */
    readonly endSessions: boolean;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<{ readonly applied: boolean; readonly sessionsRevoked: number }> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const connection = await connectionOf(deps, tenantId, input.connectionId);
  const bound = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identityAccount.findMany({
      where: { tenantId, identityProviderId: connection.id },
      select: { id: true },
    }),
  );
  const verb = input.enabled ? 'enable' : 'disable';
  if (!input.apply) {
    deps.out(
      `dry run: would ${verb} connection ${connection.id} (now enabled=${connection.enabled}), ` +
        `${bound.length} account(s) bound${!input.enabled && input.endSessions ? ', sessions ended' : ''}; nothing changed (add --apply)`,
    );
    return { applied: false, sessionsRevoked: 0 };
  }
  const reference = requireReference(input.reference);
  await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identitySsoConnection.update({
      where: { id: connection.id },
      data: { enabled: input.enabled, updatedAt: new Date(), updatedBy: `operator:${reference}` },
    }),
  );
  let sessionsRevoked = 0;
  if (!input.enabled && input.endSessions) {
    for (const account of bound) {
      const outcome = await deps.security.revocation.revokeAllForUser(
        tenantId,
        account.id as UserId,
        'admin-revoked',
      );
      sessionsRevoked += outcome.sessions;
    }
  }
  await audit(deps, tenantId, 'security.policy.changed', reference, {
    change: input.enabled ? 'sso-connection-enabled' : 'sso-connection-disabled',
    connectionId: connection.id,
    sessionsRevoked,
  });
  deps.out(
    `applied: connection ${connection.id} ${verb}d, ${sessionsRevoked} session(s) ended, reference ${reference}`,
  );
  return { applied: true, sessionsRevoked };
};

export const ssoConnectionList = async (
  deps: OperatorDeps,
  input: { readonly organisation?: string | undefined },
): Promise<void> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const rows = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identitySsoConnection.findMany({
      where: { tenantId },
      include: { domains: { select: { domain: true } } },
      orderBy: { createdAt: 'asc' },
    }),
  );
  if (rows.length === 0) deps.out('no company sign-in connections');
  for (const row of rows) {
    const accounts = await deps.prisma.withTenant(tenantId, (tx) =>
      tx.identityAccount.groupBy({
        by: ['externalId'],
        where: { tenantId, identityProviderId: row.id },
        _count: true,
      }),
    );
    const total = accounts.reduce((sum, group) => sum + group._count, 0);
    const waiting = accounts.find((group) => group.externalId === null)?._count ?? 0;
    deps.out(
      `${row.id} ${row.provider} directory=${row.directoryId} enabled=${row.enabled} ` +
        `trust-provider-mfa=${row.trustProviderMfa} domains=${row.domains.map((d) => d.domain).join(',')} ` +
        `accounts=${total} (not yet signed in: ${waiting})`,
    );
  }
};

// -------------------------------------------------------------------------------------------------
// Accounts
// -------------------------------------------------------------------------------------------------

/**
 * Create an account that signs in only through a company connection: no password, status active,
 * bound to the person at their first company sign-in. Optionally grants one role.
 */
export const ssoAccountCreate = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly connectionId?: string | undefined;
    readonly account?: string | undefined;
    readonly role?: string | undefined;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<{ readonly accountId: UserId | undefined; readonly applied: boolean }> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const connection = await connectionOf(deps, tenantId, input.connectionId);
  const email = (input.account ?? '').trim().toLowerCase();
  const domain = domainOf(email);
  if (domain === undefined)
    throw new OperatorError('--account must be the person’s work email address');
  if (!connection.domains.includes(domain)) {
    throw new OperatorError(
      `${domain} is not a domain of this connection (${connection.domains.join(', ')})`,
    );
  }
  if ((await deps.security.directory.findByIdentifier(tenantId, email)) !== undefined) {
    throw new OperatorError(
      'An account with that address already exists in this organisation. Use sso-account-convert to move it to company sign-in.',
    );
  }
  const role = input.role?.trim();
  if (role !== undefined && role !== '') {
    const known = (await deps.security.roles.listRoles(tenantId)).some(
      (entry) => entry.id === role,
    );
    if (!known) throw new OperatorError(`No role ${role} in that organisation`);
  }

  if (!input.apply) {
    deps.out(
      `dry run: would create a company sign-in account on connection ${connection.id}` +
        `${role ? ` with role ${role}` : ''}; nothing changed (add --apply)`,
    );
    return { accountId: undefined, applied: false };
  }
  const reference = requireReference(input.reference);
  const id = randomUUID() as UserId;
  await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identityAccount.create({
      data: {
        id,
        tenantId,
        identifier: (input.account ?? '').trim(),
        identifierNormalized: email,
        passwordHash: null,
        status: 'active',
        identitySource: 'federated',
        identityProviderId: connection.id,
        externalId: null,
        createdBy: `operator:${reference}`,
        updatedBy: `operator:${reference}`,
      },
    }),
  );
  if (role !== undefined && role !== '') {
    await deps.security.roles.assign({
      tenantId,
      userId: id,
      roleId: role,
      assignedAt: Date.now(),
    });
  }
  await audit(
    deps,
    tenantId,
    'auth.provider.linked',
    reference,
    {
      stage: 'pre-created',
      connectionId: connection.id,
      provider: connection.provider,
      role: role ?? null,
    },
    { type: 'account', id },
  );
  deps.out(
    `applied: account ${id} created for company sign-in on connection ${connection.id}` +
      `${role ? `, role ${role}` : ''}, reference ${reference}`,
  );
  return { accountId: id, applied: true };
};

/**
 * Move an existing password account to company sign-in: the password is removed, every session,
 * refresh lineage and outstanding reset link ends, and the account is bound at its next company
 * sign-in. Roles, MFA enrollment and the account id are kept, so Work, Control and every product
 * that refers to the account by its `sub` see no change.
 *
 * Refused when it would leave the organisation with no active password account: company sign-in
 * keeps a local administrator as the way back in when the company's directory is unreachable or
 * misconfigured (`docs/runbooks/sso.md`, "Break-glass").
 */
export const ssoAccountConvert = async (
  deps: OperatorDeps,
  input: {
    readonly organisation?: string | undefined;
    readonly connectionId?: string | undefined;
    readonly account?: string | undefined;
    readonly accountId?: string | undefined;
    readonly reference?: string | undefined;
    readonly apply: boolean;
  },
): Promise<{ readonly accountId: UserId; readonly applied: boolean }> => {
  const tenantId = await tenantOf(deps, input.organisation);
  const connection = await connectionOf(deps, tenantId, input.connectionId);
  const byIdentifier = input.account !== undefined && input.account.trim() !== '';
  const byId = input.accountId !== undefined && input.accountId.trim() !== '';
  if (byIdentifier === byId) {
    throw new OperatorError('Give exactly one of --account-id (preferred) or --account');
  }
  const account = byId
    ? await deps.security.directory.findById(tenantId, input.accountId!.trim() as UserId)
    : await deps.security.directory.findByIdentifier(tenantId, input.account!);
  if (account === undefined) throw new OperatorError('No such account in that organisation');
  const userId = account.userId;

  const row = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identityAccount.findFirst({
      where: { tenantId, id: userId },
      select: { identitySource: true, identifierNormalized: true },
    }),
  );
  if (row === null) throw new OperatorError('No such account in that organisation');
  if (row.identitySource !== 'local') {
    throw new OperatorError('That account already signs in through a company connection');
  }
  const domain = domainOf(row.identifierNormalized);
  if (domain === undefined || !connection.domains.includes(domain)) {
    throw new OperatorError(
      `The account’s address is not in a domain of this connection (${connection.domains.join(', ')})`,
    );
  }
  const otherLocal = await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identityAccount.count({
      where: { tenantId, identitySource: 'local', status: 'active', id: { not: userId } },
    }),
  );
  if (otherLocal === 0) {
    throw new OperatorError(
      'Refused: this is the organisation’s last active password account. Keep one as break-glass.',
    );
  }

  if (!input.apply) {
    deps.out(
      `dry run: would move account ${userId} to company sign-in on connection ${connection.id}, ` +
        'removing its password and ending its sessions; nothing changed (add --apply)',
    );
    return { accountId: userId, applied: false };
  }
  const reference = requireReference(input.reference);
  await deps.prisma.withTenant(tenantId, (tx) =>
    tx.identityAccount.update({
      where: { id: userId },
      data: {
        identitySource: 'federated',
        identityProviderId: connection.id,
        externalId: null,
        passwordHash: null,
        passwordAlgorithm: null,
        passwordUpdatedAt: null,
        mustChangePassword: false,
        updatedBy: `operator:${reference}`,
      },
    }),
  );
  const outcome = await deps.security.lockdown.suspectedCompromise(
    tenantId,
    userId,
    actor(reference),
  );
  await deps.security.recovery.revokeOutstanding(tenantId, userId);
  await audit(
    deps,
    tenantId,
    'auth.provider.linked',
    reference,
    { stage: 'converted', connectionId: connection.id, provider: connection.provider },
    { type: 'account', id: userId },
  );
  deps.out(
    `applied: account ${userId} moved to company sign-in on connection ${connection.id}, password removed, ` +
      `${outcome.sessions} session(s) ended, reference ${reference}`,
  );
  return { accountId: userId, applied: true };
};
