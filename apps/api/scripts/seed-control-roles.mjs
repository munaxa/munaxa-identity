#!/usr/bin/env node
/**
 * Provision the Munaxa Control operator roles in the operator organisation.
 *
 * Every grant is read from `artifacts/control-permissions.json`, which Munaxa Control generated
 * (`pnpm catalogue:emit` there). Nothing here types a Control permission: the roles below are
 * filters over the catalogue, and a filter that matches nothing is an error rather than an empty
 * role, for the same reason as in `seed-work-roles.mjs`.
 *
 * Control refuses an operator token whose `tid` is not its `OPERATOR_ORGANISATION_ID`, so these
 * roles mean something only in that one organisation. Seed them there and nowhere else: a
 * customer organisation holding `control:*` grants authorizes nothing today, and is one
 * misconfiguration away from authorizing everything.
 *
 * The same three rules as the Work seed are enforced rather than trusted: no wildcard, no scope,
 * nothing the catalogue does not declare. Control drops an undeclared grant, so catching it here
 * turns a 403 nobody can explain into a provisioning failure.
 *
 * Run as the migration owner, after the organisation exists (`db:bootstrap-account` creates it):
 *
 *   DIRECT_DATABASE_URL=… node apps/api/scripts/seed-control-roles.mjs --organisation <slug>
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

import pg from 'pg';

const here = dirname(fileURLToPath(import.meta.url));
const CATALOGUE = resolve(here, '../../../artifacts/control-permissions.json');

const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
};

const catalogue = JSON.parse(readFileSync(CATALOGUE, 'utf8'));
const declared = new Set(catalogue);

/**
 * The operator roles.
 *
 * The administrator holds the whole catalogue: issuing licences, managing deployment credentials
 * and editing customers are the reason an operator signs in at all. The viewer holds only the
 * reads, so support staff can look without being able to issue, and so Testing can show a real
 * 403 on a write.
 */
const ROLES = [
  {
    key: 'control-operator-admin',
    name: 'Munaxa Control — operator administrator',
    description:
      'Every Munaxa Control operator permission: customers, subscriptions, catalogue, licences, ' +
      'deployment credentials, usage and audit. For Munaxa Group staff in the operator organisation only.',
    grants: () => [...catalogue],
  },
  {
    key: 'control-operator-viewer',
    name: 'Munaxa Control — operator viewer',
    description:
      'Read-only Munaxa Control: customers, subscriptions, catalogue, usage and audit. Cannot ' +
      'issue licences, manage credentials or change anything.',
    grants: () => catalogue.filter((grant) => grant.endsWith(':read')),
  },
];

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const run = async () => {
  const connection =
    process.env.DIRECT_DATABASE_URL ??
    process.env.DATABASE_MIGRATION_URL ??
    process.env.TEST_DIRECT_DATABASE_URL;
  const slug = (argument('organisation') ?? '').trim();

  if (!connection)
    fail(
      'Set DIRECT_DATABASE_URL (or DATABASE_MIGRATION_URL) to a migrated Identity database, as the migration owner.',
    );
  // No fallback to IDENTITY_DEFAULT_ORGANISATION: that is the customer-facing default, and these
  // grants belong to the operator organisation only.
  if (slug === '') fail('Give --organisation <slug>: the operator organisation, named explicitly.');

  for (const grant of catalogue) {
    if (!grant.startsWith('control:'))
      fail(`The catalogue holds ${grant}, which is not a Control permission. Refresh it.`);
  }

  const pool = new pg.Pool({ connectionString: connection, max: 1 });
  const client = await pool.connect();

  try {
    const tenant = await client.query(
      'select id from identity_tenant where key = $1 and status = $2',
      [slug.toLowerCase(), 'active'],
    );
    const tenantId = tenant.rows[0]?.id;
    if (tenantId === undefined)
      fail(`No active organisation "${slug}". Create it with db:bootstrap-account first.`);

    for (const role of ROLES) {
      const grants = role.grants();

      if (grants.length === 0)
        fail(`Role ${role.key} expanded to no grants. The catalogue moved under it.`);
      for (const grant of grants) {
        if (grant.includes('*'))
          fail(`Role ${role.key} contains a wildcard (${grant}). Control refuses these.`);
        if (!declared.has(grant))
          fail(`Role ${role.key} names ${grant}, which Munaxa Control does not declare.`);
      }

      await client.query('begin');
      await client.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
      await client.query(
        `insert into identity_role (id, tenant_id, key, name, description, permissions, inherits, system, created_at, updated_at)
         values ($1, $2, $3, $4, $5, $6, '{}', true, now(), now())
         on conflict (tenant_id, key) do update
           set name = excluded.name, description = excluded.description,
               permissions = excluded.permissions, updated_at = now()`,
        [randomUUID(), tenantId, role.key, role.name, role.description, grants],
      );
      await client.query('commit');

      process.stdout.write(
        `${role.key}: ${grants.length} Control grants in organisation ${slug}.\n`,
      );
    }
    process.stdout.write(
      `\n  OPERATOR_ORGANISATION_ID  ${tenantId}\n\n` +
        'Assignments are not made here. Grant a role to an account with db:bootstrap-account --role.\n\n' +
        'RESTART IDENTITY BEFORE THESE ROLES TAKE EFFECT: the PermissionResolver caches role\n' +
        'definitions in process, and a script writing over pg cannot invalidate that cache.\n',
    );
  } finally {
    client.release();
    await pool.end();
  }
};

await run().catch((error) =>
  fail(`Seeding failed: ${error instanceof Error ? error.message : String(error)}`),
);
