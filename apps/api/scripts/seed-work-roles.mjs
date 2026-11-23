#!/usr/bin/env node
/**
 * Provision the Munaxa Work roles an organisation grants.
 *
 * Every grant is read from `artifacts/work-permissions.json`, which Munaxa Work generated. Nothing
 * here invents a Work permission: the role definitions in `work-roles.mjs` name *groups* — a
 * module, a module filtered to its reads, a module without its decisions — and the decisions
 * themselves by name, and every name is expanded and checked against the catalogue. A group that expands to nothing is an error rather than an empty role, because an
 * empty role is a person who can sign in and do nothing, diagnosed as a broken product.
 *
 * Three rules are enforced here rather than trusted:
 *
 *   - **No wildcard.** Munaxa Work refuses any grant containing `*` by construction, so a wildcard
 *     seeded here would read as "all of Work" and authorize nothing.
 *   - **No scope.** A Platform scope suffixes every permission in the role, producing a string Work
 *     drops as undeclared — a silent, total denial that looks like a permission that simply does
 *     not work.
 *   - **Nothing undeclared.** A grant absent from the catalogue is dropped by Work with a reason;
 *     catching it here makes it a provisioning failure instead of a 403 nobody can explain.
 *
 * Run as the migration owner: seeding a system role is provisioning, and the application role
 * writes roles only through the permission-gated administration path.
 *
 *   DIRECT_DATABASE_URL=… node apps/api/scripts/seed-work-roles.mjs --organisation <slug>
 *
 * The eight Testing persona roles (MW-003, keys `work-testing-*`) are provisioned only on request,
 * and only outside production:
 *
 *   DIRECT_DATABASE_URL=… node apps/api/scripts/seed-work-roles.mjs --organisation <slug> \
 *     --testing-personas --environment testing
 *
 * See `testingPersonasRefusal` for exactly what is refused and why.
 */
import { randomUUID } from 'node:crypto';

import pg from 'pg';

import {
  TESTING_PERSONA_PREFIX,
  testingPersonasRefusal,
  workCatalogue,
  workRoles,
} from './work-roles.mjs';

const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
};
const flag = (name) => process.argv.includes(`--${name}`);

const declared = new Set(workCatalogue());

/** The role definitions live in `work-roles.mjs`, where the token-size test measures them too. */
const { staging, testing } = workRoles();

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const run = async () => {
  const withPersonas = flag('testing-personas');

  // Before anything connects: a refused run must not be able to write a single row.
  if (withPersonas) {
    const refusal = testingPersonasRefusal({
      environment: argument('environment'),
      nodeEnv: process.env.NODE_ENV,
      baseUrl: process.env.IDENTITY_BASE_URL,
    });
    if (refusal !== undefined) fail(`Refused: ${refusal}`);
  }
  const roles = withPersonas ? [...staging, ...testing] : staging;

  for (const role of roles) {
    if (role.key.startsWith(TESTING_PERSONA_PREFIX) !== testing.includes(role))
      fail(`Role ${role.key} is misfiled: only Testing personas carry ${TESTING_PERSONA_PREFIX}.`);
  }

  const connection =
    process.env.DIRECT_DATABASE_URL ??
    process.env.DATABASE_MIGRATION_URL ??
    process.env.TEST_DIRECT_DATABASE_URL;
  const slug = (argument('organisation') ?? process.env.IDENTITY_DEFAULT_ORGANISATION ?? '').trim();

  if (!connection)
    fail(
      'Set DIRECT_DATABASE_URL (or DATABASE_MIGRATION_URL) to a migrated Identity database, as the migration owner.',
    );
  if (slug === '') fail('Give --organisation <slug>: roles are per-organisation, never global.');

  const pool = new pg.Pool({ connectionString: connection, max: 1 });
  const client = await pool.connect();

  try {
    const tenant = await client.query(
      'select id from identity_tenant where key = $1 and status = $2',
      [slug.toLowerCase(), 'active'],
    );
    const tenantId = tenant.rows[0]?.id;
    if (tenantId === undefined)
      fail(`No active organisation "${slug}". Create it before seeding roles.`);

    for (const role of roles) {
      const grants = role.grants;

      if (grants.length === 0)
        fail(`Role ${role.key} expanded to no grants. The catalogue moved under it.`);
      for (const grant of grants) {
        if (grant.includes('*'))
          fail(`Role ${role.key} contains a wildcard (${grant}). Work refuses these.`);
        if (!declared.has(grant))
          fail(`Role ${role.key} names ${grant}, which Munaxa Work does not declare.`);
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

      process.stdout.write(`${role.key}: ${grants.length} Work grants in organisation ${slug}.\n`);
    }
    process.stdout.write(
      'Assignments are not made here. Grant a role to an account with db:bootstrap-account --role.\n\nRESTART IDENTITY BEFORE THESE ROLES TAKE EFFECT.\n  This script writes role rows straight to the database, which is correct for provisioning and\n  insufficient on its own: the PermissionResolver caches role *definitions* in process,\n  and that cache is invalidated by RoleAdministration — a path a standalone script connecting\n  over pg cannot take. Neither the 60s Redis entry nor FLUSHALL clears it. Measured: a role\n  edited here kept resolving its previous grants indefinitely, and one restart fixed it.\n  This matters most when a grant is REMOVED, because the stale definition is the permissive one.\n',
    );
  } finally {
    client.release();
    await pool.end();
  }
};

await run().catch((error) =>
  fail(`Seeding failed: ${error instanceof Error ? error.message : String(error)}`),
);
