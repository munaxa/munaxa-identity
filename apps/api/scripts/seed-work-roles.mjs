#!/usr/bin/env node
/**
 * Provision the Munaxa Work roles an organisation grants.
 *
 * Every grant is read from `artifacts/work-permissions.json`, which Munaxa Work generated. Nothing
 * here types a Work permission, and nothing here invents one: the role definitions below name
 * *groups* — a module, or a module filtered to its reads — and the group is expanded against the
 * catalogue. A group that expands to nothing is an error rather than an empty role, because an
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
 * The connection — the owner credential and its verified TLS (`DATABASE_TLS_CA` against RDS) — is
 * the migration runner's, through `owner-connection.mjs`; see `docs/runbooks/migrations.md`.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

import { describeOwnerDatabase, ownerDatabase } from './owner-connection.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CATALOGUE = resolve(here, '../../../artifacts/work-permissions.json');

const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
};

const catalogue = JSON.parse(readFileSync(CATALOGUE, 'utf8'));
const declared = new Set(catalogue);

/** `work:<module>:…` — every grant in one Work module. */
const module_ = (name) => catalogue.filter((grant) => grant.startsWith(`work:${name}:`));
/** The same, filtered to grants whose final segment is `read`. */
const reads = (name) => module_(name).filter((grant) => grant.endsWith(':read'));

/**
 * The staging roles.
 *
 * The operator is composed to satisfy both halves of the acceptance test with real permissions: it
 * can read a person (`work:people:person:read`) and it deliberately holds nothing from payroll, so
 * `work:payroll:accounting` is a genuine 403 rather than a fabricated one.
 *
 * The recruiter exists so that shared staging can be tested by more than one person at once, and so
 * that "these two accounts see different things" is something the environment can actually
 * demonstrate. The two overlap only on People reads and each holds a whole module the other does
 * not, which is what makes a cross-check meaningful in both directions.
 */
const ROLES = [
  {
    key: 'work-staging-operator',
    name: 'Munaxa Work — staging operator',
    description:
      'Identity, People (read), Leave and Attendance (read) in Munaxa Work. Deliberately excludes payroll and compensation, so a forbidden request has something real to be forbidden from.',
    grants: () => [
      ...module_('identity'),
      ...reads('people'),
      ...module_('leave'),
      ...reads('attendance'),
    ],
  },
  {
    key: 'work-staging-recruiter',
    name: 'Munaxa Work — staging recruiter',
    description:
      'Recruitment and onboarding in Munaxa Work, plus People (read). Deliberately holds nothing ' +
      'from leave or attendance, which the operator role does hold — so the two roles differ in ' +
      'both directions and neither is a subset of the other. A multi-user test where one role ' +
      'contains the other proves only that grants accumulate, not that they are separated.',
    grants: () => [...module_('recruitment'), ...module_('onboarding'), ...reads('people')],
  },
];

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const run = async () => {
  // First, so a missing owner credential or an unverifiable TLS configuration stops the script
  // before anything else happens. It does not connect yet.
  const database = await ownerDatabase('munaxa-identity-seed-roles');
  const slug = (argument('organisation') ?? process.env.IDENTITY_DEFAULT_ORGANISATION ?? '').trim();

  if (slug === '') fail('Give --organisation <slug>: roles are per-organisation, never global.');

  process.stdout.write(describeOwnerDatabase(database.describe));
  const pool = database.openPool();
  const client = await pool.connect();

  try {
    const tenant = await client.query(
      'select id from identity_tenant where key = $1 and status = $2',
      [slug.toLowerCase(), 'active'],
    );
    const tenantId = tenant.rows[0]?.id;
    if (tenantId === undefined)
      fail(`No active organisation "${slug}". Create it before seeding roles.`);

    for (const role of ROLES) {
      const grants = role.grants();

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
