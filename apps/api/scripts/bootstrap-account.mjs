#!/usr/bin/env node
/**
 * Create the first account in an organisation, and grant it a role.
 *
 * **Administrative, not public.** There is no self-registration endpoint in this service and this
 * script is not a substitute for one: it is run by an operator with the database URL in hand, which
 * is a credential they already hold. Every other account is created through permission-gated admin
 * routes once one administrator exists — this solves only the chicken-and-egg.
 *
 * **Idempotent.** A second run reports what it found and writes nothing. Re-hashing the password
 * would move `password_updated_at` and could overwrite a password somebody deliberately changed.
 *
 * **It validates the password against the real policy** rather than exempting itself. A bootstrap
 * that accepts a weak password is how the weakest credential in a deployment ends up being the
 * first one, on the account with the most reach.
 *
 * **It connects as the migration owner, not as the application role**, because creating an
 * organisation is provisioning: `identity_app` holds `select` on `identity_tenant` and nothing
 * more, deliberately, so a compromised service cannot invent an organisation to put accounts in.
 * Row-level security still applies — the owner is not a superuser and every table carries FORCE —
 * so this script sets a tenant context exactly as the service does.
 *
 *   DIRECT_DATABASE_URL=… IDENTITY_OWNER_EMAIL=… IDENTITY_OWNER_PASSWORD=… \
 *     node apps/api/scripts/bootstrap-account.mjs --organisation acme [--role work-staging-operator]
 */
import { randomUUID } from 'node:crypto';

import { PasswordPolicyService, StaticBreachRegistry } from '@munaxa/auth';
import { defaultPasswordHasher } from '@munaxa/crypto';
import pg from 'pg';

const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
};

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const withTenant = async (client, tenantId, work) => {
  await client.query('begin');
  try {
    await client.query('select set_config($1, $2, true)', ['identity.tenant_id', tenantId]);
    const result = await work();
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback').catch(() => undefined);
    throw error;
  }
};

const run = async () => {
  const connection = process.env.DIRECT_DATABASE_URL ?? process.env.TEST_DIRECT_DATABASE_URL;
  const email = (process.env.IDENTITY_OWNER_EMAIL ?? '').trim();
  const password = process.env.IDENTITY_OWNER_PASSWORD ?? '';
  const slug = (argument('organisation') ?? process.env.IDENTITY_DEFAULT_ORGANISATION ?? '').trim();
  const organisationName = argument('organisation-name') ?? slug;
  const roleKey = argument('role');

  if (!connection) {
    fail(
      'Set DIRECT_DATABASE_URL to a migrated Identity database, as the migration owner. Provisioning ' +
        'an organisation is not something the application role may do, and this script does not ask it to.',
    );
  }
  if (email === '') fail('Set IDENTITY_OWNER_EMAIL.');
  if (password === '')
    fail('Set IDENTITY_OWNER_PASSWORD. It is never echoed and never stored in plaintext.');
  if (slug === '')
    fail('Give --organisation <slug>: an account belongs to exactly one organisation.');

  // The real policy, not a relaxed one. Violations are listed all at once so an operator fixes
  // them in one attempt.
  const policy = new PasswordPolicyService({ breachRegistry: new StaticBreachRegistry() });
  const validation = await policy.validate(password, { userInfo: [email] });
  if (!validation.valid) {
    fail(
      `IDENTITY_OWNER_PASSWORD does not meet the password policy:\n  - ${validation.violations
        .map((violation) => violation.message ?? violation.rule ?? String(violation))
        .join('\n  - ')}`,
    );
  }

  const pool = new pg.Pool({ connectionString: connection, max: 1 });
  const client = await pool.connect();

  try {
    // The organisation is provisioned here too: an account cannot exist without one, and asking an
    // operator to write the row by hand is the manual SQL step this script exists to remove.
    const tenantId = randomUUID();
    const tenant = await client.query(
      `insert into identity_tenant (id, key, name, status, created_at)
       values ($1, $2, $3, 'active', now())
       on conflict (key) do update set key = excluded.key
       returning id`,
      [tenantId, slug.toLowerCase(), organisationName],
    );
    const organisation = tenant.rows[0].id;

    const normalized = email.toLowerCase();
    const existing = await withTenant(client, organisation, () =>
      client.query(
        'select id, status from identity_account where tenant_id = $1 and identifier_normalized = $2',
        [organisation, normalized],
      ),
    );

    let accountId = existing.rows[0]?.id;

    if (accountId !== undefined) {
      process.stdout.write(
        `Already bootstrapped. ${email} exists in organisation ${slug} with status ${existing.rows[0].status}.` +
          ' No password was written.\n',
      );
    } else {
      const encoded = await defaultPasswordHasher.hash(password);
      accountId = randomUUID();

      await withTenant(client, organisation, () =>
        client.query(
          `insert into identity_account
             (id, tenant_id, identifier, identifier_normalized, password_hash, password_algorithm,
              password_updated_at, status, token_version, mfa_enrolled, must_change_password,
              identity_source, created_at, created_by, updated_at, updated_by, version)
           values ($1, $2, $3, $4, $5, $6, now(), 'active', 1, false, false, 'local', now(),
                   'system:bootstrap', now(), 'system:bootstrap', 1)`,
          [accountId, organisation, email, normalized, encoded, encoded.split('$')[1] ?? 'unknown'],
        ),
      );
      process.stdout.write(`Created ${email} in organisation ${slug}.\n`);
    }

    if (roleKey !== undefined) {
      const assigned = await withTenant(client, organisation, async () => {
        const role = await client.query(
          'select id from identity_role where tenant_id = $1 and key = $2',
          [organisation, roleKey],
        );
        if (role.rows[0] === undefined) return false;
        await client.query(
          `insert into identity_role_assignment (tenant_id, account_id, role_id, scope, assigned_at, assigned_by)
           values ($1, $2, $3, '', now(), 'system:bootstrap')
           on conflict (tenant_id, account_id, role_id, scope) do nothing`,
          [organisation, accountId, role.rows[0].id],
        );
        return true;
      });
      if (!assigned)
        fail(
          `No role "${roleKey}" in organisation ${slug}. Run db:seed-work-roles or db:seed-control-roles first.`,
        );
      // Unscoped, deliberately: a Platform scope suffixes every Work grant in the role, producing
      // strings Munaxa Work drops as undeclared.
      process.stdout.write(`Assigned ${roleKey}, unscoped.\n`);
    }

    process.stdout.write(
      `\n  organisation  ${organisation}  (${slug})\n` +
        `  sub           ${accountId}\n\n` +
        'That `sub` is the value Munaxa Work needs:\n' +
        `  pnpm db:bootstrap --platform-user-id ${accountId}\n`,
    );
  } finally {
    client.release();
    await pool.end();
  }
};

await run().catch((error) =>
  fail(`Bootstrap failed: ${error instanceof Error ? error.message : String(error)}`),
);
