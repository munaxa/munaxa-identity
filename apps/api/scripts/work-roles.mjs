#!/usr/bin/env node
/**
 * The Munaxa Work roles Identity provisions, as data: no database, no dependency, no side effect.
 *
 * `seed-work-roles.mjs` writes these to an organisation; the token-size integration test measures
 * them; Munaxa Work's persona test reads a copy of the JSON this file prints. One definition, three
 * readers, so the role that is measured is the role that is seeded is the role Work is tested with.
 *
 *   node apps/api/scripts/work-roles.mjs                      # every role, as JSON
 *   node apps/api/scripts/work-roles.mjs --testing-personas   # the eight Testing personas only
 *
 * Every grant is read from `artifacts/work-permissions.json`, which Munaxa Work generated. The
 * definitions name *groups* — a module, a module's reads, a module without its decisions — and the
 * few single grants named below are the decisions themselves, written out precisely so that where
 * each one lives is something a reviewer can read rather than derive. Every name is checked against
 * the catalogue when the roles are built, and `check-catalogue-drift.mjs` checks every literal here.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const CATALOGUE_PATH = resolve(here, '../../../artifacts/work-permissions.json');

/** The Work permission catalogue, in Platform's `work:` grant form. */
export const workCatalogue = () => JSON.parse(readFileSync(CATALOGUE_PATH, 'utf8'));

/**
 * The decisions: every grant that approves, finalizes, pays out, reverses or decides something
 * another person prepared.
 *
 * Segregation of duties for Testing is defined over this list, the same rule for every persona:
 * a role holding a decision in a module holds nothing else in that module but reads and grants over
 * the holder's own record. So nobody decides what they prepared:
 *
 *   - payroll and compensation decisions belong to the payroll approver, and the payroll preparer
 *     holds none of them;
 *   - the career decisions (confirming a successor, deciding a mobility recommendation) belong to
 *     the HR records officer, and the manager, who nominates and recommends, holds neither — the
 *     career module separates the two acts and nothing in it refuses a self-decision;
 *   - every other decision belongs to the approver (manager), who prepares none of the records
 *     those decisions are taken on.
 *
 * `payroll.payment` (the payment instruction file) and `payroll.reverse` are on the approver's side
 * deliberately: a preparer who could release the file that pays people, or reverse a finalized run,
 * would have the whole cycle in one pair of hands.
 */
export const PAYROLL_DECISIONS = [
  'work:payroll:approve',
  'work:payroll:finalize',
  'work:payroll:payment',
  'work:payroll:reverse',
  'work:compensation:approve',
];

export const OTHER_DECISIONS = [
  'work:attendance:approve',
  'work:attendance:correct:approve',
  'work:leave:approve',
  'work:letter:approve',
  'work:organization:establishment:approve',
  'work:recruitment:offer:approve',
  'work:recruitment:requisition:approve',
  'work:workflow:approval:decide',
];

/** Recording that the organisation agrees with a nomination or a recommendation the manager made. */
export const CAREER_DECISIONS = ['work:career:mobility:decide', 'work:career:successor:confirm'];

export const DECISIONS = [...PAYROLL_DECISIONS, ...CAREER_DECISIONS, ...OTHER_DECISIONS];

/** The prefix that marks a role as provisioned for the Testing environment and nowhere else. */
export const TESTING_PERSONA_PREFIX = 'work-testing-';

/** The environments a Testing persona may be provisioned in, as `--environment` names them. */
export const NON_PRODUCTION_ENVIRONMENTS = ['testing', 'staging', 'development', 'ci'];

/**
 * Hosts that are not production: Testing's own zone, loopback, and the reserved `.example` names
 * tests use. Anything else is treated as production, so a host this does not recognise is refused.
 * Not `.internal`: production's private service names (`prod.munaxa.internal`) end in it too.
 */
const isNonProductionHost = (host) =>
  host.endsWith('.test.munaxa.com') ||
  host === 'localhost' ||
  host.endsWith('.localhost') ||
  host === '127.0.0.1' ||
  host === '::1' ||
  host.endsWith('.example');

/**
 * Why the Testing personas must not be provisioned here, or `undefined` when they may be.
 *
 * `NODE_ENV` cannot answer it: Testing runs Identity with `NODE_ENV=production`, exactly as
 * production does, and an operator's shell may not set it at all. So each of these is required,
 * whatever `NODE_ENV` says, and each is checked rather than trusted:
 *
 *   1. the operator names the environment (`--environment testing`, or another non-production
 *      name) — an explicit statement, never a default;
 *   2. `IDENTITY_BASE_URL` is set and names a non-production host (`id.test.munaxa.com`): it is the
 *      token issuer, so it says which Identity these roles would sign into;
 *   3. the database the script would write to is not production's: `databaseRefusal` in
 *      `database-target.mjs`, which reads the connection string with pg's own parser and so has a
 *      dependency this file deliberately does not.
 *
 * Checked before any connection. What neither can see is a tunnel: a production database reached
 * through `localhost` is caught only by 1 and 2, which is why neither is optional.
 */
export const testingPersonasRefusal = ({ environment, baseUrl }) => {
  if (environment === undefined || environment.trim() === '')
    return 'Testing personas need --environment <name> (testing, staging, development or ci).';
  if (!NON_PRODUCTION_ENVIRONMENTS.includes(environment.trim().toLowerCase()))
    return `Testing personas are never provisioned in "${environment}". They are for Testing only.`;

  if (baseUrl === undefined || baseUrl.trim() === '')
    return 'Set IDENTITY_BASE_URL to the Testing Identity (https://id.test.munaxa.com) to confirm the target.';
  let host;
  try {
    host = new URL(baseUrl).hostname.toLowerCase().replace(/^\[|\]$/g, '');
  } catch {
    return 'IDENTITY_BASE_URL is not a URL, so the target Identity cannot be confirmed as non-production.';
  }
  if (!isNonProductionHost(host))
    return `IDENTITY_BASE_URL names ${host}, not a non-production host. Testing personas are refused there.`;

  return undefined;
};

/**
 * Build the roles against a catalogue.
 *
 * Each `grants` list is deduplicated and sorted, which makes the output stable and diffable, and
 * every name in it is a declared grant or this throws.
 */
export const workRoles = (catalogue = workCatalogue()) => {
  const declared = new Set(catalogue);

  const named = (...grants) => {
    for (const grant of grants) {
      if (!declared.has(grant)) throw new Error(`${grant} is not in the Work catalogue.`);
    }
    return grants;
  };
  /** `work:<module>:…` — every grant in one Work module. */
  const module_ = (name) => catalogue.filter((grant) => grant.startsWith(`work:${name}:`));
  /** The same, filtered to grants whose final segment is `read`. */
  const reads = (name) => module_(name).filter((grant) => grant.endsWith(':read'));
  /** A module without its decisions. */
  const prepares = (name) => module_(name).filter((grant) => !DECISIONS.includes(grant));
  /** Grants a person holds over their own record only. */
  const own = () =>
    catalogue.filter((grant) => grant.endsWith('-own') || grant.endsWith(':read-about-self'));

  const role = (definition) => {
    const grants = [...new Set(definition.grants)].sort();
    return { ...definition, grants };
  };

  /**
   * The staging roles.
   *
   * The operator is composed to satisfy both halves of the acceptance test with real permissions: it
   * can read a person (`work:people:person:read`) and it deliberately holds nothing from payroll, so
   * `work:payroll:accounting` is a genuine 403 rather than a fabricated one.
   *
   * The recruiter exists so that shared staging can be tested by more than one person at once, and
   * so that "these two accounts see different things" is something the environment can actually
   * demonstrate. The two overlap only on People reads and each holds a whole module the other does
   * not, which is what makes a cross-check meaningful in both directions.
   */
  const staging = [
    role({
      key: 'work-staging-operator',
      name: 'Munaxa Work — staging operator',
      description:
        'Identity, People (read), Leave and Attendance (read) in Munaxa Work. Deliberately excludes payroll and compensation, so a forbidden request has something real to be forbidden from.',
      grants: [
        ...module_('identity'),
        ...reads('people'),
        ...module_('leave'),
        ...reads('attendance'),
      ],
    }),
    role({
      key: 'work-staging-recruiter',
      name: 'Munaxa Work — staging recruiter',
      description:
        'Recruitment and onboarding in Munaxa Work, plus People (read). Deliberately holds nothing ' +
        'from leave or attendance, which the operator role does hold — so the two roles differ in ' +
        'both directions and neither is a subset of the other. A multi-user test where one role ' +
        'contains the other proves only that grants accumulate, not that they are separated.',
      grants: [...module_('recruitment'), ...module_('onboarding'), ...reads('people')],
    }),
  ];

  /**
   * The Testing personas (MW-003).
   *
   * Eight roles that between them hold every grant in the catalogue, so that every Work screen can
   * be reached by somebody in Testing, and each of which fits a browser cookie with a quarter of
   * the cookie to spare (`packages/testing/src/token-size.integration.test.ts`). A role holding the
   * whole catalogue cannot be issued as one token (MW-012); eight can.
   *
   * Where a module sits is decided by who would do the work in a real organisation, and where that
   * leaves a module with no natural owner small enough to fit, by the cookie: Relations sits with
   * the HR records officer, Assets and Learning with the payroll preparer, and Documents and Letters
   * with the recruiter. None of those placements puts a decision next to what it decides. These are Testing personas for reaching screens,
   * not a recommended production role design.
   *
   * Testing only. `seed-work-roles.mjs` provisions them only when asked to, and refuses to in
   * production (see its guard).
   */
  const testing = [
    role({
      key: 'work-testing-org-admin',
      name: 'Munaxa Work - Testing only - organization administrator',
      description:
        'TESTING ONLY. Organization structure, Work identity administration (users, memberships, ' +
        'invitations, portals, delegations) and workflow configuration. Holds no decision: ' +
        'establishment approval and workflow approval belong to the approver persona.',
      grants: [...prepares('organization'), ...module_('identity'), ...prepares('workflow')],
    }),
    role({
      key: 'work-testing-hr-officer',
      name: 'Munaxa Work - Testing only - HR records officer',
      description:
        'TESTING ONLY. People records (including sensitive fields and identifiers), employment ' +
        'records and contracts, and employee relations cases. Decides career matters for the ' +
        'organisation (confirms successors, decides mobility recommendations) that the manager ' +
        'persona nominates and recommends, and prepares none of them.',
      grants: [
        ...module_('people'),
        ...module_('employment'),
        ...module_('relations'),
        ...CAREER_DECISIONS,
        ...named('work:career:mobility:read', 'work:career:succession:read'),
      ],
    }),
    role({
      key: 'work-testing-time-leave-officer',
      name: 'Munaxa Work - Testing only - time and leave officer',
      description:
        'TESTING ONLY. Attendance, rosters and schedules, and leave administration. Approves ' +
        'neither attendance nor leave: those belong to the approver persona.',
      grants: [...prepares('attendance'), ...prepares('leave'), ...reads('people')],
    }),
    role({
      key: 'work-testing-payroll-preparer',
      name: 'Munaxa Work - Testing only - payroll preparer',
      description:
        'TESTING ONLY. Payroll configuration, calculation, adjustment and accounting output, ' +
        'compensation administration, company assets and learning administration. Cannot ' +
        'approve, finalize, release payment for or reverse a payroll, and cannot approve a ' +
        'compensation change.',
      grants: [
        ...prepares('payroll'),
        ...prepares('compensation'),
        ...module_('assets'),
        ...module_('learning'),
        ...named(
          'work:people:person:read',
          'work:employment:employment:read',
          'work:employment:contract:read',
          'work:organization:legal-entity:read',
          'work:organization:cost-center:read',
        ),
      ],
    }),
    role({
      key: 'work-testing-payroll-approver',
      name: 'Munaxa Work - Testing only - payroll approver',
      description:
        'TESTING ONLY. Approves, finalizes, releases payment for and reverses payroll runs, and ' +
        'approves compensation changes, with the reads those decisions need. Prepares nothing: ' +
        'holds no payroll calculation, adjustment or configuration grant.',
      grants: [
        ...PAYROLL_DECISIONS,
        ...named(
          'work:payroll:read',
          'work:payroll:read-result',
          'work:compensation:read',
          'work:people:person:read',
          'work:employment:employment:read',
        ),
      ],
    }),
    role({
      key: 'work-testing-recruiter',
      name: 'Munaxa Work - Testing only - recruiter',
      description:
        'TESTING ONLY. Recruitment, onboarding, documents and letters. Approves neither ' +
        'requisitions, offers nor letters: those belong to the approver persona.',
      grants: [
        ...prepares('recruitment'),
        ...module_('onboarding'),
        ...module_('document'),
        ...prepares('letter'),
        ...named('work:people:person:read'),
      ],
    }),
    role({
      key: 'work-testing-manager',
      name: 'Munaxa Work - Testing only - approver and manager',
      description:
        'TESTING ONLY. Decides what the other personas prepare (attendance, leave, letters, ' +
        'establishment, requisitions, offers, workflow approvals), and runs performance and ' +
        'career for a team: nominates successors and recommends moves, which the HR records ' +
        'officer persona confirms or decides. Holds no payroll, compensation or career decision.',
      grants: [
        ...OTHER_DECISIONS,
        ...module_('performance'),
        ...prepares('career'),
        ...named(
          'work:workflow:instance:read',
          'work:attendance:read',
          'work:leave:read',
          'work:people:person:read',
        ),
      ],
    }),
    role({
      key: 'work-testing-employee',
      name: 'Munaxa Work - Testing only - employee',
      description:
        'TESTING ONLY. Self-service: their own attendance, leave, payslips, compensation, ' +
        'documents, learning, career and performance records, their own requests, and their ' +
        'profile and preferences. No grant over anybody else.',
      grants: [
        ...own(),
        ...named(
          'work:identity:invitation:accept',
          'work:identity:profile:read',
          'work:identity:preference:read',
          'work:identity:preference:manage',
          'work:attendance:correct:request',
          'work:performance:feedback:give',
          'work:workflow:approval:read-own',
        ),
      ],
    }),
  ];

  for (const { key, grants } of [...staging, ...testing]) {
    for (const grant of grants) {
      if (!declared.has(grant))
        throw new Error(`Role ${key} names ${grant}, which Work does not declare.`);
    }
  }

  return { staging, testing };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { staging, testing } = workRoles();
  const roles = process.argv.includes('--testing-personas') ? testing : [...staging, ...testing];
  process.stdout.write(`${JSON.stringify(roles, null, 2)}\n`);
}
