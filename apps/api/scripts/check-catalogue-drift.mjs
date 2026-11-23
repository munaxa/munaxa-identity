#!/usr/bin/env node
/**
 * Fail the build when a seeded Work role names a permission Munaxa Work no longer declares.
 *
 * Without this the failure is silent and remote: Work drops the unknown grant with a reason nobody
 * reads, the operator sees a 403, and the cause is a file in another repository that moved three
 * weeks ago. The drop is the *safe* behaviour — it is a denial, never an escalation — but a safe
 * failure that takes an afternoon to diagnose is still worth turning into a red build.
 *
 * It also refuses the two grant shapes Work will not accept, so a role that cannot work is caught
 * before it is provisioned rather than after somebody signs in with it.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const catalogue = JSON.parse(
  readFileSync(resolve(here, '../../../artifacts/work-permissions.json'), 'utf8'),
);
const sources = ['seed-work-roles.mjs', 'work-roles.mjs'].map((file) => [
  file,
  readFileSync(resolve(here, file), 'utf8'),
]);

const declared = new Set(catalogue);
const problems = [];

if (catalogue.length === 0) problems.push('The Work permission catalogue is empty.');

for (const grant of catalogue) {
  if (typeof grant !== 'string' || !grant.startsWith('work:')) {
    problems.push(`Catalogue entry ${JSON.stringify(grant)} is not a work: grant.`);
  } else if (grant.includes('*')) {
    problems.push(`Catalogue entry ${grant} contains a wildcard. Munaxa Work refuses these.`);
  } else if (!/^work:[a-z0-9][a-z0-9_-]*(?::[a-z0-9][a-z0-9_-]*)*$/.test(grant)) {
    problems.push(`Catalogue entry ${grant} is not in Platform's resource:action grammar.`);
  }
}

// Every literal `work:…` string written in the role definitions must be a declared grant. Roles are
// composed mostly from module filters, and the few literals (the decisions, and the reads a
// persona needs beside its own module) are exactly where drift becomes possible.
for (const [file, source] of sources) {
  for (const [, literal] of source.matchAll(/'(work:[^']+)'/g)) {
    if (!declared.has(literal))
      problems.push(`${file} names ${literal}, which Work does not declare.`);
  }
}

if (problems.length > 0) {
  process.stderr.write(
    `Work permission catalogue drift:\n  - ${problems.join('\n  - ')}\n\n` +
      'Refresh artifacts/work-permissions.json from munaxa-work:\n' +
      '  node scripts/emit-permission-catalogue.mjs > ../munaxa-identity/artifacts/work-permissions.json\n',
  );
  process.exit(1);
}

process.stdout.write(`Work permission catalogue: ${catalogue.length} grants, no drift.\n`);
