#!/usr/bin/env node
/**
 * Refresh Munaxa Work's permission catalogue from an explicitly named source.
 *
 * The catalogue is committed, so a clean clone of this repository builds, tests and deploys with no
 * external dependency at all — that property is the point and this script does not weaken it. What
 * this adds is a *stated* way to refresh it, because the alternative was a sentence in a README
 * assuming a sibling `../munaxa-work` directory, which is a machine-specific assumption dressed up
 * as a procedure.
 *
 * The source is always named. There is no default that reaches out to a network location, because a
 * silent fetch is how a build starts depending on something nobody declared.
 *
 *   node apps/api/scripts/refresh-work-catalogue.mjs --from ~/src/munaxa-work
 *   node apps/api/scripts/refresh-work-catalogue.mjs --from https://…/work-permissions.json
 *   node apps/api/scripts/refresh-work-catalogue.mjs --from ./downloaded.json --check
 *
 * `--check` compares without writing, which is what CI runs: it turns "the catalogue moved under
 * us" into a failed build rather than a 403 in staging that nobody can explain.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const TARGET = resolve(HERE, '../../../artifacts/work-permissions.json');
const EMITTER = 'scripts/emit-permission-catalogue.mjs';
const GRANT = /^work:[a-z0-9][a-z0-9_-]*(?::[a-z0-9][a-z0-9_-]*)*$/;

const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
};

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

/** Run Work's own emitter in a checkout, so the source of truth stays Work's script. */
const fromCheckout = (directory) => {
  try {
    statSync(resolve(directory, EMITTER));
  } catch {
    fail(`${directory} is not a Munaxa Work checkout: it has no ${EMITTER}.`);
  }
  return execFileSync('node', [EMITTER], { cwd: directory, encoding: 'utf8' });
};

const fromUrl = async (url) => {
  const response = await fetch(url);
  if (!response.ok) fail(`${url} answered ${String(response.status)}.`);
  return response.text();
};

const fromFile = (path) => readFileSync(path, 'utf8');

/**
 * Everything Munaxa Work would refuse, refused here instead.
 *
 * A wildcard or a scoped grant reaching a role produces a silent, total denial — Work drops it and
 * the operator sees a permission that simply does not work. Catching the shape at the boundary
 * makes it a failed refresh rather than an afternoon.
 */
const validate = (text) => {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail('The source did not produce JSON. Expected an array of "work:" grants.');
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    fail('The catalogue must be a non-empty JSON array.');
  }
  const problems = parsed.flatMap((grant) => {
    if (typeof grant !== 'string') return [`${JSON.stringify(grant)} is not a string.`];
    if (grant.includes('*')) return [`${grant} contains a wildcard; Munaxa Work refuses these.`];
    if (grant.includes('@'))
      return [`${grant} carries a scope; Munaxa Work drops these as undeclared.`];
    if (!GRANT.test(grant)) return [`${grant} is not a work: grant in Platform's grammar.`];
    return [];
  });
  if (problems.length > 0)
    fail(`The source is not a usable catalogue:\n  - ${problems.join('\n  - ')}`);

  const sorted = [...parsed].sort();
  if (new Set(sorted).size !== sorted.length) fail('The catalogue contains duplicates.');
  return sorted;
};

const run = async () => {
  const from = argument('from');
  if (from === undefined) {
    fail(
      'Give --from: a Munaxa Work checkout, a URL, or a downloaded JSON file. There is deliberately ' +
        'no default — a build that silently fetches is a build depending on something nobody declared.',
    );
  }

  const raw =
    from.startsWith('http://') || from.startsWith('https://')
      ? await fromUrl(from)
      : from.endsWith('.json')
        ? fromFile(from)
        : fromCheckout(from);

  const fresh = validate(raw);
  const current = JSON.parse(readFileSync(TARGET, 'utf8'));
  const added = fresh.filter((grant) => !current.includes(grant));
  const removed = current.filter((grant) => !fresh.includes(grant));

  if (added.length === 0 && removed.length === 0) {
    process.stdout.write(
      `No drift: ${String(fresh.length)} grants, identical to the committed catalogue.\n`,
    );
    return;
  }

  const summary =
    `${String(current.length)} → ${String(fresh.length)} grants` +
    `${added.length > 0 ? `\n  added:   ${added.join('\n           ')}` : ''}` +
    `${removed.length > 0 ? `\n  removed: ${removed.join('\n           ')}` : ''}`;

  if (process.argv.includes('--check')) {
    fail(
      `The committed catalogue is out of date.\n  ${summary}\n\n` +
        'Refresh it, review the diff, and re-run the role seed: a removed grant silently drops out ' +
        'of every role that named it.',
    );
  }

  writeFileSync(TARGET, `${JSON.stringify(fresh, null, 2)}\n`);
  process.stdout.write(
    `Updated artifacts/work-permissions.json.\n  ${summary}\n\n` +
      'Review the diff and re-seed roles: pnpm db:seed-work-roles --organisation <slug>.\n',
  );
};

await run();
