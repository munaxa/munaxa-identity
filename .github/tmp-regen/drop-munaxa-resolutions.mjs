// Removes the @munaxa/* entries from the `packages:` section of a pnpm-lock.yaml (their resolution
// and integrity), leaving importers and snapshots, so `pnpm install --lockfile-only` must resolve
// them again from the configured @munaxa registry. Usage: node drop-munaxa-resolutions.mjs pnpm-lock.yaml
import { readFileSync, writeFileSync } from 'node:fs';
const file = process.argv[2];
const lines = readFileSync(file, 'utf8').split('\n');
const out = [];
let section = '', dropping = false, dropped = 0;
for (const line of lines) {
  if (/^\S/.test(line)) { section = line; dropping = false; }
  if (section === 'packages:' && /^  \S/.test(line)) {
    dropping = /^  '@munaxa\//.test(line);
    if (dropping) dropped++;
  }
  if (!dropping) out.push(line);
}
writeFileSync(file, out.join('\n'));
console.log(`dropped ${dropped} @munaxa package entries`);
