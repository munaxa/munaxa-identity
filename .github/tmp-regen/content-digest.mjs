// Canonical content digest of npm tarballs: SHA-256 over sorted (path, sha256(content)) where
// package.json is re-serialised with sorted keys. Independent of tar order, gzip and key order.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v;
const walk = (d, b = d) => readdirSync(d).flatMap((e) => { const p = path.join(d, e); return statSync(p).isDirectory() ? walk(p, b) : [path.relative(b, p)]; });
for (const tgz of process.argv.slice(2)) {
  const dir = mkdtempSync(path.join(tmpdir(), 'cd-'));
  execFileSync('tar', ['xzf', tgz, '-C', dir]);
  const h = createHash('sha256');
  for (const f of walk(dir).sort()) {
    let buf = readFileSync(path.join(dir, f));
    if (f === 'package/package.json') buf = Buffer.from(JSON.stringify(sortKeys(JSON.parse(buf))));
    h.update(f + '\0' + createHash('sha256').update(buf).digest('hex') + '\n');
  }
  console.log(h.digest('hex') + '  ' + path.basename(tgz));
  rmSync(dir, { recursive: true });
}
