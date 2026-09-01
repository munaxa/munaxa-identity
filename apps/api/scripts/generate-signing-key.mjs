#!/usr/bin/env node
/**
 * Generate the ES256 keypair Identity signs access tokens with.
 *
 * Run by an operator, once per key, and never by the service. A service that generates its own
 * keypair generates a new one on every restart, so every token issued before the restart stops
 * verifying and Munaxa Work's configured public key silently becomes wrong — an outage with no
 * change to explain it.
 *
 * The private half goes to the deployment's secret store and nowhere else. The public half is what
 * an operator pastes into Work's PLATFORM_AUTH_PUBLIC_KEYS. Neither is written to disk here: a file
 * is a thing that gets committed, and a key in a shell history is at least a key somebody can see
 * they need to rotate.
 *
 *   node apps/api/scripts/generate-signing-key.mjs [--kid identity-staging-2026-09]
 */
import { generateKeyPairSync } from 'node:crypto';

const argument = (name) => {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
};

const month = new Date().toISOString().slice(0, 7);
const kid = argument('kid') ?? `identity-${process.env.NODE_ENV ?? 'staging'}-${month}`;

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

process.stdout.write(
  [
    `# Key id: ${kid}`,
    '',
    '# ---- Munaxa Identity: the deployment secret store, and nowhere else ----',
    `IDENTITY_SIGNING_ALGORITHM=ES256`,
    `IDENTITY_SIGNING_KID=${kid}`,
    'IDENTITY_SIGNING_PRIVATE_KEY="' + privatePem.trimEnd() + '"',
    '',
    '# ---- Munaxa Work: PLATFORM_AUTH_PUBLIC_KEYS (public half only) ----',
    `PLATFORM_AUTH_ALGORITHM=ES256`,
    'PLATFORM_AUTH_PUBLIC_KEYS=' + JSON.stringify([{ kid, publicKey: publicPem.trimEnd() }]),
    '',
    '# Rotation, in the only order that never breaks a live session:',
    '#   1 generate            2 add the public key to Work    3 deploy Work (verifies both)',
    '#   4 make this key primary in Identity                   5 wait >= access TTL + skew',
    '#   6 remove the old public key from Work                 7 retire the old key here',
    '',
  ].join('\n'),
);
