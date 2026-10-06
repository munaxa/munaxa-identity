import { execFile } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import {
  STUB_REFUSAL,
  makeTestCertificates,
  startTlsPostgresStub,
  type TestCertificates,
  type TlsPostgresStub,
} from './tls-postgres-stub.js';

/**
 * The provisioning scripts' database connection, observed from the server's side of a real TLS
 * handshake.
 *
 * `bootstrap-account.mjs` and `seed-work-roles.mjs` are run as they are run in an ECS one-off task —
 * `node scripts/<name>.mjs`, a child process, configured only through its environment — against a
 * stub that speaks just enough PostgreSQL to perform the TLS handshake and then refuses the login.
 * So each test sees what the script actually did on the wire: no connection at all, plain text, a
 * handshake the client abandoned because it rejected the certificate, or a verified session
 * carrying the owner's user name.
 *
 * Needs the built `dist` (the scripts load the shared connection module from it, as they do in the
 * image) and the `openssl` CLI for the throwaway certificates. Needs no PostgreSQL. The same
 * behaviour against a real TLS-enabled PostgreSQL is in the runbook's verification notes; RDS
 * itself is not reachable from a test.
 */

const API = resolve(__dirname, '..');
const SCRIPTS = {
  'bootstrap-account': {
    file: join(API, 'scripts', 'bootstrap-account.mjs'),
    args: ['--organisation', 'acme'],
    applicationName: 'munaxa-identity-bootstrap',
    extraEnv: {
      IDENTITY_OWNER_EMAIL: 'operator@example.invalid',
      IDENTITY_OWNER_PASSWORD: 'tls-stub-Passphrase-Long-Enough-2026',
    },
  },
  'seed-work-roles': {
    file: join(API, 'scripts', 'seed-work-roles.mjs'),
    args: ['--organisation', 'acme'],
    applicationName: 'munaxa-identity-seed-roles',
    extraEnv: {},
  },
} as const;
type ScriptName = keyof typeof SCRIPTS;

interface RunResult {
  readonly code: number;
  readonly output: string;
}

/** Only what the test names: nothing ambient can satisfy a variable the script is meant to need. */
const run = (script: ScriptName, env: Readonly<Record<string, string>>): Promise<RunResult> => {
  const { file, args, extraEnv } = SCRIPTS[script];
  return new Promise((done) => {
    execFile(
      process.execPath,
      [file, ...args],
      { cwd: API, env: { PATH: process.env.PATH ?? '', ...extraEnv, ...env }, timeout: 20_000 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : 1;
        done({ code, output: `${stdout}${stderr}` });
      },
    );
  });
};

let pki: TestCertificates;
let stub: TlsPostgresStub | undefined;

const owner = (port: number, query = ''): string =>
  `postgresql://identity_mig:not-a-real-password@localhost:${String(port)}/identity${query}`;

const caFile = (pem: string, name = 'ca-bundle.pem'): string => {
  const path = join(pki.directory, name);
  writeFileSync(path, pem);
  return path;
};

const serve = async (certificate = pki.server): Promise<TlsPostgresStub> => {
  stub = await startTlsPostgresStub(certificate);
  return stub;
};

beforeAll(() => {
  if (!existsSync(join(API, 'dist', 'database', 'direct-connection.js'))) {
    throw new Error('apps/api/dist is not built. Run `pnpm build` before these tests.');
  }
  pki = makeTestCertificates();
});

afterEach(async () => {
  await stub?.close();
  stub = undefined;
});

afterAll(() => {
  pki?.remove();
});

describe.each(Object.keys(SCRIPTS) as ScriptName[])('%s', (script) => {
  it('verifies the server against DATABASE_TLS_CA_FILE and connects as the owner', async () => {
    const server = await serve();

    const result = await run(script, {
      NODE_ENV: 'production',
      DIRECT_DATABASE_URL: owner(server.port),
      DATABASE_TLS_CA_FILE: caFile(pki.caPem),
    });

    expect(server.seen.verified).toBe(true);
    expect(server.seen.plaintext).toBe(false);
    expect(server.seen.startup).toMatchObject({
      user: 'identity_mig',
      database: 'identity',
      application_name: SCRIPTS[script].applicationName,
    });
    expect(result.output).toContain('TLS verify-full (configured CA)');
    // The stub then refuses the login, so the script fails — with the server's message, which is
    // proof the TLS session carried the startup to it.
    expect(result.code).toBe(1);
    expect(result.output).toContain(STUB_REFUSAL);
    expect(result.output).not.toContain('not-a-real-password');
  });

  it('takes the CA as content and the owner URL from DIRECT_DATABASE_URL_FILE, which wins', async () => {
    const server = await serve();
    const urlFile = join(pki.directory, `${script}-url`);
    writeFileSync(urlFile, `${owner(server.port)}\n`);

    await run(script, {
      NODE_ENV: 'production',
      // Ambient and wrong: a closed port. The file must win, or nothing reaches the stub.
      DIRECT_DATABASE_URL: owner(1),
      DIRECT_DATABASE_URL_FILE: urlFile,
      DATABASE_TLS_CA: pki.caPem,
    });

    expect(server.seen.verified).toBe(true);
    expect(server.seen.startup?.user).toBe('identity_mig');
  });

  it('accepts a bundle of several certificates, as Amazon ships the regional RDS bundle', async () => {
    const server = await serve();

    await run(script, {
      NODE_ENV: 'production',
      DIRECT_DATABASE_URL: owner(server.port),
      DATABASE_TLS_CA_FILE: caFile(`${pki.otherCaPem}${pki.caPem}`, 'multi.pem'),
    });

    expect(server.seen.verified).toBe(true);
  });

  it('refuses a server whose certificate another CA signed, before sending anything', async () => {
    const server = await serve();

    const result = await run(script, {
      NODE_ENV: 'production',
      DIRECT_DATABASE_URL: owner(server.port),
      DATABASE_TLS_CA_FILE: caFile(pki.otherCaPem, 'other.pem'),
    });

    expect(result.code).toBe(1);
    expect(server.seen.verified).toBe(false);
    expect(server.seen.handshakeFailed).toBe(true);
    expect(server.seen.startup).toBeUndefined();
    expect(result.output).toMatch(/self[- ]signed|unable to verify/i);
  });

  it('refuses a certificate from the right CA for the wrong host name', async () => {
    const server = await serve(pki.wrongName);

    const result = await run(script, {
      NODE_ENV: 'production',
      DIRECT_DATABASE_URL: owner(server.port),
      DATABASE_TLS_CA_FILE: caFile(pki.caPem),
    });

    expect(result.code).toBe(1);
    expect(server.seen.verified).toBe(false);
    expect(server.seen.startup).toBeUndefined();
    expect(result.output).toMatch(/does not match certificate|altnames/i);
  });

  it('cannot be talked out of verification by a weaker sslmode, with or without a CA', async () => {
    const server = await serve();

    for (const mode of ['require', 'no-verify', 'prefer', 'allow', 'verify-ca', 'disable']) {
      const withCa = await run(script, {
        NODE_ENV: 'production',
        DIRECT_DATABASE_URL: owner(server.port, `?sslmode=${mode}`),
        DATABASE_TLS_CA_FILE: caFile(pki.caPem),
      });
      expect([mode, withCa.code]).toEqual([mode, 1]);
      expect(withCa.output).toMatch(/Remove sslmode/);

      const withoutCa = await run(script, {
        NODE_ENV: 'production',
        DIRECT_DATABASE_URL: owner(server.port, `?sslmode=${mode}`),
      });
      expect([mode, withoutCa.code]).toEqual([mode, 1]);
    }

    // Outside production too, `no-verify` is refused rather than honoured.
    const local = await run(script, {
      DIRECT_DATABASE_URL: owner(server.port, '?sslmode=no-verify'),
    });
    expect(local.code).toBe(1);
    expect(local.output).toMatch(/not supported here/);

    // Refused before connecting, every time: nothing reached the server at all.
    expect(server.seen.connections).toBe(0);
  });

  it('refuses plain text in production instead of falling back to it', async () => {
    const server = await serve();

    const result = await run(script, {
      NODE_ENV: 'production',
      DIRECT_DATABASE_URL: owner(server.port),
    });

    expect(result.code).toBe(1);
    expect(result.output).toMatch(/Refusing an unverified database connection in production/);
    expect(server.seen.connections).toBe(0);
  });

  it('still connects to a local database without TLS outside production', async () => {
    const server = await serve();

    const result = await run(script, { DIRECT_DATABASE_URL: owner(server.port) });

    expect(server.seen.plaintext).toBe(true);
    expect(server.seen.startup?.user).toBe('identity_mig');
    expect(result.output).toContain('TLS none');
  });

  it('refuses the runtime DATABASE_URL as a substitute for the owner', async () => {
    const server = await serve();

    const result = await run(script, { NODE_ENV: 'production', DATABASE_URL: owner(server.port) });

    expect(result.code).toBe(1);
    expect(result.output).toMatch(/DIRECT_DATABASE_URL/);
    expect(server.seen.connections).toBe(0);
  });

  it('loads the shared connection module and nothing of the HTTP service, Redis or Prisma', async () => {
    const server = await serve();
    const record = join(pki.directory, `${script}-modules.json`);
    const hook = join(pki.directory, 'record-modules.cjs');
    writeFileSync(
      hook,
      `process.on('exit', () => require('node:fs').writeFileSync(${JSON.stringify(record)}, ` +
        'JSON.stringify(Object.keys(require.cache))));\n',
    );

    await run(script, {
      NODE_OPTIONS: `--require ${hook}`,
      DIRECT_DATABASE_URL: owner(server.port),
    });

    const loaded = JSON.parse(readFileSync(record, 'utf8')) as string[];
    expect(
      loaded.some((path) => path.endsWith(join('dist', 'database', 'direct-connection.js'))),
    ).toBe(true);
    expect(
      loaded.filter((path) =>
        /@nestjs|[\\/]dist[\\/](main|app\.module)\.js$|ioredis|@prisma|\.prisma|@identity[\\/]config/.test(
          path,
        ),
      ),
    ).toEqual([]);
  });
});

describe('the scripts have no connection logic of their own', () => {
  const source = (file: string) => readFileSync(join(API, 'scripts', file), 'utf8');

  it.each(['bootstrap-account.mjs', 'seed-work-roles.mjs'])('%s', (file) => {
    const text = source(file);

    expect(text).toContain("from './owner-connection.mjs'");
    expect(text).not.toMatch(
      /from 'pg'|new pg\.|connectionString|sslmode|process\.env\.DIRECT_DATABASE_URL/,
    );
  });

  it('owner-connection.mjs builds nothing about TLS itself; the shared module does', () => {
    const text = source('owner-connection.mjs');
    const imports = [...text.matchAll(/^import .* from '([^']+)';$/gm)].map((match) => match[1]);

    expect(imports).toEqual(['pg']);
    expect(text).toContain("'../dist/database/direct-connection.js'");
    expect(text).not.toMatch(/rejectUnauthorized|sslmode|BEGIN CERTIFICATE|process\.env\.DIRECT/);
  });
});
