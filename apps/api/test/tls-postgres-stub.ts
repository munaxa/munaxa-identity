import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TLSSocket } from 'node:tls';

/**
 * A PostgreSQL server that does exactly one thing: the TLS handshake, for real.
 *
 * It answers the client's `SSLRequest` with `S`, runs an actual TLS handshake with the certificate it
 * was given, reads the startup message to learn which user and database the client asked for, and
 * then refuses the login with a recognisable error. That is everything the connection-verification
 * tests need to observe, from the outside, what a script actually did: whether it attempted TLS at
 * all, whether the handshake completed (so the client accepted the certificate), or whether the
 * client tore it down (so it refused it) — and it needs no PostgreSQL to do it.
 *
 * The certificates are generated per run with `openssl` and never written into the repository.
 */

const SSL_REQUEST_CODE = 80877103;
export const STUB_REFUSAL = 'tls-stub: handshake verified, login refused by the stub';

export interface StubObservation {
  connections: number;
  /** A client sent the startup message without asking for TLS first. */
  plaintext: boolean;
  /** The TLS handshake completed — the client accepted the server's certificate. */
  verified: boolean;
  /** The handshake failed on the server side; the client hung up during it. */
  handshakeFailed: boolean;
  startup?: Readonly<Record<string, string>>;
}

export interface TlsPostgresStub {
  readonly port: number;
  readonly seen: StubObservation;
  close(): Promise<void>;
}

const errorResponse = (message: string): Buffer => {
  const fields = Buffer.concat([
    Buffer.from('SFATAL\0VFATAL\0C28000\0', 'utf8'),
    Buffer.from(`M${message}\0`, 'utf8'),
    Buffer.from([0]),
  ]);
  const header = Buffer.alloc(5);
  header.write('E', 0, 'utf8');
  header.writeInt32BE(fields.length + 4, 1);
  return Buffer.concat([header, fields]);
};

const parseStartup = (buffer: Buffer): Record<string, string> => {
  const parameters: Record<string, string> = {};
  const parts = buffer.subarray(8).toString('utf8').split('\0');
  for (let index = 0; index + 1 < parts.length; index += 2) {
    const key = parts[index];
    if (key === undefined || key === '') break;
    parameters[key] = parts[index + 1] ?? '';
  }
  return parameters;
};

export const startTlsPostgresStub = async (certificate: {
  readonly key: string;
  readonly cert: string;
}): Promise<TlsPostgresStub> => {
  const seen: StubObservation = {
    connections: 0,
    plaintext: false,
    verified: false,
    handshakeFailed: false,
  };

  const server: Server = createServer((socket: Socket) => {
    seen.connections += 1;
    socket.on('error', () => undefined);
    socket.once('data', (first) => {
      if (first.length >= 8 && first.readInt32BE(4) === SSL_REQUEST_CODE) {
        socket.write('S');
        const secure = new TLSSocket(socket, {
          isServer: true,
          key: certificate.key,
          cert: certificate.cert,
        });
        secure.on('secure', () => {
          seen.verified = true;
        });
        // A client that rejects the certificate aborts the handshake — with an alert, or by simply
        // closing. Either way the session never became secure.
        const abandoned = () => {
          if (!seen.verified) seen.handshakeFailed = true;
        };
        secure.on('error', abandoned);
        secure.on('close', abandoned);
        secure.once('data', (startup) => {
          seen.startup = parseStartup(startup);
          secure.end(errorResponse(STUB_REFUSAL));
        });
        return;
      }
      seen.plaintext = true;
      seen.startup = parseStartup(first);
      socket.end(errorResponse(STUB_REFUSAL));
    });
  });

  // Every local address, so `localhost` reaches it whether it resolves to 127.0.0.1 or ::1. The
  // clients connect by name because that is how the certificate is checked: `pg` passes no TLS server
  // name for an IP-literal host, and Node then checks the certificate against "localhost" instead.
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;

  return {
    port,
    seen,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
};

export interface TestCertificates {
  readonly directory: string;
  /** The CA that signed both server certificates. */
  readonly caPem: string;
  /** A CA that signed nothing here. */
  readonly otherCaPem: string;
  /** Valid for `localhost`. */
  readonly server: { readonly key: string; readonly cert: string };
  /** Signed by the right CA, but only for a name the client never connects to. */
  readonly wrongName: { readonly key: string; readonly cert: string };
  remove(): void;
}

/** A throwaway PKI, made with the `openssl` CLI. */
export const makeTestCertificates = (): TestCertificates => {
  const directory = mkdtempSync(join(tmpdir(), 'identity-tls-'));
  const at = (name: string) => join(directory, name);
  const openssl = (args: readonly string[]) =>
    execFileSync('openssl', args, { cwd: directory, stdio: 'pipe' });

  const ca = (name: string) =>
    openssl([
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      `/CN=${name}`,
      '-keyout',
      at(`${name}.key`),
      '-out',
      at(`${name}.pem`),
    ]);
  const leaf = (name: string, subjectAltName: string) => {
    openssl([
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-subj',
      `/CN=${name}`,
      '-keyout',
      at(`${name}.key`),
      '-out',
      at(`${name}.csr`),
    ]);
    writeFileSync(at(`${name}.ext`), `subjectAltName=${subjectAltName}\n`);
    openssl([
      'x509',
      '-req',
      '-in',
      at(`${name}.csr`),
      '-CA',
      at('test-ca.pem'),
      '-CAkey',
      at('test-ca.key'),
      '-CAcreateserial',
      '-days',
      '1',
      '-extfile',
      at(`${name}.ext`),
      '-out',
      at(`${name}.crt`),
    ]);
    return {
      key: readFileSync(at(`${name}.key`), 'utf8'),
      cert: readFileSync(at(`${name}.crt`), 'utf8'),
    };
  };

  ca('test-ca');
  ca('other-ca');
  const server = leaf('server', 'DNS:localhost');
  const wrongName = leaf('wrong-name', 'DNS:db.elsewhere.invalid');

  return {
    directory,
    caPem: readFileSync(at('test-ca.pem'), 'utf8'),
    otherCaPem: readFileSync(at('other-ca.pem'), 'utf8'),
    server,
    wrongName,
    remove: () => rmSync(directory, { recursive: true, force: true }),
  };
};
