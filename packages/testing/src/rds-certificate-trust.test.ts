import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { rootCertificates } from 'node:tls';

import { describe, expect, it } from 'vitest';

/**
 * The shared AWS stack's identity-bootstrap task runs the account and role scripts
 * (apps/api/scripts) from the runtime image. They connect with node-postgres, which reads
 * `sslmode=require` in the owner URL as `verify-full`. Amazon RDS certificates chain to Amazon's own
 * regional roots, which are not in Node's bundled store, so without them every run fails with
 * SELF_SIGNED_CERT_IN_CHAIN and no operator or Control role can be created.
 *
 * The image appends the eu-central-1 roots through NODE_EXTRA_CA_CERTS. These tests hold the
 * vendored bundle and the Dockerfile wiring to that, so neither can drift silently.
 */

// vitest runs from packages/testing.
const repository = join(process.cwd(), '../..');
const BUNDLE = 'deploy/aws/rds-ca-eu-central-1.crt';
const IMAGE_PATH = '/usr/local/share/ca-certificates/rds-ca-eu-central-1.crt';

/** SHA-256 fingerprints of AWS's eu-central-1 bundle (truststore.pki.rds.amazonaws.com), 4 Nov 2026. */
const EXPECTED_ROOTS = new Map([
  [
    'Amazon RDS eu-central-1 Root CA ECC384 G1',
    'AE:69:7D:08:2E:E1:86:2F:71:1E:CA:E3:89:3C:3C:61:3B:73:15:D0:20:F7:46:74:05:15:34:A5:B1:66:D4:7B',
  ],
  [
    'Amazon RDS eu-central-1 Root CA RSA2048 G1',
    '3D:8B:08:A7:39:0C:9B:10:D1:90:A6:B3:49:D7:03:AE:00:BA:E4:65:83:64:33:19:C7:FA:CC:F3:E5:DC:4A:8B',
  ],
  [
    'Amazon RDS eu-central-1 Root CA RSA4096 G1',
    '31:11:F3:22:E4:48:C2:6E:A2:72:2C:02:E2:97:14:DA:CE:16:D5:C3:93:36:CD:F6:DF:BF:FB:C0:36:8D:53:32',
  ],
]);

const certificates = (pem: string): X509Certificate[] =>
  (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map(
    (block) => new X509Certificate(block),
  );

const commonName = (certificate: X509Certificate): string =>
  /(?:^|\n)CN=([^\n]+)/.exec(certificate.subject)?.[1] ?? '';

describe('Amazon RDS certificate trust', () => {
  const bundle = readFileSync(join(repository, BUNDLE), 'utf8');
  const roots = certificates(bundle);

  it('vendors exactly the eu-central-1 roots, unchanged', () => {
    expect(bundle).not.toMatch(/PRIVATE KEY/);
    expect(new Map(roots.map((root) => [commonName(root), root.fingerprint256] as const))).toEqual(
      EXPECTED_ROOTS,
    );
  });

  it('holds self-signed CA certificates that are in date', () => {
    const now = Date.now();
    for (const root of roots) {
      expect(root.ca).toBe(true);
      expect(root.checkIssued(root)).toBe(true);
      expect(Date.parse(root.validFrom)).toBeLessThan(now);
      expect(Date.parse(root.validTo)).toBeGreaterThan(now);
    }
  });

  it('is needed: Node does not already trust these roots', () => {
    const bundled = new Set(rootCertificates.map((pem) => new X509Certificate(pem).fingerprint256));
    for (const root of roots) expect(bundled.has(root.fingerprint256)).toBe(false);
  });

  it('is appended to Node trust in the runtime image', () => {
    const dockerfile = readFileSync(join(repository, 'apps/api/Dockerfile'), 'utf8');
    const start = dockerfile.indexOf('AS runtime\n');
    expect(start).toBeGreaterThan(-1);
    const next = dockerfile.indexOf('\nFROM ', start);
    const runtime = dockerfile.slice(start, next === -1 ? undefined : next);
    expect(runtime).toContain(`COPY ${BUNDLE} ${IMAGE_PATH}`);
    expect(runtime).toContain(`ENV NODE_EXTRA_CA_CERTS=${IMAGE_PATH}`);
  });
});
