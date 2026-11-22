# D-SSL: temporary, Testing-only OpenSSL exception (expires 2026-12-01T00:00:00Z)

**Owner decision D-SSL (22 Nov 2026, 14:07 UTC):** the first Munaxa Docs Testing deployment and its
required dependencies (Identity, Control, Docs) may use images whose only HIGH findings are the
OpenSSL 3.5.9-r1 findings below, until OpenSSL 3.5.10 is available (target 1 Dec 2026). Testing
only. Never production. Not a permanent suppression. Work and School are not covered.

## What is accepted, exactly

|                     |                                                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| CVEs                | CVE-2026-107493, CVE-2026-107494, CVE-2026-121482, CVE-2026-124709, CVE-2026-84786                                   |
| Packages            | `libssl3` and `libcrypto3`, version `3.5.9-r1`, type `apk` (10 exact combinations)                                   |
| Images (scan names) | `identity-runtime` (ECR `munaxa-identity/api`) and `identity-migrate` (ECR `munaxa-identity/migrate`).               |
| Workflows           | `ci.yml`, `publish-images-ecr.yml` (**not** the GHCR `publish-images.yml`, which still runs the permanent gate only) |
| Environment         | `testing` (any other value is refused)                                                                               |
| Expiry              | **2026-12-01T00:00:00Z**, hard-coded in `scan-exception.py` as well as in the JSON                                   |

Source of the list: the Grype scans of 21 Nov 2026 (e.g. munaxa-docs run 44900058536, Grype DB built
2026-11-21T06:20:06Z); re-confirmed by the CI run of the pull request that added this file.

## How it works

1. `.github/scripts/scan-image.sh` is the **permanent gate** and is **unchanged** (SHA-256
   `68c9f23c…acca2`): Grype `--fail-on high`, digest-pinned scanners, no ignore rule.
2. `.github/scripts/scan-image-testing.sh` runs `verify-permanent-gate.py`, then the permanent gate.
   If the gate passes, nothing else happens.
3. Only if the gate fails, `scan-exception.py` reads that scan's own Grype JSON and accepts it only
   when **every** HIGH/CRITICAL finding is one of the exact combinations in
   `.github/security/dssl-testing-exception.json`, for a listed image, from a listed workflow, in
   environment `testing`, with a trustworthy clock (not before 22 Nov, consistent with the Grype
   database build time) and before the expiry. Anything else (a new CVE, another package or version,
   another image, production, an expired or malformed exception, an untrustworthy date) is refused
   and the job fails.
4. An accepted scan is loud: a `::warning::` annotation, a step-summary section and
   `image-reports/<name>.dssl-exception.json` (kept with the SBOM and the full Grype report).
5. Production cannot consume these images: the platform stack refuses any product image in
   `prod` while the exception exists, refuses every listed Testing-only digest in `prod` for ever,
   and after the expiry refuses to start a Testing session with them
   (munaxa-platform `infra/aws/stack/dssl-exception.tf`).

## Verify the permanent gate (anyone, any time)

```sh
python3 -I .github/scripts/verify-permanent-gate.py .
python3 -I -m unittest discover -s .github/scripts -p 'test_scan_exception.py' -v
```

## After expiry (fail closed)

From 2026-12-01T00:00:00Z every image scan with an OpenSSL 3.5.9-r1 finding fails again, in CI and
before every push: no new affected image is published. Nothing needs to be done for that to happen.

## Removal procedure (on or after 1 Dec, when OpenSSL 3.5.10 is in Alpine v3.24/main)

1. Merge the OpenSSL 3.5.10 bump PR once its image scans pass the **permanent** gate with 0 HIGH / 0 CRITICAL.
2. In one PR: delete `.github/scripts/scan-exception.py`, `scan-image-testing.sh`,
   `verify-permanent-gate.py`, `test_scan_exception.py`, `.github/security/dssl-testing-exception.json`
   and this file; change every `scan-image-testing.sh … testing` call back to `scan-image.sh …`;
   remove the "Verify the permanent vulnerability gate" CI step. `git grep -n -i 'dssl\|scan-image-testing'`
   must then find nothing.
3. In munaxa-platform: move every digest in `dssl_testing_only_image_digests` to
   `withdrawn-images.tf`, then remove the guard (`dssl-exception.tf`), in one reviewed PR.
