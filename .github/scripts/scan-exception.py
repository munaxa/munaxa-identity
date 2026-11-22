#!/usr/bin/env python3
"""Temporary, Testing-only acceptance of the D-SSL OpenSSL findings (owner decision D-SSL, 22 Nov 2026).

This is NOT part of the permanent vulnerability gate. The permanent gate is .github/scripts/scan-image.sh
(Grype, --fail-on high, .grype.yaml with no ignore rule) and it is run unchanged, every time, first.
Only when that gate has FAILED does scan-image-testing.sh call this script, which reads the gate's own
Grype JSON and decides whether EVERY HIGH or CRITICAL finding in it is one of the exact findings the
owner accepted. If any finding is not, or anything about the exception cannot be proved, it refuses.

It accepts only when ALL of these hold, and refuses otherwise (fail closed):
  1. --environment is exactly "testing" (any other value, "production" included, is refused);
  2. the exception file exists, parses, has exactly the expected keys, and stays inside the hard limits
     written in THIS script (packages, version, CVEs, cutoff), so widening the JSON alone widens nothing;
  3. the clock can be trusted: now is not before the decision (2026-11-22T00:00:00Z) and agrees with the
     build time of the Grype database the scan used (an independent clock), and now < expiry;
  4. inside GitHub Actions, the running workflow file is listed in the exception; --now is refused there;
  5. the image name is listed in the exception;
  6. every HIGH/CRITICAL match is (CVE id, package, version, type) exactly listed in the exception.
A new CVE, another package, another version or another image therefore fails, as the permanent gate does.

Exit 0 = accepted (loudly: a ::warning:: annotation, the step summary and an evidence JSON).
Exit 1 = refused (the permanent gate's failure stands). Exit 2 = usage error.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys

SCHEMA = "munaxa-scan-exception/v1"
EXCEPTION_ID = "D-SSL-2026-11"
# Hard limits. The exception file can only narrow these. Changing them needs a reviewed PR to this script.
HARD_EXPIRY = dt.datetime(2026, 12, 1, 0, 0, 0, tzinfo=dt.timezone.utc)
NOT_BEFORE = dt.datetime(2026, 11, 22, 0, 0, 0, tzinfo=dt.timezone.utc)  # the owner's decision day
ALLOWED_PACKAGES = {"libssl3", "libcrypto3"}
ALLOWED_VERSION = "3.5.9-r1"
ALLOWED_TYPE = "apk"
ALLOWED_CVES = {"CVE-2026-124709", "CVE-2026-107494", "CVE-2026-121482", "CVE-2026-84786", "CVE-2026-107493"}
ENVIRONMENT = "testing"
BLOCKING = {"high", "critical"}
DB_MAX_AGE = dt.timedelta(days=7)      # grype itself refuses a database older than 5 days (validate-age)
CLOCK_SKEW = dt.timedelta(hours=1)
TOP_KEYS = {"schema", "id", "decision", "environment", "expires_utc", "workflows", "images", "findings"}
FINDING_KEYS = {"vulnerability", "package", "version", "type"}
WORKFLOW_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class Refused(Exception):
    pass


def parse_utc(value, what):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})", value):
        raise Refused(f"{what} is not an RFC 3339 UTC timestamp: {value!r}")
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise Refused(f"{what} cannot be parsed: {value!r} ({e})")
    if t.tzinfo is None:
        raise Refused(f"{what} has no time zone: {value!r}")
    return t.astimezone(dt.timezone.utc)


def load_exception(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise Refused(f"exception file missing or unreadable: {path} ({e.strerror})")
    try:
        exc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused(f"exception file is not valid JSON: {e}")
    if not isinstance(exc, dict) or set(exc) != TOP_KEYS:
        raise Refused(f"exception file must have exactly the keys {sorted(TOP_KEYS)}")
    if exc["schema"] != SCHEMA or exc["id"] != EXCEPTION_ID:
        raise Refused("exception file has the wrong schema or id")
    if not isinstance(exc["decision"], str) or len(exc["decision"].strip()) < 10:
        raise Refused("exception file must name the owner decision")
    if exc["environment"] != ENVIRONMENT:
        raise Refused(f"exception environment must be {ENVIRONMENT!r}, is {exc['environment']!r}")
    expires = parse_utc(exc["expires_utc"], "expires_utc")
    if expires > HARD_EXPIRY:
        raise Refused(f"expires_utc {exc['expires_utc']} is after the hard cutoff {HARD_EXPIRY:%Y-%m-%dT%H:%M:%SZ}")
    for key, rx in (("workflows", WORKFLOW_RE), ("images", IMAGE_RE)):
        v = exc[key]
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and rx.match(x) for x in v) or len(set(v)) != len(v):
            raise Refused(f"exception {key} must be a non-empty list of distinct exact names")
    if any("prod" in i for i in exc["images"]):
        raise Refused("an image name that mentions production can never carry this exception")
    findings = exc["findings"]
    if not isinstance(findings, list) or not findings:
        raise Refused("exception findings must be a non-empty list")
    allowed = set()
    for f in findings:
        if not isinstance(f, dict) or set(f) != FINDING_KEYS or not all(isinstance(f[k], str) for k in FINDING_KEYS):
            raise Refused(f"each finding has exactly the keys {sorted(FINDING_KEYS)}, all strings: {f!r}")
        if not CVE_RE.match(f["vulnerability"]) or f["vulnerability"] not in ALLOWED_CVES:
            raise Refused(f"finding {f['vulnerability']} is not one of the owner-accepted D-SSL CVEs")
        if f["package"] not in ALLOWED_PACKAGES or f["version"] != ALLOWED_VERSION or f["type"] != ALLOWED_TYPE:
            raise Refused(f"finding {f!r} is outside the OpenSSL {ALLOWED_VERSION} apk packages the owner accepted")
        t = (f["vulnerability"], f["package"], f["version"], f["type"])
        if t in allowed:
            raise Refused(f"duplicate finding {t}")
        allowed.add(t)
    return exc, expires, allowed, hashlib.sha256(raw).hexdigest()


def db_built(report):
    d = (report.get("descriptor") or {}).get("db") or {}
    for v in ((d.get("status") or {}).get("built"), d.get("built")):
        if v:
            return parse_utc(v, "the Grype database build time")
    raise Refused("the scan report does not say when its Grype database was built, so the date cannot be checked independently")


def evaluate(report, exc_path, image, environment, now, workflow_ref, in_actions):
    if environment != ENVIRONMENT:
        raise Refused(f"environment {environment!r}: the D-SSL exception applies to Testing only (never production)")
    if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
        raise Refused("the scan report is malformed (no matches list)")
    blocking = []
    for m in report["matches"]:
        try:
            sev = m["vulnerability"]["severity"]
            if str(sev).lower() in BLOCKING:
                a = m["artifact"]
                blocking.append((m["vulnerability"]["id"], a["name"], a["version"], a["type"], sev))
        except (KeyError, TypeError):
            raise Refused("the scan report has a malformed match")
    if not blocking:
        raise Refused("the permanent gate failed but its report has no HIGH or CRITICAL finding; the failure has another cause and no exception applies")
    exc, expires, allowed, exc_sha = load_exception(exc_path)
    if now < NOT_BEFORE:
        raise Refused(f"the clock reads {now:%Y-%m-%dT%H:%M:%SZ}, before the owner's decision; the date cannot be trusted")
    built = db_built(report)
    if built > now + CLOCK_SKEW or now - built > DB_MAX_AGE:
        raise Refused(f"the clock ({now:%Y-%m-%dT%H:%M:%SZ}) disagrees with the Grype database build time ({built:%Y-%m-%dT%H:%M:%SZ}); the date cannot be trusted")
    if now >= expires or built >= expires:
        raise Refused(f"the D-SSL exception expired at {expires:%Y-%m-%dT%H:%M:%SZ}: install OpenSSL 3.5.10 (or a reviewed replacement) and let the permanent gate pass")
    if in_actions:
        m = re.fullmatch(r"[^/]+/[^/]+/(\.github/workflows/[^@]+)@.+", workflow_ref or "")
        if not m or m.group(1) not in exc["workflows"]:
            raise Refused(f"workflow {workflow_ref!r} is not one the exception lists ({', '.join(exc['workflows'])})")
    if image not in exc["images"]:
        raise Refused(f"image {image!r} is not in the exception's image set ({', '.join(exc['images'])})")
    unlisted = sorted({b for b in blocking if b[:4] not in allowed})
    if unlisted:
        raise Refused("findings NOT covered by the exception: " + "; ".join(f"{s} {c} {p}@{v} ({t})" for c, p, v, t, s in unlisted))
    return {
        "decision": "accepted-temporary-testing-only",
        "exception_id": exc["id"],
        "exception_sha256": exc_sha,
        "owner_decision": exc["decision"],
        "environment": environment,
        "image": image,
        "expires_utc": f"{expires:%Y-%m-%dT%H:%M:%SZ}",
        "evaluated_at_utc": f"{now:%Y-%m-%dT%H:%M:%SZ}",
        "grype_db_built_utc": f"{built:%Y-%m-%dT%H:%M:%SZ}",
        "workflow_ref": workflow_ref if in_actions else "(outside GitHub Actions)",
        "accepted_findings": [{"severity": s, "vulnerability": c, "package": p, "version": v, "type": t} for c, p, v, t, s in sorted(set(blocking))],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--grype-json", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--environment", required=True)
    ap.add_argument("--exception", required=True)
    ap.add_argument("--evidence")
    ap.add_argument("--now", help="tests only; refused inside GitHub Actions")
    ap.add_argument("--outside-actions", action="store_true", help="required to run outside GitHub Actions (local checks)")
    a = ap.parse_args(argv)
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    result = {"decision": "refused", "image": a.image, "environment": a.environment, "exception_id": EXCEPTION_ID}
    try:
        if in_actions and a.now is not None:
            raise Refused("--now is refused inside GitHub Actions: the exception is judged against the real clock")
        if not in_actions and not a.outside_actions:
            raise Refused("not running in GitHub Actions; pass --outside-actions for a local check")
        now = parse_utc(a.now, "--now") if a.now is not None else dt.datetime.now(dt.timezone.utc)
        try:
            with open(a.grype_json, encoding="utf-8") as f:
                report = json.load(f)
        except (OSError, ValueError) as e:
            raise Refused(f"the scan report cannot be read: {e}")
        result = evaluate(report, a.exception, a.image, a.environment, now, os.environ.get("GITHUB_WORKFLOW_REF", ""), in_actions)
        code = 0
    except Refused as e:
        result["reason"] = str(e)
        code = 1
    if a.evidence:
        with open(a.evidence, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
    if code == 0:
        lines = [f"{x['severity']} {x['vulnerability']} {x['package']}@{x['version']}" for x in result["accepted_findings"]]
        msg = (f"{a.image}: TEMPORARY TESTING-ONLY exception {EXCEPTION_ID} accepted {len(lines)} HIGH/CRITICAL finding(s), "
               f"expires {result['expires_utc']}. Not for production. " + "; ".join(lines))
        print(f"::warning title=D-SSL temporary exception ({a.image})::{msg}")
        print(json.dumps(result, indent=2, sort_keys=True))
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(f"\n### {a.image}: D-SSL temporary Testing-only exception USED\n\nExpires **{result['expires_utc']}**. "
                        f"Not for production. Exception file sha256 `{result['exception_sha256']}`.\n\n"
                        + "\n".join(f"- {l}" for l in lines) + "\n")
    else:
        print(f"::error title=D-SSL exception refused ({a.image})::{result['reason']}")
    return code


if __name__ == "__main__":
    sys.exit(main())
