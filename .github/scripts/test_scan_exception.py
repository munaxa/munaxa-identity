#!/usr/bin/env python3
"""Tests of the temporary D-SSL exception and the permanent-gate verification.

  python3 -I -m unittest discover -s .github/scripts -p 'test_scan_exception.py' -v

No network, no Docker: the end-to-end wrapper tests put a fake `docker` first on PATH that writes the
SBOM and a Grype report from a fixture, exactly where the unchanged scan-image.sh expects them.
"""
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
REAL_EXCEPTION = os.path.join(ROOT, ".github", "security", "dssl-testing-exception.json")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EXC = load("scan_exception", "scan-exception.py")
GATE = load("verify_permanent_gate", "verify-permanent-gate.py")
CVES = sorted(EXC.ALLOWED_CVES)
BEFORE = "2026-11-25T12:00:00Z"
DB_BUILT = "2026-11-25T06:00:00Z"

with open(REAL_EXCEPTION, encoding="utf-8") as f:
    REAL = json.load(f)
IMAGE = REAL["images"][0]
WORKFLOW = REAL["workflows"][0]
WORKFLOW_REF = f"munaxa/repo/{WORKFLOW}@refs/heads/main"


def match(cve, pkg="libssl3", ver="3.5.9-r1", typ="apk", sev="High"):
    return {"vulnerability": {"id": cve, "severity": sev}, "artifact": {"name": pkg, "version": ver, "type": typ}}


def report(extra=(), db=DB_BUILT, openssl=True):
    m = [match(c, p) for c in CVES for p in ("libssl3", "libcrypto3")] if openssl else []
    m += [match("CVE-2026-95690", sev="Medium"), match("GHSA-g3hv-75wg-m249", "minimatch", "10.2.6", "npm", "Medium")]
    m += list(extra)
    d = {"matches": m, "descriptor": {"name": "grype", "db": {"status": {"built": db, "valid": True}}}}
    if db is None:
        d["descriptor"]["db"] = {}
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.exc_path = os.path.join(self.tmp, "exc.json")
        self.write_exc(REAL)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}

    def write_exc(self, data, raw=None):
        with open(self.exc_path, "w", encoding="utf-8") as f:
            f.write(raw if raw is not None else json.dumps(data))

    def run_eval(self, rep=None, image=IMAGE, environment="testing", now=BEFORE, workflow_ref=WORKFLOW_REF, in_actions=True):
        return EXC.evaluate(report() if rep is None else rep, self.exc_path, image, environment,
                            EXC.parse_utc(now, "now"), workflow_ref, in_actions)

    def refused(self, needle, **kw):
        with self.assertRaises(EXC.Refused) as cm:
            self.run_eval(**kw)
        self.assertIn(needle, str(cm.exception))


class RealExceptionFile(Base):
    def test_real_file_is_inside_the_hard_limits(self):
        exc, expires, allowed, _ = EXC.load_exception(REAL_EXCEPTION)
        self.assertEqual(f"{expires:%Y-%m-%dT%H:%M:%SZ}", "2026-12-01T00:00:00Z")
        self.assertEqual(exc["environment"], "testing")
        self.assertEqual(allowed, {(c, p, "3.5.9-r1", "apk") for c in CVES for p in ("libssl3", "libcrypto3")})
        for i in exc["images"]:
            self.assertNotIn("antivirus", i)  # the Ubuntu ClamAV image is not in the exception
        for w in exc["workflows"]:
            self.assertTrue(os.path.exists(os.path.join(ROOT, w)), w)


class Accepts(Base):
    def test_exact_findings_before_expiry_are_accepted(self):
        r = self.run_eval()
        self.assertEqual(r["decision"], "accepted-temporary-testing-only")
        self.assertEqual(len(r["accepted_findings"]), 10)
        self.assertEqual(r["expires_utc"], "2026-12-01T00:00:00Z")

    def test_every_listed_image_is_accepted(self):
        for image in REAL["images"]:
            self.assertEqual(self.run_eval(image=image)["image"], image)

    def test_medium_findings_do_not_need_the_exception(self):
        r = self.run_eval(rep=report(extra=[match("CVE-2026-1", "zlib", "1.4-r0", sev="Medium")]))
        self.assertTrue(all(f["severity"] == "High" for f in r["accepted_findings"]))

    def test_last_second_before_expiry(self):
        self.run_eval(now="2026-11-30T23:59:59Z", rep=report(db="2026-11-30T06:00:00Z"))


class Refuses(Base):
    def test_unrelated_cve(self):
        self.refused("NOT covered", rep=report(extra=[match("CVE-2026-99999")]))

    def test_new_cve_on_the_same_package_is_not_inherited(self):
        self.refused("NOT covered", rep=report(extra=[match("CVE-2026-130001", "libcrypto3")]))

    def test_cve_removed_from_the_file_is_no_longer_accepted(self):
        narrowed = copy.deepcopy(REAL)
        narrowed["findings"] = [f for f in narrowed["findings"] if f["vulnerability"] != CVES[0]]
        self.write_exc(narrowed)
        self.refused("NOT covered")

    def test_unrelated_package(self):
        self.refused("NOT covered", rep=report(extra=[match("CVE-2026-124709", "zlib", "1.4-r0")]))

    def test_unrelated_package_version(self):
        self.refused("NOT covered", rep=report(extra=[match("CVE-2026-124709", "libssl3", "3.5.9-r2")]))

    def test_unrelated_critical(self):
        self.refused("NOT covered", rep=report(extra=[match("CVE-2026-5", "node", "22.0.0", "binary", "Critical")]))

    def test_unrelated_image(self):
        self.refused("not in the exception's image set", image="docs-antivirus")
        self.refused("not in the exception's image set", image="work-api")
        self.refused("not in the exception's image set", image="school-api")

    def test_production(self):
        for env in ("production", "prod", "nonprod", "Testing", "", "testing "):
            self.refused("Testing only", environment=env)

    def test_after_expiry(self):
        self.refused("expired", now="2026-12-01T00:00:00Z", rep=report(db="2026-11-30T20:00:00Z"))
        self.refused("expired", now="2026-12-03T00:00:00Z", rep=report(db="2026-12-02T20:00:00Z"))

    def test_database_built_after_expiry(self):
        self.refused("expired", now="2026-11-30T23:30:00Z", rep=report(db="2026-12-01T00:10:00Z"))

    def test_clock_before_the_decision(self):
        self.refused("cannot be trusted", now="2026-11-01T00:00:00Z", rep=report(db="2026-11-01T00:00:00Z"))

    def test_clock_disagrees_with_the_database(self):
        self.refused("disagrees", now="2026-11-25T12:00:00Z", rep=report(db="2026-11-26T12:00:00Z"))
        self.refused("disagrees", now="2026-11-30T12:00:00Z", rep=report(db="2026-11-22T06:00:00Z"))

    def test_no_database_time(self):
        self.refused("cannot be checked", rep=report(db=None))

    def test_unparsable_time(self):
        with self.assertRaises(EXC.Refused):
            EXC.parse_utc("1 Dec 2026", "now")
        with self.assertRaises(EXC.Refused):
            EXC.parse_utc("2026-12-01T00:00:00", "now")  # no zone

    def test_missing_exception_file(self):
        os.remove(self.exc_path)
        self.refused("missing")

    def test_malformed_exception_file(self):
        self.write_exc(None, raw="{not json")
        self.refused("not valid JSON")

    def test_exception_file_with_an_extra_key(self):
        bad = dict(REAL, ignore_all=True)
        self.write_exc(bad)
        self.refused("exactly the keys")

    def test_exception_file_widened_past_the_hard_limits(self):
        for field, value, needle in (
            ("expires_utc", "2026-12-15T00:00:00Z", "hard cutoff"),
            ("environment", "production", "environment must be"),
        ):
            bad = dict(REAL, **{field: value})
            self.write_exc(bad)
            self.refused(needle)
        bad = copy.deepcopy(REAL)
        bad["findings"].append({"vulnerability": "CVE-2026-99999", "package": "libssl3", "version": "3.5.9-r1", "type": "apk"})
        self.write_exc(bad)
        self.refused("not one of the owner-accepted")
        bad = copy.deepcopy(REAL)
        bad["findings"].append({"vulnerability": CVES[0], "package": "zlib", "version": "3.5.9-r1", "type": "apk"})
        self.write_exc(bad)
        self.refused("outside the OpenSSL")
        bad = copy.deepcopy(REAL)
        bad["images"].append("docs-api-prod")
        self.write_exc(bad)
        self.refused("production")

    def test_workflow_not_listed(self):
        self.refused("is not one the exception lists", workflow_ref="munaxa/repo/.github/workflows/terraform-eu-prod.yml@refs/heads/main")
        self.refused("is not one the exception lists", workflow_ref="")

    def test_gate_failed_for_another_reason(self):
        self.refused("another cause", rep=report(openssl=False))

    def test_malformed_report(self):
        self.refused("malformed", rep={"nothing": []})


class CommandLine(Base):
    def cli(self, *args, env_extra=None):
        rep = os.path.join(self.tmp, "r.json")
        with open(rep, "w") as f:
            json.dump(report(db=None if "--no-db" in args else DB_BUILT), f)
        evidence = os.path.join(self.tmp, "e.json")
        env = dict(self.env, **(env_extra or {}))
        args = [a for a in args if a != "--no-db"]
        p = subprocess.run(["python3", "-I", os.path.join(HERE, "scan-exception.py"), "--grype-json", rep, "--image", IMAGE,
                            "--exception", self.exc_path, "--evidence", evidence, *args], env=env, capture_output=True, text=True)
        with open(evidence) as f:
            return p.returncode, json.load(f), p.stdout

    def test_now_refused_inside_actions(self):
        code, ev, _ = self.cli("--environment", "testing", "--now", BEFORE,
                               env_extra={"GITHUB_ACTIONS": "true", "GITHUB_WORKFLOW_REF": WORKFLOW_REF})
        self.assertEqual(code, 1)
        self.assertIn("--now is refused", ev["reason"])

    def test_outside_actions_needs_the_flag(self):
        code, ev, _ = self.cli("--environment", "testing", "--now", BEFORE)
        self.assertEqual(code, 1)
        code, ev, out = self.cli("--environment", "testing", "--now", BEFORE, "--outside-actions")
        self.assertEqual(code, 0, ev)
        self.assertIn("::warning title=D-SSL temporary exception", out)
        self.assertIn("Not for production", out)

    def test_production_evidence(self):
        code, ev, out = self.cli("--environment", "production", "--now", BEFORE, "--outside-actions")
        self.assertEqual((code, ev["decision"]), (1, "refused"))
        self.assertIn("::error", out)


class PermanentGate(Base):
    def copy_repo(self):
        dst = tempfile.mkdtemp(dir=self.tmp)
        os.makedirs(os.path.join(dst, ".github"))
        for sub in ("scripts", "workflows", "security"):
            src = os.path.join(ROOT, ".github", sub)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(dst, ".github", sub))
        if os.path.exists(os.path.join(ROOT, ".grype.yaml")):
            shutil.copy(os.path.join(ROOT, ".grype.yaml"), dst)
        return dst

    def append(self, path, text):
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)

    def test_this_repository_is_intact(self):
        self.assertEqual(GATE.check(ROOT), [])

    def test_ignore_rule_is_detected(self):
        r = self.copy_repo()
        with open(os.path.join(r, ".grype.yaml"), "w") as f:
            f.write("# exception: CVE-2026-124709 owner=x expires=2026-12-01 reason=y\nignore:\n  - vulnerability: CVE-2026-124709\n")
        self.assertTrue(any("ignore rule" in p for p in GATE.check(r)))

    def test_another_grype_config_is_detected(self):
        r = self.copy_repo()
        self.append(os.path.join(r, ".grype.yml"), "fail-on-severity: critical\n")
        self.assertTrue(any("unexpected Grype configuration" in p for p in GATE.check(r)))

    def test_threshold_change_is_detected(self):
        r = self.copy_repo()
        p = os.path.join(r, ".github/scripts/scan-image.sh")
        with open(p) as f:
            s = f.read()
        with open(p, "w") as f:
            f.write(s.replace('FAIL_ON="high"', 'FAIL_ON="critical"'))
        self.assertTrue(any("scan-image.sh changed" in p for p in GATE.check(r)))

    def test_weakened_workflow_is_detected(self):
        for line, needle in (("      continue-on-error: true\n", "continue-on-error"),
                             ("        run: .github/scripts/scan-image.sh x y z || true\n", "ignored"),
                             ("      GRYPE_FAIL_ON_SEVERITY: critical\n", "GRYPE_"),
                             ("        run: grype x --only-fixed\n", "Grype flag")):
            r = self.copy_repo()
            self.append(os.path.join(r, ".github/workflows/zz.yml"), "jobs:\n  x:\n    steps:\n" + line)
            self.assertTrue(any(needle in p for p in GATE.check(r)), line)

    def test_wrapper_passing_now_is_detected(self):
        r = self.copy_repo()
        self.append(os.path.join(r, ".github/scripts/scan-image-testing.sh"), "# --now 2026-11-01T00:00:00Z\n")
        self.assertTrue(any("--now" in p for p in GATE.check(r)))


FAKE_DOCKER = r"""#!/usr/bin/env bash
# Fake docker for the wrapper tests: syft writes an SBOM, grype writes $FAKE_GRYPE_REPORT and exits as grype would.
out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-v" ]; then case "$a" in *:/out) out="${a%:/out}" ;; esac; fi
  prev="$a"
done
case "$*" in
  *anchore/syft*) for a in "$@"; do case "$a" in syft-json=/out/*) echo '{"artifacts":[]}' > "$out/${a#syft-json=/out/}" ;; esac; done ;;
  *"db status"*) echo "Built: fake" ;;
  *anchore/grype*) for a in "$@"; do case "$a" in json=/out/*) cp "$FAKE_GRYPE_REPORT" "$out/${a#json=/out/}" ;; esac; done
                   exit "$FAKE_GRYPE_EXIT" ;;
esac
exit 0
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash")
class Wrapper(PermanentGate):
    def run_wrapper(self, rep, grype_exit, image=IMAGE, environment="testing", workflow_ref=WORKFLOW_REF, drop_exception=False):
        r = self.copy_repo()
        if drop_exception:
            os.remove(os.path.join(r, ".github/security/dssl-testing-exception.json"))
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir, exist_ok=True)
        with open(os.path.join(bindir, "docker"), "w") as f:
            f.write(FAKE_DOCKER)
        os.chmod(os.path.join(bindir, "docker"), 0o755)
        rp = os.path.join(self.tmp, "fixture.json")
        with open(rp, "w") as f:
            json.dump(rep, f)
        env = dict(self.env, PATH=bindir + os.pathsep + os.environ["PATH"], FAKE_GRYPE_REPORT=rp,
                   FAKE_GRYPE_EXIT=str(grype_exit), GITHUB_ACTIONS="true", GITHUB_WORKFLOW_REF=workflow_ref,
                   RUNNER_TEMP=self.tmp)
        p = subprocess.run(["bash", ".github/scripts/scan-image-testing.sh", "img:ci", image, "out", environment],
                           cwd=r, env=env, capture_output=True, text=True)
        ev = os.path.join(r, "out", f"{image}.dssl-exception.json")
        if not os.path.exists(ev):
            return p, None
        with open(ev, encoding="utf-8") as f:
            return p, json.load(f)

    def now_report(self, **kw):
        import datetime as dt
        built = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return report(db=built, **kw)

    def expired_now(self):
        import datetime as dt
        return dt.datetime.now(dt.timezone.utc) >= EXC.HARD_EXPIRY

    def test_clean_image_passes_without_the_exception(self):
        p, ev = self.run_wrapper(self.now_report(openssl=False), 0)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIsNone(ev)

    def test_openssl_only_image_in_testing(self):
        p, ev = self.run_wrapper(self.now_report(), 2)
        if self.expired_now():  # after 1 Dec the same run must fail closed
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("expired", ev["reason"])
        else:
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(ev["decision"], "accepted-temporary-testing-only")
            self.assertIn("permanent gate FAILED", p.stdout)

    def test_openssl_only_image_in_production(self):
        p, ev = self.run_wrapper(self.now_report(), 2, environment="production")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(ev["decision"], "refused")

    def test_unrelated_high_still_fails(self):
        p, ev = self.run_wrapper(self.now_report(extra=[match("CVE-2026-777", "musl", "1.2.5-r9")]), 2)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(ev["decision"], "refused")

    def test_without_the_exception_file_the_gate_result_stands(self):
        p, ev = self.run_wrapper(self.now_report(), 2, drop_exception=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("failure stands", p.stdout + p.stderr)
        self.assertIsNone(ev)

if __name__ == "__main__":
    unittest.main()
