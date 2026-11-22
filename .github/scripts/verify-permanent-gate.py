#!/usr/bin/env python3
"""Proves the PERMANENT vulnerability gate is intact (D-SSL owner decision, 22 Nov 2026).

  python3 -I .github/scripts/verify-permanent-gate.py [repository root]

Checks, failing on any deviation:
  1. .github/scripts/scan-image.sh is byte-for-byte the reviewed permanent gate (SHA-256 below):
     Grype --fail-on high, digest-pinned scanners, the .grype.yaml exception rules;
  2. no Grype ignore rule exists: .grype.yaml is absent or holds only `ignore: []` and comments, and no
     other Grype configuration file exists anywhere in the repository;
  3. no workflow weakens the gate: no continue-on-error, no GRYPE_* setting, no --fail-on / --only-fixed
     of its own, no scan call followed by `|| true` or `|| :`;
  4. the temporary wrapper (scan-image-testing.sh) runs the permanent gate first and never passes --now.
Run in CI before every scan, by the wrapper itself, and by hand (exit 0 = intact).
"""
import hashlib
import os
import re
import subprocess
import sys

PERMANENT_GATE_SHA256 = "68c9f23ce5400790e5f41a099f4d8c55276ee4bafdab19bc60d5e1dd921acca2"
GRYPE_CONFIG_NAMES = re.compile(r"(^|/)(\.?grype\.ya?ml|\.grype/.*)$")


def files(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard"], check=True,
                             capture_output=True, text=True).stdout.splitlines()
        if out:
            return out
    except (OSError, subprocess.CalledProcessError):
        pass
    found = []
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
        found += [os.path.relpath(os.path.join(d, n), root) for n in names]
    return found


def check(root):
    problems = []
    gate = os.path.join(root, ".github/scripts/scan-image.sh")
    try:
        with open(gate, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        if sha != PERMANENT_GATE_SHA256:
            problems.append(f"scan-image.sh changed (sha256 {sha}, reviewed {PERMANENT_GATE_SHA256})")
    except OSError:
        problems.append("scan-image.sh is missing")

    all_files = [p.replace(os.sep, "/") for p in files(root)]
    for p in all_files:
        if GRYPE_CONFIG_NAMES.search(p) and p != ".grype.yaml":
            problems.append(f"unexpected Grype configuration file {p}")
    cfg = os.path.join(root, ".grype.yaml")
    if os.path.exists(cfg):
        with open(cfg, encoding="utf-8") as f:
            body = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        if body != ["ignore: []"]:
            problems.append(f".grype.yaml must hold only 'ignore: []' (no ignore rule); it holds {body}")

    for p in all_files:
        if not re.match(r"^\.github/workflows/.+\.ya?ml$", p):
            continue
        with open(os.path.join(root, p), encoding="utf-8") as f:
            text = f.read()
        for n, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r"continue-on-error\s*:", code):
                problems.append(f"{p}:{n}: continue-on-error")
            if re.search(r"\bGRYPE_[A-Z_]+", code):
                problems.append(f"{p}:{n}: a GRYPE_* setting outside the gate")
            if re.search(r"--(fail-on|only-fixed|only-notfixed|ignore-states)\b", code):
                problems.append(f"{p}:{n}: a Grype flag outside the gate")
            if re.search(r"scan-image(-testing)?\.sh.*\|\|\s*(true|:)\s*$", code):
                problems.append(f"{p}:{n}: a scan whose failure is ignored")

    wrapper = os.path.join(root, ".github/scripts/scan-image-testing.sh")
    if os.path.exists(wrapper):
        with open(wrapper, encoding="utf-8") as f:
            w = f.read()
        if "--now" in w:
            problems.append("scan-image-testing.sh passes --now")
        if '"$HERE/scan-image.sh" "$REF" "$NAME" "$OUT"' not in w:
            problems.append("scan-image-testing.sh does not run the permanent gate")
    return problems


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    problems = check(root)
    for p in problems:
        print(f"::error title=Permanent vulnerability gate::{p}")
    if problems:
        return 1
    print(f"Permanent vulnerability gate intact: scan-image.sh sha256 {PERMANENT_GATE_SHA256}, Grype --fail-on high, no ignore rule, no weakened workflow.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
