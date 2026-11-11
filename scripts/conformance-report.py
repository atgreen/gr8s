#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Build a conformance evidence report from a finished Sonobuoy results archive.

A `certified-conformance` run produces a Sonobuoy `.tar.gz` holding the Ginkgo
JUnit (`plugins/e2e/results/global/junit_01.xml`), the e2e log, and run
metadata. This script reads that archive and emits the evidence JSON recorded in
`docs/CONFORMANCE.md`'s ledger: measured per-case outcomes, per-SIG counts,
suite totals, and artifact SHA-256s. Every field is derived from the archive (or
passed in explicitly); nothing is authored here.

Usage:
    scripts/conformance-report.py --tarball <results.tar.gz> \\
        [--gr8s-log <gr8s.log>] [--version <gr8s version>] \\
        [--commit <sha>] [--command <launch command>]

Writes the report JSON to stdout.
"""
import argparse
import datetime
import hashlib
import json
import re
import sys
import tarfile
import xml.etree.ElementTree as ET

JUNIT_MEMBER = "plugins/e2e/results/global/junit_01.xml"
E2E_LOG_MEMBER = "plugins/e2e/results/global/e2e.log"
SONOBUOY_LOG_MEMBER = "podlogs/sonobuoy/sonobuoy/logs/kube-sonobuoy.txt"
CONFIG_MEMBER = "meta/config.json"
SIG_RE = re.compile(r"\[(sig-[a-z-]+)\]")
# Ginkgo suite hooks (BeforeSuite/AfterSuite/report nodes) carry a status but
# are not selected conformance cases; they have no [sig-*] label.
SPEC_RE = re.compile(r"\[sig-")


def _read_member(tar, name):
    try:
        f = tar.extractfile(name)
        return f.read() if f is not None else None
    except KeyError:
        return None


def _sha256(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def build_report(path, gr8s_log=None, version=None, commit=None, command=None):
    with tarfile.open(path, "r:gz") as tar:
        junit = _read_member(tar, JUNIT_MEMBER)
        e2e_log = _read_member(tar, E2E_LOG_MEMBER)
        sonobuoy_log = _read_member(tar, SONOBUOY_LOG_MEMBER)
        config_raw = _read_member(tar, CONFIG_MEMBER)
    if junit is None:
        sys.exit(f"no {JUNIT_MEMBER} in {path}: not a finished e2e archive")

    config = json.loads(config_raw) if config_raw else {}
    root = ET.fromstring(junit)
    suite_el = root.find("testsuite") if root.tag == "testsuites" else root

    # The selected conformance set is the [Conformance]-tagged specs, as ginkgo's
    # "Will run N of M specs" reports. Ginkgo suite hooks (BeforeSuite/report
    # nodes, no [sig-*] label) and any incidental non-[Conformance] [sig-] spec
    # are counted separately, not as conformance cases.
    cases, hooks = [], 0
    counts_by_sig = {}
    passed = failed = 0
    for tc in suite_el.iter("testcase"):
        name = tc.get("name", "")
        status = tc.get("status") or (
            "skipped" if tc.find("skipped") is not None
            else "failed" if tc.find("failure") is not None
            else "passed")
        if "[Conformance]" not in name:
            if not SPEC_RE.search(name) and status != "skipped":
                hooks += 1                    # a suite hook, not a case
            continue
        if status == "skipped":
            continue
        ok = status == "passed"
        passed += ok
        failed += not ok
        cases.append({"name": name, "seconds": tc.get("time", ""), "passed": ok})
        sig_m = SIG_RE.search(name)
        if sig_m:
            sig = sig_m.group(1)[4:]          # strip "sig-"
            bucket = counts_by_sig.setdefault(sig, {"passed": 0, "failed": 0})
            bucket["passed" if ok else "failed"] += 1

    total = int(suite_el.get("tests", 0))
    skipped = int(suite_el.get("skipped") or suite_el.get("disabled") or 0)
    return {
        "date": datetime.date.today().isoformat(),
        "scope": "upstream Kubernetes certified-conformance on native gr8s "
                 "(two-node), via scripts/e2e-two-node.sh",
        "result": "passed" if failed == 0 else "failed",
        "isCertificationResult": False,
        "sourceCommit": commit,
        "version": version,
        "sonobuoyVersion": config.get("Version"),
        "command": command,
        "suite": {
            "executed": len(cases),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "suiteHookEntries": hooks,
            "seconds": float(suite_el.get("time", 0.0)),
        },
        "countsBySIG": dict(sorted(counts_by_sig.items())),
        "officialSonobuoy": {
            "status": "passed" if failed == 0 else "failed",
            "totalCases": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "passedIncludingHooks": passed + hooks,
        },
        "artifactSHA256": {
            k: v for k, v in {
                "junit_01.xml": _sha256(junit),
                "e2e.log": _sha256(e2e_log),
                "kube-sonobuoy.log": _sha256(sonobuoy_log),
                "gr8s.log": _sha256(open(gr8s_log, "rb").read()) if gr8s_log else None,
                "sonobuoy-results.tar.gz": _sha256(open(path, "rb").read()),
            }.items() if v is not None
        },
        "upstreamCases": sorted(cases, key=lambda c: c["name"]),
        "generatedBy": "scripts/conformance-report.py",
        "generatedAt": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat(),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tarball", required=True, help="Sonobuoy results .tar.gz")
    ap.add_argument("--gr8s-log", help="control-plane gr8s log, hashed into the report")
    ap.add_argument("--version", help="gr8s version string (e.g. git describe)")
    ap.add_argument("--commit", help="source commit SHA")
    ap.add_argument("--command", help="the launch command, recorded verbatim")
    args = ap.parse_args()
    report = build_report(args.tarball, args.gr8s_log, args.version,
                          args.commit, args.command)
    json.dump(report, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
