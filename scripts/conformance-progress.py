#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Live progress monitor for a running gr8s conformance suite.

A full `certified-conformance` run takes hours, and Sonobuoy's built-in
progress reporting is unreliable on this suite version, so a run is otherwise
blind until it finishes. This script tails the Ginkgo e2e log out of the
running e2e pod and prints running pass/fail/remaining counts every few
seconds.

How it reads progress: Ginkgo writes the suite log to a file inside the e2e
container (`/tmp/sonobuoy/results/e2e.log`), not to stdout, so `kubectl logs`
usually shows nothing useful mid-run. We therefore `kubectl exec ... cat` that
file through gr8s's own exec path (which doubles as a live exercise of exec),
and fall back to `kubectl logs` if exec is unavailable.

Usage:
    scripts/conformance-progress.py --kubeconfig <rundir>/kubeconfig [--interval 10]

Point --kubeconfig at the same kubeconfig the run was launched with (see the
`guestRunDirectory` in a run's evidence JSON, e.g. /var/tmp/gr8s-conformance.*/kubeconfig).
"""

import argparse
import json
import re
import subprocess
import sys
import time

NAMESPACE = "sonobuoy"
E2E_LOG_PATH = "/tmp/sonobuoy/results/e2e.log"
DEFAULT_TOTAL = 462  # upstream v1.37 certified-conformance selection (v1.36 selected 446)

# Ginkgo v2 summary lines, e.g.
#   "SUCCESS! -- 64 Passed | 382 Failed | 0 Pending | 0 Skipped"
#   "FAIL! -- 64 Passed | 382 Failed | 0 Pending | 7 Skipped"
SUMMARY_RE = re.compile(
    r"(?:SUCCESS|FAIL)!\s*--\s*(\d+)\s+Passed\s*\|\s*(\d+)\s+Failed", re.I
)
WILL_RUN_RE = re.compile(r"Will run (\d+) of (\d+) specs")
RAN_RE = re.compile(r"Ran (\d+) of (\d+) Specs")


def kubectl(kubeconfig, *args, timeout=30):
    """Run kubectl and return (rc, stdout, stderr); never raises on nonzero."""
    try:
        proc = subprocess.run(
            ["kubectl", "--kubeconfig", kubeconfig, *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        sys.exit("error: kubectl not found on PATH")
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"


def find_e2e_pod(kubeconfig):
    """Return the name of the Sonobuoy e2e pod, or None if not present yet."""
    rc, out, _ = kubectl(kubeconfig, "get", "pods", "-n", NAMESPACE, "-o", "json")
    if rc != 0 or not out.strip():
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    for pod in data.get("items", []):
        name = pod.get("metadata", {}).get("name", "")
        if "e2e" in name:
            return name
    return None


def read_e2e_log(kubeconfig, pod):
    """Read the Ginkgo log file from the e2e container; '' if unavailable."""
    # Preferred: exec + cat the file Ginkgo actually writes to.
    rc, out, _ = kubectl(
        kubeconfig, "exec", "-n", NAMESPACE, pod, "-c", "e2e",
        "--", "cat", E2E_LOG_PATH, timeout=60,
    )
    if rc == 0 and out:
        return out
    # Fallback: container stdout (may be sparse, but better than nothing).
    rc, out, _ = kubectl(kubeconfig, "logs", "-n", NAMESPACE, pod, "-c", "e2e", timeout=60)
    return out if rc == 0 else ""


def parse_progress(text, total):
    """Extract (passed, failed, total, complete) from a Ginkgo log snapshot."""
    complete = False

    # A final summary line, if present, is authoritative.
    summary = None
    for m in SUMMARY_RE.finditer(text):
        summary = m
    if summary:
        return int(summary.group(1)), int(summary.group(2)), total, True

    # Otherwise count progress bullets: '•' is a completed spec; failures are
    # marked by a following [FAILED] on the same progress segment.
    passed = failed = 0
    for line in text.splitlines():
        s = line.strip()
        if "•" in s:
            if "[FAILED]" in s or "[FAIL]" in s:
                failed += s.count("•")
            else:
                passed += s.count("•")
        if s.startswith("Ran "):
            complete = True

    # Prefer the detected selection size for the denominator if we saw it.
    # "Will run 446 of 7000 specs" / "Ran 446 of 7000 Specs" -> 446 selected.
    m = WILL_RUN_RE.search(text) or RAN_RE.search(text)
    if m:
        total = int(m.group(1))
    return passed, failed, total, complete


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kubeconfig", required=True,
                    help="kubeconfig the conformance run was launched with")
    ap.add_argument("--interval", type=int, default=10,
                    help="seconds between polls (default: 10)")
    ap.add_argument("--total", type=int, default=DEFAULT_TOTAL,
                    help=f"expected spec count (default: {DEFAULT_TOTAL}; auto-detected when seen)")
    args = ap.parse_args()

    print("=== gr8s conformance progress monitor ===")
    print(f"kubeconfig: {args.kubeconfig}  |  polling every {args.interval}s")
    print("")

    while True:
        pod = find_e2e_pod(args.kubeconfig)
        if not pod:
            print(f"{time.strftime('%H:%M:%S')} | no e2e pod yet; waiting...")
            time.sleep(args.interval)
            continue

        text = read_e2e_log(args.kubeconfig, pod)
        if not text:
            print(f"{time.strftime('%H:%M:%S')} | {pod}: no log output yet...")
            time.sleep(args.interval)
            continue

        passed, failed, total, complete = parse_progress(text, args.total)
        done = passed + failed
        remaining = max(0, total - done)
        rate = f"{passed * 100 / done:.1f}%" if done else "0.0%"
        print(f"{time.strftime('%H:%M:%S')} | passed: {passed} | failed: {failed} "
              f"| done: {done}/{total} | remaining: {remaining} | pass rate: {rate}")

        if complete:
            print("")
            print(f"=== suite complete: {passed} passed, {failed} failed "
                  f"({passed}/{done}) ===")
            return 0

        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n(monitor stopped; the conformance run itself is unaffected)")
        sys.exit(130)
