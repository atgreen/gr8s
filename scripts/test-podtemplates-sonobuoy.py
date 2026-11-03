#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 gr8s contributors
# SPDX-License-Identifier: MIT
"""Run the upstream PodTemplate lifecycle and chunking cases in a disposable native cluster.

Requires root in a disposable Linux guest, a native gr8s executable and Sonobuoy.
This is focused API validation, not a certified-conformance run. The second
chunking case intentionally waits for the normal five-minute history expiry.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tarfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

FOCUS = "PodTemplates|Servers with support for API chunking"


def verify_upstream_results(archive, e2e_log, summary):
    """Distinguish the five actual specs from the extra suite-hook JUnit entries."""
    cases = []
    hooks = 0
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            if not (member.name.startswith("plugins/e2e/results/") and Path(member.name).name.startswith("junit") and member.name.endswith(".xml")):
                continue
            root = ET.fromstring(bundle.extractfile(member).read())
            for case in root.findall(".//testcase"):
                if case.find("skipped") is not None:
                    continue
                if case.get("name", "").startswith("[It] "):
                    cases.append({"name": case.get("name"), "seconds": case.get("time"),
                                  "passed": case.find("failure") is None and case.find("error") is None})
                else:
                    hooks += 1
    starts = e2e_log.count("Running Suite: Kubernetes e2e suite")
    selected = re.findall(r"Will run (\d+) of (\d+) specs", e2e_log)
    passed = ("Status: passed" in summary and re.search(r"^Failed:\s+0\s*$", summary, re.M) is not None
              and "Test Suite Passed" in e2e_log and starts == 1 and len(selected) == 1 and selected[0][0] == "5"
              and len(cases) == 5 and all(case["passed"] for case in cases))
    return {"passed": passed, "suiteStarts": starts, "selectedSpecs": selected, "upstreamCases": cases, "suiteHookEntries": hooks}


def main():
    """Launch native gr8s, preserve actual upstream output, and clean up its owned Pods."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--sonobuoy", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--api-port", type=int, default=18190)
    parser.add_argument("--node-port", type=int, default=17447)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run this privileged integration test inside a disposable Linux guest")
    root = Path(tempfile.mkdtemp(prefix="gr8s-podtemplates.", dir=args.state_parent))
    state = root / "state"
    base = f"http://127.0.0.1:{args.api_port}"
    report = {"focus": FOCUS, "isCertificationResult": False, "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest()}
    native_log = (root / "gr8s.log").open("w")
    process = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                "--port", str(args.api_port), "--node-port", str(args.node_port), "--kubeconfig", str(root / "kubeconfig")],
                               stdout=native_log, stderr=subprocess.STDOUT)

    def request(path, method="GET"):
        """Read an actual administrative HTTP response without interpreting Pod phase as a test result."""
        try:
            with urllib.request.urlopen(urllib.request.Request(base + path, method=method), timeout=30) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    def owned_shims():
        """Find only runtime shims belonging to this newly created state directory."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    def logs_for(pod, container):
        """Read the real CRI log directly, avoiding API operation queues during image pulls."""
        path = Path("/var/log/gr8s/pods") / pod["metadata"]["uid"] / (container + ".log")
        return path.read_text(errors="replace") if path.exists() else ""

    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Native gr8s exited before readiness")
            try:
                if 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in request("/metrics")[1]:
                    break
            except OSError:
                pass
            time.sleep(.1)
        else:
            raise RuntimeError("Native agent did not become ready")
        report["nativeAgentReady"] = True
        report["version"] = json.loads(request("/version")[1])
        report["sonobuoyVersion"] = subprocess.check_output([str(args.sonobuoy), "version", "--short"], text=True).strip()
        command = [str(args.sonobuoy), "run", "--kubeconfig", str(root / "kubeconfig"), "--dns-pod-labels=", "--plugin=e2e",
                   "--e2e-focus=" + FOCUS, "--e2e-skip="]
        report["command"] = command
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        report["sonobuoyRunExitCode"] = result.returncode
        (root / "sonobuoy.stdout.log").write_text(result.stdout)
        (root / "sonobuoy.stderr.log").write_text(result.stderr)
        if result.returncode:
            raise RuntimeError("Sonobuoy submission failed; see stderr")
        deadline = time.monotonic() + args.timeout
        pods = []
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Native gr8s exited during e2e run")
            try:
                pods = json.loads(request("/api/v1/pods")[1]).get("items", [])
            except OSError as error:
                report.setdefault("observationErrors", []).append(str(error))
                continue
            aggregator = next((pod for pod in pods if pod["metadata"]["name"] == "sonobuoy"), None)
            if aggregator:
                log = logs_for(aggregator, "kube-sonobuoy")
                match = re.search(r"Results available at (\S+\.tar\.gz)", log)
                if match:
                    archive = Path("/var/log/gr8s/pods") / aggregator["metadata"]["uid"] / "volumes/output-volume" / Path(match[1]).name
                    shutil.copyfile(archive, root / "sonobuoy-results.tar.gz")
                    break
            time.sleep(1)
        else:
            raise RuntimeError("Upstream cases did not complete within the integration timeout")
        report["podsAtCompletion"] = pods
        for pod in pods:
            for container in pod["spec"]["containers"]:
                (root / (container["name"] + ".log")).write_text(logs_for(pod, container["name"]))
        result = subprocess.run([str(args.sonobuoy), "results", str(root / "sonobuoy-results.tar.gz")], text=True, capture_output=True, timeout=30)
        (root / "sonobuoy-results.txt").write_text(result.stdout + result.stderr)
        e2e = (root / "e2e.log").read_text()
        report.update(verify_upstream_results(root / "sonobuoy-results.tar.gz", e2e, result.stdout))
        if not report["passed"]:
            raise RuntimeError("PodTemplate conformance cases did not all pass; inspect the official archive and logs")
    except Exception as error:
        report["error"] = str(error)
    finally:
        try:
            if process.poll() is None:
                for pod in json.loads(request("/api/v1/pods")[1]).get("items", []):
                    meta = pod["metadata"]
                    code, _ = request(f"/api/v1/namespaces/{meta['namespace']}/pods/{meta['name']}", "DELETE")
                    if code not in (200, 404):
                        raise RuntimeError("Owned Pod cleanup request failed")
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline:
                    # Cache removal occurs after CRI deletion returns. Waiting
                    # for both avoids stopping containerd midway through removal.
                    if not owned_shims() and not list((state / "agent/runtime/desired").glob("*.json")):
                        break
                    time.sleep(.2)
                else:
                    raise RuntimeError("Owned runtime deletion did not finish")
        except Exception as error:
            report["cleanupError"] = str(error)
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            report["forcedShutdown"] = True
        native_log.close()
        report["nativeExitCode"] = process.returncode
        report["ownedShimsRemaining"] = owned_shims()
        report["artifactSHA256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"reportDirectory": str(root), "passed": report.get("passed", False), "error": report.get("error"),
                          "cleanupError": report.get("cleanupError"), "ownedShimsRemaining": len(report["ownedShimsRemaining"])}), flush=True)
    return 0 if report.get("passed") and not report.get("cleanupError") and not report["ownedShimsRemaining"] and process.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
