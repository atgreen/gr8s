#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Run upstream conformance cases in a disposable native cluster.

Requires root in a disposable Linux guest, a native gr8s executable and Sonobuoy.
The default focus covers the five PodTemplate lifecycle and chunking specs,
including normal five-minute history expiry. Custom focused runs are supplemental;
--certified-conformance always selects the full upstream certified suite.
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


def verify_upstream_results(archive, e2e_log, summary, expected_specs=5):
    """Count actual specs separately from suite hooks and require complete upstream success."""
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
              and "Test Suite Passed" in e2e_log and starts == 1 and len(selected) == 1 and int(selected[0][0]) > 0
              and (expected_specs is None or int(selected[0][0]) == expected_specs)
              and len(cases) == int(selected[0][0]) and all(case["passed"] for case in cases))
    return {"passed": passed, "suiteStarts": starts, "selectedSpecs": selected, "upstreamCases": cases, "suiteHookEntries": hooks}


def main():
    """Launch native gr8s, preserve actual upstream output, and clean up its owned Pods."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--sonobuoy", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--state-directory", type=Path, help="Reuse an explicitly owned, stopped state and its image cache")
    parser.add_argument("--api-port", type=int, default=18190)
    parser.add_argument("--node-port", type=int, default=17447)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--certified-conformance", action="store_true",
                        help="Run the entire upstream certified selection instead of the five focused specs")
    parser.add_argument("--focus", default=FOCUS, help="Upstream regex for a supplemental focused run")
    parser.add_argument("--expected-specs", type=int, default=5, help="Require this many executed specs in a focused run")
    args = parser.parse_args()
    if args.expected_specs < 1:
        parser.error("--expected-specs must be positive")
    if args.certified_conformance and (args.focus != FOCUS or args.expected_specs != 5):
        parser.error("Custom focus/count cannot be combined with the full certified selection")
    if os.geteuid() != 0:
        parser.error("Run this privileged integration test inside a disposable Linux guest")
    root = Path(tempfile.mkdtemp(prefix="gr8s-conformance." if args.certified_conformance else "gr8s-podtemplates.", dir=args.state_parent))
    state = args.state_directory or root / "state"
    base = f"http://127.0.0.1:{args.api_port}"
    report = {"focus": None if args.certified_conformance else args.focus,
              "mode": "certified-conformance" if args.certified_conformance else "focused",
              "isCertificationResult": False, "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "stateDirectory": str(state), "reusedState": args.state_directory is not None}
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
        if args.state_directory:
            operations = []
            code, body = request("/api/v1/namespaces/sonobuoy/pods")
            if code != 200:
                raise RuntimeError("Could not list prior owned Sonobuoy Pods")
            for obj in json.loads(body)["items"]:
                metadata = obj["metadata"]
                code, _ = request("/api/v1/namespaces/sonobuoy/pods/" + metadata["name"], "DELETE")
                operations.append({"resource": "pods", "name": metadata["name"], "uid": metadata["uid"], "code": code})
                if code not in (200, 404):
                    raise RuntimeError("Could not remove prior owned Sonobuoy Pod")
            deadline = time.monotonic() + 90
            while json.loads(request("/api/v1/namespaces/sonobuoy/pods")[1])["items"]:
                if time.monotonic() > deadline:
                    raise RuntimeError("Prior owned Sonobuoy Pod API deletion did not finish")
                time.sleep(.2)
            for prefix, resources in (("/api/v1", ("configmaps", "secrets", "serviceaccounts", "services")),
                                      ("/apis/rbac.authorization.k8s.io/v1", ("roles", "rolebindings"))):
                for resource in resources:
                    collection = prefix + "/namespaces/sonobuoy/" + resource
                    code, body = request(collection)
                    if code != 200:
                        raise RuntimeError("Could not list prior owned Sonobuoy namespace resources")
                    for obj in json.loads(body)["items"]:
                        metadata = obj["metadata"]
                        code, _ = request(collection + "/" + metadata["name"], "DELETE")
                        operations.append({"resource": resource, "name": metadata["name"], "uid": metadata["uid"], "code": code})
                        if code not in (200, 404):
                            raise RuntimeError("Could not remove prior owned Sonobuoy namespace resource")
            for resource in ("clusterrolebindings", "clusterroles"):
                collection = "/apis/rbac.authorization.k8s.io/v1/" + resource
                code, body = request(collection + "?labelSelector=component%3Dsonobuoy%2Cnamespace%3Dsonobuoy")
                if code != 200:
                    raise RuntimeError("Could not list prior owned Sonobuoy RBAC resources")
                for obj in json.loads(body)["items"]:
                    metadata = obj["metadata"]
                    code, _ = request(collection + "/" + metadata["name"], "DELETE")
                    operations.append({"resource": resource, "name": metadata["name"], "uid": metadata["uid"], "code": code})
                    if code not in (200, 404):
                        raise RuntimeError("Could not remove prior owned Sonobuoy RBAC resource")
            code, _ = request("/api/v1/namespaces/sonobuoy", "DELETE")
            operations.append({"resource": "namespaces", "name": "sonobuoy", "code": code})
            if code not in (200, 404):
                raise RuntimeError("Could not remove prior owned Sonobuoy namespace")
            deadline = time.monotonic() + 60
            while request("/api/v1/namespaces/sonobuoy")[0] != 404:
                if time.monotonic() > deadline:
                    raise RuntimeError("Prior owned Sonobuoy namespace deletion did not finish")
                time.sleep(.2)
            report["stateReuseCleanupOperations"] = operations
        command = [str(args.sonobuoy), "run", "--kubeconfig", str(root / "kubeconfig"), "--dns-pod-labels=", "--plugin=e2e",
                   *(["--mode=certified-conformance"] if args.certified_conformance else ["--e2e-focus=" + args.focus, "--e2e-skip="])]
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
        report.update(verify_upstream_results(root / "sonobuoy-results.tar.gz", e2e, result.stdout,
                                              expected_specs=None if args.certified_conformance else args.expected_specs))
        if not report["passed"]:
            raise RuntimeError("Upstream conformance cases did not all pass; inspect the official archive and logs")
    except Exception as error:
        report["error"] = str(error)
    finally:
        try:
            if process.poll() is None:
                for pod in json.loads(request("/api/v1/pods")[1]).get("items", []):
                    # Preserve partial test output even when no archive exists.
                    for container in pod["spec"]["containers"]:
                        log = logs_for(pod, container["name"])
                        if log:
                            (root / (container["name"] + ".log")).write_text(log)
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
