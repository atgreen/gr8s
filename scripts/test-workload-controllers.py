#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Validate real workload controllers in a disposable privileged native guest."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def main():
    """Run actual scaling, replacement, rollout, restart and deletion scenarios."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--api-port", type=int, default=18205)
    parser.add_argument("--node-port", type=int, default=17462)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-workloads.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    namespace = "workloads-" + uuid.uuid4().hex[:8]
    marker_prefix = "gr8s-" + namespace + "-"
    base = f"http://127.0.0.1:{args.api_port}"
    log = (root / "gr8s.log").open("w")
    process = None
    seen = {}
    report = {"directory": str(root), "stateDirectory": str(state), "namespace": namespace,
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "scenarios": {}, "nativeExitCodes": [], "passed": False}
    print(json.dumps({"directory": str(root), "namespace": namespace}), flush=True)

    def request(path, method="GET", obj=None):
        """Read a real local API result without interpreting transport success as test success."""
        data = None if obj is None else json.dumps(obj).encode()
        try:
            req = urllib.request.Request(base + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def wait(predicate, description, timeout=300):
        """Keep observing the same operation through transient observation errors."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except OSError as error:
                report.setdefault("observationErrors", []).append(str(error))
            time.sleep(.2)
        raise TimeoutError(description)

    def start():
        """Start the same durable cluster and require actual node readiness."""
        child = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd",
                                  "--state-directory", str(state), "--port", str(args.api_port),
                                  "--node-port", str(args.node_port), "--kubeconfig", str(root / "kubeconfig")],
                                 stdout=log, stderr=subprocess.STDOUT)

        def ready():
            """Detect an early exit while waiting for the native node."""
            if child.poll() is not None:
                raise RuntimeError(f"native exited {child.returncode}")
            with urllib.request.urlopen(base + "/metrics", timeout=2) as response:
                return 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in response.read().decode()

        try:
            wait(ready, "native node readiness", 90)
        except BaseException:
            child.terminate()
            report["nativeExitCodes"].append(child.wait(timeout=45))
            raise
        return child

    def stop():
        """Stop only the owned native process and retain its real exit status."""
        nonlocal process
        if process is not None:
            process.terminate()
            code = process.wait(timeout=45)
            report["nativeExitCodes"].append(code)
            process = None
            assert code == 0, code

    def path(resource, name=None):
        """Return this namespace's real resource endpoint."""
        prefix = "/api/v1" if resource == "pods" else "/apis/apps/v1"
        return f"{prefix}/namespaces/{namespace}/{resource}" + ("/" + name if name else "")

    def pods(app=None):
        """List actual workload Pods in the private namespace."""
        code, result = request(path("pods"))
        assert code == 200, (code, result)
        for pod in result["items"]:
            seen[pod["metadata"]["uid"]] = pod
        return [p for p in result["items"] if app is None or p["metadata"].get("labels", {}).get("app") == app]

    def host_pids(marker):
        """Find real uniquely tagged workload shells without trusting API phase."""
        result = []
        for candidate in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                fields = candidate.read_bytes().split(b"\0")
            except OSError:
                continue
            if len(fields) >= 3 and fields[1] == b"-c" and marker.encode() in fields[2]:
                result.append(int(candidate.parent.name))
        return result

    def shims():
        """Find only shims belonging to the test's explicitly owned state directory."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    def template(app, revision):
        """Use a cached real image and uniquely tagged process for each template revision."""
        marker = marker_prefix + app + "-" + revision
        return {"metadata": {"labels": {"app": app}},
                "spec": {"restartPolicy": "Always", "terminationGracePeriodSeconds": 0,
                         "containers": [{"name": "main", "image": "docker.io/library/busybox:1.36.1",
                                         "imagePullPolicy": "IfNotPresent",
                                         "command": ["sh", "-c", "trap 'exit 0' TERM; echo READY-" + revision +
                                                     "; while :; do sleep 1; done # " + marker]}]}}

    def create(resource, name, replicas, revision="v1", strategy=None):
        """Create an actual controller resource."""
        kind = "ReplicaSet" if resource == "replicasets" else "Deployment"
        obj = {"apiVersion": "apps/v1", "kind": kind, "metadata": {"name": name},
               "spec": {"replicas": replicas, "selector": {"matchLabels": {"app": name}},
                        "template": template(name, revision)}}
        if strategy:
            obj["spec"]["strategy"] = {"type": strategy}
        code, body = request(path(resource), "POST", obj)
        assert code == 201, (code, body)
        return body

    def ready(resource, name, count):
        """Require actual ready Pods, real container IDs, and matching observed generation."""
        code, owner = request(path(resource, name))
        children = [p for p in pods(name) if not p["metadata"].get("deletionTimestamp")]
        status = owner.get("status", {})
        good = (code == 200 and status.get("observedGeneration") == owner["metadata"]["generation"]
                and status.get("replicas", 0) == count and status.get("readyReplicas", 0) == count
                and status.get("availableReplicas", 0) == count and len(children) == count)
        for child in children:
            good &= any(c["type"] == "Ready" and c["status"] == "True" for c in child.get("status", {}).get("conditions", []))
            good &= bool(child.get("status", {}).get("containerStatuses", [{}])[0].get("containerID"))
        return (owner, children) if good else None

    def identities(children):
        """Record exact Pod UIDs and actual CRI container identities."""
        return {p["metadata"]["uid"]: p["status"]["containerStatuses"][0]["containerID"] for p in children}

    def scale(resource, name, count):
        """Change desired replicas through the real Scale subresource."""
        def update():
            """Retry only an actual optimistic conflict using the new resource version."""
            code, obj = request(path(resource, name) + "/scale")
            assert code == 200
            obj["spec"]["replicas"] = count
            code, result = request(path(resource, name) + "/scale", "PUT", obj)
            if code == 409:
                return None
            assert code == 200 and result["spec"]["replicas"] == count, (code, result)
            return result
        wait(update, "optimistic Scale update", 30)

    def replace_template(resource, name, revision, strategy=None):
        """Update desired workload through normal optimistic PUT."""
        def update():
            """Use the current resource version when concurrent status publication wins."""
            code, obj = request(path(resource, name))
            assert code == 200
            obj["spec"]["template"] = template(name, revision)
            if strategy:
                obj["spec"]["strategy"] = {"type": strategy}
            code, result = request(path(resource, name), "PUT", obj)
            if code == 409:
                return None
            assert code == 200, (code, result)
            return result
        return wait(update, "optimistic template update", 30)

    try:
        process = start()
        code, result = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, result)
        rs = create("replicasets", "direct", 2)
        _, children = wait(lambda: ready("replicasets", "direct", 2), "two actual ReplicaSet Pods")
        initial = identities(children)
        initial_pids = host_pids(marker_prefix + "direct-v1")
        assert len(initial_pids) == 2
        scale("replicasets", "direct", 3)
        _, children = wait(lambda: ready("replicasets", "direct", 3), "scale to three actual Pods")
        assert initial.items() <= identities(children).items(), (initial, identities(children))
        victim = children[0]
        code, result = request(path("pods", victim["metadata"]["name"]), "DELETE",
                               {"gracePeriodSeconds": 0, "preconditions": {"uid": victim["metadata"]["uid"]}})
        assert code == 200, (code, result)
        def replacement_ready():
            """Observe the replacement UID and actual ready container exactly once per poll."""
            current = ready("replicasets", "direct", 3)
            return current if current and victim["metadata"]["uid"] not in identities(current[1]) else None

        wait(replacement_ready, "replacement actual Pod UID")
        scale("replicasets", "direct", 1)
        wait(lambda: ready("replicasets", "direct", 1), "scale down to one actual Pod")
        code, result = request(path("replicasets", "direct"), "DELETE", {"propagationPolicy": "Foreground"})
        assert code == 200, (code, result)
        wait(lambda: request(path("replicasets", "direct"))[0] == 404 and not pods("direct")
             and not host_pids(marker_prefix + "direct-v1"), "foreground RS and real process deletion")
        report["scenarios"]["replicaSetScaleReplacementDeletion"] = {"passed": True, "initialIdentities": initial,
                                                                    "initialHostPids": initial_pids,
                                                                    "actualOldProcessesGone": True}
        print(json.dumps({"scenario": "ReplicaSet", "passed": True}), flush=True)

        deployment = create("deployments", "rolling", 2)
        _, children = wait(lambda: ready("deployments", "rolling", 2), "two actual Deployment Pods")
        before = identities(children)
        maximum, minimum = 2, 2
        replace_template("deployments", "rolling", "v2")

        def rolled():
            """Observe actual overlap and availability while the new template replaces the old one."""
            nonlocal maximum, minimum
            current = [p for p in pods("rolling") if not p["metadata"].get("deletionTimestamp")]
            maximum = max(maximum, len(current))
            ready_count = sum(any(c["type"] == "Ready" and c["status"] == "True"
                                  for c in p.get("status", {}).get("conditions", [])) for p in current)
            minimum = min(minimum, ready_count)
            result = ready("deployments", "rolling", 2)
            return result if result and not (set(identities(result[1])) & set(before)) else None

        _, children = wait(rolled, "actual rolling replacement")
        assert maximum <= 3 and minimum >= 2, (maximum, minimum)
        wait(lambda: not host_pids(marker_prefix + "rolling-v1"), "old rolling processes gone")
        after = identities(children)
        report["scenarios"]["rollingUpdate"] = {"passed": True, "before": before, "after": after,
                                                 "maximumActivePods": maximum, "minimumReadyPods": minimum}
        stop()
        process = start()
        _, children = wait(lambda: ready("deployments", "rolling", 2), "deployment recovery after native restart")
        assert identities(children) == after, (after, identities(children))
        report["scenarios"]["restartPersistence"] = {"passed": True, "unchangedIdentities": after}
        print(json.dumps({"scenario": "RollingUpdateAndRestart", "passed": True}), flush=True)

        replace_template("deployments", "rolling", "v3", strategy="Recreate")

        def recreated():
            """A newly started recreate workload must never overlap old real processes."""
            current = pods("rolling")
            new_running = any(p["spec"]["containers"][0]["command"][-1].endswith(marker_prefix + "rolling-v3")
                              and p.get("status", {}).get("containerStatuses") for p in current)
            if new_running:
                assert not host_pids(marker_prefix + "rolling-v2"), "Recreate overlapped old processes"
            result = ready("deployments", "rolling", 2)
            return result if result and all(p["spec"]["containers"][0]["command"][-1].endswith(marker_prefix + "rolling-v3")
                                           for p in result[1]) else None

        wait(recreated, "actual recreate replacement")
        report["scenarios"]["recreateUpdate"] = {"passed": True, "oldProcessesGoneBeforeNewRunning": True}
        report["passed"] = True
    except Exception as error:
        report["error"] = repr(error)
    finally:
        try:
            if process is not None:
                for resource in ("deployments", "replicasets"):
                    code, listing = request(path(resource))
                    if code == 200:
                        for obj in listing["items"]:
                            request(path(resource, obj["metadata"]["name"]), "DELETE",
                                    {"propagationPolicy": "Foreground", "preconditions": {"uid": obj["metadata"]["uid"]}})
                wait(lambda: not request(path("deployments"))[1]["items"] and not request(path("replicasets"))[1]["items"],
                     "owned controller cleanup", 120)
                for pod in pods():
                    request(path("pods", pod["metadata"]["name"]), "DELETE",
                            {"gracePeriodSeconds": 0, "preconditions": {"uid": pod["metadata"]["uid"]}})
                wait(lambda: not pods() and not host_pids(marker_prefix) and not shims(), "owned real process and sandbox cleanup", 120)
                request("/api/v1/namespaces/" + namespace, "DELETE")
        except Exception as error:
            report["cleanupError"] = repr(error)
            report["passed"] = False
        finally:
            try:
                stop()
            except Exception as error:
                report["shutdownError"] = repr(error)
                report["passed"] = False
        log.close()
        report["pods"] = [{"name": pod["metadata"]["name"], "uid": pod["metadata"]["uid"],
                           "phase": pod.get("status", {}).get("phase"),
                           "containerIDs": [s.get("containerID") for s in pod.get("status", {}).get("containerStatuses", [])]}
                          for pod in seen.values()]
        for pod in seen.values():
            for container in pod["spec"]["containers"]:
                source = Path("/var/log/gr8s/pods") / pod["metadata"]["uid"] / (container["name"] + ".log")
                if source.exists():
                    (root / (pod["metadata"]["uid"] + "-" + container["name"] + ".log")).write_bytes(source.read_bytes())
        report["ownedShimsRemaining"] = shims()
        if report["ownedShimsRemaining"]:
            report["passed"] = False
        report["artifactSHA256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob("*.log")}
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
