#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Verify real ordered init execution and recovery in an owned privileged guest.

This is supplemental native evidence. The unchanged upstream init-container
selection must be run separately, including its actual CPU resource limits.
"""
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
    """Own real native processes and retain exact API, file and container observations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--image", default="registry.k8s.io/e2e-test-images/busybox:1.37.0-1")
    parser.add_argument("--api-port", type=int, default=18290)
    parser.add_argument("--node-port", type=int, default=17490)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-init-native.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    namespace = "init-" + uuid.uuid4().hex[:10]
    base = f"http://127.0.0.1:{args.api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    log = (root / "gr8s.log").open("wb")
    native = None
    pods = []
    report = {"sourceCommit": args.source_commit, "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "harnessSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "stateDirectory": str(state), "namespace": namespace, "isCertificationResult": False,
              "scenarios": {}, "nativeExitCodes": [], "passed": False}
    print(json.dumps({"reportDirectory": str(root)}), flush=True)

    def request(path, method="GET", obj=None):
        """Read actual API status and body with no guest proxy environment."""
        req = urllib.request.Request(base + path, method=method,
                                     data=None if obj is None else json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            return response.code, json.loads(body) if body else None

    def wait(predicate, timeout, description):
        """Poll the same live process; never restart it on an observation timeout."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if native is not None and native.poll() is not None:
                raise RuntimeError(f"native exited while waiting for {description}: {native.returncode}")
            try:
                value = predicate()
                if value:
                    return value
            except OSError as error:
                report.setdefault("observationErrors", []).append(str(error))
            time.sleep(.2)
        raise TimeoutError(description)

    def start():
        """Start only this explicitly owned stopped state."""
        nonlocal native
        native = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                   "--port", str(args.api_port), "--node-port", str(args.node_port),
                                   "--kubeconfig", str(root / "kubeconfig")], stdout=log, stderr=subprocess.STDOUT)
        wait(lambda: request("/api/v1/pods")[0] == 200, 90, "native API readiness")

    def stop():
        """Require clean native shutdown and preserve an exceptional forced stop as failure."""
        nonlocal native
        if native is None:
            return
        native.terminate()
        try:
            code = native.wait(timeout=45)
        except subprocess.TimeoutExpired:
            native.kill()
            code = native.wait(timeout=10)
            report["forcedShutdown"] = True
        report["nativeExitCodes"].append(code)
        native = None
        assert code == 0 and not report.get("forcedShutdown"), f"native shutdown failed: {code}"

    def path(pod):
        """Address the exact smoke-owned namespace and Pod name."""
        return f"/api/v1/namespaces/{namespace}/pods/{pod['metadata']['name']}"

    def current(pod):
        """Reject missing or replacement Pod identities during observations."""
        code, obj = request(path(pod))
        assert code == 200 and obj["metadata"]["uid"] == pod["metadata"]["uid"], (code, obj)
        return obj

    def create(init_commands, app_command, policy):
        """Run real commands with a shared emptyDir and standard credential admission."""
        def container(name, command):
            """Use the same ordinary CRI configuration for init and application containers."""
            return {"name": name, "image": args.image, "imagePullPolicy": "IfNotPresent",
                    "command": ["sh", "-c", command], "volumeMounts": [{"name": "work", "mountPath": "/work"}]}
        code, pod = request(f"/api/v1/namespaces/{namespace}/pods", "POST",
                            {"apiVersion": "v1", "kind": "Pod", "metadata": {"generateName": "init-"},
                             "spec": {"restartPolicy": policy, "terminationGracePeriodSeconds": 0,
                                      "volumes": [{"name": "work", "emptyDir": {}}],
                                      "initContainers": [container(f"init-{i}", cmd) for i, cmd in enumerate(init_commands)],
                                      "containers": [container("app", app_command)]}})
        assert code == 201, (code, pod)
        pods.append(pod)
        return pod

    def statuses(obj, kind="initContainerStatuses"):
        """Index real observed status by its container declaration name."""
        return {value["name"]: value for value in obj.get("status", {}).get(kind, [])}

    def volume(pod):
        """Locate the actual emptyDir where processes leave ordering and attempt evidence."""
        return Path("/var/log/gr8s/pods") / pod["metadata"]["uid"] / "volumes/work"

    def save(name, obj):
        """Retain the complete observation supporting an assertion."""
        (root / name).write_text(json.dumps(obj, indent=2) + "\n")

    def owned_shims():
        """Find physical shim processes belonging only to the owned state."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    try:
        start()
        code, existing = request("/api/v1/pods")
        assert code == 200
        assert all(p["metadata"].get("deletionTimestamp") for p in existing["items"]), existing
        wait(lambda: not request("/api/v1/pods")[1]["items"] and not owned_shims()
             and not list((state / "agent/runtime/desired").glob("*.json")), 120, "prior owned deleting Pod replay")
        code, body = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, body)
        ordered = create(["test -s /var/run/secrets/kubernetes.io/serviceaccount/token || exit 41; "
                          "while [ ! -f /work/release ]; do sleep 1; done; echo one > /work/order",
                          "test \"$(cat /work/order)\" = one || exit 42; echo two >> /work/order"],
                         "test \"$(cat /work/order)\" = \"$(printf 'one\\ntwo')\" || exit 43; "
                         "echo ordered > /work/app-ran; exec sleep 600", "Always")

        def first_running():
            """Require an actual init process while later containers remain unstarted."""
            obj = current(ordered)
            return obj if "running" in statuses(obj).get("init-0", {}).get("state", {}) else None
        before = wait(first_running, 600, "blocked first init process")
        first_id = statuses(before)["init-0"]["containerID"]
        assert before["status"]["phase"] == "Pending", before
        assert not statuses(before)["init-1"].get("containerID"), before
        assert not statuses(before, "containerStatuses")["app"].get("containerID"), before
        save("ordered-before-restart.json", before)
        stop()
        start()
        recovered = wait(first_running, 90, "same init process after native restart")
        assert statuses(recovered)["init-0"]["containerID"] == first_id, recovered
        (volume(ordered) / "release").touch()
        ready = wait(lambda: (obj if (obj := current(ordered))["status"]["phase"] == "Running"
                              and (volume(ordered) / "app-ran").exists() else None), 120, "ordered application execution")
        assert (volume(ordered) / "order").read_text() == "one\ntwo\n"
        assert all(s["state"]["terminated"]["exitCode"] == 0 and s["ready"] and s["restartCount"] == 0
                   for s in statuses(ready).values()), ready
        assert statuses(ready)["init-0"]["containerID"] == first_id, ready
        save("ordered-complete.json", ready)
        report["scenarios"]["orderedExecutionAndRestartAdoption"] = {"passed": True, "firstContainerID": first_id,
                                                                    "actualSharedFile": (volume(ordered) / "order").read_text()}
        failed = create(["echo first > /work/first", "exit 17"], "touch /work/app-ran; exec sleep 600", "Never")
        failed_obj = wait(lambda: (obj if (obj := current(failed))["status"]["phase"] == "Failed" else None),
                          600, "actual Never init failure")
        assert statuses(failed_obj)["init-1"]["state"]["terminated"]["exitCode"] == 17, failed_obj
        assert not (volume(failed) / "app-ran").exists() and not statuses(failed_obj, "containerStatuses")["app"].get("containerID")
        save("never-failed.json", failed_obj)
        report["scenarios"]["neverFailurePreventsApplication"] = {"passed": True, "exitCode": 17}
        retry = create(["n=$(cat /work/count 2>/dev/null || echo 0); n=$((n+1)); echo $n > /work/count; exit 19",
                        "touch /work/second-ran"], "touch /work/app-ran; exec sleep 600", "Always")
        retried = wait(lambda: (obj if statuses(obj := current(retry)).get("init-0", {}).get("restartCount", 0) >= 3
                                else None), 600, "actual init retry attempts")
        assert retried["status"]["phase"] == "Pending", retried
        assert int((volume(retry) / "count").read_text()) >= 4
        assert not (volume(retry) / "second-ran").exists() and not (volume(retry) / "app-ran").exists()
        save("always-retried.json", retried)
        report["scenarios"]["alwaysRetriesOnlyFailedInit"] = {"passed": True, "actualExecutedAttempts": int((volume(retry) / "count").read_text())}
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
    finally:
        try:
            if native is not None and native.poll() is None:
                for pod in pods:
                    code, observed = request(path(pod))
                    save(pod["metadata"]["uid"] + "-before-cleanup.json", {"code": code, "pod": observed})
                    for source in (Path("/var/log/gr8s/pods") / pod["metadata"]["uid"]).glob("*.log"):
                        (root / (pod["metadata"]["uid"] + "-" + source.name)).write_bytes(source.read_bytes())
                    code, body = request(path(pod), "DELETE", {"apiVersion": "v1", "kind": "DeleteOptions",
                                                               "preconditions": {"uid": pod["metadata"]["uid"]}, "gracePeriodSeconds": 0})
                    assert code in (200, 404), (code, body)
                wait(lambda: not request(f"/api/v1/namespaces/{namespace}/pods")[1]["items"] and not owned_shims()
                     and not list((state / "agent/runtime/desired").glob("*.json")), 120, "physical init/application cleanup")
        except Exception as error:
            report["cleanupError"] = str(error)
        try:
            stop()
        except Exception as error:
            report["shutdownError"] = str(error)
        log.close()
        report["ownedShimsRemaining"] = owned_shims()
        report["artifactSHA256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
        save("report.json", report)
        print(json.dumps({"reportDirectory": str(root), "passed": report["passed"], "error": report.get("error"),
                          "cleanupError": report.get("cleanupError"), "ownedShimsRemaining": len(report["ownedShimsRemaining"])}), flush=True)
    return 0 if report["passed"] and not report.get("cleanupError") and not report.get("shutdownError") and not report["ownedShimsRemaining"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
