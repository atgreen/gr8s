#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 gr8s contributors
# SPDX-License-Identifier: MIT
"""Exercise real Pod shutdown in an isolated privileged guest with native gr8s.

Requires a disposable Linux guest with bpffs mounted. Verifies SIGTERM handling,
the shared deadline of multiple containers, force shortening and restart recovery.
Keeps logs and a machine-readable report, including cleanup outcomes, on failure.
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


def wait_for(predicate, timeout, description):
    """Wait for actual observable completion without replacing a running operation."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise TimeoutError(description)


def main():
    """Run the native deletion scenarios and preserve all owned diagnostics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--api-port", type=int, default=18195)
    parser.add_argument("--node-port", type=int, default=17452)
    parser.add_argument("--state-directory", type=Path,
                        help="Reuse an owned, stopped test cluster and its cached images")
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-pod-termination.", dir="/var/tmp"))
    base = f"http://127.0.0.1:{args.api_port}"
    state = args.state_directory or root / "state"
    process = None
    log = (root / "gr8s.log").open("w")
    pods = []
    report = {"nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "directory": str(root), "stateDirectory": str(state), "scenarios": {},
              "nativeExitCodes": [], "passed": False}
    print(json.dumps({"reportDirectory": str(root)}), flush=True)

    def request(path, method="GET", obj=None):
        """Return the status and decoded JSON from the actual local API."""
        data = None if obj is None else json.dumps(obj).encode()
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def start():
        """Start or restart the same durable native cluster and await agent readiness."""
        child = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd",
                                  "--state-directory", str(state), "--port", str(args.api_port),
                                  "--node-port", str(args.node_port), "--kubeconfig", str(root / "kubeconfig")],
                                 stdout=log, stderr=subprocess.STDOUT)

        def ready():
            """Observe agent readiness while also detecting an early process exit."""
            if child.poll() is not None:
                raise RuntimeError(f"native gr8s exited {child.returncode}")
            try:
                with urllib.request.urlopen(base + "/metrics", timeout=1) as response:
                    return 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in response.read().decode()
            except OSError:
                return False

        try:
            wait_for(ready, 90, "native agent readiness")
        except Exception:
            child.terminate()
            report["nativeExitCodes"].append(child.wait(timeout=45))
            raise
        return child

    def stop():
        """Stop the owned native process and require a clean exit."""
        nonlocal process
        if process is not None:
            process.terminate()
            code = process.wait(timeout=45)
            report["nativeExitCodes"].append(code)
            process = None
            if code:
                raise RuntimeError(f"native shutdown exited {code}")

    def pod_path(name):
        """Return the test Pod's API path."""
        return "/api/v1/namespaces/default/pods/" + name

    def owned_shims():
        """Find only sandbox and container shims belonging to this cluster's state path."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    def logs(pod, name="main"):
        """Read persistent CRI logs even after the API object has been removed."""
        path = Path("/var/log/gr8s/pods") / pod["metadata"]["uid"] / (name + ".log")
        return path.read_text(errors="replace") if path.exists() else ""

    def create(name, grace, command, count=1):
        """Launch real containers and wait until every shell has installed its signal trap."""
        command += f" # gr8s-shutdown-test-{name}-{time.time_ns()}"
        containers = [{"name": "main" if index == 0 else f"side{index}",
                       "image": "docker.io/library/busybox:1.36.1", "imagePullPolicy": "IfNotPresent",
                       "command": ["sh", "-c", command]} for index in range(count)]
        code, pod = request("/api/v1/namespaces/default/pods", "POST",
                            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "generation": 100},
                             "spec": {"terminationGracePeriodSeconds": grace, "restartPolicy": "Never",
                                      "containers": containers}})
        assert code == 201, (code, pod)
        assert pod["metadata"]["generation"] == 1, pod
        pods.append(pod)
        wait_for(lambda: all("READY" in logs(pod, container["name"]) for container in containers),
                 600, f"Pod {name} shell readiness")
        def observed():
            """Wait for real agent container IDs instead of using the create-time Pending status."""
            code, current = request(pod_path(name))
            statuses = current.get("status", {}).get("containerStatuses", [])
            return current if (code == 200 and len(statuses) == count
                               and all(item.get("containerID") for item in statuses)
                               and current.get("status", {}).get("observedGeneration") == 1) else None

        current = wait_for(observed, 30, f"Pod {name} container status")
        pod.clear()
        pod.update(current)
        pod["testHostPids"] = host_container_pids(pod)
        assert len(pod["testHostPids"]) >= count, pod["testHostPids"]
        return pod

    def delete(name, **options):
        """Start deletion and require the API to respond before containers finish."""
        started = time.monotonic()
        code, body = request(pod_path(name), "DELETE", options)
        assert code == 200, (code, body)
        elapsed = time.monotonic() - started
        assert elapsed < 3, f"DELETE blocked for {elapsed}s"
        return started, body

    def gone(name):
        """Observe durable removal of the API object after native shutdown."""
        return request(pod_path(name))[0] == 404

    def containers_gone(pod):
        """Require real container processes to exit, independently of API and shim cleanup."""
        if "testHostPids" in pod:
            return all(not Path(f"/proc/{pid}").exists() for pid in pod["testHostPids"])
        return not host_container_pids(pod)

    def host_container_pids(pod):
        """Find the exact uniquely tagged test shells, independently of sandbox shim layout."""
        commands = {container["command"][-1].encode() for container in pod["spec"]["containers"]}
        pids = []
        for path in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                fields = path.read_bytes().split(b"\0")
            except OSError:
                continue
            if len(fields) >= 3 and fields[1] == b"-c" and fields[2] in commands:
                pids.append(int(path.parent.name))
        return pids

    ignore = "trap 'echo TERM' TERM; echo READY; while :; do sleep 1; done"
    try:
        process = start()
        graceful = create("graceful", 8, "trap 'echo TERM; sleep 2; echo EXIT; exit 0' TERM; echo READY; while :; do sleep 1; done")
        started, body = delete("graceful")
        assert body["metadata"]["deletionGracePeriodSeconds"] == 8, body
        assert body["metadata"]["generation"] == 2, body
        assert request(pod_path("graceful"))[0] == 200, "terminating Pod disappeared before shutdown"
        wait_for(lambda: containers_gone(graceful), 7, "SIGTERM handler process exit")
        exit_seconds = time.monotonic() - started
        wait_for(lambda: gone("graceful"), 90, "graceful sandbox cleanup and API completion")
        assert "TERM" in logs(graceful) and "EXIT" in logs(graceful), logs(graceful)
        assert containers_gone(graceful)
        report["scenarios"]["sigtermHandler"] = {"passed": True, "processExitSeconds": exit_seconds,
                                                  "apiRemovalSeconds": time.monotonic() - started}

        parallel = create("parallel", 5, ignore, 2)
        started, _ = delete("parallel")
        wait_for(lambda: containers_gone(parallel), 9, "parallel forced process termination")
        elapsed = time.monotonic() - started
        assert 3 <= elapsed < 9, elapsed
        wait_for(lambda: gone("parallel"), 90, "parallel sandbox cleanup and API completion")
        assert all("TERM" in logs(parallel, name) for name in ("main", "side1"))
        assert containers_gone(parallel)
        report["scenarios"]["sharedDeadline"] = {"passed": True, "seconds": elapsed, "containers": 2, "grace": 5}

        force = create("force", 30, ignore)
        delete("force")
        wait_for(lambda: "TERM" in logs(force), 8, "initial SIGTERM")
        started, _ = delete("force", gracePeriodSeconds=0)
        wait_for(lambda: gone("force") and containers_gone(force), 12, "force shortening process exit")
        process_seconds = time.monotonic() - started
        replacement = create("force", 0, ignore)
        assert replacement["metadata"]["uid"] != force["metadata"]["uid"]
        delete("force", gracePeriodSeconds=0)
        wait_for(lambda: containers_gone(replacement), 12, "replacement process cleanup")
        wait_for(lambda: not owned_shims(), 90, "force sandbox cleanup")
        report["scenarios"]["forceShortening"] = {"passed": True, "processExitSeconds": process_seconds,
                                                    "replacementUID": replacement["metadata"]["uid"]}

        restart = create("restart", 15, ignore)
        started, body = delete("restart")
        original_deadline = body["metadata"]["deletionTimestamp"]
        wait_for(lambda: "TERM" in logs(restart), 8, "pre-restart SIGTERM")
        time.sleep(4)
        stop()
        process = start()
        code, recovered = request(pod_path("restart"))
        if code == 200:
            assert recovered["metadata"]["deletionTimestamp"] == original_deadline
            assert recovered["metadata"]["uid"] == restart["metadata"]["uid"]
        else:
            assert code == 404, (code, recovered)
        wait_for(lambda: containers_gone(restart), 20, "restart process termination")
        assert time.monotonic() - started < 22, "restart reset the runtime grace budget"
        exit_seconds = time.monotonic() - started
        wait_for(lambda: gone("restart"), 90, "restart sandbox cleanup and API completion")
        report["scenarios"]["restartRecovery"] = {"passed": True, "seconds": time.monotonic() - started,
                                                    "processExitSeconds": exit_seconds, "originalDeadline": original_deadline}
        report["passed"] = True
    except Exception as error:
        report["error"] = repr(error)
    finally:
        try:
            try:
                if process is not None:
                    for pod in pods:
                        request(pod_path(pod["metadata"]["name"]), "DELETE", {"gracePeriodSeconds": 0})
                    wait_for(lambda: all(containers_gone(pod) for pod in pods) and not owned_shims(),
                             90, "owned container and sandbox cleanup")
            finally:
                stop()
        except Exception as error:
            report["cleanupError"] = repr(error)
            report["passed"] = False
        log.close()
        report["pods"] = [{"name": pod["metadata"]["name"], "uid": pod["metadata"]["uid"],
                           "hostPids": pod.get("testHostPids", []),
                           "containerIDs": [status.get("containerID") for status in pod.get("status", {}).get("containerStatuses", [])]}
                          for pod in pods]
        for pod in pods:
            for container in pod["spec"]["containers"]:
                (root / (pod["metadata"]["name"] + "-" + pod["metadata"]["uid"] + "-" + container["name"] + ".log")).write_text(logs(pod, container["name"]))
        report["ownedShimsRemaining"] = owned_shims()
        if report["ownedShimsRemaining"]:
            report["passed"] = False
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
