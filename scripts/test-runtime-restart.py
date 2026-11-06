#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Kill the managed containerd under a running workload and observe its recovery.

Run as root inside a disposable Linux guest with bpffs mounted (podster-uqb.138).
The agent must notice the exit, report the Node NotReady while containerd is
down, restart it, keep the running Pods' containers, start the Pods created
during the outage, and not retry Pod starts in a hot loop meanwhile.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

IMAGE = "docker.io/library/busybox:1.36.1"


def main():
    """Run the outage scenario twice against one native cluster and always clean up."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--api-port", type=int, default=18207)
    parser.add_argument("--node-port", type=int, default=17464)
    parser.add_argument("--pods", type=int, default=4)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-runtime-restart.", dir="/var/tmp"))
    state = root / "state"
    base = f"http://127.0.0.1:{args.api_port}"
    log_path = root / "gr8s.log"
    log = log_path.open("w")
    native = None
    report = {"directory": str(root), "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "outages": [], "passed": False}
    print(json.dumps({"reportDirectory": str(root)}), flush=True)

    def request(path, method="GET", obj=None, text=False):
        """Return the HTTP status and payload, preserving API failures."""
        req = urllib.request.Request(base + path, method=method,
                                     data=None if obj is None else json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read().decode()
            return response.code, data if text else json.loads(data)

    def wait(predicate, timeout, description, interval=.2):
        """Poll PREDICATE through transient connection errors until it holds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except OSError as error:
                report.setdefault("observationErrors", []).append(str(error))
            time.sleep(interval)
        raise TimeoutError(description)

    def containerd_pids():
        """The managed containerd processes this cluster's state directory owns."""
        config = str(state / "agent" / "containerd" / "config.toml")
        return [int(line.split()[0]) for line in
                subprocess.check_output(["ps", "-eo", "pid=,args="], text=True).splitlines()
                if config in line and "containerd-shim" not in line]

    def node_ready():
        """Return the local Node's Ready condition."""
        code, node = request("/api/v1/nodes/gr8s-local")
        assert code == 200, (code, node)
        return next(c for c in node["status"]["conditions"] if c["type"] == "Ready")

    def create(name):
        """Create one long-running Pod."""
        code, pod = request("/api/v1/namespaces/default/pods", "POST",
                            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                             "spec": {"terminationGracePeriodSeconds": 0,
                                      "containers": [{"name": "main", "image": IMAGE,
                                                      "imagePullPolicy": "IfNotPresent",
                                                      "command": ["sh", "-c", "echo UP; while :; do sleep 1; done"]}]}})
        assert code == 201, (code, pod)
        return pod

    def running(name):
        """Return the Pod's running container identity, or None."""
        code, pod = request(f"/api/v1/namespaces/default/pods/{name}")
        if code != 200 or pod.get("status", {}).get("phase") != "Running":
            return None
        statuses = pod["status"].get("containerStatuses", [])
        if len(statuses) == 1 and "running" in statuses[0].get("state", {}) and statuses[0].get("ready"):
            return {"containerID": statuses[0]["containerID"], "restartCount": statuses[0]["restartCount"]}
        return None

    def log_text():
        return log_path.read_text(errors="replace")

    try:
        native = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd",
                                   "--state-directory", str(state), "--port", str(args.api_port),
                                   "--node-port", str(args.node_port), "--kubeconfig", str(root / "kubeconfig")],
                                  stdout=log, stderr=subprocess.STDOUT)

        def agent_ready():
            if native.poll() is not None:
                raise RuntimeError(f"native startup exited {native.returncode}")
            return node_ready()["status"] == "True"

        wait(agent_ready, 120, "native agent readiness")
        names = [f"steady-{index}" for index in range(args.pods)]
        for name in names:
            create(name)
        before = {name: wait(lambda name=name: running(name), 600, f"{name} running") for name in names}
        report["before"] = before

        for outage in range(2):
            pids = containerd_pids()
            assert len(pids) == 1, pids
            errors_before = log_text().count("runtime error:")
            # A workload in flight: Pods created just before and during the outage.
            late = [f"late-{outage}-{index}" for index in range(args.pods)]
            create(late[0])
            # SIGABRT makes Go exit 2 with a goroutine dump, like the run 15 panic.
            os.kill(pids[0], signal.SIGABRT)
            killed = time.monotonic()
            for name in late[1:]:
                create(name)
            down = wait(lambda: (lambda c: c if c["status"] == "False" else None)(node_ready()), 30,
                        "Node NotReady while containerd is down", interval=.05)
            restarted = wait(lambda: (lambda p: p if p and p != pids else None)(containerd_pids()), 120,
                             "containerd restarted")
            wait(lambda: node_ready()["status"] == "True", 120, "Node Ready again")
            recovered = time.monotonic() - killed
            after_late = {name: wait(lambda name=name: running(name), 600, f"{name} running") for name in late}
            after = {name: running(name) for name in names}
            text = log_text()
            entry = {"killedPid": pids[0], "restartedPids": restarted, "notReadyCondition": down,
                     "secondsToReady": round(recovered, 1), "latePods": after_late, "steadyPods": after,
                     "runtimeErrorLinesDuringOutage": text.count("runtime error:") - errors_before,
                     "exitLogged": text.count("gr8s managed containerd exited"),
                     "restartLogged": text.count("gr8s managed containerd restarted")}
            report["outages"].append(entry)
            assert "container runtime is down" in down.get("message", ""), down
            # Containers outlive containerd: same IDs, no restarts.
            assert after == before, (before, after)
            assert entry["exitLogged"] == outage + 1 and entry["restartLogged"] == outage + 1, entry
            assert entry["runtimeErrorLinesDuringOutage"] < 20, entry
            names += late
            before = {name: running(name) for name in names}
        report["passed"] = True
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        if native is not None:
            for name in [n for n in request("/api/v1/namespaces/default/pods")[1].get("items", [])]:
                request(f"/api/v1/namespaces/default/pods/{name['metadata']['name']}", "DELETE")
            try:
                wait(lambda: not request("/api/v1/namespaces/default/pods")[1].get("items"), 120, "Pods deleted")
            except Exception as error:
                report["cleanupError"] = repr(error)
            native.terminate()
            try:
                report["nativeExitCode"] = native.wait(timeout=60)
            except subprocess.TimeoutExpired:
                native.kill()
                report["nativeExitCode"] = native.wait()
        report["containerdRemaining"] = containerd_pids()
        report["ownedShimsRemaining"] = [line for line in subprocess.check_output(
            ["ps", "-eo", "args="], text=True).splitlines() if "containerd-shim" in line and str(root) in line]
        (root / "report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
