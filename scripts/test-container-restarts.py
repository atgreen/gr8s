#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify real per-container restart policy, sibling identity and durable backoff.

Run as root inside a disposable Linux guest with bpffs mounted. Retain all logs,
the native binary hash, actual container identities and cleanup results.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    """Run controlled real container exits and restart the same durable native cluster."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--api-port", type=int, default=18205)
    parser.add_argument("--node-port", type=int, default=17462)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-container-restarts.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    base = f"http://127.0.0.1:{args.api_port}"
    log = (root / "gr8s.log").open("w")
    native = None
    pods = []
    report = {"directory": str(root), "stateDirectory": str(state),
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "scenarios": {}, "nativeExitCodes": [], "passed": False}
    print(json.dumps({"reportDirectory": str(root)}), flush=True)

    def request(path, method="GET", obj=None, text=False):
        """Return the actual HTTP status and payload, preserving API failures."""
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

    def wait(predicate, timeout, description):
        """Observe the same operation through transient connection timeouts."""
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
        """Start the native control plane and agent against the same owned state."""
        process = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd",
                                    "--state-directory", str(state), "--port", str(args.api_port),
                                    "--node-port", str(args.node_port), "--kubeconfig", str(root / "kubeconfig")],
                                   stdout=log, stderr=subprocess.STDOUT)

        def ready():
            """Require real agent readiness and detect a process that exited early."""
            if process.poll() is not None:
                raise RuntimeError(f"native startup exited {process.returncode}")
            return 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in request("/metrics", text=True)[1]

        try:
            wait(ready, 90, "native agent readiness")
        except BaseException:
            process.terminate()
            report["nativeExitCodes"].append(process.wait(timeout=45))
            raise
        return process

    def stop():
        """Join the owned native process without stopping healthy container shims."""
        nonlocal native
        if native is not None:
            native.terminate()
            code = native.wait(timeout=45)
            report["nativeExitCodes"].append(code)
            native = None
            assert code == 0, code

    def path(pod):
        """Address a created Pod by its server-selected name."""
        return "/api/v1/namespaces/default/pods/" + pod["metadata"]["name"]

    def statuses(pod):
        """Index real per-container observations by name."""
        return {item["name"]: item for item in pod.get("status", {}).get("containerStatuses", [])}

    def current(pod):
        """Fetch the exact created UID, rejecting a same-name replacement."""
        code, obj = request(path(pod))
        assert code == 200 and obj["metadata"]["uid"] == pod["metadata"]["uid"], (code, obj)
        return obj

    def create(policy, exit_code, crash=False):
        """Launch a healthy sibling and a sidecar controlled by an actual emptyDir file."""
        side = ("echo STARTED; exit 7" if crash else
                "echo SIDE_READY; while [ ! -f /work/fail ]; do sleep 0.1; done; "
                f"if [ ! -f /work/once ]; then touch /work/once; echo EXITING; exit {exit_code}; fi; "
                "echo RECOVERED; while :; do sleep 1; done")
        containers = [{"name": name, "image": "docker.io/library/busybox:1.36.1", "imagePullPolicy": "IfNotPresent",
                       "command": ["sh", "-c", command], "volumeMounts": [{"name": "work", "mountPath": "/work"}]}
                      for name, command in (("main", "echo HEALTHY; while :; do sleep 1; done"), ("side", side))]
        code, pod = request("/api/v1/namespaces/default/pods", "POST",
                            {"apiVersion": "v1", "kind": "Pod", "metadata": {"generateName": "restart-native-"},
                             "spec": {"restartPolicy": policy, "terminationGracePeriodSeconds": 0,
                                      "volumes": [{"name": "work", "emptyDir": {}}], "containers": containers}})
        assert code == 201, (code, pod)
        pods.append(pod)

        def running():
            """Wait for actual runtime IDs rather than assuming create success means execution."""
            obj = current(pod)
            observed = statuses(obj)
            return obj if (len(observed) == 2 and all(item.get("containerID") for item in observed.values())
                           and "running" in observed["main"].get("state", {})
                           and (crash or "running" in observed["side"].get("state", {}))) else None

        return pod, wait(running, 600, "real two-container Pod startup")

    def owned_shims():
        """Find only shims owned by this newly created cluster state directory."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    try:
        native = start()
        for policy, exit_code, restart in (("OnFailure", 7, True), ("Always", 0, True),
                                           ("OnFailure", 0, False), ("Never", 7, False)):
            pod, before = create(policy, exit_code)
            (root / f"{policy}-{exit_code}-before.json").write_text(json.dumps(before, indent=2) + "\n")
            before_status = statuses(before)
            volume = Path("/var/log/gr8s/pods") / pod["metadata"]["uid"] / "volumes/work"
            (volume / "fail").touch()

            def completed_policy():
                """Observe the requested exit or its actual replacement container."""
                obj = current(pod)
                observed = statuses(obj)
                side = observed.get("side", {})
                if restart:
                    matches = (side.get("restartCount") == 1 and "running" in side.get("state", {})
                               and side.get("lastState", {}).get("terminated", {}).get("exitCode") == exit_code)
                else:
                    matches = side.get("state", {}).get("terminated", {}).get("exitCode") == exit_code
                return obj if matches else None

            after = wait(completed_policy, 120, f"{policy} after exit {exit_code}")
            (root / f"{policy}-{exit_code}-after.json").write_text(json.dumps(after, indent=2) + "\n")
            observed = statuses(after)
            assert observed["main"]["containerID"] == before_status["main"]["containerID"], after
            assert observed["main"]["restartCount"] == 0, after
            assert after["status"]["podIP"] == before["status"]["podIP"], after
            assert observed["side"]["restartCount"] == int(restart), after
            if restart:
                assert observed["side"]["containerID"] != before_status["side"]["containerID"], after
                code, output = request(path(pod) + "/log?container=side", text=True)
                assert code == 200 and "RECOVERED" in output and "EXITING" not in output, (code, output)
                assert (volume / "once").exists()
            else:
                time.sleep(3)
                assert statuses(current(pod))["side"]["containerID"] == before_status["side"]["containerID"]
            report["scenarios"][f"{policy}Exit{exit_code}"] = {
                "passed": True, "uid": pod["metadata"]["uid"], "mainIDUnchanged": True,
                "podIPUnchanged": True, "restartCount": observed["side"]["restartCount"],
                "sideContainerID": observed["side"]["containerID"]}

        crash, before = create("OnFailure", 7, crash=True)
        checkpoint = Path("/var/log/gr8s/pods") / crash["metadata"]["uid"] / "lifecycle.json"

        def durable_backoff():
            """Wait for a real repeated crash and a substantial unexpired retry budget."""
            if not checkpoint.exists():
                return None
            entry = json.loads(checkpoint.read_text())["containers"].get("side", {})
            return entry if entry.get("nextAttempt", 0) >= 4 and entry.get("nextStart", 0) - (time.time() + 2208988800) > 25 else None

        entry = wait(durable_backoff, 120, "durable native crash-loop backoff")
        (root / "backoff-before-restart.json").write_text(json.dumps(entry, indent=2) + "\n")
        healthy_id = statuses(before)["main"]["containerID"]
        deadline = entry["nextStart"]
        next_attempt = entry["nextAttempt"]
        stop()
        native = start()
        recovered = json.loads(checkpoint.read_text())["containers"]["side"]
        (root / "backoff-after-restart.json").write_text(json.dumps(recovered, indent=2) + "\n")
        if recovered["lastExitID"] == entry["lastExitID"]:
            assert recovered["nextStart"] == deadline, (entry, recovered)
        assert statuses(current(crash))["main"]["containerID"] == healthy_id

        def next_crash():
            """Observe the first actual attempt after the persisted retry deadline."""
            obj = current(crash)
            side = statuses(obj).get("side", {})
            return side if (side.get("restartCount", 0) >= next_attempt
                            and side.get("state", {}).get("waiting", {}).get("reason") == "CrashLoopBackOff") else None

        side = wait(next_crash, 120, "post-restart attempt and backoff")
        started = datetime.datetime.fromisoformat(side["lastState"]["terminated"]["startedAt"].replace("Z", "+00:00")).timestamp()
        assert started + 2208988800 >= deadline - 1, (started, deadline)
        assert statuses(current(crash))["main"]["containerID"] == healthy_id
        report["scenarios"]["durableBackoffAndRestart"] = {
            "passed": True, "uid": crash["metadata"]["uid"], "retryDeadline": deadline,
            "nextAttempt": next_attempt, "actualNextStartedUnix": started, "healthyContainerIDUnchanged": True}
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = repr(error)
    finally:
        try:
            try:
                if native is not None:
                    for pod in pods:
                        code, body = request(path(pod), "DELETE", {"gracePeriodSeconds": 0,
                                                                  "preconditions": {"uid": pod["metadata"]["uid"]}})
                        assert code in (200, 404), (code, body)
                    wait(lambda: not owned_shims(), 120, "owned native container cleanup")
            finally:
                stop()
        except Exception as error:
            report["cleanupError"] = repr(error)
            report["passed"] = False
        log.close()
        for pod in pods:
            directory = Path("/var/log/gr8s/pods") / pod["metadata"]["uid"]
            for source in directory.glob("*.log"):
                (root / (pod["metadata"]["uid"] + "-" + source.name)).write_bytes(source.read_bytes())
        report["ownedShimsRemaining"] = owned_shims()
        if report["ownedShimsRemaining"]:
            report["passed"] = False
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
