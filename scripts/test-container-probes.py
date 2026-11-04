#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Verify real exec/HTTP/TCP/gRPC probes and exact native container lifecycle.

Run only in an isolated privileged guest. Optional state reuse is limited to an
explicitly owned, stopped test cluster; reports always go in a fresh directory.
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
import uuid


def main():
    """Own native processes, real Pods and immutable per-scenario evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--busybox-image", default="registry.k8s.io/e2e-test-images/busybox:1.37.0-1")
    parser.add_argument("--agnhost-image", default="registry.k8s.io/e2e-test-images/agnhost:2.63.0")
    parser.add_argument("--api-port", type=int, default=18292)
    parser.add_argument("--node-port", type=int, default=17492)
    parser.add_argument("--startup-timeout", type=int, default=90)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-probes-native.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    namespace = "probes-" + uuid.uuid4().hex[:10]
    base = f"http://127.0.0.1:{args.api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    log = (root / "gr8s.log").open("wb")
    native = None
    pods = []
    report = {"directory": str(root), "stateDirectory": str(state), "namespace": namespace,
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "scenarios": {}, "nativeExitCodes": [], "passed": False}
    print(json.dumps({"reportDirectory": str(root)}), flush=True)

    def request(path, method="GET", obj=None, absolute=False):
        """Preserve actual API status/body and bypass guest proxy environment variables."""
        req = urllib.request.Request(path if absolute else base + path, method=method,
                                     data=None if obj is None else json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            return response.code, body if absolute else json.loads(body)

    def wait(predicate, timeout, description):
        """Observe the same running operation across transient API connection errors."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if native is not None and native.poll() is not None:
                raise RuntimeError(f"native exited during {description}: {native.returncode}")
            try:
                value = predicate()
                if value:
                    return value
            except OSError as error:
                report.setdefault("observationErrors", []).append(str(error))
            time.sleep(.2)
        raise TimeoutError(description)

    def start():
        """Start the same owned durable cluster and require real API readiness."""
        nonlocal native
        process = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                    "--port", str(args.api_port), "--node-port", str(args.node_port),
                                    "--kubeconfig", str(root / "kubeconfig")], stdout=log, stderr=subprocess.STDOUT)
        native = process

        def ready():
            """Detect a terminated server while waiting for its readiness endpoint."""
            if process.poll() is not None:
                raise RuntimeError(f"native exited {process.returncode}")
            with opener.open(base + "/readyz", timeout=2) as response:
                return response.status == 200
        wait(ready, args.startup_timeout, "native readiness")
        return process

    def stop():
        """Require clean process shutdown and retain its exact exit code."""
        nonlocal native
        if native is not None:
            process = native
            process.terminate()
            try:
                code = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait(timeout=10)
                native = None
                report["nativeExitCodes"].append(code)
                raise RuntimeError("native did not stop within45 seconds; killed owned process")
            native = None
            report["nativeExitCodes"].append(code)
            assert code == 0, f"native exit {code}"

    def path(pod):
        """Address a Pod within this smoke's private namespace."""
        return f"/api/v1/namespaces/{namespace}/pods/{pod['metadata']['name']}"

    def current(pod):
        """Read actual observed state and reject replacement identity."""
        code, obj = request(path(pod))
        assert code == 200 and obj["metadata"]["uid"] == pod["metadata"]["uid"], (code, obj)
        return obj

    def statuses(pod):
        """Index the actual reported container states by name."""
        return {value["name"]: value for value in pod.get("status", {}).get("containerStatuses", [])}

    def save(name, value):
        """Retain the complete real observation used by an assertion."""
        (root / name).write_text(json.dumps(value, indent=2) + "\n")

    def create(containers, volumes=None):
        """Create an actual namespaced Pod; configured probes are never simulated."""
        code, pod = request(f"/api/v1/namespaces/{namespace}/pods", "POST",
                            {"apiVersion": "v1", "kind": "Pod", "metadata": {"generateName": "probe-"},
                             "spec": {"restartPolicy": "OnFailure", "terminationGracePeriodSeconds": 30,
                                      "volumes": volumes or [], "containers": containers}})
        assert code == 201, (code, pod)
        pods.append(pod)
        return pod

    def events(pod):
        """Read actual server-persisted kubelet Events for the exact Pod UID."""
        code, obj = request(f"/api/v1/namespaces/{namespace}/events")
        assert code == 200, (code, obj)
        return [event for event in obj["items"] if event.get("involvedObject", {}).get("uid") == pod["metadata"]["uid"]]

    def running(pod, names):
        """Wait for actual native container IDs and Running state."""
        obj = current(pod)
        observed = statuses(obj)
        return obj if all(name in observed and "running" in observed[name].get("state", {}) for name in names) else None

    def ready(pod, name):
        """Require probe-controlled Started and Ready on the actual attempt."""
        obj = current(pod)
        observed = statuses(obj).get(name, {})
        return obj if observed.get("ready") and observed.get("started") and "running" in observed.get("state", {}) else None

    def delete(pod, timeout=90):
        """Force-delete only this smoke's exact UID and wait for actual API removal."""
        code, body = request(path(pod), "DELETE", {"gracePeriodSeconds": 0, "preconditions": {"uid": pod["metadata"]["uid"]}})
        assert code in (200, 404), (code, body)
        wait(lambda: request(path(pod))[0] == 404, timeout, "exact Pod deletion")

    def owned_shims():
        """Find shims in this explicitly owned, initially empty test state."""
        uids = {pod["metadata"]["uid"] for pod in pods}
        lines = subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
        # Managed shim command lines carry runtime container IDs rather than
        # Pod UIDs. API deletion plus zero shims in this explicitly owned,
        # otherwise-empty test state provides the physical cleanup assertion.
        return [line for line in lines if uids and line.startswith("containerd-shim") and str(state) in line]

    try:
        native = start()
        code, existing = request("/api/v1/pods")
        assert code == 200 and not existing["items"], "probe smoke requires an already-clean owned test state"
        code, body = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, body)
        shell = ("rm -f /work/failed /work/liveness-ran; httpd -f -p 8080 -h /work & child=$!; "
                 "trap 'kill $child 2>/dev/null; echo PROBE_TERM; exit 0' TERM; while :; do sleep 1; done")
        probe = create([
            {"name": "main", "image": args.busybox_image, "imagePullPolicy": "IfNotPresent", "command": ["sh", "-c", "while :; do sleep 1; done"]},
            {"name": "side", "image": args.busybox_image, "imagePullPolicy": "IfNotPresent", "command": ["sh", "-c", shell],
             "ports": [{"name": "http", "containerPort": 8080}], "volumeMounts": [{"name": "work", "mountPath": "/work"}],
             "startupProbe": {"exec": {"command": ["test", "-f", "/work/start"]}, "periodSeconds": 1, "failureThreshold": 100},
             "readinessProbe": {"httpGet": {"port": "http", "path": "/ready"}, "periodSeconds": 1, "failureThreshold": 1},
             "livenessProbe": {"exec": {"command": ["sh", "-c", "touch /work/liveness-ran; if [ -f /work/kill ]; then mv /work/kill /work/failed; fi; test ! -f /work/failed"]},
                               "periodSeconds": 1, "failureThreshold": 2, "terminationGracePeriodSeconds": 3}}],
            [{"name": "work", "emptyDir": {}}])
        before = wait(lambda: running(probe, ["main", "side"]), 600, "real startup-gated Pod")
        volume = Path("/var/log/gr8s/pods") / probe["metadata"]["uid"] / "volumes/work"
        save("startup-pending.json", before)
        assert not statuses(before)["side"]["started"] and not statuses(before)["side"]["ready"], before
        time.sleep(2)
        assert not (volume / "liveness-ran").exists(), "liveness ran before startup succeeded"
        assert not any(event.get("message", "").startswith("Readiness") for event in events(probe)), "readiness ran before startup"
        (volume / "start").touch()
        wait(lambda: statuses(current(probe))["side"].get("started"), 60, "successful startup probe")
        wait(lambda: (volume / "liveness-ran").exists(), 30, "actual liveness execution")
        assert not statuses(current(probe))["side"]["ready"], "missing HTTP file reported ready"
        (volume / "ready").write_text("ready\n")
        stable = wait(lambda: ready(probe, "side"), 60, "real HTTP readiness")
        save("http-ready.json", stable)
        report["scenarios"]["startupAndHttpReadiness"] = {"passed": True, "uid": probe["metadata"]["uid"], "startupSuppressedLiveness": True}
        healthy_id = statuses(stable)["main"]["containerID"]
        old_side = statuses(stable)["side"]["containerID"]
        (volume / "kill").touch()

        def restarted():
            """Require an actual new side container with retained real exit status."""
            obj = ready(probe, "side")
            if obj and statuses(obj)["side"].get("restartCount") == 1 and statuses(obj)["side"]["containerID"] != old_side:
                return obj
            return None
        after = wait(restarted, 180, "probe-specific native restart")
        save("liveness-restarted.json", after)
        assert statuses(after)["main"]["containerID"] == healthy_id and after["status"]["podIP"] == stable["status"]["podIP"], after
        termination = statuses(after)["side"]["lastState"]["terminated"]
        assert termination["exitCode"] == 0, termination
        failures = wait(lambda: [event for event in events(probe) if event.get("message", "").startswith("Liveness probe failed")], 30, "real liveness Warning Event")
        save("probe-events.json", events(probe))
        stop_time = datetime.datetime.fromisoformat(termination["finishedAt"].replace("Z", "+00:00")).timestamp()
        failure_time = datetime.datetime.fromisoformat(failures[0]["firstTimestamp"].replace("Z", "+00:00")).timestamp()
        assert stop_time - failure_time < 10, (termination, failures)
        report["scenarios"]["livenessZeroExitAndEvents"] = {"passed": True, "actualExitCode": 0, "healthyIDUnchanged": True,
                                                                 "actualStopSecondsAfterFirstFailure": stop_time - failure_time}
        ignored = create([{"name": "ignore", "image": args.busybox_image, "imagePullPolicy": "IfNotPresent",
                           "command": ["sh", "-c", "rm -f /work/unhealthy; trap ':' TERM; while :; do sleep 1; done"],
                           "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                           "livenessProbe": {"exec": {"command": ["sh", "-c", "test ! -f /work/unhealthy"]},
                                             "periodSeconds": 1, "failureThreshold": 1, "terminationGracePeriodSeconds": 3}}],
                         [{"name": "work", "emptyDir": {}}])
        ignored_before = wait(lambda: running(ignored, ["ignore"]), 600, "TERM-ignoring workload")
        ignored_volume = Path("/var/log/gr8s/pods") / ignored["metadata"]["uid"] / "volumes/work"
        (ignored_volume / "unhealthy").touch()

        def ignored_restarted():
            """Observe a physically stopped TERM-ignoring process and its replacement."""
            obj = current(ignored)
            value = statuses(obj).get("ignore", {})
            return obj if value.get("restartCount") == 1 and "running" in value.get("state", {}) else None
        ignored_after = wait(ignored_restarted, 120, "actual probe grace enforcement")
        save("probe-grace-enforced.json", ignored_after)
        ignored_events = wait(lambda: [event for event in events(ignored) if event.get("message", "").startswith("Liveness probe failed")],
                              30, "TERM-ignoring probe failure Event")
        killed = statuses(ignored_after)["ignore"]["lastState"]["terminated"]
        elapsed_grace = datetime.datetime.fromisoformat(killed["finishedAt"].replace("Z", "+00:00")).timestamp() - datetime.datetime.fromisoformat(
            ignored_events[0]["firstTimestamp"].replace("Z", "+00:00")).timestamp()
        assert 2 <= elapsed_grace < 10 and killed["exitCode"] != 0, (killed, ignored_events)
        report["scenarios"]["probeGraceOverridesPodGrace"] = {"passed": True, "probeGrace": 3, "podGrace": 30,
                                                            "actualStopSeconds": elapsed_grace, "exitCode": killed["exitCode"]}
        tcp_shell = ("child=''; trap 'test -z \"$child\" || kill $child; exit 0' TERM; while :; do "
                     "if [ -f /work/listen ]; then if [ -z \"$child\" ]; then httpd -f -p 9090 -h /work & child=$!; fi; "
                     "elif [ -n \"$child\" ]; then kill $child; wait $child; child=''; fi; sleep 1; done")
        tcp = create([{"name": "listener", "image": args.busybox_image, "imagePullPolicy": "IfNotPresent",
                       "command": ["sh", "-c", tcp_shell], "ports": [{"name": "tcp", "containerPort": 9090}],
                       "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                       "readinessProbe": {"tcpSocket": {"port": "tcp"}, "periodSeconds": 1, "failureThreshold": 1}}],
                     [{"name": "work", "emptyDir": {}}])
        tcp_before = wait(lambda: running(tcp, ["listener"]), 600, "actual TCP probe workload")
        tcp_id = statuses(tcp_before)["listener"]["containerID"]
        tcp_volume = Path("/var/log/gr8s/pods") / tcp["metadata"]["uid"] / "volumes/work"
        assert not statuses(tcp_before)["listener"]["ready"], tcp_before
        (tcp_volume / "listen").touch()
        wait(lambda: ready(tcp, "listener"), 30, "TCP listener readiness")
        (tcp_volume / "listen").unlink()
        wait(lambda: not statuses(current(tcp))["listener"]["ready"], 30, "physical TCP listener withdrawal")
        tcp_after = current(tcp)
        save("tcp-listener-withdrawn.json", tcp_after)
        assert statuses(tcp_after)["listener"]["containerID"] == tcp_id and statuses(tcp_after)["listener"]["restartCount"] == 0, tcp_after
        report["scenarios"]["tcpActualListenerTransitions"] = {"passed": True, "containerIDUnchanged": True}
        grpc = create([{"name": "health", "image": args.agnhost_image, "imagePullPolicy": "IfNotPresent",
                        "args": ["grpc-health-checking", "--port=5000", "--http-port=8080", "--service=application"],
                        "startupProbe": {"grpc": {"port": 5000, "service": "application"}, "periodSeconds": 1, "failureThreshold": 30},
                        "readinessProbe": {"grpc": {"port": 5000, "service": "application"}, "periodSeconds": 1, "failureThreshold": 1},
                        "livenessProbe": {"tcpSocket": {"port": 5000}, "periodSeconds": 1, "failureThreshold": 3}}])
        grpc_before = wait(lambda: ready(grpc, "health"), 600, "real gRPC SERVING")
        save("grpc-serving.json", grpc_before)
        grpc_id = statuses(grpc_before)["health"]["containerID"]
        grpc_ip = grpc_before["status"]["podIP"]
        assert request(f"http://{grpc_ip}:8080/make-not-serving", absolute=True)[0] == 200
        wait(lambda: not statuses(current(grpc))["health"]["ready"], 30, "gRPC NOT_SERVING withdrawal")
        grpc_failed = current(grpc)
        save("grpc-not-serving.json", grpc_failed)
        assert statuses(grpc_failed)["health"]["containerID"] == grpc_id and statuses(grpc_failed)["health"]["restartCount"] == 0, grpc_failed
        assert request(f"http://{grpc_ip}:8080/make-serving", absolute=True)[0] == 200
        wait(lambda: ready(grpc, "health"), 30, "gRPC readiness recovery")
        report["scenarios"]["grpcActualService"] = {"passed": True, "uid": grpc["metadata"]["uid"], "containerIDUnchanged": True}
        before_restart = {pod["metadata"]["uid"]: statuses(current(pod)) for pod in (probe, grpc)}
        stop()
        native = start()
        for pod in (probe, grpc):
            after_restart = wait(lambda pod=pod: ready(pod, "side" if pod is probe else "health"), 60, "probe state across native restart")
            assert {name: value["containerID"] for name, value in statuses(after_restart).items()} == {
                name: value["containerID"] for name, value in before_restart[pod["metadata"]["uid"]].items()}, after_restart
        report["scenarios"]["nativeRestartKeepsActualAttempts"] = {"passed": True}
        blocked = create([{"name": "blocked", "image": args.busybox_image, "imagePullPolicy": "IfNotPresent",
                           "command": ["sh", "-c", "while :; do sleep 1; done"], "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                           "readinessProbe": {"exec": {"command": ["sh", "-c", "touch /work/probe-running; sleep 60"]},
                                              "timeoutSeconds": 60, "periodSeconds": 1}}], [{"name": "work", "emptyDir": {}}])
        marker = Path("/var/log/gr8s/pods") / blocked["metadata"]["uid"] / "volumes/work/probe-running"
        wait(lambda: marker.exists(), 600, "actual blocked exec probe")
        deletion_start = time.monotonic()
        delete(blocked, timeout=30)
        report["scenarios"]["deleteCancelsBlockedProbe"] = {"passed": True, "seconds": time.monotonic() - deletion_start}
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = repr(error)
    finally:
        try:
            if native is not None:
                for pod in pods:
                    delete(pod)
                wait(lambda: not owned_shims(), 120, "zero test-state shims")
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
        report["ownedShimsRemaining"] = owned_shims()
        if report["ownedShimsRemaining"]:
            report["passed"] = False
        save("report.json", report)
        print(json.dumps(report), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
