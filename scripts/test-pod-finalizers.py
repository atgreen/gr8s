#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Prove finalizer-retained Pods preserve real native exits after physical cleanup.

Run only in an isolated privileged guest. State reuse requires an explicitly
owned, stopped cluster with no desired Pods. Each run writes fresh evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def main():
    """Own native processes, exact Pod UIDs and immutable scenario observations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--image", default="registry.k8s.io/e2e-test-images/busybox:1.37.0-1")
    parser.add_argument("--api-port", type=int, default=18293)
    parser.add_argument("--node-port", type=int, default=17493)
    parser.add_argument("--with-probes", action="store_true", help="Also prove cancellation of an actual blocked Exec probe")
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-finalizers-native.", dir="/var/tmp"))
    state = (args.state_directory or root / "state").resolve()
    namespace = "finalizers-" + uuid.uuid4().hex[:10]
    finalizer = "gr8s.io/native-finalizer-proof"
    base = f"http://127.0.0.1:{args.api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    native = None
    pods = []
    runtime_log = state / "agent/containerd/containerd.log"
    runtime_log_start = runtime_log.stat().st_size if runtime_log.exists() else 0
    log = (root / "gr8s.log").open("wb")
    report = {"directory": str(root), "stateDirectory": str(state), "namespace": namespace,
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "scenarios": {}, "nativeExitCodes": [], "passed": False}
    print(json.dumps({"reportDirectory": str(root)}), flush=True)

    def request(path, method="GET", obj=None):
        """Retain actual API status/body while bypassing guest proxy settings."""
        req = urllib.request.Request(base + path, method=method,
                                     data=None if obj is None else json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.code, json.loads(response.read())

    def wait(predicate, seconds, description):
        """Observe one owned operation without restarting it on silence or transient errors."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if native is not None and native.poll() is not None:
                raise RuntimeError(f"native exited during {description}: {native.returncode}")
            try:
                value = predicate()
                if value:
                    return value
            except OSError as error:
                errors = report.setdefault("observationErrors", [])
                if len(errors) < 100:
                    errors.append(str(error))
            time.sleep(.2)
        raise TimeoutError(description)

    def processes():
        """Read exact test-state runtime ownership from actual guest process arguments."""
        lines = subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
        return [line for line in lines if str(state) in line and
                (line.split(None, 1)[0].startswith("containerd") or
                 line.split(None, 1)[0] in {"gr8s", "gr8s.bin", args.gr8s.name[:15]})]

    def shims():
        """Require physical test-state shim removal independently of API deletion."""
        return [line for line in processes() if line.startswith("containerd-shim")]

    def start():
        """Take subprocess ownership before waiting so failed readiness still gets cleanup."""
        nonlocal native
        assert native is None
        native = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                   "--port", str(args.api_port), "--node-port", str(args.node_port),
                                   "--kubeconfig", str(root / "kubeconfig")], stdout=log, stderr=subprocess.STDOUT)

        def ready():
            """Check actual server readiness, allowing process failure to abort immediately."""
            with opener.open(base + "/readyz", timeout=2) as response:
                return response.status == 200
        wait(ready, 120, "native readiness")

    def stop():
        """Reap only the owned native process and require clean shutdown."""
        nonlocal native
        if native is not None:
            process = native
            process.send_signal(signal.SIGTERM)
            try:
                code = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait(timeout=10)
                raise RuntimeError(f"owned native required SIGKILL: {code}")
            finally:
                native = None
                report["nativeExitCodes"].append(process.returncode)
            assert code == 0, f"native exit {code}"

    def path(pod):
        """Address the test Pod in the private namespace."""
        return f"/api/v1/namespaces/{namespace}/pods/{pod['metadata']['name']}"

    def current(pod):
        """Reject replacement identity when observing a specific native attempt."""
        code, obj = request(path(pod))
        assert code == 200 and obj["metadata"]["uid"] == pod["metadata"]["uid"], (code, obj)
        return obj

    def status(pod):
        """Read the single actual native container status."""
        values = pod.get("status", {}).get("containerStatuses", [])
        return values[0] if len(values) == 1 else {}

    def save(name, value):
        """Preserve the exact observation used for an assertion."""
        (root / name).write_text(json.dumps(value, indent=2) + "\n")

    def preserve_native_history(label, pod, expected):
        """Capture exact private CRI history and log bytes before releasing UID ownership."""
        directory = Path("/var/log/gr8s/pods") / pod["metadata"]["uid"]
        history = directory / "lifecycle.json"
        data = history.read_bytes()
        record = json.loads(data)
        assert record["uid"] == pod["metadata"]["uid"], record
        assert record["containers"]["main"]["lastStatus"]["state"]["terminated"]["exitCode"] == expected, record
        name = label + "-lifecycle.json"
        (root / name).write_bytes(data)
        report.setdefault("nativeHistory", []).append({"source": str(history), "file": name,
                                                        "sha256": hashlib.sha256(data).hexdigest()})
        source = directory / "main.log"
        data = source.read_bytes()
        name = label + "-cri.log"
        (root / name).write_bytes(data)
        report["nativeHistory"].append({"source": str(source), "file": name,
                                        "sha256": hashlib.sha256(data).hexdigest()})

    def create(name, command, probe=False):
        """Create a genuine finalizer-retained native Pod, never a synthetic completion."""
        container = {"name": "main", "image": args.image, "imagePullPolicy": "IfNotPresent", "command": command}
        spec = {"restartPolicy": "Never", "terminationGracePeriodSeconds": 3, "containers": [container]}
        if probe:
            container.update({"volumeMounts": [{"name": "work", "mountPath": "/work"}],
                              "readinessProbe": {"exec": {"command": ["sh", "-c", "touch /work/probe-running; sleep 60"]},
                                                 "timeoutSeconds": 60, "periodSeconds": 1}})
            spec["volumes"] = [{"name": "work", "emptyDir": {}}]
        code, pod = request(f"/api/v1/namespaces/{namespace}/pods", "POST",
                            {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "finalizers": [finalizer]}, "spec": spec})
        assert code == 201, (code, pod)
        pods.append(pod)
        return pod

    def terminal(pod, code):
        """Require the actual CRI exit status and corresponding terminal phase."""
        obj = current(pod)
        termination = status(obj).get("state", {}).get("terminated", {})
        return obj if termination.get("exitCode") == code and obj.get("status", {}).get("phase") == ("Succeeded" if code == 0 else "Failed") else None

    def delete(pod, grace=0):
        """Persist shutdown only for the exact owned UID, allowing already-removed identities."""
        code, body = request(path(pod), "DELETE", {"gracePeriodSeconds": grace, "preconditions": {"uid": pod["metadata"]["uid"]}})
        if code == 409:
            actual_code, actual = request(path(pod))
            assert actual_code == 404 or actual["metadata"]["uid"] != pod["metadata"]["uid"], (code, body)
        else:
            assert code in (200, 404), (code, body)

    def release(pod):
        """Remove only this test's finalizer and never mutate a same-name replacement."""
        code, obj = request(path(pod))
        if code == 404 or obj["metadata"]["uid"] != pod["metadata"]["uid"]:
            return
        names = obj["metadata"].get("finalizers", [])
        if finalizer in names:
            obj["metadata"]["finalizers"] = [name for name in names if name != finalizer]
            code, body = request(path(pod), "PUT", obj)
            assert code == 200, (code, body)
        wait(lambda: request(path(pod))[0] == 404, 90, "last-finalizer API removal")

    try:
        assert not processes(), "test state must be stopped before explicit reuse"
        start()
        code, existing = request("/api/v1/pods")
        assert code == 200 and not existing["items"], "test state must have no pre-existing desired Pods"
        code, body = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, body)
        success = create("succeeded", ["sh", "-c", "echo FINALIZER_SUCCESS; exit 0"])
        before = wait(lambda: terminal(success, 0), 600, "actual successful exit")
        save("successful-before-delete.json", before)
        delete(success)
        retained = wait(lambda: terminal(success, 0) if current(success)["metadata"].get("deletionTimestamp") else None, 120, "successful finalizer retention")
        wait(lambda: not shims(), 120, "zero physical shims while successful API Pod remains")
        assert retained["metadata"].get("finalizers") == [finalizer], retained
        assert status(retained)["containerID"] == status(before)["containerID"], retained
        assert retained["status"].get("podIP") == before["status"].get("podIP"), retained
        save("successful-api-retained-runtime-removed.json", retained)
        preserve_native_history("successful", success, 0)
        report["scenarios"]["successRetainsActualExitAfterPhysicalCleanup"] = {"passed": True, "uid": success["metadata"]["uid"], "exitCode": 0}
        stop()
        start()
        reopened = wait(lambda: terminal(success, 0), 120, "terminal finalizer retention across native restart")
        assert status(reopened)["containerID"] == status(retained)["containerID"], reopened
        save("successful-after-native-restart.json", reopened)
        report["scenarios"]["restartRetainsActualTerminalAttempt"] = {"passed": True}
        release(success)
        replacement = create("succeeded", ["sh", "-c", "echo FINALIZER_RUNNING; while :; do sleep 1; done"])
        assert replacement["metadata"]["uid"] != success["metadata"]["uid"], replacement
        running = wait(lambda: (obj if "running" in status(obj).get("state", {}) else None) if (obj := current(replacement)) else None,
                       600, "actual same-name replacement Running")
        assert status(running)["containerID"] != status(retained)["containerID"], running
        assert not status(running).get("lastState", {}).get("terminated"), running
        save("same-name-replacement-running.json", running)
        delete(replacement)
        failed = wait(lambda: terminal(replacement, 137), 120, "actual SIGKILL exit retained by finalizer")
        wait(lambda: not shims(), 120, "zero physical shims while failed API Pod remains")
        assert failed["metadata"].get("finalizers") == [finalizer], failed
        save("failed-api-retained-runtime-removed.json", failed)
        preserve_native_history("failed", replacement, 137)
        report["scenarios"]["uidReuseAndActualFailedExit"] = {"passed": True, "uid": replacement["metadata"]["uid"], "exitCode": 137}
        release(replacement)
        if args.with_probes:
            blocked = create("blocked-probe", ["sh", "-c", "while :; do sleep 1; done"], probe=True)
            marker = Path("/var/log/gr8s/pods") / blocked["metadata"]["uid"] / "volumes/work/probe-running"
            wait(marker.exists, 600, "actual blocked Exec probe")
            start_delete = time.monotonic()
            delete(blocked)
            failed = wait(lambda: terminal(blocked, 137), 30, "finalized deletion cancels blocked probe")
            wait(lambda: not shims(), 30, "zero shims after blocked probe cancellation")
            assert not status(failed).get("ready"), failed
            save("blocked-probe-api-retained-runtime-removed.json", failed)
            preserve_native_history("blocked-probe", blocked, 137)
            report["scenarios"]["blockedProbeCancellation"] = {"passed": True, "seconds": time.monotonic() - start_delete}
            release(blocked)
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = repr(error)
    finally:
        try:
            if native is not None and native.poll() is None:
                for pod in pods:
                    delete(pod)
                    release(pod)
                wait(lambda: not shims(), 120, "zero test-state shims")
                desired = state / "agent/runtime/desired/pods"
                assert desired.is_dir(), "native desired-state path was never established"
                wait(lambda: not list(desired.rglob("*.json")), 120, "zero node desired Pods")
                report["desiredPodFilesRemaining"] = [str(path) for path in desired.rglob("*.json")]
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
        report["ownedShimsRemaining"] = shims()
        if report["ownedShimsRemaining"]:
            report["passed"] = False
        if runtime_log.exists():
            with runtime_log.open("rb") as source:
                end = source.seek(0, 2)
                start_offset = runtime_log_start if end >= runtime_log_start else 0
                source.seek(start_offset)
                (root / "containerd.log").write_bytes(source.read())
            report["containerdLogCapture"] = {"source": str(runtime_log), "startOffset": start_offset, "endOffset": end}
        report["artifacts"] = [{"file": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                               for path in sorted(root.iterdir()) if path.is_file() and path.name not in ("report.json", "kubeconfig")]
        save("report.json", report)
        print(json.dumps(report), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
