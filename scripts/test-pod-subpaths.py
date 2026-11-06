#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Prove genuine native subpath mounts, metadata retries, recovery and safe cleanup."""

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
    """Exercise real API Pods and Linux mounts in one explicitly owned native state."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-subpaths.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    namespace = "subpath-" + uuid.uuid4().hex[:8]
    base = "http://127.0.0.1:18210"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    report = {"directory": str(root), "stateDirectory": str(state), "namespace": namespace,
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "passed": False, "nativeExitCodes": []}
    process, foreign_mount = None, None
    log = (root / "gr8s.log").open("w")
    print(json.dumps({"directory": str(root), "namespace": namespace}), flush=True)

    def request(path, method="GET", value=None):
        """Return actual API status and JSON, including rejected requests."""
        data = None if value is None else json.dumps(value).encode()
        try:
            with opener.open(urllib.request.Request(base + path, data=data, method=method,
                              headers={"Content-Type": "application/json"}), timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def path(resource, name=None):
        """Confine API mutations to this harness's namespace."""
        return f"/api/v1/namespaces/{namespace}/{resource}" + ("/" + name if name else "")

    def wait(predicate, description, timeout=180):
        """Poll one genuine observation without replaying its mutation."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, TimeoutError):
                pass
            if process and process.poll() is not None:
                raise RuntimeError(f"native exited {process.returncode}: {description}")
            time.sleep(0.25)
        raise TimeoutError(description)

    def shims():
        """Inspect only shims belonging to this explicitly owned state."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    def mounts():
        """Read real kernel mount targets beneath the owned runtime state."""
        targets = []
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            target = line.split()[4]
            for encoded, value in [(r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")]:
                target = target.replace(encoded, value)
            if str(state) + "/" in target and "/volume-subpaths/" in target:
                targets.append(target)
        return targets

    def pod(name):
        """Read this test's actual Pod identity and observations."""
        code, value = request(path("pods", name))
        return value if code == 200 else None

    def running(name):
        """Require an observed real container ID and readiness before reading HTTP."""
        value = pod(name)
        statuses = value.get("status", {}).get("containerStatuses", []) if value else []
        return value if len(statuses) == 1 and statuses[0].get("ready") and statuses[0].get("containerID") else None

    def pending_error(name):
        """Require an actual failed runtime attempt with no fabricated running container."""
        value = pod(name)
        status = value.get("status", {}) if value else {}
        return value if status.get("phase") == "Pending" and status.get("reason") == "RuntimeError" else None

    def create(resource, value):
        """Require creation of a genuine namespaced object."""
        code, result = request(path(resource), "POST", value)
        assert code == 201, (code, result)
        return result

    def read_file(name):
        """Read bytes served by the real Pod HTTP process through the API proxy."""
        with opener.open(base + path("pods", "writer") + "/proxy/" + name, timeout=5) as response:
            return response.read().decode().strip()

    def start():
        """Start this binary/state and require actual dataplane readiness."""
        nonlocal process
        process = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                    "--port", "18210", "--node-port", "17467"], stdout=log, stderr=subprocess.STDOUT)
        def ready():
            """Observe the real registered local worker's readiness metric."""
            with opener.open(base + "/metrics", timeout=2) as response:
                return 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in response.read().decode()
        wait(ready, "native readiness", 90)

    def stop():
        """Join normal shutdown without a forced kill or hiding an abnormal exit."""
        nonlocal process
        if process:
            process.terminate()
            code = process.wait(timeout=45)
            report["nativeExitCodes"].append(code)
            process = None
            assert code == 0, code

    try:
        assert not shims() and not mounts(), "owned state still has runtime processes or staged mounts"
        start()
        code, value = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, value)
        marker = namespace + "-actual-content"
        create("configmaps", {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "source"}, "data": {"value": marker}})
        command = (f"mkdir -p /results; echo {marker} >/part/value; "
                   "cat /whole/actual-directory/writer/value >/results/directory; "
                   "cat /configuration >/results/file; "
                   "if echo forbidden >/configuration; then echo BAD >/results/readonly; else echo readonly >/results/readonly; fi; "
                   "httpd -f -p 8080 -h /results")
        writer = create("pods", {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "writer"},
                  "spec": {"terminationGracePeriodSeconds": 0,
                           "volumes": [{"name": "data", "emptyDir": {}},
                                       {"name": "config", "configMap": {"name": "source", "items": [{"key": "value", "path": "nested/value"}]}}],
                           "containers": [{"name": "writer", "image": "docker.io/library/busybox:1.36.1", "command": ["sh", "-c", command],
                              "ports": [{"containerPort": 8080}], "env": [
                                {"name": "ANNOTATION", "valueFrom": {"fieldRef": {"fieldPath": "metadata.annotations['mysubpath']"}}},
                                {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}],
                              "volumeMounts": [{"name": "data", "mountPath": "/part", "subPathExpr": "$(ANNOTATION)/$(POD_NAME)"},
                                               {"name": "data", "mountPath": "/whole"},
                                               {"name": "config", "mountPath": "/configuration", "subPath": "nested/value"}]}]}})
        pending = wait(lambda: pending_error("writer"), "actual missing annotation runtime error")
        assert not pending.get("status", {}).get("containerStatuses"), pending["status"]
        replacement = pod("writer")
        replacement["metadata"]["annotations"] = {"mysubpath": "actual-directory"}
        code, value = request(path("pods", "writer"), "PUT", replacement)
        assert code == 200, (code, value)
        writer = wait(lambda: running("writer"), "actual mount retry after annotation update")
        wait(lambda: read_file("directory") == marker and read_file("file") == marker, "actual directory and file subpath content")
        assert read_file("readonly") == "readonly"
        staged = mounts()
        assert len(staged) == 2, staged
        before = writer["status"]["containerStatuses"][0]["containerID"]
        report["actualMountedContent"] = {"uid": writer["metadata"]["uid"], "marker": marker, "stagedTargets": staged,
                                          "directoryResponse": read_file("directory"), "fileResponse": read_file("file"), "readonly": read_file("readonly")}
        stop()
        start()
        recovered = wait(lambda: running("writer"), "actual staged mount recovery")
        assert recovered["status"]["containerStatuses"][0]["containerID"] == before
        assert sorted(mounts()) == sorted(staged) and read_file("directory") == marker
        report["unchangedContainerIDAfterRestart"] = before
        outside, evil = root / "outside", root / "malicious-volume"
        outside.mkdir()
        evil.mkdir()
        (outside / "sentinel").write_text("untouched")
        (evil / "escape").symlink_to(outside, target_is_directory=True)
        negative = create("pods", {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "escape"},
                    "spec": {"terminationGracePeriodSeconds": 0, "volumes": [{"name": "evil", "hostPath": {"path": str(evil), "type": "Directory"}}],
                             "containers": [{"name": "escape", "image": "docker.io/library/busybox:1.36.1",
                                "command": ["sh", "-c", "echo CHANGED >/part/sentinel; sleep 600"],
                                "volumeMounts": [{"name": "evil", "mountPath": "/part", "subPath": "escape"}]}]}})
        rejected = wait(lambda: pending_error("escape"), "actual escaping symlink rejection")
        assert not rejected.get("status", {}).get("containerStatuses")
        assert (outside / "sentinel").read_text() == "untouched"
        report["escapingSymlinkBlocked"] = {"uid": negative["metadata"]["uid"], "actualStatus": rejected["status"], "outsideSentinel": "untouched"}
        uid_root = Path(staged[0].split("/volume-subpaths/")[0])
        foreign_mount = uid_root.with_name(uid_root.name + "-foreign") / "volume-subpaths" / "foreign"
        foreign_mount.parent.mkdir(parents=True)
        foreign_mount.touch()
        subprocess.run(["mount", "--bind", str(outside / "sentinel"), str(foreign_mount)], check=True)
        code, values = request(path("pods"))
        assert code == 200
        for value in values["items"]:
            request(path("pods", value["metadata"]["name"]), "DELETE", {"gracePeriodSeconds": 0, "preconditions": {"uid": value["metadata"]["uid"]}})
        wait(lambda: not shims() and mounts() == [str(foreign_mount)], "owned runtime and subpath cleanup preserving sibling mount", 120)
        assert foreign_mount.read_text() == "untouched"
        report["foreignSiblingMountPreserved"] = str(foreign_mount)
        report["passed"] = True
    except Exception as error:
        report["error"] = repr(error)
    finally:
        try:
            if process and process.poll() is None:
                code, listing = request(path("pods"))
                if code == 200:
                    for value in listing["items"]:
                        request(path("pods", value["metadata"]["name"]), "DELETE", {"gracePeriodSeconds": 0, "preconditions": {"uid": value["metadata"]["uid"]}})
                wait(lambda: not shims() and all(target == str(foreign_mount) for target in mounts()), "owned cleanup", 120)
                request("/api/v1/namespaces/" + namespace, "DELETE")
        except Exception as error:
            report["cleanupError"] = repr(error)
            report["passed"] = False
        if foreign_mount and str(foreign_mount) in mounts():
            result = subprocess.run(["umount", str(foreign_mount)], check=False)
            if result.returncode:
                report["foreignFixtureCleanupError"] = result.returncode
                report["passed"] = False
        try:
            stop()
        except Exception as error:
            report["shutdownError"] = repr(error)
            report["passed"] = False
        log.close()
        report["ownedShimsRemaining"], report["ownedSubpathMountsRemaining"] = shims(), mounts()
        if report["ownedShimsRemaining"] or report["ownedSubpathMountsRemaining"]:
            report["passed"] = False
        report["artifactSHA256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob("*.log")}
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"directory": str(root), "passed": report["passed"], "error": report.get("error"), "cleanupError": report.get("cleanupError")}), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
