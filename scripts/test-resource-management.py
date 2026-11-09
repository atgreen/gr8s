#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise CPU/NUMA admission, hugepages and upstream PodResources in a disposable VM.

Requires root, a 4-CPU guest with NUMA0=0-1 and NUMA1=2-3, kubectl, and the
static Go helper from scripts/resource-probe. Creates and removes its own pods.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request

IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"


def wait(predicate, label, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.5)
    raise AssertionError(f"timed out: {label}")


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Smoke:
    def __init__(self, args, directory):
        self.args, self.dir = args, directory
        self.config = directory / "kubeconfig"
        self.api, self.node = port(), port()
        self.process = None
        self.log = (directory / "server.log").open("ab")
        self.names = set()

    def start(self):
        self.process = subprocess.Popen([
            self.args.binary, "serve", "--state-directory", str(self.dir / "state"),
            "--port", str(self.api), "--node-port", str(self.node), "--node-name", "resource-node",
            "--kubeconfig", str(self.config), "--containerd-log-root", str(self.dir / "logs"),
            "--cpu-manager-policy", "static", "--reserved-cpus", "0",
            "--topology-manager-policy", "single-numa-node", "--topology-manager-scope", "pod",
        ], stdout=self.log, stderr=subprocess.STDOUT)

        def ready():
            assert self.process.poll() is None, "server exited; inspect server.log"
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.api}/readyz", timeout=2) as r:
                    return r.status == 200 and self.config.exists()
            except OSError:
                return False
        wait(ready, "server readiness")

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            code = self.process.wait(timeout=90)
            self.process = None
            assert code == 0, f"shutdown exit {code}"

    def k(self, *args, obj=None, check=True):
        return subprocess.run(["kubectl", "--kubeconfig", str(self.config), "--request-timeout=15s", *args],
                              input=json.dumps(obj) if obj else None, text=True, capture_output=True, check=check, timeout=40)

    def get(self, resource, name):
        r = self.k("get", resource, name, "-o", "json", check=False)
        if r.returncode and "NotFound" in r.stderr:
            return None
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    def pod(self, name, cpu=None, huge=False, device=False, node=False, command=None, restart="Always"):
        limits = {"memory": "128Mi"}
        if cpu:
            limits["cpu"] = str(cpu)
        if huge:
            limits["hugepages-2Mi"] = "4Mi"
        if device:
            limits["devices.example.test/numa"] = "1"
        c = {"name": "main", "image": IMAGE, "resources": {"limits": limits},
             "command": ["sh", "-c", command or "sleep 3600"],
             "volumeMounts": [{"name": "probe", "mountPath": "/resource-probe", "readOnly": True}]}
        volumes = [{"name": "probe", "hostPath": {"path": self.args.probe, "type": "File"}}]
        if huge:
            volumes.append({"name": "huge", "emptyDir": {"medium": "HugePages-2Mi", "sizeLimit": "4Mi"}})
            c["volumeMounts"].append({"name": "huge", "mountPath": "/huge"})
        spec = {"containers": [c], "volumes": volumes, "terminationGracePeriodSeconds": 1, "restartPolicy": restart}
        if node:
            spec["nodeName"] = "resource-node"
        self.names.add(name)
        self.k("create", "-f", "-", obj={"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec})

    def running(self, name):
        def check():
            p = self.get("pod", name)
            if p and p.get("status", {}).get("phase") == "Failed":
                raise AssertionError(f"{name} failed: {json.dumps(p['status'], sort_keys=True)}")
            return p if p and p.get("status", {}).get("phase") == "Running" else None
        return wait(check, f"{name} Running")

    def affinity(self, name):
        return self.k("exec", name, "--", "sh", "-c", "grep -E '^(Cpus_allowed_list|Mems_allowed_list):' /proc/self/status").stdout

    def report(self, name="exclusive"):
        r = subprocess.run([self.args.probe, "-name", name], text=True, capture_output=True, timeout=30)
        if r.returncode:
            with (self.dir / "report-errors.log").open("a") as log:
                log.write(r.stderr)
            r.check_returncode()
        return json.loads(r.stdout)

    def delete(self, name):
        self.k("delete", "pod", name, "--wait=false", "--ignore-not-found=true")
        wait(lambda: self.get("pod", name) is None, f"{name} removed")
        self.names.discard(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda x: str(Path(x).resolve()))
    parser.add_argument("probe", type=lambda x: str(Path(x).resolve()))
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0, "run in a disposable VM as root"
    directory = args.directory or Path(tempfile.mkdtemp(prefix="gr8s-resources-", dir="/var/tmp"))
    directory.mkdir(parents=True, exist_ok=True)
    print(f"evidence={directory}", flush=True)
    pages = Path("/sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages")
    old_pages = pages.read_text().strip()
    pages.write_text("32")
    assert int(pages.read_text()) >= 32
    smoke = Smoke(args, directory)
    plugin = None
    proof = {"binarySHA256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()}
    try:
        smoke.start()
        plugin = subprocess.Popen([args.probe, "-mode", "plugin"], stdout=(directory / "plugin.log").open("wb"), stderr=subprocess.STDOUT)
        wait(lambda: (smoke.get("node", "resource-node") or {}).get("status", {}).get("allocatable", {}).get("devices.example.test/numa") == "2", "device inventory")
        smoke.pod("shared")
        smoke.running("shared")
        proof["sharedBefore"] = smoke.affinity("shared")
        assert "0-1" in proof["sharedBefore"], proof
        smoke.pod("unalignable", cpu=3, node=True)
        failed = wait(lambda: (p if (p := smoke.get("pod", "unalignable")).get("status", {}).get("phase") == "Failed" else None), "NUMA admission rejection")
        assert failed["status"]["reason"] == "TopologyAffinityError", failed
        proof["numaRejection"] = failed["status"]
        smoke.delete("unalignable")
        smoke.pod("dedicated", cpu=1)
        smoke.running("dedicated")
        proof["sharedAfter"] = wait(lambda: (a if "Cpus_allowed_list:\t0\n" in (a := smoke.affinity("shared")) else None), "shared CPU exclusion")
        smoke.pod("exclusive", cpu=2, huge=True, device=True,
                  command="/resource-probe -mode probe -directory /huge -pages 2 && echo devices=$ALLOCATED_NUMA_DEVICES && sleep 3600")
        running = smoke.running("exclusive")
        proof["containerID"] = running["status"]["containerStatuses"][0]["containerID"]
        proof["processStartTicksBefore"] = smoke.k("exec", "exclusive", "--", "cat", "/proc/1/stat").stdout.split(") ", 1)[1].split()[19]
        logs = wait(lambda: (r.stdout if "RESOURCE_PROBE_OK" in (r := smoke.k("logs", "exclusive")).stdout else None), "kernel probe")
        (directory / "probe.log").write_text(logs)
        assert "Cpus_allowed_list:\t2-3" in logs and "Mems_allowed_list:\t1" in logs, logs
        assert "N1=16384" in logs, logs
        assert "hugepage-touched=2" in logs and "hugetlb.2MB.max=4194304" in logs, logs
        assert "devices=numa1-" in logs, logs
        proof["beforeRestart"] = smoke.report()
        report = proof["beforeRestart"]
        assert report["notFoundCode"] == "NotFound", report
        c = report["get"]["pod_resources"]["containers"][0]
        assert c["cpu_ids"] == [2, 3], c
        assert c["devices"][0]["topology"]["nodes"] == [{"ID": 1}], c
        assert report["allocatable"]["cpu_ids"] == [1, 2, 3], report
        pod = smoke.get("pod", "exclusive")
        pod["spec"]["ephemeralContainers"] = [{"name": "debug", "image": IMAGE, "targetContainerName": "main",
            "command": ["sh", "-c", "grep -E '^(Cpus_allowed_list|Mems_allowed_list):' /proc/self/status; echo DEBUG_AFFINITY_OK; sleep 3600"]}]
        smoke.k("replace", "--raw", "/api/v1/namespaces/default/pods/exclusive/ephemeralcontainers", "-f", "-", obj=pod)
        proof["debugAffinity"] = wait(lambda: (r.stdout if "DEBUG_AFFINITY_OK" in (r := smoke.k("logs", "exclusive", "-c", "debug", check=False)).stdout else None), "dedicated debug affinity")
        assert "Cpus_allowed_list:\t2-3" in proof["debugAffinity"] and "Mems_allowed_list:\t1" in proof["debugAffinity"], proof
        smoke.stop()
        smoke.start()
        after = smoke.running("exclusive")
        assert after["status"]["containerStatuses"][0]["containerID"] == proof["containerID"], after
        def restored_report():
            try:
                report = smoke.report()
            except subprocess.CalledProcessError as error:
                if any(code in error.stderr for code in ("code = Unavailable", "code = DeadlineExceeded", "code = NotFound")):
                    return None
                raise
            container = report["get"]["pod_resources"]["containers"][0]
            return report if container.get("devices", [{}])[0].get("topology") else None
        proof["afterRestart"] = wait(restored_report, "restored plugin topology")
        def normalized(value):
            if isinstance(value, list):
                return sorted((normalized(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
            if isinstance(value, dict):
                return {key: normalized(item) for key, item in value.items()}
            return value
        assert normalized(proof["afterRestart"]["get"]) == normalized(proof["beforeRestart"]["get"]), proof
        smoke.delete("dedicated")
        smoke.pod("reused", cpu=1)
        smoke.running("reused")
        proof["reusedAffinity"] = smoke.affinity("reused")
        assert "Cpus_allowed_list:\t1\n" in proof["reusedAffinity"], proof
        smoke.delete("reused")
        smoke.pod("finished", cpu=1, command="true", restart="Never")
        wait(lambda: (smoke.get("pod", "finished") or {}).get("status", {}).get("phase") == "Succeeded", "terminal Pod release")
        smoke.pod("after-terminal", cpu=1)
        smoke.running("after-terminal")
        proof["afterTerminalAffinity"] = smoke.affinity("after-terminal")
        assert "Cpus_allowed_list:\t1\n" in proof["afterTerminalAffinity"], proof
        proof["processStartTicksAfter"] = smoke.k("exec", "exclusive", "--", "cat", "/proc/1/stat").stdout.split(") ", 1)[1].split()[19]
        proof["containerIDAfter"] = smoke.get("pod", "exclusive")["status"]["containerStatuses"][0]["containerID"]
        assert proof["processStartTicksAfter"] == proof["processStartTicksBefore"], proof
        assert proof["containerIDAfter"] == proof["containerID"], proof
        over = smoke.k("exec", "exclusive", "--", "/resource-probe", "-mode", "probe", "-directory", "/huge", "-pages", "3", check=False)
        (directory / "hugepage-overlimit.log").write_text(over.stdout + over.stderr)
        assert over.returncode != 0 and "hugepage-touched=2" in over.stdout and "hugepage-touched=3" not in over.stdout, over
        proof["hugepageOverLimitExit"] = over.returncode
        proof["passed"] = True
    except Exception as error:
        proof["failure"] = repr(error)
        if smoke.process is not None and smoke.process.poll() is None:
            for resource in ("pods", "nodes", "events"):
                result = smoke.k("get", resource, "-o", "json", check=False)
                (directory / f"failure-{resource}.json").write_text(result.stdout or result.stderr)
        raise
    finally:
        if smoke.process is not None:
            for name in list(smoke.names):
                smoke.delete(name)
        if plugin:
            plugin.terminate()
            plugin.wait(timeout=15)
        smoke.stop()
        pages.write_text(old_pages)
        (directory / "result.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({"passed": True, "evidence": str(directory)}), flush=True)


if __name__ == "__main__":
    main()
