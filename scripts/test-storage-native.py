#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify real static local-PV mounts, protection, Retain and native restart.

Run as root on an isolated Linux test node with kubectl and the dumped gr8s
executable. Every server, resource and backing directory belongs to a fresh
state directory; the smoke never reuses or removes another run's state.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def free_port():
    """Choose a currently unused loopback port for this isolated server."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, description, timeout=120):
    """Poll a concrete condition with a bounded deadline."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}")


class NativeStorageSmoke:
    """Own one native server and its real backing storage for the smoke."""
    def __init__(self, binary, directory):
        """Allocate paths without touching any previous test state."""
        self.binary = str(Path(binary).resolve())
        self.directory = directory
        self.state = directory / "state"
        self.backing = directory / "backing"
        self.backing.mkdir()
        self.config = directory / "kubeconfig"
        self.port = free_port()
        self.node_port = free_port()
        self.process = None
        self.log = (directory / "server.log").open("ab")

    def kubectl(self, *args, input_object=None, check=True, timeout=30):
        """Run kubectl against only this server, preserving real nonzero status."""
        return subprocess.run(
            ["kubectl", "--kubeconfig", str(self.config), "--request-timeout=10s", *args],
            input=None if input_object is None else json.dumps(input_object),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, timeout=timeout,
        )

    def object(self, resource, name):
        """Read one resource, or return None only for a genuine NotFound."""
        result = self.kubectl("get", resource, name, "-o", "json", check=False)
        if result.returncode:
            if "NotFound" in result.stderr:
                return None
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    def phase(self, resource, name):
        """Return an actually observed storage or Pod phase."""
        obj = self.object(resource, name)
        return None if obj is None else obj.get("status", {}).get("phase")

    def start(self):
        """Start the dumped executable with its own managed containerd and local agent."""
        assert self.process is None
        self.process = subprocess.Popen(
            [self.binary, "serve", "--runtime", "containerd", "--node-name", "gr8s-storage",
             "--state-directory", str(self.state), "--port", str(self.port),
             "--node-port", str(self.node_port), "--kubeconfig", str(self.config),
             "--containerd-log-root", str(self.directory / "pod-logs") + "/"],
            stdout=self.log, stderr=subprocess.STDOUT,
        )

        def ready():
            """Check this process and its readiness endpoint, rather than a stale marker."""
            if self.process.poll() is not None:
                raise AssertionError(f"native server exited early: {self.process.returncode}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/readyz", timeout=2) as response:
                    return response.status == 200 and self.config.exists()
            except OSError:
                return False
        wait_for(ready, "native server readiness", 90)

    def stop(self):
        """Stop this server and require a clean native exit."""
        if self.process is not None:
            self.process.terminate()
            code = self.process.wait(timeout=30)
            self.process = None
            assert code == 0, f"native shutdown returned {code}"

    def apply(self, obj):
        """Create a resource through the genuine Kubernetes HTTP API."""
        self.kubectl("apply", "-f", "-", input_object=obj)

    def pod(self, name, *, readonly=False):
        """Create a real BusyBox consumer with direct hostPath and PVC bind mounts."""
        command = "sleep 300" if readonly else "echo started >> /data/starts; echo native-write > /data/native; cat /host-data/native; sleep 300"
        return {
            "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"terminationGracePeriodSeconds": 1,
                     "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "storage-claim", "readOnly": readonly}},
                                 {"name": "host-data", "hostPath": {"path": str(self.backing), "type": "Directory"}}],
                     "containers": [{"name": "main", "image": "docker.io/library/busybox:1.37.0",
                                     "command": ["sh", "-c", command],
                                     "volumeMounts": [{"name": "data", "mountPath": "/data"},
                                                      {"name": "host-data", "mountPath": "/host-data", "readOnly": True}]}]},
        }

    def wait_running(self, name):
        """Wait for the agent to observe a real running container."""
        wait_for(lambda: self.phase("pod", name) == "Running", f"Pod {name} Running")

    def owned_shims(self):
        """Find only containerd shims whose command line belongs to this smoke."""
        result = []
        needle = str(self.state).encode()
        for entry in Path("/proc").glob("[0-9]*"):
            try:
                args = (entry / "cmdline").read_bytes().split(b"\0")
                if args and b"containerd-shim" in Path(os.fsdecode(args[0])).name.encode() and any(needle in arg for arg in args):
                    result.append(entry.name)
            except (OSError, ValueError):
                pass
        return result

    def run(self):
        """Prove writes, readonly enforcement, protection, restart and explicit reclamation."""
        self.start()
        self.apply({"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "local-static"},
                    "provisioner": "kubernetes.io/no-provisioner", "reclaimPolicy": "Retain", "volumeBindingMode": "WaitForFirstConsumer"})
        self.apply({"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": "storage-pv"},
                    "spec": {"capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"], "storageClassName": "local-static",
                             "persistentVolumeReclaimPolicy": "Retain", "local": {"path": str(self.backing)},
                             "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                                 {"key": "kubernetes.io/hostname", "operator": "In", "values": ["gr8s-storage"]}]}]}}}})
        claim = {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "storage-claim"},
                 "spec": {"storageClassName": "local-static", "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}}
        self.apply(claim)
        assert self.phase("pvc", "storage-claim") == "Pending", "delayed claim bound without a consumer"
        self.apply(self.pod("storage-writer"))
        self.wait_running("storage-writer")
        assert self.phase("pvc", "storage-claim") == "Bound"
        assert (self.backing / "native").read_text().strip() == "native-write"
        assert self.kubectl("exec", "storage-writer", "--", "cat", "/host-data/native").stdout.strip() == "native-write"
        assert (self.backing / "starts").read_text().splitlines() == ["started"]
        print("real local-PV/PVC and direct hostPath mounts passed", flush=True)

        self.stop()
        self.start()
        self.wait_running("storage-writer")
        assert self.kubectl("exec", "storage-writer", "--", "cat", "/data/native").stdout.strip() == "native-write"
        assert (self.backing / "starts").read_text().splitlines() == ["started"], "healthy consumer restarted during server recovery"
        print("native restart retained the running consumer and backing data", flush=True)

        self.apply(self.pod("storage-reader", readonly=True))
        self.wait_running("storage-reader")
        denied = self.kubectl("exec", "storage-reader", "--", "sh", "-c", "echo forbidden >/data/readonly-write", check=False)
        assert denied.returncode != 0 and not (self.backing / "readonly-write").exists(), "readonly PVC mount accepted a write"
        old_uid = self.object("pvc", "storage-claim")["metadata"]["uid"]
        self.kubectl("delete", "pvc", "storage-claim", "--wait=false")
        wait_for(lambda: self.object("pvc", "storage-claim").get("metadata", {}).get("deletionTimestamp"), "PVC protection")
        assert self.phase("pv", "storage-pv") == "Bound"
        self.kubectl("delete", "pod", "storage-writer", "storage-reader", "--timeout=90s", timeout=100)
        wait_for(lambda: self.object("pvc", "storage-claim") is None, "claim release after actual Pod deletion")
        wait_for(lambda: self.phase("pv", "storage-pv") == "Released", "Retain release")
        assert (self.backing / "native").read_text().strip() == "native-write"
        self.apply(claim)
        assert self.object("pvc", "storage-claim")["metadata"]["uid"] != old_uid
        time.sleep(2)
        assert self.phase("pvc", "storage-claim") == "Pending", "old PV claimant UID was reassigned"
        self.kubectl("patch", "pv", "storage-pv", "--type=merge", "-p", '{"spec":{"claimRef":null}}')
        self.apply(self.pod("storage-reclaimed", readonly=True))
        self.wait_running("storage-reclaimed")
        assert self.kubectl("exec", "storage-reclaimed", "--", "cat", "/data/native").stdout.strip() == "native-write"
        self.kubectl("delete", "pod", "storage-reclaimed", "--timeout=90s", timeout=100)
        self.kubectl("delete", "pvc", "storage-claim", "--timeout=30s", timeout=40)
        self.kubectl("delete", "pv", "storage-pv", "--timeout=30s", timeout=40)
        self.kubectl("delete", "storageclass", "local-static")
        wait_for(lambda: not self.owned_shims(), "zero smoke-owned containerd shims", 30)
        self.stop()
        assert not self.owned_shims()
        print("readonly, claim protection, Retain UID ownership, explicit reclamation and clean native exit passed", flush=True)

    def cleanup(self):
        """Attempt Pod deletion before stopping only this smoke's server."""
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.kubectl("delete", "pod", "storage-writer", "storage-reader", "storage-reclaimed",
                                 "--ignore-not-found", "--grace-period=0", "--force", "--wait=false", timeout=15)
                    wait_for(lambda: not self.owned_shims(), "failed-smoke workload cleanup", 30)
                except (Exception, AssertionError):
                    pass
                try:
                    self.stop()
                except Exception:
                    if self.process is not None:
                        self.process.kill()
                        self.process.wait(timeout=10)
                        self.process = None
            else:
                self.process = None
        self.log.close()


def main():
    """Run on an isolated privileged node and preserve the state for review."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("native storage smoke requires root on an isolated test node")
    directory = Path(tempfile.mkdtemp(prefix="gr8s-storage-native-"))
    print(f"storage smoke state: {directory}", flush=True)
    smoke = NativeStorageSmoke(args.executable, directory)
    try:
        smoke.run()
    finally:
        smoke.cleanup()
        print(f"remaining smoke-owned shims: {smoke.owned_shims()}", flush=True)


if __name__ == "__main__":
    main()
