#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify dynamic local and NFS volumes, ephemeral volumes and emptyDir limits on real mounts.

Run as root on an isolated Linux test node with kubectl and the dumped gr8s
executable. NFS checks run only with --nfs-server and --nfs-share, which must name
an export this node can write to; the script creates and removes only pvc-*,
archived-pvc-* and its own static directory beneath it.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location(
    "storage_native", Path(__file__).resolve().parent / "test-storage-native.py")
storage_native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage_native)
wait_for = storage_native.wait_for


class DynamicStorageSmoke(storage_native.NativeStorageSmoke):
    """Prove provisioning and reclamation against this node's real filesystem and kernel."""

    def __init__(self, binary, directory, nfs_server, nfs_share):
        """Record the optional real NFS export this run may use."""
        super().__init__(binary, directory)
        self.nfs_server = nfs_server
        self.nfs_share = nfs_share
        self.local_root = directory / "local-volumes"

    def claim(self, name, class_name, modes=("ReadWriteOnce",)):
        """Build a filesystem claim in the named class."""
        return {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": name},
                "spec": {"storageClassName": class_name, "accessModes": list(modes),
                         "resources": {"requests": {"storage": "1Gi"}}}}

    def consumer(self, name, volume, command="echo native-write > /data/native; sleep 300"):
        """Build a real BusyBox Pod that writes through the given volume."""
        return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
                "spec": {"terminationGracePeriodSeconds": 1, "volumes": [{"name": "data", **volume}],
                         "containers": [{"name": "main", "image": "docker.io/library/busybox:1.37.0",
                                         "command": ["sh", "-c", command],
                                         "volumeMounts": [{"name": "data", "mountPath": "/data"}]}]}}

    def volume_of(self, claim):
        """Return the name of the PV a claim is bound to."""
        return self.object("pvc", claim)["spec"]["volumeName"]

    def delete_pod(self, name):
        """Delete a Pod and wait for the runtime to finish with it."""
        self.kubectl("delete", "pod", name, "--timeout=90s", timeout=100)

    def wait_reclaimed(self, name):
        """Wait for a provisioned PV to be reclaimed and removed."""
        wait_for(lambda: self.object("pv", name) is None, f"PV {name} reclaimed", 90)

    def nfs_mounts(self):
        """Count this server's NFS mounts in the kernel's table."""
        needle = str(self.directory)
        return [line for line in Path("/proc/self/mountinfo").read_text().splitlines()
                if " - nfs" in line and needle in line]

    def check_default_class(self):
        """Prove the seeded class exists and that a defaulted claim would use it."""
        default = self.object("storageclass", "local-path")
        assert default["provisioner"] == "gr8s.io/local-path"
        assert default["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"] == "true"
        print("default local-path class passed", flush=True)

    def check_local_path(self):
        """Prove a local claim provisions on demand, stores data and is deleted."""
        self.apply({"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "fast"},
                    "provisioner": "gr8s.io/local-path", "volumeBindingMode": "WaitForFirstConsumer",
                    "parameters": {"path": str(self.local_root)}})
        self.apply(self.claim("local-claim", "fast"))
        time.sleep(2)
        assert self.phase("pvc", "local-claim") == "Pending", "delayed claim provisioned without a consumer"
        self.apply(self.consumer("local-writer", {"persistentVolumeClaim": {"claimName": "local-claim"}}))
        self.wait_running("local-writer")
        name = self.volume_of("local-claim")
        backing = self.local_root / name
        wait_for((backing / "native").exists, "write through a provisioned local volume", 30)
        assert (backing / "native").read_text().strip() == "native-write"
        assert backing.stat().st_mode & 0o777 == 0o777
        # A planted link must not redirect the root deletion that reclaims this directory.
        outside = self.directory / "outside"
        outside.mkdir()
        (outside / "keep").write_text("keep")
        (backing / "escape").symlink_to(outside)
        self.delete_pod("local-writer")
        self.kubectl("delete", "pvc", "local-claim", "--timeout=60s", timeout=70)
        self.wait_reclaimed(name)
        assert not backing.exists(), "reclaim left a provisioned directory behind"
        assert (outside / "keep").read_text() == "keep", "reclaim followed a tenant's symbolic link"
        print("local-path provision, write, reclaim and link safety passed", flush=True)

    def check_empty_dir_limit(self):
        """Prove a disk-backed emptyDir is evicted once it outgrows its limit."""
        self.apply(self.consumer("scratch", {"emptyDir": {"sizeLimit": "1Mi"}},
                                 "dd if=/dev/zero of=/data/big bs=1M count=8; sleep 300"))
        wait_for(lambda: self.phase("pod", "scratch") == "Failed", "emptyDir eviction", 120)
        assert self.object("pod", "scratch")["status"]["reason"] == "Evicted"
        self.delete_pod("scratch")
        print("disk-backed emptyDir eviction passed", flush=True)

    def check_ephemeral(self):
        """Prove a generic ephemeral volume is owned by its Pod and removed with it."""
        self.apply(self.consumer("ephemeral", {"ephemeral": {"volumeClaimTemplate": {"spec": {
            "storageClassName": "fast", "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "1Gi"}}}}}}))
        self.wait_running("ephemeral")
        claim = self.object("pvc", "ephemeral-data")
        assert claim["metadata"]["ownerReferences"][0]["name"] == "ephemeral"
        name = claim["spec"]["volumeName"]
        self.delete_pod("ephemeral")
        wait_for(lambda: self.object("pvc", "ephemeral-data") is None, "ephemeral claim collection", 60)
        self.wait_reclaimed(name)
        print("generic ephemeral volume lifecycle passed", flush=True)

    def check_nfs(self):
        """Prove static and dynamic NFS across real kernel mounts, then their cleanup."""
        share = self.directory / "share-view"
        share.mkdir()
        subprocess.run(["mount", "-t", "nfs4", f"{self.nfs_server}:{self.nfs_share}", str(share)], check=True)
        try:
            static_dir = share / f"gr8s-smoke-{os.getpid()}"
            static_dir.mkdir()
            self.apply(self.consumer(
                "nfs-direct",
                {"nfs": {"server": self.nfs_server, "path": f"{self.nfs_share.rstrip('/')}/{static_dir.name}"}}))
            self.wait_running("nfs-direct")
            wait_for((static_dir / "native").exists, "write through a Pod nfs volume", 30)
            assert self.nfs_mounts(), "no kernel NFS mount was made for the Pod"
            self.delete_pod("nfs-direct")
            wait_for(lambda: not self.nfs_mounts(), "NFS unmount after Pod deletion", 30)
            assert (static_dir / "native").exists(), "Pod deletion removed data on the share"
            shutil.rmtree(static_dir)
            print("static Pod NFS volume passed", flush=True)

            self.apply({"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass", "metadata": {"name": "shared"},
                        "provisioner": "gr8s.io/nfs", "allowVolumeExpansion": True,
                        "mountOptions": ["hard", "noatime"],
                        "parameters": {"server": self.nfs_server, "share": self.nfs_share}})
            self.apply(self.claim("nfs-claim", "shared", modes=("ReadWriteMany",)))
            wait_for(lambda: self.phase("pvc", "nfs-claim") == "Bound", "immediate NFS binding", 30)
            name = self.volume_of("nfs-claim")
            self.apply(self.consumer("nfs-one", {"persistentVolumeClaim": {"claimName": "nfs-claim"}}))
            self.apply(self.consumer("nfs-two", {"persistentVolumeClaim": {"claimName": "nfs-claim"}},
                                     "sleep 300"))
            self.wait_running("nfs-one")
            self.wait_running("nfs-two")
            wait_for((share / name / "native").exists, "write through a dynamic NFS volume", 30)
            read = self.kubectl("exec", "nfs-two", "--", "cat", "/data/native").stdout.strip()
            assert read == "native-write", "second Pod did not see the shared write"
            self.kubectl("patch", "pvc", "nfs-claim", "--type=merge", "-p",
                         '{"spec":{"resources":{"requests":{"storage":"2Gi"}}}}')
            wait_for(lambda: self.object("pvc", "nfs-claim")["status"]["capacity"]["storage"] == "2Gi",
                     "NFS claim expansion", 30)
            self.delete_pod("nfs-one")
            self.delete_pod("nfs-two")
            self.kubectl("delete", "pvc", "nfs-claim", "--timeout=60s", timeout=70)
            self.wait_reclaimed(name)
            assert not (share / name).exists(), "reclaim left the NFS directory behind"
            wait_for(lambda: not self.nfs_mounts(), "all NFS mounts removed", 30)
            print("dynamic NFS sharing, expansion, reclaim and unmount passed", flush=True)
        finally:
            subprocess.run(["umount", str(share)], check=False)

    def run(self):
        """Run every check and require a clean exit with nothing left behind."""
        self.start()
        self.check_default_class()
        self.check_local_path()
        self.check_empty_dir_limit()
        self.check_ephemeral()
        if self.nfs_server:
            self.check_nfs()
        else:
            print("NFS checks skipped: pass --nfs-server and --nfs-share", flush=True)
        wait_for(lambda: not self.owned_shims(), "zero smoke-owned containerd shims", 30)
        self.stop()
        assert not self.owned_shims()
        print("clean native exit passed", flush=True)

    def cleanup(self):
        """Stop only this smoke's server."""
        if self.process is not None and self.process.poll() is None:
            try:
                self.stop()
            except Exception:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process = None
        self.log.close()


def main():
    """Run on an isolated privileged node and preserve the state for review."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--nfs-server")
    parser.add_argument("--nfs-share")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("dynamic storage smoke requires root on an isolated test node")
    if bool(args.nfs_server) != bool(args.nfs_share):
        raise SystemExit("--nfs-server and --nfs-share go together")
    directory = Path(tempfile.mkdtemp(prefix="gr8s-storage-dynamic-"))
    print(f"storage smoke state: {directory}", flush=True)
    smoke = DynamicStorageSmoke(args.executable, directory, args.nfs_server, args.nfs_share)
    try:
        smoke.run()
    finally:
        smoke.cleanup()
        print(f"remaining smoke-owned shims: {smoke.owned_shims()}", flush=True)


if __name__ == "__main__":
    main()
