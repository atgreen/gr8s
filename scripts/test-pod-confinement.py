#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Verify Pod confinement and tmpfs volumes from inside real native containers.

Requires root in a disposable Linux guest, a native gr8s executable, kubectl and
access to the busybox image. Admission and CRI unit tests cannot show that the
kernel applied a setting, so this reads /proc/self/status inside each container
and the host mount table: RuntimeDefault must install a seccomp filter, dropped
capabilities must be absent, and a Memory emptyDir must be a real size-limited
tmpfs that survives a container restart and agent restart and is unmounted, with
its data removed, when the Pod is deleted.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CAP_NET_BIND_SERVICE = 1 << 10
IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"
PROBE = (
    "grep -E '^(Seccomp|CapEff|Groups|NoNewPrivs):' /proc/self/status; "
    "stat -f -c 'fs=%T size=%b bsize=%S' /scratch; stat -c 'mode=%a' /scratch; "
    "echo kept >> /scratch/attempts; echo attempts=$(wc -l < /scratch/attempts); "
    "if [ \"$(wc -l < /scratch/attempts)\" = 1 ]; then echo restart-now; exit 3; fi; "
    "echo ready; sleep 3600"
)


def pod_manifest():
    """Return a Pod whose confinement differs between its two containers."""
    scratch = [{"name": "scratch", "mountPath": "/scratch"}]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "confinement", "namespace": "default"},
        "spec": {
            "terminationGracePeriodSeconds": 1,
            "securityContext": {
                "seccompProfile": {"type": "RuntimeDefault"},
                "supplementalGroups": [4321],
                "seLinuxOptions": {"level": "s0:c10,c20"},
            },
            "volumes": [{"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}],
            "containers": [
                {
                    "name": "confined",
                    "image": IMAGE,
                    "command": ["sh", "-c", PROBE],
                    "volumeMounts": scratch,
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
                    },
                },
                {
                    "name": "unconfined",
                    "image": IMAGE,
                    "command": ["sh", "-c", "grep -E '^Seccomp:' /proc/self/status; echo ready; sleep 3600"],
                    "securityContext": {"seccompProfile": {"type": "Unconfined"}},
                },
            ],
        },
    }


class Cluster:
    """Own one disposable native gr8s process and its state directory."""

    def __init__(self, binary, parent, port, node_port):
        """Reserve a fresh state root without starting anything."""
        self.binary, self.port, self.node_port = binary, port, node_port
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-confinement.", dir=parent))
        self.state = self.root / "state"
        self.logs = self.root / "pods"
        self.kubeconfig = self.root / "kubeconfig"
        self.process = None

    def start(self):
        """Start the agent-bearing control plane and wait for a schedulable node."""
        log = open(self.root / "gr8s.log", "ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--runtime", "containerd",
             "--state-directory", str(self.state), "--port", str(self.port),
             "--node-port", str(self.node_port), "--containerd-log-root", str(self.logs),
             "--kubeconfig", str(self.kubeconfig)],
            stdout=log, stderr=subprocess.STDOUT)
        wait_for("node registration", 180, lambda: self.kubectl("get", "nodes", "-o", "name", check=False))

    def stop(self):
        """Stop gr8s with SIGTERM so it joins its runtime work before exiting."""
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=180)
        self.process = None

    def kubectl(self, *arguments, stdin=None, check=True):
        """Run kubectl against this cluster, returning stdout or "" on allowed failure."""
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(self.kubeconfig), *arguments],
            input=stdin, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            if check:
                raise RuntimeError(f"kubectl {arguments}: {result.stderr}")
            return ""
        return result.stdout


def wait_for(description, seconds, predicate):
    """Poll PREDICATE until truthy, failing with DESCRIPTION at the deadline."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {description}")


def status_field(log, field):
    """Return one /proc/self/status field recorded in a container log."""
    # Tolerates raw CRI "<time> <stream> <tag> " prefixes, which are not under test here.
    match = re.search(rf"(?:^|\s){field}:\s*(.*)$", log, re.MULTILINE)
    if match:
        return match.group(1).strip()
    raise RuntimeError(f"{field} missing from container log:\n{log}")


def host_mounts(prefix):
    """Return (mountpoint, type, options) under PREFIX from the host's mount table."""
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        separator = fields.index("-")
        if fields[4].startswith(str(prefix)):
            mounts.append((fields[4], fields[separator + 1], fields[separator + 3]))
    return mounts


def main():
    """Run every scenario and report independently verified observations as JSON."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--api-port", type=int, default=18191)
    parser.add_argument("--node-port", type=int, default=17448)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("this test mounts and runs containers; use a disposable guest as root")

    cluster = Cluster(arguments.gr8s, arguments.state_parent, arguments.api_port, arguments.node_port)
    report = {"root": str(cluster.root)}
    failures = []

    def check(name, passed, observed):
        """Record one observation, keeping later scenarios running after a failure."""
        report[name] = {"passed": bool(passed), "observed": observed}
        if not passed:
            failures.append(name)

    try:
        cluster.start()
        cluster.kubectl("apply", "-f", "-", stdin=json.dumps(pod_manifest()))

        def logs(container, previous=False):
            """Return a container's log text, or "" while it is not yet available."""
            extra = ["--previous"] if previous else []
            return cluster.kubectl("logs", "confinement", "-c", container, *extra, check=False)

        wait_for("both containers ready", 600,
                 lambda: "ready" in logs("confined") and "ready" in logs("unconfined"))
        confined, unconfined = logs("confined"), logs("unconfined")

        check("runtimeDefaultInstallsSeccompFilter", status_field(confined, "Seccomp") == "2",
              status_field(confined, "Seccomp"))
        check("containerUnconfinedOverridesPod", status_field(unconfined, "Seccomp") == "0",
              status_field(unconfined, "Seccomp"))
        effective = int(status_field(confined, "CapEff"), 16)
        check("dropAllKeepsOnlyTheAddedCapability", effective == CAP_NET_BIND_SERVICE, hex(effective))
        check("allowPrivilegeEscalationFalseSetsNoNewPrivs",
              status_field(confined, "NoNewPrivs") == "1", status_field(confined, "NoNewPrivs"))
        check("supplementalGroupIsApplied", "4321" in status_field(confined, "Groups").split(),
              status_field(confined, "Groups"))
        check("emptyDirIsTmpfsInsideContainer", "fs=tmpfs" in confined, confined)
        check("containerRestartKeepsTmpfsContents", "attempts=2" in confined, confined)

        pod = json.loads(cluster.kubectl("get", "pod", "confinement", "-o", "json"))
        uid = pod["metadata"]["uid"]
        volume_root = cluster.logs / uid / "volumes"
        mounts = host_mounts(volume_root)
        check("hostHasExactlyOneSizeLimitedTmpfs",
              len(mounts) == 1 and mounts[0][1] == "tmpfs" and "size=16384k" in mounts[0][2], mounts)

        # Durable agent restart must reuse the live tmpfs, neither stacking nor clearing it.
        cluster.stop()
        check("tmpfsSurvivesAgentStop", len(host_mounts(volume_root)) == 1, host_mounts(volume_root))
        cluster.start()
        wait_for("Pod after agent restart", 240, lambda: "ready" in logs("confined"))
        check("agentRestartDoesNotStackMounts", len(host_mounts(volume_root)) == 1, host_mounts(volume_root))
        scratch = Path(host_mounts(volume_root)[0][0]) / "attempts"
        check("agentRestartKeepsTmpfsContents", scratch.exists() and scratch.read_text().count("kept") >= 2,
              scratch.read_text() if scratch.exists() else None)

        cluster.kubectl("delete", "pod", "confinement", "--wait=true", "--timeout=180s")
        wait_for("volume removal", 120, lambda: not volume_root.exists())
        check("deletionUnmountsTmpfs", not host_mounts(volume_root), host_mounts(volume_root))
        check("deletionRemovesVolumeData", not volume_root.exists(), str(volume_root))
    except Exception as error:  # Every failure is still reported with partial observations.
        failures.append(f"exception: {error}")
    finally:
        cluster.stop()
        report["failures"] = failures
        print(json.dumps(report, indent=2, default=str))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
