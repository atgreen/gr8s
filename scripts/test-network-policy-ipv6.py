#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Prove IPv6 NetworkPolicy through the native CNI and endpoint guards.

Run as root in a disposable Linux guest. The test creates two dual-stack
agnhost Pods and exercises the real API projection, pinned maps, TC attachment,
kernel routing, and TCP traffic. Its paired ingress/egress policies require
stateful reply admission in both directions rather than merely proving that the
policy bytecode loads.
"""

import argparse
import ipaddress
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


BUSYBOX = "docker.io/library/busybox:1.37"


def wait_for(description, seconds, predicate):
    """Poll PREDICATE until it returns a truthy observation."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {description}")


class Cluster:
    """Own one disposable dual-stack gr8s process and its state."""

    def __init__(self, binary, parent, api_port, node_port, image_archive):
        self.binary = binary
        self.api_port = api_port
        self.node_port = node_port
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-netpol-ipv6.", dir=parent))
        self.kubeconfig = self.root / "kubeconfig"
        self.image_archive = image_archive
        self.process = None

    def start(self):
        """Start gr8s and wait for the embedded agent to register."""
        images = self.root / "state" / "agent" / "images"
        images.mkdir(parents=True)
        shutil.copy2(self.image_archive, images / self.image_archive.name)
        log = open(self.root / "gr8s.log", "ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--runtime", "containerd",
             "--state-directory", str(self.root / "state"),
             "--port", str(self.api_port), "--node-port", str(self.node_port),
             "--containerd-log-root", str(self.root / "pods"),
             "--kubeconfig", str(self.kubeconfig),
             "--cluster-pod-cidr", "10.42.0.0/16,fd42::/56"],
            stdout=log, stderr=subprocess.STDOUT)
        wait_for("node registration", 180,
                 lambda: self.kubectl("get", "nodes", "-o", "name", check=False))

    def kubectl(self, *arguments, stdin=None, check=True):
        """Run kubectl and return its stdout."""
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(self.kubeconfig), *arguments],
            input=stdin, capture_output=True, text=True, check=False)
        if result.returncode and check:
            raise RuntimeError(f"kubectl {arguments}: {result.stderr}")
        return result.stdout if result.returncode == 0 else ""

    def apply(self, *objects):
        """Server-side apply OBJECTS as one Kubernetes List."""
        self.kubectl("apply", "-f", "-", stdin=json.dumps(
            {"apiVersion": "v1", "kind": "List", "items": list(objects)}))

    def delete_policies(self):
        """Remove every test policy before starting the next independent phase."""
        self.kubectl("delete", "networkpolicy", "--all", "--ignore-not-found=true")

    def get(self, *arguments):
        """Return one API object as parsed JSON."""
        return json.loads(self.kubectl("get", *arguments, "-o", "json"))

    def connect(self, source, destination):
        """Fetch one HTTP response from SOURCE through DESTINATION's IPv6 address."""
        return subprocess.run(
            ["kubectl", "--kubeconfig", str(self.kubeconfig), "exec", source, "--",
             "wget", "-T", "3", "-qO-", f"http://[{destination}]:8080/"],
            capture_output=True, text=True, check=False)

    def stop(self):
        """Stop gr8s, detach owned mounts, and remove disposable state."""
        if self.process and self.process.poll() is None:
            # Let the kubelet/containerd path issue CNI DEL while the API and
            # agent are still alive. Otherwise deleting the temporary state
            # directory can strand the Pods' veth routes in this reusable VM.
            self.kubectl("delete", "pod", "--all", "--grace-period=0", "--wait=true",
                         check=False)
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=30)
        mounts = [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()
                  if line.split()[4].startswith(str(self.root) + "/")]
        for mount in sorted(mounts, reverse=True):
            subprocess.run(["umount", "-l", mount], check=False)
        subprocess.run(["rm", "-rf", "--one-file-system", str(self.root)], check=False)


def pod(name, role):
    """Return a dual-stack BusyBox HTTP Pod with a named port."""
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "default", "labels": {"role": role}},
        "spec": {"terminationGracePeriodSeconds": 1,
                 "containers": [{"name": "server", "image": BUSYBOX,
                                  "imagePullPolicy": "Never",
                                  "command": ["sh", "-c"],
                                  "args": ["mkdir -p /www; echo ok > /www/index.html; "
                                           "exec httpd -f -p 8080 -h /www"],
                                  "ports": [{"name": "http", "containerPort": 8080}],
                                  "readinessProbe": {"httpGet": {"path": "/",
                                                                   "port": 8080},
                                                     "periodSeconds": 1}}]}}


def policy(name, selector, types, ingress=None, egress=None):
    """Return one networking.k8s.io/v1 NetworkPolicy."""
    spec = {"podSelector": {"matchLabels": selector}, "policyTypes": types}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": "default"}, "spec": spec}


def ipv6_of(cluster, name):
    """Return NAME's IPv6 address once its dual-stack status is ready."""
    def address():
        status = cluster.get("pod", name).get("status", {})
        addresses = [entry.get("ip") for entry in status.get("podIPs", [])]
        return next((value for value in addresses
                     if value and ipaddress.ip_address(value).version == 6), None)
    return wait_for(f"{name} IPv6 address", 600, address)


def main():
    """Run independent IPv6 policy phases and emit machine-readable evidence."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--image-archive", required=True, type=Path)
    parser.add_argument("--api-port", type=int, default=18193)
    parser.add_argument("--node-port", type=int, default=17450)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("this test runs containers and eBPF; use a disposable guest as root")

    cluster = Cluster(arguments.gr8s, arguments.state_parent,
                      arguments.api_port, arguments.node_port, arguments.image_archive)
    report = {"root": str(cluster.root)}
    failures = []

    def check(name, passed, observed):
        report[name] = {"passed": bool(passed), "observed": observed}
        if not passed:
            failures.append(name)

    def connection(source, destination, allowed, description):
        def observe():
            result = cluster.connect(source, destination)
            matches = (result.returncode == 0) == allowed
            return result if matches else None
        result = wait_for(description, 90, observe)
        check(description, (result.returncode == 0) == allowed,
              {"returncode": result.returncode,
               "output": (result.stdout + result.stderr)[-500:]})

    try:
        cluster.start()
        cluster.apply(pod("client", "client"), pod("server", "server"))
        client6 = ipv6_of(cluster, "client")
        server6 = ipv6_of(cluster, "server")
        report["podIPv6"] = {"client": client6, "server": server6}
        wait_for("both Pods Ready", 600, lambda: all(
            any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in cluster.get("pod", name).get("status", {}).get("conditions", []))
            for name in ("client", "server")))

        connection("client", server6, True, "baselineIpv6PodTraffic")

        cluster.apply(policy("server-default-deny", {"role": "server"},
                             ["Ingress"], ingress=[]))
        connection("client", server6, False, "ipv6IngressDefaultDeny")
        cluster.delete_policies()
        connection("client", server6, True, "trafficRecoversAfterPolicyDelete")

        # The client may initiate only to the server's named port and accepts no
        # new ingress. The server accepts only that client/port and may initiate
        # no egress. A completed request therefore requires both guards to admit
        # packets belonging to the established flow in the reverse direction.
        cluster.apply(
            policy("client-paired", {"role": "client"}, ["Ingress", "Egress"],
                   ingress=[], egress=[{"to": [{"podSelector": {
                       "matchLabels": {"role": "server"}}}],
                       "ports": [{"protocol": "TCP", "port": "http"}]}]),
            policy("server-paired", {"role": "server"}, ["Ingress", "Egress"],
                   ingress=[{"from": [{"podSelector": {
                       "matchLabels": {"role": "client"}}}],
                       "ports": [{"protocol": "TCP", "port": "http"}]}], egress=[]))
        connection("client", server6, True, "ipv6NamedPortAndStatefulReplies")
        connection("server", client6, False, "unrelatedIpv6EgressRemainsDenied")

        cluster.delete_policies()
        cluster.apply(policy(
            "server-ipblock-except", {"role": "server"}, ["Ingress"],
            ingress=[{"from": [{"ipBlock": {"cidr": "fd42::/56",
                                               "except": [f"{client6}/128"]}}],
                      "ports": [{"protocol": "TCP", "port": 8080}]}]))
        connection("client", server6, False, "ipv6IpBlockExceptDeniesClient")
        cluster.delete_policies()
        cluster.apply(policy(
            "server-ipblock", {"role": "server"}, ["Ingress"],
            ingress=[{"from": [{"ipBlock": {"cidr": "fd42::/56"}}],
                      "ports": [{"protocol": "TCP", "port": 8080}]}]))
        connection("client", server6, True, "ipv6IpBlockAllowsClient")

        cluster.delete_policies()
        cluster.apply(policy("client-egress-deny", {"role": "client"},
                             ["Egress"], egress=[]))
        connection("client", server6, False, "ipv6EgressDefaultDeny")
    except Exception as error:
        failures.append(f"exception: {error}")
        report["exception"] = repr(error)
        if cluster.root.exists() and (cluster.root / "gr8s.log").exists():
            report["logTail"] = (cluster.root / "gr8s.log").read_text(errors="replace")[-4000:]
    finally:
        cluster.stop()
        report["failures"] = failures
        print(json.dumps(report, indent=2))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
