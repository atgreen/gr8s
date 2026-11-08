#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Prove dual-stack ClusterIP TCP and UDP through the native Service dataplane.

Run this as root in a disposable Linux guest with a native gr8s executable and
kubectl.  The client and deterministic local backends run in the host cgroup
governed by gr8s's socket load balancer.  Hand-written, ready EndpointSlices
publish non-loopback test addresses for each family, avoiding any image-registry
dependency while exercising the real API, controller, maps, hooks, and kernel.
"""

import argparse
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path


BACKEND_TCP_PORT = 18080
BACKEND_UDP_PORT = 18081
BACKENDS = ((socket.AF_INET, "198.18.0.1", "198.18.0.1/32"),
            (socket.AF_INET6, "fd88::1", "fd88::1/128"))


def wait_for(description, seconds, predicate):
    """Poll PREDICATE until it returns a value, or fail at the deadline."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {description}")


class Cluster:
    """Own one disposable dual-stack gr8s process and its state directory."""

    def __init__(self, binary, parent, port, node_port):
        self.binary, self.port, self.node_port = binary, port, node_port
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-service-ipv6.", dir=parent))
        self.kubeconfig = self.root / "kubeconfig"
        self.process = None

    def start(self):
        """Start gr8s with IPv4 and IPv6 Pod pools and wait for its node."""
        log = open(self.root / "gr8s.log", "ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--runtime", "containerd",
             "--state-directory", str(self.root / "state"), "--port", str(self.port),
             "--node-port", str(self.node_port), "--containerd-log-root", str(self.root / "pods"),
             "--kubeconfig", str(self.kubeconfig),
             "--cluster-pod-cidr", "10.42.0.0/16,fd42::/56"],
            stdout=log, stderr=subprocess.STDOUT)
        wait_for("node registration", 180,
                 lambda: self.kubectl("get", "nodes", "-o", "name", check=False))

    def kubectl(self, *arguments, stdin=None, check=True):
        """Run kubectl against this cluster and return stdout."""
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(self.kubeconfig), *arguments],
            input=stdin, capture_output=True, text=True, check=False)
        if result.returncode and check:
            raise RuntimeError(f"kubectl {arguments}: {result.stderr}")
        return result.stdout if result.returncode == 0 else ""

    def apply(self, *objects):
        """Apply OBJECTS as a Kubernetes List."""
        self.kubectl("apply", "-f", "-",
                     stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": list(objects)}))

    def get(self, *arguments):
        """Return one Kubernetes object as parsed JSON."""
        return json.loads(self.kubectl("get", *arguments, "-o", "json"))

    def stop(self):
        """Stop gr8s gracefully and remove mounts and state owned by the test."""
        if self.process and self.process.poll() is None:
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


class LocalBackend:
    """Serve deterministic TCP and UDP replies on IPv4 and IPv6 loopback."""

    def __init__(self):
        self.sockets = []
        self.threads = []

    def start(self):
        """Bind all four listeners before publishing their EndpointSlices."""
        for family, address, prefix in BACKENDS:
            subprocess.run(["ip", "address", "add", prefix, "dev", "lo"], check=True)
            tcp = socket.socket(family, socket.SOCK_STREAM)
            if family == socket.AF_INET6:
                tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((address, BACKEND_TCP_PORT))
            tcp.listen()
            udp = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            udp.bind((address, BACKEND_UDP_PORT))
            self.sockets.extend((tcp, udp))
            self.threads.extend((threading.Thread(target=self.serve_tcp, args=(tcp,), daemon=True),
                                 threading.Thread(target=self.serve_udp, args=(udp,), daemon=True)))
        for thread in self.threads:
            thread.start()

    @staticmethod
    def serve_tcp(listener):
        """Answer each HTTP request with the backend identity."""
        while True:
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.recv(4096)
                    body = b"dual-backend"
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n" + body)
            except OSError:
                return

    @staticmethod
    def serve_udp(listener):
        """Return the backend identity to every datagram sender."""
        while True:
            try:
                _, sender = listener.recvfrom(256)
                listener.sendto(b"dual-backend", sender)
            except OSError:
                return

    def stop(self):
        """Close listeners so their daemon threads can leave."""
        for listener in self.sockets:
            listener.close()
        for _, _, prefix in BACKENDS:
            subprocess.run(["ip", "address", "del", prefix, "dev", "lo"], check=False)


def dual_service():
    """Return a selectorless RequireDualStack TCP and UDP Service."""
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "dual-service", "namespace": "default"},
        "spec": {"ipFamilyPolicy": "RequireDualStack", "ipFamilies": ["IPv4", "IPv6"],
                 "ports": [{"name": "http", "port": 80, "targetPort": BACKEND_TCP_PORT, "protocol": "TCP"},
                           {"name": "udp", "port": 81, "targetPort": BACKEND_UDP_PORT, "protocol": "UDP"}]}}


def endpoint_slice(name, address_type, address):
    """Return one ready endpoint for a Service address family."""
    return {
        "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "addressType": address_type,
        "metadata": {"name": name, "namespace": "default",
                     "labels": {"kubernetes.io/service-name": "dual-service",
                                "endpointslice.kubernetes.io/managed-by": "test.gr8s.io"}},
        "ports": [{"name": "http", "port": BACKEND_TCP_PORT, "protocol": "TCP"},
                  {"name": "udp", "port": BACKEND_UDP_PORT, "protocol": "UDP"}],
        "endpoints": [{"addresses": [address], "conditions": {"ready": True}}]}


def http_hostname(address):
    """Return the backend identity through ADDRESS, or None while it converges."""
    host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    try:
        with urllib.request.urlopen(f"http://{host}:80/hostname", timeout=3) as response:
            return response.read().decode().strip()
    except OSError:
        return None


def udp_hostname(address, connected):
    """Return a UDP reply tuple through ADDRESS, or None while it converges."""
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    destination = (address, 81, 0, 0) if family == socket.AF_INET6 else (address, 81)
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        try:
            if connected:
                client.connect(destination)
                client.send(b"hostname")
            else:
                client.sendto(b"hostname", destination)
            data, source = client.recvfrom(256)
            return data.decode().strip(), source[0], source[1]
        except OSError:
            return None


def main():
    """Run the native dual-stack Service checks and print their evidence as JSON."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--api-port", type=int, default=18192)
    parser.add_argument("--node-port", type=int, default=17449)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("this test runs containers and eBPF; use a disposable guest as root")

    cluster = Cluster(arguments.gr8s, arguments.state_parent, arguments.api_port, arguments.node_port)
    backend = LocalBackend()
    report = {"root": str(cluster.root)}
    failures = []

    def check(name, passed, observed):
        report[name] = {"passed": bool(passed), "observed": observed}
        if not passed:
            failures.append(name)

    try:
        backend.start()
        cluster.start()
        cluster.apply({"apiVersion": "networking.k8s.io/v1", "kind": "ServiceCIDR",
                       "metadata": {"name": "ipv6"}, "spec": {"cidrs": ["fd96::/112"]}})
        cluster.apply(dual_service(),
                      endpoint_slice("dual-service-v4", "IPv4", "198.18.0.1"),
                      endpoint_slice("dual-service-v6", "IPv6", "fd88::1"))

        service = cluster.get("service", "dual-service")["spec"]
        cluster_ips = service["clusterIPs"]
        check("serviceHasBothFamilies",
              {ipaddress.ip_address(address).version for address in cluster_ips} == {4, 6}, cluster_ips)

        for address in cluster_ips:
            family = ipaddress.ip_address(address).version
            hostname = wait_for(f"IPv{family} TCP ClusterIP", 120,
                                lambda address=address: http_hostname(address))
            check(f"ipv{family}TcpClusterIP", hostname == "dual-backend", hostname)
            for connected in (False, True):
                reply = wait_for(f"IPv{family} UDP ClusterIP", 120,
                                 lambda address=address, connected=connected: udp_hostname(address, connected))
                mode = "Connected" if connected else "Unconnected"
                check(f"ipv{family}{mode}UdpClusterIP", reply[0] == "dual-backend", reply)
                check(f"ipv{family}{mode}UdpRepliesFromClusterIP",
                      ipaddress.ip_address(reply[1]) == ipaddress.ip_address(address) and reply[2] == 81, reply)
    except Exception as error:
        failures.append(f"exception: {error}")
    finally:
        cluster.stop()
        backend.stop()
        report["failures"] = failures
        print(json.dumps(report, indent=2, default=str))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
