#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Verify Service traffic policies and external addresses through the real dataplane.

Requires root in a disposable Linux guest, a native gr8s executable, kubectl and
access to the agnhost image. Unit tests show the plans; this shows what the kernel
does with them. The test process runs in the host cgroup tree, which the socket
load balancer governs, so it is itself a node-local client:

* a ClusterIP and its externalIPs reach the Service's Pods;
* an unconnected UDP sendto(2) to a ClusterIP is load balanced, and the reply comes
  back from the ClusterIP, as it does for a connected socket;
* ClientIP session affinity keeps a client on its backend when another backend joins;
* internalTrafficPolicy Local keeps a ClusterIP on this node's endpoints, read from a
  hand-written EndpointSlice that also lists an unreachable endpoint on another node;
* a Local LoadBalancer's healthCheckNodePort answers 200 with this node's ready
  endpoints and 503 without them, as kube-proxy's does;
* a Local node port still serves this node's own clients;
* a ClusterIP from an extra ServiceCIDR is claimed by an IPAddress and serves.

It accepts and ignores the arguments gr8s-upstream passes, so that tool can run it.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

AGNHOST = "registry.k8s.io/e2e-test-images/agnhost:2.66.1"
UNREACHABLE = "192.0.2.1"   # TEST-NET-1: nothing answers, so a connection there fails.
EXTERNAL_IP = "203.0.113.77"


class Cluster:
    """Own one disposable native gr8s process and its state directory."""

    def __init__(self, binary, parent, port, node_port):
        """Reserve a fresh state root without starting anything."""
        self.binary, self.port, self.node_port = binary, port, node_port
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-service-traffic.", dir=parent))
        self.kubeconfig = self.root / "kubeconfig"
        self.process = None

    def start(self):
        """Start the agent-bearing control plane and wait for a schedulable node."""
        log = open(self.root / "gr8s.log", "ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--runtime", "containerd",
             "--state-directory", str(self.root / "state"), "--port", str(self.port),
             "--node-port", str(self.node_port), "--containerd-log-root", str(self.root / "pods"),
             "--kubeconfig", str(self.kubeconfig)],
            stdout=log, stderr=subprocess.STDOUT)
        wait_for("node registration", 180, lambda: self.kubectl("get", "nodes", "-o", "name", check=False))

    def stop(self):
        """Stop gr8s with SIGTERM so it joins its runtime work before exiting."""
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=180)
        self.process = None

    def remove(self):
        """Unmount whatever the stopped cluster left under its root, then delete the root."""
        mounts = [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()
                  if line.split()[4].startswith(str(self.root) + "/")]
        for mount in sorted(mounts, reverse=True):
            subprocess.run(["umount", "-l", mount], check=False)
        subprocess.run(["rm", "-rf", "--one-file-system", str(self.root)], check=False)

    def kubectl(self, *arguments, stdin=None, check=True):
        """Run kubectl against this cluster, returning stdout or "" on allowed failure."""
        result = subprocess.run(["kubectl", "--kubeconfig", str(self.kubeconfig), *arguments],
                                input=stdin, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            if check:
                raise RuntimeError(f"kubectl {arguments}: {result.stderr}")
            return ""
        return result.stdout

    def apply(self, *objects):
        """Apply OBJECTS as one List."""
        self.kubectl("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": list(objects)}))

    def get(self, *arguments):
        """Return one object or list as parsed JSON."""
        return json.loads(self.kubectl("get", *arguments, "-o", "json"))


def wait_for(description, seconds, predicate):
    """Poll PREDICATE until truthy, failing with DESCRIPTION at the deadline."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {description}")


def http_get(address, port, path, timeout=3):
    """Return (status, body) for GET http://ADDRESS:PORT/PATH, or (None, error)."""
    try:
        with urllib.request.urlopen(f"http://{address}:{port}{path}", timeout=timeout) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()
    except Exception as error:  # A refused or timed-out connection is an observation.
        return None, str(error)


def server_pod(name):
    """Return an agnhost netexec Pod serving HTTP on 8080 and UDP on 8081."""
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "default", "labels": {"app": "web"}},
            "spec": {"terminationGracePeriodSeconds": 1,
                     "containers": [{"name": "netexec", "image": AGNHOST, "imagePullPolicy": "IfNotPresent",
                                     "args": ["netexec", "--http-port=8080", "--udp-port=8081"],
                                     "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080},
                                                        "periodSeconds": 1}}]}}


def service(name, ports, **spec):
    """Return a Service manifest with PORTS and the given spec fields."""
    body = {"ports": ports}
    body.update(spec)
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": "default"}, "spec": body}


HTTP = {"name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP"}
UDP = {"name": "udp", "port": 81, "targetPort": 8081, "protocol": "UDP"}


def udp_hostname(address, port, connected):
    """Ask agnhost's UDP server for its hostname; return (reply, source address) or (None, error)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        try:
            if connected:
                client.connect((address, port))
                client.send(b"hostname")
            else:
                client.sendto(b"hostname", (address, port))
            data, source = client.recvfrom(256)
            return data.decode().strip(), source
        except OSError as error:
            return None, str(error)


def main():
    """Run every scenario and report independently verified observations as JSON."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--api-port", type=int, default=18192)
    parser.add_argument("--node-port", type=int, default=17449)
    # gr8s-upstream passes these to every runner; this test has no use for them.
    for ignored in ("--sonobuoy", "--timeout", "--expected-specs", "--focus", "--kubernetes-version"):
        parser.add_argument(ignored)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("this test runs containers and an eBPF dataplane; use a disposable guest as root")

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
        node = cluster.kubectl("get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")
        cluster.apply(server_pod("web-0"), server_pod("web-1"))
        wait_for("ready servers", 600, lambda: all(
            any(c["type"] == "Ready" and c["status"] == "True"
                for c in cluster.get("pod", name).get("status", {}).get("conditions", []))
            for name in ("web-0", "web-1")))
        addresses = {name: cluster.get("pod", name)["status"]["podIP"] for name in ("web-0", "web-1")}

        # A ClusterIP and its external IP, both through the socket hook.
        cluster.apply(service("web", [HTTP, UDP], selector={"app": "web"}, externalIPs=[EXTERNAL_IP]))
        cluster_ip = cluster.get("service", "web")["spec"]["clusterIP"]
        wait_for("ClusterIP answers", 120, lambda: http_get(cluster_ip, 80, "/hostname")[0] == 200)
        hosts = {http_get(cluster_ip, 80, "/hostname")[1] for _ in range(30)}
        check("clusterIPReachesEveryPod", hosts == {"web-0", "web-1"}, sorted(hosts))
        external = wait_for("external IP answers", 60,
                            lambda: (lambda result: result if result[0] == 200 else None)(
                                http_get(EXTERNAL_IP, 80, "/hostname")))
        check("externalIPReachesThePods", external[1] in ("web-0", "web-1"), external)

        # Unconnected and connected UDP: balanced, and answered from the ClusterIP.
        wait_for("UDP ClusterIP answers", 60, lambda: udp_hostname(cluster_ip, 81, False)[0])
        for connected in (False, True):
            replies = [udp_hostname(cluster_ip, 81, connected) for _ in range(30)]
            name = "connectedUDP" if connected else "unconnectedUDP"
            check(name + "IsBalanced", {reply for reply, _ in replies} == {"web-0", "web-1"}, replies[:6])
            check(name + "RepliesFromClusterIP", all(source == (cluster_ip, 81) for _, source in replies),
                  sorted({str(source) for _, source in replies}))

        # ClientIP affinity holds this client on its backend while a new backend joins.
        cluster.apply(service("sticky", [HTTP], selector={"app": "web"}, sessionAffinity="ClientIP"))
        sticky_ip = cluster.get("service", "sticky")["spec"]["clusterIP"]
        wait_for("affinity ClusterIP answers", 60, lambda: http_get(sticky_ip, 80, "/hostname")[0] == 200)
        held = {http_get(sticky_ip, 80, "/hostname")[1] for _ in range(10)}
        check("affinityHoldsAClient", len(held) == 1, sorted(held))
        cluster.apply(server_pod("web-2"))
        wait_for("third backend in the slice", 300, lambda: len([
            endpoint for slice_ in cluster.get("endpointslices", "-l", "kubernetes.io/service-name=sticky")["items"]
            for endpoint in slice_.get("endpoints") or [] if endpoint.get("conditions", {}).get("ready")]) == 3)
        time.sleep(3)
        after = {http_get(sticky_ip, 80, "/hostname")[1] for _ in range(10)}
        check("affinitySurvivesANewBackend", after == held, {"before": sorted(held), "after": sorted(after)})

        # internalTrafficPolicy Local over a slice listing a remote, unreachable endpoint.
        def manual(policy):
            """The selectorless Service over the hand-written slice, with POLICY."""
            return service("local-web", [HTTP], internalTrafficPolicy=policy)
        cluster.apply(manual("Local"), {
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "addressType": "IPv4",
            "metadata": {"name": "local-web-manual", "namespace": "default",
                         "labels": {"kubernetes.io/service-name": "local-web",
                                    "endpointslice.kubernetes.io/managed-by": "test.gr8s.io"}},
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": [{"addresses": [addresses["web-0"]], "nodeName": node, "conditions": {"ready": True}},
                          {"addresses": [UNREACHABLE], "nodeName": "elsewhere", "conditions": {"ready": True}}]})
        local_ip = cluster.get("service", "local-web")["spec"]["clusterIP"]
        wait_for("Local ClusterIP answers", 120, lambda: http_get(local_ip, 80, "/hostname")[0] == 200)
        local_results = [http_get(local_ip, 80, "/hostname", timeout=2) for _ in range(20)]
        check("internalLocalUsesOnlyThisNodesEndpoint", all(r == (200, "web-0") for r in local_results),
              local_results)
        cluster.apply(manual("Cluster"))

        def reaches_remote():
            """Return a round of results once one of them failed, as the remote endpoint does."""
            results = [http_get(local_ip, 80, "/hostname", timeout=2) for _ in range(12)]
            return results if any(r[0] is None for r in results) else None
        try:
            spread = wait_for("Cluster policy to include the remote endpoint", 60, reaches_remote)
        except RuntimeError as error:
            spread = str(error)
        check("internalClusterIncludesRemoteEndpoints", isinstance(spread, list), spread)

        # A Local LoadBalancer's health check node port, then a Local node port.
        cluster.apply(service("lb", [HTTP], type="LoadBalancer", externalTrafficPolicy="Local",
                              selector={"app": "web"}))
        lb = cluster.get("service", "lb")["spec"]
        health = lb.get("healthCheckNodePort")
        check("localLoadBalancerHasHealthCheckNodePort", isinstance(health, int), lb)
        ready = wait_for("health check 200", 60, lambda: (lambda r: r if r[0] == 200 else None)(
            http_get("127.0.0.1", health, "/healthz")))
        check("healthCheckReportsLocalEndpoints", json.loads(ready[1]).get("localEndpoints") == 3, ready)
        node_port = lb["ports"][0]["nodePort"]
        local_origin = wait_for("Local node port from this node", 60, lambda: (lambda r: r if r[0] == 200 else None)(
            http_get("127.0.0.1", node_port, "/hostname")))
        check("localNodePortServesThisNodesClients", local_origin[1] in ("web-0", "web-1", "web-2"), local_origin)
        cluster.apply(service("lb", [HTTP], type="LoadBalancer", externalTrafficPolicy="Local",
                              healthCheckNodePort=health, selector={"app": "nothing"}))
        empty = wait_for("health check 503", 60, lambda: (lambda r: r if r[0] == 503 else None)(
            http_get("127.0.0.1", health, "/healthz")))
        check("healthCheckFailsWithoutLocalEndpoints", json.loads(empty[1]).get("localEndpoints") == 0, empty)
        cluster.apply(service("lb", [HTTP], type="LoadBalancer", externalTrafficPolicy="Cluster",
                              selector={"app": "web"}))
        gone = wait_for("health check listener to close", 60, lambda: (lambda r: r if r[0] is None else None)(
            http_get("127.0.0.1", health, "/healthz")))
        check("clusterPolicyClosesHealthCheck", gone[0] is None, gone)

        # A ClusterIP from a second ServiceCIDR.
        cluster.apply({"apiVersion": "networking.k8s.io/v1", "kind": "ServiceCIDR",
                       "metadata": {"name": "extra"}, "spec": {"cidrs": ["198.51.100.0/24"]}})
        cluster.apply(service("extra", [HTTP], selector={"app": "web"}, clusterIP="198.51.100.10"))
        claim = cluster.get("ipaddress", "198.51.100.10")
        check("extraRangeAddressIsClaimed", claim["spec"]["parentRef"].get("name") == "extra", claim["spec"])
        served = wait_for("extra-range ClusterIP answers", 60, lambda: (lambda r: r if r[0] == 200 else None)(
            http_get("198.51.100.10", 80, "/hostname")))
        check("extraRangeClusterIPServes", served[1] in ("web-0", "web-1", "web-2"), served)
    except Exception as error:  # Every failure is still reported with partial observations.
        failures.append(f"exception: {error}")
    finally:
        cluster.stop()
        cluster.remove()
        report["failures"] = failures
        print(json.dumps(report, indent=2, default=str))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
