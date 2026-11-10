#!/usr/bin/env python3
"""Verify that a live node stages v2 maps and publishes backend risk keys.

Run as root in a disposable VM with test-service-traffic.py and
test-service-guest.py alongside this script. No Kata bundle is required.
"""

import argparse
import errno
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import struct
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


traffic = load("service_traffic", "test-service-traffic.py")
guest = load("service_guest", "test-service-guest.py")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--api-port", type=int, default=18192)
    parser.add_argument("--node-port", type=int, default=17449)
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("run in a disposable VM as root")

    os.environ["GR8S_ENABLE_PACKET_SERVICES"] = "1"
    os.environ["GR8S_PREPARE_PACKET_SERVICES_V2"] = "1"
    cluster = traffic.Cluster(args.gr8s, args.state_parent, args.api_port, args.node_port)
    report = {"root": str(cluster.root)}
    try:
        cluster.start()
        # A manual EndpointSlice proves control-plane publication without relying
        # on a container registry; the Kata test exercises the live packet path.
        backend = "192.0.2.50"
        cluster.apply(traffic.service("staged", [traffic.HTTP, traffic.UDP]), {
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice", "addressType": "IPv4",
            "metadata": {"name": "staged-manual", "namespace": "default",
                         "labels": {"kubernetes.io/service-name": "staged",
                                    "endpointslice.kubernetes.io/managed-by": "test.gr8s.io"}},
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"},
                      {"name": "udp", "port": 8081, "protocol": "UDP"}],
            "endpoints": [{"addresses": [backend], "conditions": {"ready": False}}]})
        service = cluster.get("service", "staged")
        vip = service["spec"]["clusterIP"]
        network_file = cluster.root / "state/agent/runtime/network.json"
        traffic.wait_for("applied node network", 120, network_file.exists)
        network = json.loads(network_file.read_text())
        cidrs = network.get("clusterPodCIDRs") or [network["clusterPodCIDR"]]
        managed = cluster.root / "state/agent/containerd/bpf/service-lb/gr8s_nat_pod_v2"
        probes = [ipaddress.ip_network(cidr).network_address + 1
                  for cidr in cidrs if isinstance(ipaddress.ip_network(cidr), ipaddress.IPv4Network)]
        if not probes:
            raise RuntimeError("staging test requires an IPv4 cluster Pod CIDR")

        def managed_published():
            if not managed.exists():
                return False
            keys = [struct.pack("<I", 32) + address.packed for address in probes]
            return guest.read_pinned_values(managed, keys, 1) == [b"\x01"] * len(keys)

        traffic.wait_for("v2 managed Pod CIDRs", 120, managed_published)
        risk = cluster.root / "state/agent/containerd/bpf/service-lb/gr8s_nat_risk_v2"
        keys = [ipaddress.ip_address(backend).packed + struct.pack("!HBB", port, proto, 0)
                for port, proto in ((8080, 6), (8081, 17))]

        def published():
            if not risk.exists():
                return False
            try:
                return guest.read_pinned_values(risk, keys, 4) == [struct.pack("<I", 1)] * 2
            except OSError as error:
                if error.errno == errno.ENOENT:
                    return False
                raise

        traffic.wait_for("v2 backend risk publication", 120, published)
        report.update({"backend": backend, "service": vip, "riskKeys": [key.hex() for key in keys],
                       "riskMap": str(risk), "managedPodCIDRs": cidrs,
                       "managedPodMap": str(managed), "source": "unready manual EndpointSlice"})
        print(json.dumps(report, indent=2))
    finally:
        cluster.stop()
        cluster.remove()


if __name__ == "__main__":
    main()
