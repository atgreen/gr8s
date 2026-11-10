#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Probe inverse Service requests against the standalone v2 graph.

Two endpoints initiate independent Services from opposite ports. Each request
must reach the other endpoint as a request, rather than acquiring the source
VIP of its unrelated outbound Service. Test both arrival orders and node-map
topologies. Default mode is the historical failing regression; --risk seeds
advertised backend source tuples to test the no-envelope mitigation.
--kernel is for a disposable root VM only; no live CNI or socket claim.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location(
    "nat_graph", Path(__file__).with_name("test-service-nat-guard.py"))
graph = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graph)
p, n = graph.p, graph.n


def risk_key(address, port, protocol):
    return (ipaddress.ip_address(address).packed +
            struct.pack("!H", port) + bytes([protocol, 0]))


def probe(factory, protocol, shared, crossed, risk=False):
    client = factory()
    backend = None
    try:
        backend = factory(client if shared else None)
        for endpoint in (client, backend):
            n.owner(endpoint, p.CLIENT, n.ALIAS, 1)
            n.owner(endpoint, p.BACKEND, n.BACK_ALIAS, 2)
        graph.configure(client, p.CLIENT, n.ALIAS, 1, graph.CLIENT_MAC)
        graph.configure(backend, p.BACKEND, n.BACK_ALIAS, 2, graph.BACK_MAC)
        p.publish(client, protocol)
        if risk:
            client.update("gr8s_nat_risk_v2", risk_key(p.CLIENT, 49000 + protocol, protocol), struct.pack("<I", 1))
            backend.update("gr8s_nat_risk_v2", risk_key(p.BACKEND, 8080, protocol), struct.pack("<I", 1))
        original = graph.packet(protocol=protocol, sport=49000 + protocol)
        wire = graph.run(client, 0, original)
        incoming = None if crossed else graph.run(backend, 1, wire)
        second_vip = "10.96.0.99"
        key = p.service_key(second_vip, protocol=protocol)
        value = p.backend_value(p.CLIENT, 49000 + protocol)
        # Use a distinct backend slot even when both endpoints share node maps.
        backend.update("gr8s_backend_v4", struct.pack("<I", 1), value)
        backend.update("gr8s_backend_index_v4", key + value, struct.pack("<I", 1))
        backend.update("gr8s_service_v4", key, struct.pack("<HHIII", 1, 0, 1, 60, 0))
        other = graph.packet(p.BACKEND, second_vip, 8080, 80, protocol,
                             seq=9000, mac=graph.BACK_MAC)
        other_wire = graph.run(backend, 0, other)
        if crossed:
            incoming = graph.run(backend, 1, wire)
        other_incoming = graph.run(client, 1, other_wire)
        return {
            "protocol": protocol, "sharedNodeMaps": shared,
            "riskPublished": risk,
            "order": "bothEmittedBeforeIngress" if crossed else "firstAdmittedBeforeSecondEmitted",
            "firstRequest": p.endpoints(original), "firstWire": p.endpoints(wire),
            "secondRequest": p.endpoints(other), "secondWire": p.endpoints(other_wire),
            "firstDelivered": p.endpoints(incoming),
            "secondDelivered": p.endpoints(other_incoming),
            "misdelivered": (p.endpoints(incoming)[0] == second_vip or
                             p.endpoints(other_incoming)[0] == p.VIP),
        }
    finally:
        if backend:
            backend.close()
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    parser.add_argument("--risk", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(
        args.fixture, names=graph.ROOTS + graph.STAGES + ("gr8s_nat_gc",))
    cls = graph.Kernel if args.kernel else graph.Interpreter
    factory = lambda shared=None: cls(programs, ids, descriptors, shared)
    cases = [probe(factory, protocol, shared, crossed, args.risk)
             for protocol in (6, 17) for shared in (True, False) for crossed in (False, True)]
    passed = not any(case["misdelivered"] for case in cases)
    print(json.dumps({"passed": passed, "kernel": args.kernel, "cases": cases}))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
