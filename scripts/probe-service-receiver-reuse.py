#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Reproduce retained receiver ownership after source Service collection.

--kernel requires a disposable root VM. Until fixed, exits1 when a new Service
request is incorrectly dropped. This is synthetic graph evidence, not live CNI.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("wire_graph", Path(__file__).with_name("test-service-wire-guard.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
p, n = t.p, t.n


def age(runner, seconds):
    for table, offset in ((n.FWD, 8), (t.RX, 80)):
        for key in runner.keys(table):
            value = bytearray(runner.lookup(table, key))
            stamp = struct.unpack_from("<Q", value, offset)[0]
            struct.pack_into("<Q", value, offset, (stamp - seconds * 1_000_000_000) & p.endpoint.MASK)
            runner.update(table, key, value)


def control(key):
    data = bytearray(52)
    data[:14] = bytes.fromhex("0200000000010200000000020800")
    data[14], data[22], data[23] = 0x45, 64, 253
    struct.pack_into("!H", data, 16, 38)
    struct.pack_into("!H", data, 24, p.checksum(bytes(data[14:34])))
    data[36:] = key
    return bytes(data)


def exercise(factory):
    client, backend = factory(), factory()
    try:
        t.setup(client, backend)
        p.publish(client, 17)
        first = t.graph.packet(protocol=17, sport=43017)
        first_wire = t.run(client, 0, first)
        visible = t.run(backend, 1, first_wire)
        for runner in (client, backend):
            age(runner, 179)
        source, destination, sport, dport = p.endpoints(visible)
        response = t.graph.packet(destination, source, dport, sport, 17, mac=t.graph.BACK_MAC)
        # A reply refreshes backend ownership, but the network loses it.
        delayed_reply = t.run(backend, 0, response)
        for runner in (client, backend):
            age(runner, 2)
        data = control(n.key(first))
        verdict, output = client.run("gr8s_nat_gc", data)
        assert verdict == 1 and output == data
        assert not client.keys(n.FWD) and not client.keys(n.REV)
        assert len(backend.keys(t.RX)) == len(backend.keys(t.RI)) == 1
        new_vip = "10.96.0.99"
        p.publish(client, 17, vip=new_vip)
        second = t.graph.packet(destination=new_vip, protocol=17, sport=43017)
        second_wire = t.run(client, 0, second)
        assert p.endpoints(t.inner(second_wire)) == p.endpoints(t.inner(first_wire))
        verdict, delivered = backend.run(t.graph.ROOTS[1], second_wire)
        n.unlocked(backend)
        assert not backend.keys(t.WL)
        result = {"newRequestVerdict": verdict, "expectedVerdict": p.OK,
                  "receiverRows": len(backend.keys(t.RX)), "receiverIndexes": len(backend.keys(t.RI)),
                  "translatedTuple": p.endpoints(t.inner(second_wire))}
        if verdict != p.OK:
            result["passed"] = False
            return result
        source, destination, sport, dport = p.endpoints(delivered)
        response = t.graph.packet(destination, source, dport, sport, 17, mac=t.graph.BACK_MAC)
        restored = t.run(client, 1, t.run(backend, 0, response))
        assert p.endpoints(restored) == (new_vip, p.CLIENT, 80, 43017)
        t.run(client, 1, delayed_reply, p.SHOT)
        result["passed"] = True
        return result
    finally:
        backend.close()
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=t.graph.ROOTS + t.graph.STAGES + t.EXTRA + ("gr8s_nat_gc", t.WIRE_GC))
    cls = t.Kernel if args.kernel else t.Interpreter
    result = exercise(lambda: cls(programs, ids, descriptors))
    result["kernel"] = args.kernel
    print(json.dumps(result))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
