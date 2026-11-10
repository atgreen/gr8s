#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Test bounded per-key receiver collection; --kernel is disposable-VM only.

Rows and identities are seeded fixtures. This does not prove an installed agent
scanner, endpoint upgrades or live guest/native socket behavior.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import threading
import time

spec = importlib.util.spec_from_file_location("wire_graph", Path(__file__).with_name("test-service-wire-guard.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
p, n, RX, RI, WL = t.p, t.n, t.RX, t.RI, t.WL
GC = "gr8s_wire_gc"
FL, RL = "gr8s_nat_fl_v2", "gr8s_nat_rl_v2"


class Machine(p.PacketMachine):
    def call(self, helper):
        if helper == 3 and getattr(self.maps, "fail_delete", None):
            name = self.maps.names[self.registers[1]]
            if self.maps.fail_delete == name:
                self.maps.fail_delete = None
                self.registers[0] = -5 & p.endpoint.MASK
                self.registers[1:6] = [0xdeadbeef] * 5
                return
        super().call(helper)


class Interpreter(p.Interpreter):
    def keys(self, name):
        return list(self.maps.entries[name])

    def run(self, program, data):
        machine = Machine(self.programs[program], self.maps, bytes(data), self.clock)
        verdict = machine.run()
        return verdict, bytes(machine.memory[0x100000])


def frame(kind, key):
    data = bytearray(36 + len(key))
    data[:14] = bytes.fromhex("0200000000010200000000020800")
    data[14], data[22], data[23], data[34] = 0x45, 64, 253, kind
    struct.pack_into("!H", data, 16, len(data) - 14)
    struct.pack_into("!H", data, 24, p.checksum(bytes(data[14:34])))
    data[36:] = key
    return bytes(data)


def unlocked(runner):
    for name in (FL, RL, WL):
        assert not runner.keys(name), (name, runner.keys(name))


def collect(runner, kind, key, expected, locks=True):
    data = frame(kind, key)
    verdict, output = runner.run(GC, data)
    assert verdict == expected, (kind, verdict, expected)
    assert output == data
    if locks:
        unlocked(runner)


def setup(runner):
    n.owner(runner, p.CLIENT, n.ALIAS, 1, flags=15)
    n.owner(runner, p.BACKEND, n.BACK_ALIAS, 2, flags=15)


def seed(runner, protocol=17, active=1, indexed=True, age=0, port=49000, visible_port=None):
    now = runner.clock[0] if isinstance(runner, Interpreter) else time.monotonic_ns()
    incoming = n.key(p.packet(p.CLIENT, p.BACKEND, port, 8080, protocol))
    address = n.ALIAS if visible_port is not None else p.CLIENT
    visible_in = n.key(p.packet(address, p.BACKEND, visible_port or port, 8080, protocol))
    visible = n.key(p.packet(p.BACKEND, address, 8080, visible_port or port, protocol))
    row = (t.wire.metadata(protocol) + incoming + visible_in +
           struct.pack("<QII", (now - int(age * 1e9)) & p.endpoint.MASK, 1, active))
    runner.update(RX, visible, row)
    if indexed:
        runner.update(RI, row[:64], visible)
    return row[:64], visible, row


def snapshot(runner):
    return {name: {key: runner.lookup(name, key) for key in runner.keys(name)} for name in (RX, RI)}


def exercise(factory, kernel):
    cases = []

    def case(name, action):
        runner = factory()
        try:
            setup(runner)
            action(runner)
            unlocked(runner)
            cases.append(name)
        finally:
            runner.close()

    for protocol, lifetime in ((6, 7200), (17, 180)):
        for direction in (0, 1):
            def lifetime_case(r, protocol=protocol, lifetime=lifetime, direction=direction):
                wire, visible, _ = seed(r, protocol, visible_port=52000)
                held = snapshot(r)
                collect(r, direction, (visible, wire)[direction], 0)
                assert snapshot(r) == held
                wire, visible, _ = seed(r, protocol, age=lifetime + 1, visible_port=52000)
                collect(r, direction, (visible, wire)[direction], 1)
                assert snapshot(r) == {RX: {}, RI: {}}
                collect(r, direction, (visible, wire)[direction], 0)
            case(f"protocol{protocol}Direction{direction}Lifetime", lifetime_case)

    for active, indexed, direction in ((0, True, 0), (0, True, 1), (0, False, 0), (1, False, 0)):
        def pending_case(r, active=active, indexed=indexed, direction=direction):
            wire, visible, _ = seed(r, 6, active=active, indexed=indexed)
            collect(r, direction, (visible, wire)[direction], 0)
            wire, visible, _ = seed(r, 6, active=active, indexed=indexed, age=6)
            collect(r, direction, (visible, wire)[direction], 1)
            assert not r.keys(RX) and not r.keys(RI)
        case(f"active{active}Indexed{indexed}Direction{direction}Pending", pending_case)

    def missing_rx(r):
        wire, visible, _ = seed(r)
        r.delete(RX, visible)
        collect(r, 1, wire, 1)
        collect(r, 1, wire, 0)
        assert not r.keys(RI)
    case("OrphanIndex", missing_rx)

    def foreign_index(r):
        wire, old, _ = seed(r, age=181)
        _, foreign, foreign_row = seed(r, visible_port=53000)
        collect(r, 0, old, 1)
        assert r.lookup(RX, old) is None
        assert r.lookup(RI, wire) == foreign
        assert r.lookup(RX, foreign) == foreign_row
        collect(r, 1, wire, 0)
    case("ExpiredReceiverPreservesForeignIndex", foreign_index)

    def foreign_rx(r):
        old_wire, visible, _ = seed(r)
        new_wire, new_visible, new_row = seed(r, port=49001, visible_port=49000)
        assert new_visible != visible  # The second row deliberately uses an alias.
        r.delete(RX, visible)
        r.update(RI, old_wire, new_visible)
        collect(r, 1, old_wire, 1)
        assert r.lookup(RI, old_wire) is None
        assert r.lookup(RI, new_wire) == new_visible
        assert r.lookup(RX, new_visible) == new_row
    case("OrphanIndexPreservesForeignReceiver", foreign_rx)

    for direction in (0, 1):
        for field, value in ((88, 0), (88, 2), (88, 0xffffffff), (92, 2), (92, 0xffffffff)):
            def unknown(r, direction=direction, field=field, value=value):
                wire, visible, row = seed(r, age=7201)
                row = bytearray(row)
                struct.pack_into("<I", row, field, value)
                r.update(RX, visible, row)
                held = snapshot(r)
                collect(r, direction, (visible, wire)[direction], 3)
                assert snapshot(r) == held
            case(f"UnknownSchemaDirection{direction}Field{field}Value{value}", unknown)
        def bad_key(r, direction=direction):
            wire, visible, row = seed(r, age=7201)
            row = bytearray(row)
            row[64] ^= 1
            r.update(RX, visible, row)
            held = snapshot(r)
            collect(r, direction, (visible, wire)[direction], 3)
            assert snapshot(r) == held
        case(f"StoredKeyMismatchDirection{direction}", bad_key)

    for endpoint, alias in ((p.CLIENT, n.ALIAS), (p.BACKEND, n.BACK_ALIAS)):
        for byte in range(16):
            for direction in (0, 1):
                def incarnation(r, endpoint=endpoint, alias=alias, byte=byte, direction=direction):
                    wire, visible, _ = seed(r, 6)
                    for address in (endpoint, alias):
                        key = ipaddress.ip_address(address).packed
                        owner = bytearray(r.lookup(n.IDENT, key))
                        owner[8 + byte] ^= 0x80
                        r.update(n.IDENT, key, owner)
                    collect(r, direction, (visible, wire)[direction], 1)
                    assert not r.keys(RX) and not r.keys(RI)
                case(f"Epoch{endpoint}Byte{byte}Direction{direction}", incarnation)

    for direction in (0, 1):
        for lock in (FL, RL, WL):
            def contention(r, direction=direction, lock=lock):
                wire, visible, _ = seed(r, age=181)
                key = wire[48:] if lock == RL else visible
                sentinel = b"\xa5" * 8
                r.update(lock, key, sentinel)
                held = snapshot(r)
                collect(r, direction, (visible, wire)[direction], 2, locks=False)
                assert snapshot(r) == held
                for name in (FL, RL, WL):
                    assert r.keys(name) == ([key] if name == lock else [])
                assert r.lookup(lock, key) == sentinel
                r.delete(lock, key)
                collect(r, direction, (visible, wire)[direction], 1)
            case(f"ContentionDirection{direction}{lock}", contention)

    def invalid(r):
        wire, _, _ = seed(r)
        held = snapshot(r)
        valid = frame(0, wire[48:])
        packets = [valid[:14], valid[:51], valid + b"\0", frame(2, wire)]
        for offset, value in ((12, 0), (14, 0x46), (23, 6), (35, 1), (49, 1), (50, 1)):
            changed = bytearray(valid)
            changed[offset] = value
            packets.append(changed)
        for packet in packets:
            verdict, output = r.run(GC, packet)
            assert verdict == 3 and output == packet
            assert snapshot(r) == held
            unlocked(r)
    case("InvalidControlEnvelope", invalid)

    if not kernel:
        for table in (RX, RI):
            def failure(r, table=table):
                wire, visible, row = seed(r, age=181)
                r.maps.fail_delete = table
                collect(r, 0, visible, 2)
                assert r.lookup(RX, visible) == row
                assert r.lookup(RI, wire) == (visible if table == RI else None)
                collect(r, 0, visible, 1)
                assert not r.keys(RX) and not r.keys(RI)
            case(f"InterpreterDeleteFailure{table}", failure)
    return cases


def capacity(factory, table, direction):
    runner = factory()
    try:
        setup(runner)
        wire, visible, _ = seed(runner, age=181)
        foreign = n.key(p.packet(p.BACKEND, p.CLIENT, 59000, 59001, 17))
        sentinel = b"\x5a" * 8
        runner.update(table, foreign, sentinel)
        held = snapshot(runner)
        collect(runner, direction, (visible, wire)[direction], 2, locks=False)
        assert snapshot(runner) == held
        assert runner.lookup(table, foreign) == sentinel
        for name in (FL, RL, WL):
            assert runner.keys(name) == ([foreign] if name == table else [])
        runner.delete(table, foreign)
        collect(runner, direction, (visible, wire)[direction], 1)
        assert not runner.keys(RX) and not runner.keys(RI)
        return f"Capacity{table}Direction{direction}"
    finally:
        runner.close()


def concurrent_collection(factory):
    runner = factory()
    observed = {0: 0, 1: 0, 2: 0}
    try:
        setup(runner)
        with ThreadPoolExecutor(max_workers=6) as pool:
            for group in range(32):
                protocol = 6 if group % 2 else 17
                wire, visible, _ = seed(runner, protocol, age=7201)
                barrier = threading.Barrier(6)

                def invoke(index):
                    data = frame(index % 2, (visible, wire)[index % 2])
                    barrier.wait(timeout=30)
                    verdict, output = runner.run(GC, data)
                    assert output == data
                    return verdict

                verdicts = list(pool.map(invoke, range(6)))
                assert all(value in observed for value in verdicts), verdicts
                assert verdicts.count(1) == 1, verdicts
                for value in verdicts:
                    observed[value] += 1
                assert not runner.keys(RX) and not runner.keys(RI)
                unlocked(runner)
        return {"groups": 32, "callersPerGroup": 6, "verdicts": observed}
    finally:
        runner.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=(GC,))
    cls = p.Kernel if args.kernel else Interpreter
    cases = exercise(lambda: cls(programs, ids, descriptors), args.kernel)
    small = {name: value[:3] + (1, value[4]) if name in (FL, RL, WL) else value
             for name, value in descriptors.items()}
    cases.extend(capacity(lambda: cls(programs, ids, small), table, direction)
                 for table in (FL, RL, WL) for direction in (0, 1))
    concurrent = concurrent_collection(lambda: cls(programs, ids, descriptors)) if args.kernel else None
    print(json.dumps({"passed": True, "kernel": args.kernel, "cases": cases,
                      "concurrentCollection": concurrent}))


if __name__ == "__main__":
    main()
