#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise the experimental typed Service graph; --kernel is disposable-VM only.

Identities/readiness are fixture inputs. This is not live CNI or socket proof.
"""
import argparse
import json
from pathlib import Path
import struct

import importlib.util


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


graph = load("wire_graph_base", "test-service-nat-guard.py")
wire = load("wire_codec", "test-service-wire.py")
p, n = graph.p, graph.n
EXTRA = ("gr8s_wire_request", "gr8s_wire_reply", "gr8s_wire_receive", "gr8s_wire_reply_commit")
RX, RI, WL = "gr8s_nat_rx_v2", "gr8s_nat_ri_v2", "gr8s_nat_wl_v2"
graph.GLOBAL.update((RX, RI, WL))


class Machine(wire.Machine):
    def call(self, helper):
        if helper != 12:
            return super().call(helper)
        r = self.registers
        pointer = self.maps.lookup(self.maps.names[r[2]], struct.pack("<I", r[3]))
        fd = self.read(pointer, 4) if pointer else 0
        if fd in self.stage_programs and self.tail_count < 33:
            raise graph.g.TailCall(self.stage_programs[fd])
        r[0], r[1:6] = 0, [0xdeadbeef] * 5


class Interpreter(graph.Interpreter):
    def __init__(self, programs, ids, descriptors, shared=None):
        super().__init__(programs, ids, descriptors, shared)
        for index, name in enumerate(EXTRA, 8):
            self.update(graph.TABLE, struct.pack("<I", index), struct.pack("<I", self.program_fds[name]))

    def run(self, name, data, context=n.ZERO):
        self.visited = []
        targets = {fd: name for name, fd in self.program_fds.items()}
        for count in range(34):
            machine = Machine(self.programs[name], self.maps, bytes(data), self.clock)
            machine.memory[0x200000][48:68] = context
            machine.stage_programs, machine.tail_count = targets, count
            self.visited.append(name)
            try:
                verdict = machine.run()
            except graph.g.TailCall as jump:
                name = jump.args[0]
                data = bytes(machine.memory[machine.packet_address])
                context = bytes(machine.memory[0x200000][48:68])
                continue
            except BaseException as error:
                raise AssertionError(f"stage {name}, path {self.visited}") from error
            self.lastcontext = bytes(machine.memory[0x200000][48:68])
            return verdict, bytes(machine.memory[machine.packet_address])
        raise AssertionError("tail-call limit did not fail closed")


class Kernel(graph.Kernel):
    def __init__(self, programs, ids, descriptors, shared=None):
        super().__init__(programs, ids, descriptors, shared)
        for index, name in enumerate(EXTRA, 8):
            self.update(graph.TABLE, struct.pack("<I", index), struct.pack("<I", self.program_fds[name]))


def inner(data):
    return data[102:] if len(data) >= 136 and data[54:58] == b"GR8S" else data


def run(runner, direction, data, expected=p.OK):
    verdict, output = runner.run(graph.ROOTS[direction], data)
    assert verdict == expected, (verdict, expected, runner.visited if hasattr(runner, "visited") else None)
    n.unlocked(runner)
    assert not runner.keys(WL)
    if verdict == p.OK:
        p.check_checksums(output)
        p.check_checksums(inner(output))
        assert runner.lastcontext == n.ZERO
    return output


def setup(client, backend):
    for endpoint in (client, backend):
        n.owner(endpoint, p.CLIENT, n.ALIAS, 1)
        n.owner(endpoint, p.BACKEND, n.BACK_ALIAS, 2)
    graph.configure(client, p.CLIENT, n.ALIAS, 1, graph.CLIENT_MAC)
    graph.configure(backend, p.BACKEND, n.BACK_ALIAS, 2, graph.BACK_MAC)
    for endpoint in (client, backend):
        n.owner(endpoint, p.CLIENT, n.ALIAS, 1, flags=15)
        n.owner(endpoint, p.BACKEND, n.BACK_ALIAS, 2, flags=15)


def crossed(factory, protocol, shared, simultaneous):
    client, backend = factory(), None
    try:
        backend = factory(client if shared else None)
        setup(client, backend)
        p.publish(client, protocol)
        first = graph.packet(protocol=protocol, sport=49000 + protocol)
        first_wire = run(client, 0, first)
        assert len(first_wire) == len(first) + 102
        received_first = None if simultaneous else run(backend, 1, first_wire)
        vip = "10.96.0.99"
        key, value = p.service_key(vip, protocol=protocol), p.backend_value(p.CLIENT, 49000 + protocol)
        backend.update("gr8s_backend_v4", struct.pack("<I", 1), value)
        backend.update("gr8s_backend_index_v4", key + value, struct.pack("<I", 1))
        backend.update("gr8s_service_v4", key, struct.pack("<HHIII", 1, 0, 1, 60, 0))
        second = graph.packet(p.BACKEND, vip, 8080, 80, protocol, seq=9000, mac=graph.BACK_MAC)
        second_wire = run(backend, 0, second)
        if simultaneous:
            received_first = run(backend, 1, first_wire)
        received_second = run(client, 1, second_wire)
        assert p.endpoints(received_first)[0] in (p.CLIENT, n.ALIAS)
        assert p.endpoints(received_second)[0] in (p.BACKEND, n.BACK_ALIAS)
        # Verify actual responses, not only absence of the original bad VIP.
        for server, receiver, received, original, mac, server_seq in (
                (backend, client, received_first, first, graph.BACK_MAC, 30000),
                (client, backend, received_second, second, graph.CLIENT_MAC, 40000)):
            source, destination, sport, dport = p.endpoints(received)
            response = graph.packet(destination, source, dport, sport, protocol,
                                    seq=server_seq, ack=(1001 if server is backend else 9001),
                                    flags=0x12, mac=mac)
            response_wire = run(server, 0, response)
            assert response_wire[59] == 2
            restored = run(receiver, 1, response_wire)
            origin, frontend, origin_port, frontend_port = p.endpoints(original)
            assert p.endpoints(restored) == (frontend, origin, frontend_port, origin_port)
            if protocol == 6:
                ack = graph.packet(origin, frontend, origin_port, frontend_port, protocol,
                                   seq=1001 if receiver is client else 9001,
                                   ack=server_seq + 1, flags=0x10,
                                   mac=graph.CLIENT_MAC if receiver is client else graph.BACK_MAC)
                accepted = run(server, 1, run(receiver, 0, ack))
                assert p.endpoints(accepted) == p.endpoints(received)
        return {"protocol": protocol, "shared": shared, "simultaneous": simultaneous,
                "firstDelivered": p.endpoints(received_first),
                "secondDelivered": p.endpoints(received_second)}
    finally:
        if backend:
            backend.close()
        client.close()


def direct_collision(factory, protocol, shared):
    client, backend = factory(), None
    try:
        backend = factory(client if shared else None)
        setup(client, backend)
        direct = graph.packet(p.BACKEND, p.CLIENT, 8080, 48000 + protocol, protocol,
                              seq=9000, mac=graph.BACK_MAC)
        assert run(backend, 0, direct) == direct
        active_direct = direct
        if protocol == 6:
            assert run(client, 1, direct) == direct
            syn_ack = graph.packet(p.CLIENT, p.BACKEND, 48006, 8080, 6,
                                   seq=20000, ack=9001, flags=0x12)
            assert run(backend, 1, run(client, 0, syn_ack)) == syn_ack
            ack = graph.packet(p.BACKEND, p.CLIENT, 8080, 48006, 6,
                               seq=9001, ack=20001, flags=0x10, mac=graph.BACK_MAC)
            assert run(client, 1, run(backend, 0, ack)) == ack
            active_direct = p.packet(p.BACKEND, p.CLIENT, 8080, 48006, 6,
                                     tcp_flags=0x18, seq=9001, ack=20001, payload=b"still-direct")
            active_direct = active_direct[:6] + graph.BACK_MAC + active_direct[12:]
        held = backend.lookup(n.FWD, n.key(direct))
        p.publish(client, protocol)
        original = graph.packet(protocol=protocol, sport=48000 + protocol)
        encoded = run(client, 0, original)
        visible = run(backend, 1, encoded)
        assert p.endpoints(visible) == (n.ALIAS, p.BACKEND, 48000 + protocol, 8080)
        assert backend.lookup(n.FWD, n.key(direct)) == held
        response = graph.packet(p.BACKEND, n.ALIAS, 8080, 48000 + protocol, protocol,
                                seq=30000, ack=1001, flags=0x12, mac=graph.BACK_MAC)
        restored = run(client, 1, run(backend, 0, response))
        assert p.endpoints(restored) == (p.VIP, p.CLIENT, 80, 48000 + protocol)
        # Plain traffic on the original direct connection must keep its source;
        # it cannot borrow the Service's frontend or mutate its TCP generation.
        backend.advance(1)
        seen = struct.unpack_from("<Q", backend.lookup(n.FWD, n.key(direct)), 8)[0]
        plain = run(backend, 0, active_direct)
        assert plain == active_direct
        assert run(client, 1, plain) == active_direct
        assert struct.unpack_from("<Q", backend.lookup(n.FWD, n.key(direct)), 8)[0] > seen
        return {"case": "receiverDirectCollision", "protocol": protocol, "shared": shared}
    finally:
        if backend:
            backend.close()
        client.close()


def denied_and_stale(factory, protocol, shared):
    client, backend = factory(), None
    try:
        backend = factory(client if shared else None)
        setup(client, backend)
        p.publish(client, protocol)
        original = graph.packet(protocol=protocol, sport=47000 + protocol)
        graph.mode(client, 0, 1)
        run(client, 0, original, p.SHOT)
        assert client.lookup(n.FWD, n.key(original))[39] == 0
        assert not client.keys(RX) and not client.keys(RI)
        graph.mode(client, 0, 0)
        encoded = run(client, 0, original)
        graph.mode(backend, 1, 1)
        graph.mode(backend, 0, 1)
        run(backend, 1, encoded, p.SHOT)
        assert not backend.keys(RX) and not backend.keys(RI)
        response = graph.packet(p.BACKEND, p.CLIENT, 8080, 47000 + protocol, protocol,
                                seq=30000, ack=1001, flags=0x12, mac=graph.BACK_MAC)
        run(backend, 0, response, p.SHOT)
        assert not backend.keys(RX) and not backend.keys(RI)
        # Every epoch byte is checked before policy can create a reply exception.
        flows = {key: backend.lookup("netpol_flows_v2", key) for key in backend.keys("netpol_flows_v2")}
        for offset in range(70, 102):
            stale = bytearray(encoded)
            stale[offset] ^= 1
            run(backend, 1, stale, p.SHOT)
            assert {key: backend.lookup("netpol_flows_v2", key)
                    for key in backend.keys("netpol_flows_v2")} == flows
        run(client, 0, encoded, p.SHOT)  # A Pod cannot inject a reserved envelope.
        assert not backend.keys(RX) and not backend.keys(RI)
        graph.allow(backend, "ingress", p.CLIENT, protocol, 8080)
        visible = run(backend, 1, encoded)
        source, destination, sport, dport = p.endpoints(visible)
        response = graph.packet(destination, source, dport, sport, protocol,
                                seq=30000, ack=1001, flags=0x12, mac=graph.BACK_MAC)
        restored = run(client, 1, run(backend, 0, response))
        assert p.endpoints(restored) == (p.VIP, p.CLIENT, 80, 47000 + protocol)
        return {"case": "denialAndStaleEpoch", "protocol": protocol, "shared": shared,
                "epochByteFaults": 32}
    finally:
        if backend:
            backend.close()
        client.close()


def capacity(factory, table):
    client, backend = factory(), factory()
    try:
        setup(client, backend)
        p.publish(client, 17)
        original = graph.packet(protocol=17, sport=46017)
        encoded = run(client, 0, original)
        foreign_key = n.key(graph.packet(p.BACKEND, p.CLIENT, 59999, 59998, 17))
        size = backend.descriptors[table][2] if hasattr(backend, "descriptors") else backend.maps.descriptors[table][2]
        sentinel = bytes([0xa5]) * size
        backend.update(table, foreign_key, sentinel)
        verdict, _ = backend.run(graph.ROOTS[1], encoded)
        assert verdict == p.SHOT
        n.unlocked(backend)
        assert backend.lookup(table, foreign_key) == sentinel
        for other in (RX, RI, WL):
            assert backend.keys(other) == ([foreign_key] if other == table else [])
        backend.delete(table, foreign_key)
        visible = run(backend, 1, encoded)
        assert p.endpoints(visible) == (p.CLIENT, p.BACKEND, 46017, 8080)
        response = graph.packet(p.BACKEND, p.CLIENT, 8080, 46017, 17, mac=graph.BACK_MAC)
        restored = run(client, 1, run(backend, 0, response))
        assert p.endpoints(restored) == (p.VIP, p.CLIENT, 80, 46017)
        return {"case": "capacityRecovery", "table": table}
    finally:
        backend.close()
        client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=graph.ROOTS + graph.STAGES + EXTRA + ("gr8s_nat_gc",))
    cls = Kernel if args.kernel else Interpreter
    factory = lambda shared=None: cls(programs, ids, descriptors, shared)
    cases = [crossed(factory, protocol, shared, simultaneous)
             for protocol in (6, 17) for shared in (True, False) for simultaneous in (False, True)]
    cases.extend(direct_collision(factory, protocol, shared)
                 for protocol in (6, 17) for shared in (True, False))
    cases.extend(denied_and_stale(factory, protocol, shared)
                 for protocol in (6, 17) for shared in (True, False))
    small = {key: value[:3] + (1, value[4]) if key in (RX, RI, WL) else value
             for key, value in descriptors.items()}
    cases.extend(capacity(lambda: cls(programs, ids, small), table) for table in (RX, RI, WL))
    print(json.dumps({"passed": True, "kernel": args.kernel, "cases": cases}))


if __name__ == "__main__":
    main()
