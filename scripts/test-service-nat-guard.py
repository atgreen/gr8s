#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise the complete v2 guard graph with real tail calls and endpoint maps.

--kernel requires a disposable root VM. Identity/capability rows are seeded by
the fixture; these are synthetic packets, not attached CNI/guest/socket proof.
"""
import argparse
import ctypes
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import struct


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


n = load("nat", "test-service-nat.py")
g = load("guard", "test-service-packet-guard.py")
p, e = n.packet, n.packet.endpoint
ROOTS = ("gr8s_egress_guard", "gr8s_ingress_guard")
STAGES = ("gr8s_nat_generation", "gr8s_nat_select", "gr8s_v2_eg_policy",
          "gr8s_nat_commit", "gr8s_nat_deliver", "gr8s_nat_prepare",
          "gr8s_v2_in_policy", "gr8s_nat_restore")
TABLE = "gr8s_nat_stages"
GLOBAL = {"gr8s_service_v4", "gr8s_backend_v4", "gr8s_backend_index_v4", "gr8s_pkt_affinity",
          n.FWD, n.REV, n.IDENT, "gr8s_nat_fl_v2", "gr8s_nat_rl_v2", "gr8s_nat_tcp_v2",
          "gr8s_nat_st_v2", "gr8s_nat_pod_v2"}
CLIENT_MAC, BACK_MAC = bytes.fromhex("020000000002"), bytes.fromhex("020000000003")


class Space:
    def __init__(self):
        self.memory, self.globals, self.clock = {}, {}, [1_000_000_000]
        self.next_address = 0x400000


class Maps(e.Maps):
    def __init__(self, ids, descriptors, space):
        self.space = space
        super().__init__(ids, descriptors, space.memory)
        for name in GLOBAL:
            if name in space.globals:
                self.entries[name] = space.globals[name]
            else:
                space.globals[name] = self.entries[name]

    def allocate(self, size):
        address = self.space.next_address
        self.space.next_address += max(0x100, (size + 0xff) & ~0xff)
        self.memory[address] = bytearray(size)
        return address


class Interpreter(n.Interpreter):
    def __init__(self, programs, ids, descriptors, shared=None):
        self.space = shared.space if shared else Space()
        self.programs, self.memory, self.clock = programs, self.space.memory, self.space.clock
        self.maps = Maps(ids, descriptors, self.space)
        self.program_fds = {name: 500 + index for index, name in enumerate(programs)}

    def run(self, name, data, context=n.ZERO):
        self.visited = []
        targets = {fd: name for name, fd in self.program_fds.items()}
        for count in range(34):
            machine = g.GuardMachine(self.programs[name], self.maps, bytes(data), self.clock)
            machine.memory[0x200000][48:68] = context
            machine.stage_programs, machine.tail_count = targets, count
            self.visited.append(name)
            try:
                verdict = machine.run()
            except g.TailCall as jump:
                name = jump.args[0]
                data = bytes(machine.memory[0x100000])
                context = bytes(machine.memory[0x200000][48:68])
                continue
            except BaseException as error:
                raise AssertionError(f"stage {name}, path {self.visited}") from error
            self.lastcontext = bytes(machine.memory[0x200000][48:68])
            return verdict, bytes(machine.memory[0x100000])
        raise AssertionError("tail-call limit did not fail closed")


class Kernel(n.Kernel):
    def __init__(self, programs, ids, descriptors, shared=None):
        self.map_order = iter(descriptors)
        self.shared = {name: shared.map_fds[name] for name in GLOBAL} if shared else {}
        super().__init__(programs, ids, descriptors)

    def bpf(self, command, attr):
        if command == 0:
            name = next(self.map_order)
            if name in self.shared:
                return os.dup(self.shared[name])
        return super().bpf(command, attr)

    def run(self, name, data, context=n.ZERO):
        verdict, output, self.lastcontext = self.stage_raw(name, data, context)
        return verdict, output


def configure(runner, primary, alias, epoch, mac, mode=2):
    n.owner(runner, primary, alias, epoch)
    value = struct.pack("<IIII", int(ipaddress.ip_address(primary)),
                        int.from_bytes(mac[:4], "big"), int.from_bytes(mac[4:], "big"), mode)
    runner.update("endpoint_identity", bytes(4), value + bytes(16) + struct.pack("<QQ", epoch, epoch + 100))
    runner.update("gr8s_nat_pod_v2", e.cidr_key("10.88.0.0/16"), b"\x01")
    for index, name in enumerate(STAGES):
        runner.update(TABLE, struct.pack("<I", index), struct.pack("<I", runner.program_fds[name]))


def mode(runner, direction, enabled):
    runner.update("netpol_mode", struct.pack("<I", direction), struct.pack("<I", enabled))


def allow(runner, direction, peer, protocol, port, group=1):
    runner.update(f"netpol_{direction}_cidr", e.cidr_key(peer + "/32"), struct.pack("<I", group))
    runner.update(f"netpol_{direction}_ports", e.port_key(group, protocol, port), b"\x01")


def packet(source=p.CLIENT, destination=p.VIP, sport=40000, dport=80, protocol=6,
           seq=1000, ack=0, flags=2, mac=CLIENT_MAC):
    data = p.packet(source, destination, sport, dport, protocol, seq=seq, ack=ack,
                    tcp_flags=flags, payload=b"")
    return data[:6] + mac + data[12:]


def run(runner, direction, data, expected=p.OK, context=n.ZERO):
    verdict, output = runner.run(ROOTS[direction], data, context)
    assert verdict == expected, (ROOTS[direction], verdict, expected, p.endpoints(data))
    n.unlocked(runner)
    if verdict in (p.OK, 7):
        p.check_checksums(output)
        assert runner.lastcontext == n.ZERO
    return output


def exchange(client, backend, original, expected_snat=False, server_seq=9000):
    wire = run(client, 0, original)
    assert (p.endpoints(wire)[0] == n.ALIAS) == expected_snat
    received = run(backend, 1, wire)
    assert received == wire
    source, destination, sport, dport = p.endpoints(wire)
    response = packet(destination, source, dport, sport, wire[23], server_seq,
                      struct.unpack_from("!I", original, 38)[0] + 1 if wire[23] == 6 else 0,
                      0x12, BACK_MAC if backend is not client else CLIENT_MAC)
    outgoing = run(backend, 0, response)
    assert outgoing == response
    restored = run(client, 1, outgoing)
    original_source, vip, original_sport, original_dport = p.endpoints(original)
    assert p.endpoints(restored) == (vip, original_source, original_dport, original_sport)
    if wire[23] == 6:
        seq = struct.unpack_from("!I", original, 38)[0] + 1
        ack = packet(original_source, vip, original_sport, original_dport, 6,
                     seq=seq, ack=server_seq + 1, flags=0x10)
        committed = run(client, 0, ack)
        assert p.endpoints(committed) == p.endpoints(wire)
        assert run(backend, 1, committed) == committed
    return wire


def exercise(client, backend):
    cases = []
    for endpoint in (client, backend):
        mode(endpoint, 0, 1)
        mode(endpoint, 1, 1)
    for protocol in (6, 17):
        p.publish(client, protocol)
        data = packet(protocol=protocol, sport=42000 + protocol)
        run(client, 0, data, p.SHOT)
        pending = client.lookup(n.FWD, n.key(data))
        assert pending[39] == 0
        cases.append(f"protocol{protocol}EgressDenyDoesNotCommit")
        allow(client, "egress", p.BACKEND, protocol, 8080)
        allow(backend, "ingress", p.CLIENT, protocol, 8080)
        first = packet(protocol=protocol, sport=43000 + protocol)
        wire = exchange(client, backend, first)
        cases.append(f"protocol{protocol}PolicySeesBackendBeforeVIPRestoration")
        vip = "10.96.0.61"
        p.publish(client, protocol, vip=vip)
        second = packet(destination=vip, protocol=protocol, sport=43000 + protocol, seq=2000)
        alias_wire = exchange(client, backend, second, True, 10000)
        assert p.endpoints(alias_wire) != p.endpoints(wire)
        cases.append(f"protocol{protocol}AliasMatchesCanonicalPolicyAndReplies")
        direct = packet(destination=p.BACKEND, dport=8080, protocol=protocol,
                        sport=43000 + protocol, seq=3000)
        direct_wire = exchange(client, backend, direct, True, 11000)
        assert p.endpoints(direct_wire) != p.endpoints(alias_wire)
        cases.append(f"protocol{protocol}DirectAndServiceReturnTuplesStaySeparate")
        # A self backend must work through the same default-deny guards, using
        # its validated self exception rather than another Pod's reply state.
        p.publish(client, protocol, vip="10.96.0.62", backend=p.CLIENT)
        hairpin = packet(destination="10.96.0.62", protocol=protocol, sport=44000 + protocol)
        exchange(client, client, hairpin, True, 12000)
        cases.append(f"protocol{protocol}HairpinThroughDefaultDeny")
    spoof = packet(source="10.88.0.99", sport=45000)
    run(client, 0, spoof, p.SHOT)
    assert client.lookup(n.FWD, n.key(spoof)) is None
    cases.append("sourceSpoofCannotPublishNATState")
    # MAC spoof rejection must also happen before destination selection.
    spoof = packet(sport=45001, mac=BACK_MAC)
    run(client, 0, spoof, p.SHOT)
    assert client.lookup(n.FWD, n.key(spoof)) is None
    cases.append("MACSpoofCannotPublishNATState")
    return cases


def missing_stages(client):
    cases = []
    p.publish(client, 17)
    mode(client, 0, 0)
    mode(client, 1, 0)
    original = packet(protocol=17, sport=46000)
    wire = run(client, 0, original)
    source, backend, sport, dport = p.endpoints(wire)
    response = packet(backend, source, dport, sport, 17, mac=BACK_MAC)
    forged = n.key(original) + struct.pack("<I", 0x47523802)
    for index, name in enumerate(STAGES):
        client.delete(TABLE, struct.pack("<I", index))
        data = response if index >= 5 else packet(protocol=17, sport=46100 + index)
        run(client, int(index >= 5), data, p.SHOT, forged)
        if index == 0:
            assert client.lastcontext == n.ZERO
        client.update(TABLE, struct.pack("<I", index), struct.pack("<I", client.program_fds[name]))
        cases.append(f"missingStage{index}FailsClosed")
    # A mispopulated continuation cannot turn the tail-call limit into allow.
    client.update(TABLE, struct.pack("<I", 3), struct.pack("<I", client.program_fds[STAGES[2]]))
    run(client, 0, packet(protocol=17, sport=46200), p.SHOT)
    client.update(TABLE, struct.pack("<I", 3), struct.pack("<I", client.program_fds[STAGES[3]]))
    cases.append("tailCallLimitFailsClosed")
    for direction in (0, 1):
        data = bytearray(packet(protocol=17, sport=46300 + direction))
        if direction:
            data = bytearray(response)
        struct.pack_into("!H", data, 20, 0x2000)
        struct.pack_into("!H", data, 24, 0)
        struct.pack_into("!H", data, 24, p.checksum(bytes(data[14:34])))
        run(client, direction, data, p.SHOT)
    cases.append("fragmentsCannotEscapeTupleOwnershipOrPortPolicy")
    return cases


def backend_exception(client, backend):
    p.publish(client, 17)
    n.owner(client, p.CLIENT, n.ALIAS, 1, flags=5)
    backend.update("netpol_ingress_cidr", e.cidr_key("0.0.0.0/0"), struct.pack("<I", 2))
    backend.update("netpol_ingress_ports", e.port_key(2), b"\x01")
    backend.update("netpol_ingress_cidr", e.cidr_key(p.CLIENT + "/32"), bytes(4))
    original = packet(protocol=17, sport=49400)
    wire = run(client, 0, original)
    assert p.endpoints(wire)[0] == n.ALIAS
    run(backend, 1, wire, p.SHOT)
    source, target, sport, dport = p.endpoints(wire)
    response = packet(target, source, dport, sport, 17, mac=BACK_MAC)
    run(backend, 0, response, p.SHOT)
    n.owner(client, p.CLIENT, n.ALIAS, 1)
    return ["backendIPBlockExceptMatchesCanonicalSourceAfterSNAT",
            "deniedAliasRequestCannotAuthorizeBackendReply"]


def delivery(client):
    configure(client, p.CLIENT, n.ALIAS, 1, CLIENT_MAC, mode=1)
    mode(client, 0, 0)
    mode(client, 1, 0)
    p.publish(client, 17)
    client.update("local_pod_v4", e.cidr_key(p.BACKEND + "/32"),
                  struct.pack("<I", 7) + bytes.fromhex("020000000003020000000004"))
    first = packet(protocol=17, sport=47000)
    run(client, 0, first, 7)
    p.publish(client, 17, vip="10.96.0.71")
    second = packet(destination="10.96.0.71", protocol=17, sport=47000)
    wire = run(client, 0, second, 7)
    assert p.endpoints(wire)[0] == n.ALIAS
    assert wire[:12] == bytes.fromhex("020000000003020000000004")
    state = client.lookup(n.FWD, n.key(second))
    assert state[39] == 1
    dns = packet(destination="169.254.1.1", dport=53, protocol=17, sport=47001)
    outgoing = run(client, 0, dns, 7)
    assert outgoing[:6] == bytes(6)
    assert client.lookup(n.FWD, n.key(dns))[39] == 1
    return ["sameNodeDeliveryHappensAfterSourceCommit", "nodeDNSRedirectCannotSkipCommit"]


def epoch_fence(old, factory):
    """Invoke paused stages after ownership changes, with a stale local map."""
    new = factory(old)
    cases = []
    try:
        configure(new, p.CLIENT, n.ALIAS, 9, CLIENT_MAC)
        n.owner(new, p.CLIENT, n.ALIAS, 9, flags=5)  # Conservative upgrade history.
        assert old.lookup("endpoint_identity", bytes(4))[32:] == struct.pack("<QQ", 1, 101)
        assert new.lookup("endpoint_identity", bytes(4))[32:] == struct.pack("<QQ", 9, 109)
        p.publish(new, 17)
        original = packet(protocol=17, sport=48000)
        wire = run(new, 0, original)
        assert p.endpoints(wire)[0] == n.ALIAS
        key = n.key(original)
        snapshot = new.lookup(n.FWD, key)
        source, backend, sport, dport = p.endpoints(wire)
        response = packet(backend, source, dport, sport, 17, mac=BACK_MAC)
        selected = packet(p.CLIENT, p.BACKEND, 48000, 8080, 17)
        prepared = packet(p.BACKEND, p.CLIENT, 8080, 48000, 17, mac=BACK_MAC)
        request_context = key + struct.pack("<I", 0x47523801)
        reply_context = key + struct.pack("<I", 0x47523802)
        for name, data, context in ((STAGES[1], original, n.ZERO),
                                    (STAGES[3], selected, request_context),
                                    (STAGES[5], response, n.ZERO),
                                    (STAGES[7], prepared, reply_context)):
            verdict, output = old.run(name, data, context)
            assert verdict == p.SHOT, ("stale local epoch accepted", name)
            assert output == data, ("stale endpoint modified packet", name)
            assert new.lookup(n.FWD, key) == snapshot
            n.unlocked(new)
            cases.append(name + "FencesStaleLocalEpoch")
        fresh = packet(protocol=17, sport=48001)
        verdict, _ = old.run(STAGES[1], fresh)
        assert verdict == p.SHOT
        assert new.lookup(n.FWD, n.key(fresh)) is None
        cases.append("oldEndpointCannotPublishReplacementOwnerClaim")
        p.publish(new, 6)
        syn = packet(sport=48002)
        run(new, 0, syn)
        tcp_original = n.key(syn)
        tcp_key = tcp_original + struct.pack("<QQ", 9, 109)
        held = new.lookup(n.FWD, tcp_original)
        metadata = new.lookup("gr8s_nat_tcp_v2", tcp_key)
        verdict, _ = old.run(STAGES[0], packet(sport=48002, seq=5000))
        assert verdict == p.SHOT
        assert new.lookup(n.FWD, tcp_original) == held
        assert new.lookup("gr8s_nat_tcp_v2", tcp_key) == metadata
        n.unlocked(new)
        run(new, 0, syn)
        cases.append("oldEndpointCannotRetireReplacementTCPGeneration")
        return cases
    finally:
        new.close()


def pinned_lifetime(runner):
    """A table pin must hold all eight continuations after loader FDs close."""
    directory = Path("/sys/fs/bpf") / f"gr8s_nat_graph_{os.getpid()}"
    directory.mkdir()
    pin = directory / "stages"
    try:
        filename = ctypes.create_string_buffer(str(pin).encode())
        table_fd = runner.map_fds[TABLE]
        runner.bpf(6, struct.pack("<QII", ctypes.addressof(filename), table_fd, 0))
        for fd in [table_fd, *(runner.program_fds[name] for name in STAGES)]:
            os.close(fd)
            runner.fds.remove(fd)
        p.publish(runner, 17)
        first = packet(protocol=17, sport=49500)
        run(runner, 0, first)
        p.publish(runner, 17, vip="10.96.0.81")
        second = packet(destination="10.96.0.81", protocol=17, sport=49500)
        wire = run(runner, 0, second)
        assert p.endpoints(wire)[0] == n.ALIAS
        source, backend, sport, dport = p.endpoints(wire)
        response = packet(backend, source, dport, sport, 17, mac=BACK_MAC)
        restored = run(runner, 1, response)
        assert p.endpoints(restored) == ("10.96.0.81", p.CLIENT, 80, 49500)
        return ["pinnedTableRetainsClosedContinuationFDs", "pinnedTableKeepsReversePolicyAndRestoration"]
    finally:
        pin.unlink(missing_ok=True)
        directory.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=ROOTS + STAGES + ("gr8s_nat_gc",))
    assert len(descriptors) == 29
    assert descriptors[TABLE] == (3, 4, 4, 16, 0)
    results = {}
    cls = Kernel if args.kernel else Interpreter
    for shared in (True, False):
        client = cls(programs, ids, descriptors)
        backend = None
        try:
            backend = cls(programs, ids, descriptors, client if shared else None)
            for endpoint in (client, backend):
                n.owner(endpoint, p.CLIENT, n.ALIAS, 1)
                n.owner(endpoint, p.BACKEND, n.BACK_ALIAS, 2)
            configure(client, p.CLIENT, n.ALIAS, 1, CLIENT_MAC)
            configure(backend, p.BACKEND, n.BACK_ALIAS, 2, BACK_MAC)
            results["sameNode" if shared else "separateNodeState"] = exercise(client, backend)
            if shared:
                results["backendException"] = backend_exception(client, backend)
                results["missingStages"] = missing_stages(client)
                results["delivery"] = delivery(client)
                results["localEpoch"] = epoch_fence(
                    client, lambda shared: cls(programs, ids, descriptors, shared))
        finally:
            if backend:
                backend.close()
            client.close()
    if args.kernel:
        runner = cls(programs, ids, descriptors)
        try:
            n.owner(runner, p.BACKEND, n.BACK_ALIAS, 2)
            configure(runner, p.CLIENT, n.ALIAS, 1, CLIENT_MAC)
            results["pinnedLifetime"] = pinned_lifetime(runner)
        finally:
            runner.close()
    print(json.dumps({"passed": True, "kernel": args.kernel, "cases": results}))


if __name__ == "__main__":
    main()
