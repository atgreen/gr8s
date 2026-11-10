#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Test the standalone ABI-v2 staged NAT bytecode; --kernel is disposable-VM root only.

Policy is modeled by choosing whether to run commit/restore. This is not an
agent/CNI/NetworkPolicy integration or full TCP lifecycle/GC proof.
"""
import argparse
import ctypes
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("packet_test", Path(__file__).with_name("test-service-packet-program.py"))
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)
NAMES = ("gr8s_nat_select", "gr8s_nat_commit", "gr8s_nat_prepare", "gr8s_nat_restore")
FWD, REV, IDENT = "gr8s_nat_fwd_v2", "gr8s_nat_rev_v2", "gr8s_nat_id_v2"
CLIENT, ALIAS, BACKEND, BACK_ALIAS = packet.CLIENT, "10.88.0.9", packet.BACKEND, "10.88.1.9"
ZERO = bytes(20)


class Interpreter(packet.Interpreter):
    def stage(self, name, data, context=ZERO):
        machine = packet.PacketMachine(self.programs[name], self.maps, data, self.clock)
        machine.memory[0x200000][48:68] = context
        verdict = machine.run()
        return verdict, bytes(machine.memory[0x100000]), bytes(machine.memory[0x200000][48:68])


class Kernel(packet.Kernel):
    def stage(self, name, data, context=ZERO):
        incoming, outgoing = ctypes.create_string_buffer(data), ctypes.create_string_buffer(len(data) + 256)
        ctx_in, ctx_out = ctypes.create_string_buffer(192), ctypes.create_string_buffer(192)
        ctypes.memmove(ctypes.addressof(ctx_in) + 48, context, 20)
        attr = ctypes.create_string_buffer(struct.pack(
            "<IIIIQQIIIIQQIIII", self.program_fds[name], 0, len(data), len(outgoing),
            ctypes.addressof(incoming), ctypes.addressof(outgoing), 1, 0, 192, 192,
            ctypes.addressof(ctx_in), ctypes.addressof(ctx_out), 0, 0, 0, 0))
        result = self.libc.syscall(self.syscall_number, 10, ctypes.byref(attr), 80)
        if result < 0:
            raise OSError(ctypes.get_errno(), "BPF_PROG_TEST_RUN with skb context")
        verdict, size = struct.unpack_from("<I", attr.raw, 4)[0], struct.unpack_from("<I", attr.raw, 12)[0]
        return verdict, outgoing.raw[:size], ctx_out.raw[48:68]

    def advance(self, seconds):
        for key in self.keys(FWD):
            value = bytearray(self.lookup(FWD, key))
            stamp = struct.unpack_from("<Q", value, 8)[0]
            struct.pack_into("<Q", value, 8, (stamp - int(seconds * 1e9)) & packet.endpoint.MASK)
            self.update(FWD, key, value)


def owner(runner, primary, alias, epoch, flags=7):
    for address, role in ((primary, 1), (alias, 2)):
        value = (ipaddress.ip_address(alias).packed + struct.pack("<IQQ", 0x20000 | flags, epoch, epoch + 100) +
                 ipaddress.ip_address(primary).packed + struct.pack("<I", role))
        runner.update(IDENT, ipaddress.ip_address(address).packed, value)


def key(data):
    source, destination, sport, dport = packet.endpoints(data)
    return (ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed +
            struct.pack("!HH", sport, dport) + bytes([data[23], 0, 0, 0]))


def unlocked(runner):
    for name in ("gr8s_nat_fl_v2", "gr8s_nat_rl_v2"):
        entries = list(runner.maps.entries[name]) if isinstance(runner, Interpreter) else runner.keys(name)
        assert not entries, ("leaked tuple reservations", name, entries)


def exercise(runner):
    cases = 0
    owner(runner, CLIENT, ALIAS, 1)
    owner(runner, BACKEND, BACK_ALIAS, 2)

    def stage(name, data, context=ZERO, verdict=packet.OK):
        result, output, outgoing_context = runner.stage(name, data, context)
        assert result == verdict, (name, result, verdict, packet.endpoints(data))
        unlocked(runner)
        if verdict == packet.OK:
            packet.check_checksums(output)
        return output, outgoing_context

    def forward(data, snat=False):
        selected, context = stage(NAMES[0], data)
        assert packet.endpoints(selected)[0::2] == packet.endpoints(data)[0::2], "pre-policy source changed"
        assert context != ZERO
        committed, context = stage(NAMES[1], selected, context)
        assert context == ZERO
        assert (packet.endpoints(committed)[0] == ALIAS) == snat, packet.endpoints(committed)
        return committed

    def reply(request, original, expected_source, expected_port):
        source, destination, sport, dport = packet.endpoints(request)
        response = packet.packet(destination, source, dport, sport, request[23])
        # A local backend's response must pass its outbound stages unchanged.
        outgoing, context = stage(NAMES[0], response)
        assert outgoing == response and context == ZERO
        outgoing, context = stage(NAMES[1], outgoing, context)
        assert outgoing == response and context == ZERO
        prepared, context = stage(NAMES[2], response)
        assert packet.endpoints(prepared) == (destination, CLIENT, dport, packet.endpoints(original)[2])
        assert context != ZERO, "missing validated return context"
        restored, context = stage(NAMES[3], prepared, context)
        assert packet.endpoints(restored) == (expected_source, CLIENT, expected_port, packet.endpoints(original)[2])
        assert context == ZERO
        return restored

    for protocol in (6, 17):
        packet.publish(runner, protocol)
        first = packet.packet(protocol=protocol, sport=40000)
        wire_a = forward(first)
        reply(wire_a, first, packet.VIP, 80)
        cases += 1
        # Three VIP/direct associations sharing the same client port/backend.
        for index, vip in enumerate(("10.96.0.11", "10.96.0.12")):
            packet.publish(runner, protocol, vip=vip)
            original = packet.packet(destination=vip, sport=40000, protocol=protocol)
            wire = forward(original, snat=True)
            if index:
                assert packet.endpoints(wire) != packet.endpoints(wire_b)
            else:
                wire_b = wire
            reply(wire, original, vip, 80)
            cases += 1
        direct = packet.packet(destination=BACKEND, dport=8080, sport=40000, protocol=protocol)
        wire = forward(direct, snat=True)
        reply(wire, direct, BACKEND, 8080)
        reply(wire_a, first, packet.VIP, 80)
        cases += 1
        # Protect direct traffic that arrived before the colliding Service.
        direct = packet.packet(destination=BACKEND, dport=8080, sport=41000, protocol=protocol)
        wire_direct = forward(direct)
        packet.publish(runner, protocol, vip="10.96.0.13")
        original = packet.packet(destination="10.96.0.13", sport=41000, protocol=protocol)
        wire = forward(original, snat=True)
        reply(wire, original, "10.96.0.13", 80)
        reply(wire_direct, direct, BACKEND, 8080)
        cases += 1
        # Hairpin requires alias source even with complete direct-flow history.
        packet.publish(runner, protocol, vip="10.96.0.14", backend=CLIENT)
        original = packet.packet(destination="10.96.0.14", sport=42000, protocol=protocol)
        wire = forward(original, snat=True)
        assert packet.endpoints(wire)[1] == CLIENT
        reply(wire, original, "10.96.0.14", 80)
        cases += 1
        # No policy commit means no active reply and no lifetime refresh.
        packet.publish(runner, protocol, vip="10.96.0.15")
        original = packet.packet(destination="10.96.0.15", sport=43000, protocol=protocol)
        selected, context = stage(NAMES[0], original)
        state = runner.lookup(FWD, key(original))
        assert state[39] == 0
        response = packet.packet(BACKEND, CLIENT, 8080, 43000, protocol)
        stage(NAMES[2], response, verdict=packet.SHOT)
        stage(NAMES[0], original)
        assert runner.lookup(FWD, key(original))[8:16] == state[8:16]
        runner.advance(6)
        wire = forward(original)
        reply(wire, original, "10.96.0.15", 80)
        cases += 1
        # Unknown/stale context cannot be committed.
        stage(NAMES[1], selected, bytes(16) + struct.pack("<I", 123), verdict=packet.SHOT)
        cases += 1

    # UDP zero checksum and IPv4 options remain correct through both rewrites.
    packet.publish(runner, 17, vip="10.96.0.20", backend=CLIENT)
    original = packet.packet(destination="10.96.0.20", sport=45000, protocol=17,
                             options=bytes.fromhex("01010100"), udp_zero=True)
    wire = forward(original, snat=True)
    assert wire[44:46] == bytes(2)
    reply(wire, original, "10.96.0.20", 80)
    cases += 1
    # A receiver without alias-aware capability must not receive translated traffic.
    owner(runner, CLIENT, ALIAS, 1, flags=3)
    original = packet.packet(destination="10.96.0.20", sport=45001, protocol=17)
    stage(NAMES[0], original, verdict=packet.SHOT)
    owner(runner, CLIENT, ALIAS, 1)
    wire = forward(original, snat=True)
    owner(runner, CLIENT, ALIAS, 9)
    response = packet.packet(CLIENT, ALIAS, 8080, packet.endpoints(wire)[2], 17)
    stage(NAMES[2], response, verdict=packet.SHOT)
    # An interrupted forward publication cannot authorize a return translation.
    packet.publish(runner, 17, vip="10.96.0.21")
    original = packet.packet(destination="10.96.0.21", sport=46000, protocol=17)
    selected, context = stage(NAMES[0], original)
    saved = runner.lookup(FWD, key(original))
    runner.delete(FWD, key(original))
    stage(NAMES[1], selected, context, verdict=packet.SHOT)
    runner.update(FWD, key(original), saved)
    wire = forward(original)
    reply(wire, original, "10.96.0.21", 80)
    cases += 2
    # Affinity must retain a valid member, never a foreign slot after repacking.
    peer, peer_alias, vip = "10.88.2.4", "10.88.2.9", "10.96.0.22"
    owner(runner, peer, peer_alias, 3)
    service = packet.service_key(vip, protocol=17)
    backend_a, backend_b = packet.backend_value(), packet.backend_value(peer)
    runner.update("gr8s_backend_v4", struct.pack("<I", 0), backend_a)
    runner.update("gr8s_backend_v4", struct.pack("<I", 1), backend_b)
    for index, backend in enumerate((backend_a, backend_b)):
        runner.update("gr8s_backend_index_v4", service + backend, struct.pack("<I", index))
    runner.update("gr8s_service_v4", service, struct.pack("<HHIII", 2, 1, 0, 60, 0))
    stamp = struct.unpack_from("<Q", runner.lookup(FWD, key(original)), 8)[0] // 1_000_000_000
    affinity_key = service + ipaddress.ip_address(CLIENT).packed + bytes(4)
    runner.update("gr8s_pkt_affinity", affinity_key, backend_b + struct.pack("<Q", stamp))
    original = packet.packet(destination=vip, sport=47000, protocol=17)
    wire = forward(original)
    assert packet.endpoints(wire)[1] == peer
    reply(wire, original, vip, 80)
    runner.update("gr8s_backend_v4", struct.pack("<I", 1), packet.backend_value("10.88.3.5"))
    stage(NAMES[0], packet.packet(destination=vip, sport=47001, protocol=17), verdict=packet.SHOT)
    assert packet.endpoints(forward(original))[1] == peer, "established backend changed with slots"
    cases += 2
    # Old endpoints without complete direct history must conservatively use aliases.
    owner(runner, CLIENT, ALIAS, 9, flags=5)
    packet.publish(runner, 17, vip="10.96.0.23")
    original = packet.packet(destination="10.96.0.23", sport=47500, protocol=17)
    wire = forward(original, snat=True)
    reply(wire, original, "10.96.0.23", 80)
    cases += 1
    # Bound port probing, preserve all active owners, and release reservations on failure.
    wires = []
    for index in range(16):
        vip = f"10.96.1.{index + 1}"
        packet.publish(runner, 17, vip=vip)
        original = packet.packet(destination=vip, sport=48000, protocol=17)
        wires.append((forward(original, snat=True), original, vip))
    assert len({packet.endpoints(wire) for wire, _, _ in wires}) == 16
    packet.publish(runner, 17, vip="10.96.1.17")
    stage(NAMES[0], packet.packet(destination="10.96.1.17", sport=48000, protocol=17), verdict=packet.SHOT)
    for wire, original, vip in wires:
        reply(wire, original, vip, 80)
    cases += 17
    owner(runner, CLIENT, ALIAS, 9)
    # A partially withdrawn alias row must not authorize source translation.
    alias_key = ipaddress.ip_address(ALIAS).packed
    saved = runner.lookup(IDENT, alias_key)
    disabled = bytearray(saved)
    struct.pack_into("<I", disabled, 4, 0x20000)
    runner.update(IDENT, alias_key, disabled)
    stage(NAMES[0], packet.packet(destination="10.96.0.20", sport=49000, protocol=17), verdict=packet.SHOT)
    runner.update(IDENT, alias_key, saved)
    # Source-preserved Service bindings also need a known backend incarnation.
    packet.publish(runner, 17, vip="10.96.0.24")
    original = packet.packet(destination="10.96.0.24", sport=49001, protocol=17)
    backend_key = ipaddress.ip_address(BACKEND).packed
    saved = runner.lookup(IDENT, backend_key)
    runner.delete(IDENT, backend_key)
    stage(NAMES[0], original, verdict=packet.SHOT)
    runner.update(IDENT, backend_key, saved)
    wire = forward(original)
    reply(wire, original, "10.96.0.24", 80)
    # Replacing the backend owner must neither accept an old reply nor retarget
    # the live flow on its next request. Fresh flows may use the new incarnation.
    binding = runner.lookup(FWD, key(original))
    owner(runner, BACKEND, BACK_ALIAS, 42)
    response = packet.packet(BACKEND, CLIENT, 8080, 49001, 17)
    stage(NAMES[2], response, verdict=packet.SHOT)
    stage(NAMES[0], original, verdict=packet.SHOT)
    assert runner.lookup(FWD, key(original)) == binding
    fresh = packet.packet(destination="10.96.0.24", sport=49002, protocol=17)
    wire = forward(fresh)
    reply(wire, fresh, "10.96.0.24", 80)
    cases += 3
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    if args.kernel and os.geteuid() != 0:
        parser.error("--kernel requires root in a disposable VM")
    programs, ids, descriptors = packet.read_fixture(args.fixture, names=NAMES)
    runner = (Kernel if args.kernel else Interpreter)(programs, ids, descriptors)
    try:
        cases = exercise(runner)
        print(json.dumps({"passed": True, "kernel": args.kernel, "cases": cases}))
    finally:
        runner.close()


if __name__ == "__main__":
    main()
