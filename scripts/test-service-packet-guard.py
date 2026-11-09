#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Prove TC Service translation ordering in the actual endpoint guard bytecode.

Compile with compile-endpoint-policy-fixture.lisp OUTPUT service-packet-guard.
--kernel is restricted to a disposable root VM, as for the packet-engine tests.
"""

import importlib.util
import ipaddress
import ctypes
import os
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location(
    "packet_program", Path(__file__).with_name("test-service-packet-program.py"))
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)

ZERO = struct.pack("<I", 0)
STAGES = ("gr8s_packet_forward", "gr8s_egress_policy", "gr8s_packet_reverse")


class TailCall(Exception):
    pass


class GuardMachine(packet.PacketMachine):
    def call(self, helper):
        if helper != 12:
            return super().call(helper)
        r = self.registers
        key = struct.pack("<I", r[3])
        pointer = self.maps.lookup(self.maps.names[r[2]], key)
        fd = self.read(pointer, 4) if pointer else 0
        if fd in self.stage_programs and self.tail_count < 33:
            raise TailCall(self.stage_programs[fd])
        r[0] = 0
        r[1:6] = [0xdeadbeef] * 5


class GuardInterpreter(packet.Interpreter):
    def __init__(self, programs, ids, descriptors):
        super().__init__(programs, ids, descriptors)
        self.program_fds = {name: 500 + i for i, name in enumerate(programs)}

    def run(self, program, data):
        stage_programs = {fd: name for name, fd in self.program_fds.items()}
        for count in range(34):
            machine = GuardMachine(self.programs[program], self.maps, data, self.clock)
            machine.stage_programs, machine.tail_count = stage_programs, count
            try:
                verdict = machine.run()
            except TailCall as jump:
                program = jump.args[0]
                data = bytes(machine.memory[0x100000])
                continue
            return verdict, bytes(machine.memory[0x100000])
        raise AssertionError("tail call limit did not fail closed")


def identity(runner, mode=2):
    runner.update("endpoint_identity", ZERO,
                  struct.pack("<IIII", int(ipaddress.ip_address(packet.CLIENT)),
                              0x02000000, 2, mode) + bytes(16))


def flow_key(source, destination, sport, dport, protocol=6):
    return (ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed +
            struct.pack("!HHBBH", sport, dport, protocol, 0, 0))


def allow_backend(runner, protocol):
    runner.update("netpol_egress_cidr", struct.pack("<I", 32) +
                  ipaddress.ip_address(packet.BACKEND).packed, struct.pack("<I", 1))
    runner.update("netpol_egress_ports", struct.pack("<II", 64, 1) +
                  bytes([protocol, 0]) + struct.pack("!H", 8080), b"\1")


def counter(runner, name, index):
    return struct.unpack("<Q", runner.lookup(name, struct.pack("<I", index)))[0]


def exercise(runner):
    count = 0
    identity(runner)
    runner.update("netpol_mode", ZERO, struct.pack("<I", 1))
    runner.update("netpol_mode", struct.pack("<I", 1), struct.pack("<I", 1))
    for protocol in (6, 17):
        packet.publish(runner, protocol)
        # No policy allows the Service VIP. A denied request must fail even
        # though NAT has found an endpoint and can rewrite its destination.
        data = packet.packet(sport=42000, protocol=protocol)
        verdict, _ = runner.run("gr8s_egress_guard", data)
        assert verdict == packet.SHOT, "Service request bypassed default-deny egress"
        count += 1
        # Permit only the real backend's target port. This proves that egress
        # policy runs after DNAT rather than matching the original VIP:80.
        allow_backend(runner, protocol)
        verdict, rewritten = runner.run("gr8s_egress_guard", packet.packet(
            sport=42001, protocol=protocol))
        assert verdict == packet.OK and packet.endpoints(rewritten) == (
            packet.CLIENT, packet.BACKEND, 42001, 8080), packet.endpoints(rewritten)
        packet.check_checksums(rewritten)
        count += 1
        # The ingress policy has no allow rules. It can only allow this reply
        # through the backend identity recorded by egress policy. Reverse NAT
        # before this check would present the VIP and fail that lookup.
        verdict, rewritten = runner.run("gr8s_ingress_guard", packet.packet(
            packet.BACKEND, packet.CLIENT, 8080, 42001, protocol))
        assert verdict == packet.OK and packet.endpoints(rewritten) == (
            packet.VIP, packet.CLIENT, 80, 42001), packet.endpoints(rewritten)
        packet.check_checksums(rewritten)
        count += 1
        # A direct packet already rewritten by the socket LB must cross policy
        # normally without adding a second packet translation.
        requests = counter(runner, "gr8s_pkt_stats", 0)
        data = packet.packet(destination=packet.BACKEND, dport=8080, sport=43000, protocol=protocol)
        verdict, rewritten = runner.run("gr8s_egress_guard", data)
        assert verdict == packet.OK and rewritten == data
        assert counter(runner, "gr8s_pkt_stats", 0) == requests
        count += 1
        # Anti-spoof validation must precede all Service map side effects.
        data = packet.packet(source="10.88.0.99", sport=44000, protocol=protocol)
        verdict, _ = runner.run("gr8s_egress_guard", data)
        assert verdict == packet.SHOT
        assert runner.lookup("gr8s_pkt_forward", flow_key(
            "10.88.0.99", packet.VIP, 44000, 80, protocol)) is None
        assert counter(runner, "gr8s_pkt_stats", 0) == requests
        count += 1
        # Unsolicited replies still cross ingress policy and stay untranslated.
        data = packet.packet(packet.BACKEND, packet.CLIENT, 8080, 45000, protocol)
        verdict, rewritten = runner.run("gr8s_ingress_guard", data)
        assert verdict == packet.SHOT and rewritten == data
        count += 1

    # Skipping packet NAT must continue the enclosing policy guard, never
    # return TC_ACT_OK early for fragments or non-TCP/UDP traffic.
    data = bytearray(packet.packet(sport=46000))
    struct.pack_into("!H", data, 20, 0x2000)
    verdict, _ = runner.run("gr8s_egress_guard", bytes(data))
    assert verdict == packet.SHOT, "fragment bypassed policy"
    count += 1
    data = packet.endpoint.datagram(ipaddress.ip_address(packet.CLIENT).packed,
                                    ipaddress.ip_address(packet.BACKEND).packed, 1,
                                    mac=bytes.fromhex("020000000002"))
    verdict, _ = runner.run("gr8s_egress_guard", data)
    assert verdict == packet.SHOT, "non-TCP/UDP packet bypassed policy"
    count += 1

    # Same-node routing must use the translated backend, after policy admits
    # it. A lookup of the unmodified VIP would miss and fail to redirect.
    identity(runner, mode=1)
    runner.update("local_pod_v4", struct.pack("<I", 32) +
                  ipaddress.ip_address(packet.BACKEND).packed,
                  struct.pack("<I", 7) + bytes.fromhex("020000000003020000000004"))
    verdict, rewritten = runner.run("gr8s_egress_guard", packet.packet(sport=47000))
    assert verdict == 7, ("local delivery", verdict)
    assert packet.endpoints(rewritten) == (packet.CLIENT, packet.BACKEND, 47000, 8080)
    packet.check_checksums(rewritten)
    assert counter(runner, "rejected_spoofs", 0) >= 2
    assert counter(runner, "traffic_stats", 6) >= 4
    count += 1
    # Every missing continuation fails closed; a partially populated program
    # table must never bypass policy or expose an untranslated Service reply.
    for index, name in enumerate(STAGES):
        runner.delete("gr8s_pkt_stages", struct.pack("<I", index))
        if index == 2:
            data = packet.packet(packet.BACKEND, packet.CLIENT, 8080, 42001)
            program = "gr8s_ingress_guard"
        else:
            data = packet.packet(sport=48000 + index)
            program = "gr8s_egress_guard"
        verdict, _ = runner.run(program, data)
        assert verdict == packet.SHOT, ("missing stage", index, verdict)
        runner.update("gr8s_pkt_stages", struct.pack("<I", index),
                      struct.pack("<I", runner.program_fds[name]))
        count += 1
    verdict, _ = runner.run("gr8s_egress_guard", packet.packet(sport=49000))
    assert verdict == 7
    return count + 1


def main():
    programs, ids, descriptors = packet.read_fixture(
        sys.argv[1], names=("gr8s_egress_guard", "gr8s_ingress_guard", *STAGES))
    assert len(descriptors) == 26
    runner = (packet.Kernel if "--kernel" in sys.argv[2:] else GuardInterpreter)(programs, ids, descriptors)
    try:
        for index, name in enumerate(STAGES):
            runner.update("gr8s_pkt_stages", struct.pack("<I", index),
                          struct.pack("<I", runner.program_fds[name]))
        count = exercise(runner)
        if isinstance(runner, packet.Kernel):
            # CNI closes the loader's FDs after pinning the table and links.
            # The table pin must keep its continuation programs referenced.
            directory = Path("/sys/fs/bpf") / f"gr8s_service_stages_{os.getpid()}"
            directory.mkdir()
            pin = directory / "stages"
            try:
                filename = ctypes.create_string_buffer(str(pin).encode())
                stages_fd = runner.map_fds["gr8s_pkt_stages"]
                runner.bpf(6, struct.pack("<QII", ctypes.addressof(filename), stages_fd, 0))
                for fd in [stages_fd, *(runner.program_fds[name] for name in STAGES)]:
                    os.close(fd)
                    runner.fds.remove(fd)
                verdict, translated = runner.run("gr8s_egress_guard", packet.packet(sport=50000))
                assert verdict == 7 and packet.endpoints(translated) == (
                    packet.CLIENT, packet.BACKEND, 50000, 8080)
                packet.check_checksums(translated)
                verdict, translated = runner.run("gr8s_ingress_guard", packet.packet(
                    packet.BACKEND, packet.CLIENT, 8080, 50000))
                assert verdict == packet.OK and packet.endpoints(translated) == (
                    packet.VIP, packet.CLIENT, 80, 50000)
                packet.check_checksums(translated)
                count += 2
            finally:
                pin.unlink(missing_ok=True)
                directory.rmdir()
        packet.assert_unlocked(runner)
        print(f"Service endpoint guard ({'kernel' if isinstance(runner, packet.Kernel) else 'interpreter'}): "
              f"{count} source-validation/policy/NAT/routing cases passed")
    finally:
        runner.close()


if __name__ == "__main__":
    main()
