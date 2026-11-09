#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual Whistler TC Service bytecode and verify rewritten checksums.

Compile with compile-endpoint-policy-fixture.lisp OUTPUT service-packet-lb.
The default interpreter checks bounds, stack initialization, map update flags,
and helper register clobbering. --kernel loads and executes the same programs
using BPF_PROG_TEST_RUN; run that only in a disposable root VM.
"""

import ctypes
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location(
    "endpoint_policy", Path(__file__).with_name("test-endpoint-policy.py"))
endpoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(endpoint)

CLIENT, VIP, BACKEND = "10.88.0.2", "10.96.0.10", "10.88.1.3"
OK, SHOT = 0, 2


def checksum(data):
    data += bytes(len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def packet(source=CLIENT, destination=VIP, sport=40000, dport=80, protocol=6,
           options=b"", udp_zero=False):
    source, destination = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    payload = b"service-packet-test"
    if protocol == 6:
        l4 = bytearray(struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 4096, 0, 0) + payload)
        csum_offset = 16
    else:
        l4 = bytearray(struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)
        csum_offset = 6
    pseudo = source + destination + struct.pack("!BBH", 0, protocol, len(l4))
    if not udp_zero:
        struct.pack_into("!H", l4, csum_offset, checksum(pseudo + l4) or 0xffff)
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0,
                                   20 + len(options) + len(l4), 123, 0x4000,
                                   64, protocol, 0, source, destination) + options)
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes.fromhex("0200000000010200000000020800") + header + l4


def endpoints(data):
    offset = 14 + (data[14] & 15) * 4
    return (str(ipaddress.ip_address(data[26:30])), str(ipaddress.ip_address(data[30:34])),
            *struct.unpack_from("!HH", data, offset))


def check_checksums(data):
    ihl = (data[14] & 15) * 4
    assert checksum(data[14:14 + ihl]) == 0, "bad IPv4 checksum"
    l4 = data[14 + ihl:14 + struct.unpack_from("!H", data, 16)[0]]
    protocol = data[23]
    if protocol == 17 and l4[6:8] == bytes(2):
        return
    pseudo = data[26:34] + struct.pack("!BBH", 0, protocol, len(l4))
    assert checksum(pseudo + l4) == 0, "bad transport checksum"


def read_fixture(path, names=("gr8s_packet_forward", "gr8s_packet_reverse")):
    document = json.load(open(path))
    specs = document["maps"]
    descriptors = {s["name"]: (s["type"], s["key_size"], s["value_size"],
                                s["max_entries"], s["flags"]) for s in specs}
    ids = {s["name"]: i + 100 for i, s in enumerate(specs)}
    programs = {}
    for program in document["programs"]:
        code = bytearray(program["code"])
        for offset, index in program["relocations"]:
            struct.pack_into("<I", code, offset + 4, ids[specs[index]["name"]])
        programs[program["name"]] = bytes(code)
    assert set(programs) == set(names), programs.keys()
    return programs, ids, descriptors


class PacketMachine(endpoint.Machine):
    def call(self, helper):
        r = self.registers
        if helper == 7:
            r[0] = 0
        elif helper == 2:
            name = self.maps.names[r[1]]
            _, key_size, value_size, capacity, _ = self.maps.descriptors[name]
            key = self.read_bytes(r[2], key_size)
            present = bool(self.maps.lookup(name, key))
            if r[4] == 1 and present:
                r[0] = -17 & endpoint.MASK
            elif r[4] == 2 and not present:
                r[0] = -2 & endpoint.MASK
            elif not present and len(self.maps.entries[name]) >= capacity:
                r[0] = -28 & endpoint.MASK
            else:
                self.maps.update(name, key, self.read_bytes(r[3], value_size))
                r[0] = 0
        elif helper == 9:
            data = self.memory[0x100000]
            assert r[2] + r[4] <= len(data), "skb_store_bytes outside packet"
            data[r[2]:r[2] + r[4]] = self.read_bytes(r[3], r[4])
            r[0] = 0
        elif helper == 26:
            data = self.memory[0x100000]
            if r[2] + r[4] > len(data):
                r[0] = -14 & endpoint.MASK
            else:
                for offset, value in enumerate(data[r[2]:r[2] + r[4]]):
                    self.write(r[3] + offset, 1, value)
                r[0] = 0
        elif helper in (10, 11):
            data = self.memory[0x100000]
            offset, size, flags = r[2], r[4], r[5]
            if helper == 10:
                size = flags
            else:
                size = flags & 15
            old = struct.unpack_from("!H", data, offset)[0]
            if helper != 11 or old != 0 or not flags & 32:
                before = (r[3] & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
                after = (r[4] & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
                words = struct.unpack(f"!{size // 2}H", before)
                new_words = struct.unpack(f"!{size // 2}H", after)
                value = (~old & 0xffff) + sum(~word & 0xffff for word in words) + sum(new_words)
                while value >> 16:
                    value = (value & 0xffff) + (value >> 16)
                updated = ~value & 0xffff
                if helper == 11 and updated == 0 and flags & 32:
                    updated = 0xffff
                struct.pack_into("!H", data, offset, updated)
            r[0] = 0
        else:
            return super().call(helper)
        r[1:6] = [0xdeadbeef] * 5


class Interpreter(endpoint.Interpreter):
    def run(self, program, data, linear_length=None):
        machine = PacketMachine(self.programs[program], self.maps, data, self.clock)
        if linear_length is not None:
            struct.pack_into("<I", machine.memory[0x200000], 80, 0x100000 + linear_length)
        result = machine.run()
        return result, bytes(machine.memory[0x100000])

    def delete(self, name, key):
        self.maps.entries[name].pop(key)


class Kernel(endpoint.Kernel):
    def delete(self, name, key):
        key_buffer = ctypes.create_string_buffer(bytes(key), len(key))
        self.bpf(3, struct.pack("<IIQ", self.map_fds[name], 0, ctypes.addressof(key_buffer)))

    def run(self, program, packet):
        incoming = ctypes.create_string_buffer(bytes(packet))
        outgoing = ctypes.create_string_buffer(len(packet) + 256)
        attr = ctypes.create_string_buffer(struct.pack("<IIIIQQII", self.program_fds[program],
                                                       0, len(packet), len(outgoing),
                                                       ctypes.addressof(incoming), ctypes.addressof(outgoing), 1, 0))
        result = self.libc.syscall(self.syscall_number, 10, ctypes.byref(attr), 40)
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, "BPF_PROG_TEST_RUN")
        verdict = struct.unpack_from("<I", attr.raw, 4)[0]
        size = struct.unpack_from("<I", attr.raw, 12)[0]
        return verdict, outgoing.raw[:size]


def service_key(vip=VIP, port=80, protocol=6):
    return struct.pack("!H", port) + ipaddress.ip_address(vip).packed + bytes([protocol, 0])


def backend_value(address=BACKEND, port=8080):
    return ipaddress.ip_address(address).packed + struct.pack("!H", port) + bytes(2)


def publish(runner, protocol=6, vip=VIP, backend=BACKEND, affinity=0):
    key, value = service_key(vip, protocol=protocol), backend_value(backend)
    runner.update("gr8s_backend_v4", struct.pack("<I", 0), value)
    runner.update("gr8s_backend_index_v4", key + value, struct.pack("<I", 0))
    runner.update("gr8s_service_v4", key, struct.pack("<HHIII", 1, affinity, 0, 60, 0))


def assert_forward(runner, data, backend=BACKEND):
    verdict, rewritten = runner.run("gr8s_packet_forward", data)
    assert verdict == OK, ("forward", verdict, endpoints(data))
    source, _, sport, _ = endpoints(data)
    assert endpoints(rewritten) == (source, backend, sport, 8080), endpoints(rewritten)
    check_checksums(rewritten)
    return rewritten


def exercise(runner):
    cases = 0
    for protocol in (6, 17):
        publish(runner, protocol)
        for index, options in enumerate((b"", bytes.fromhex("01010100"))):
            data = packet(protocol=protocol, sport=40000 + index, options=options)
            assert_forward(runner, data)
            verdict, reply = runner.run("gr8s_packet_reverse", packet(
                BACKEND, CLIENT, 8080, 40000 + index, protocol, options))
            assert verdict == OK and endpoints(reply) == (VIP, CLIENT, 80, 40000 + index), endpoints(reply)
            check_checksums(reply)
            cases += 2
        # A connected flow keeps its backend through endpoint replacement.
        publish(runner, protocol, backend="10.88.2.4")
        assert_forward(runner, packet(protocol=protocol))
        assert_forward(runner, packet(protocol=protocol, sport=40002), "10.88.2.4")
        cases += 2
        # A second Service cannot claim the same backend return tuple.
        publish(runner, protocol, vip="10.96.0.11", backend="10.88.2.4")
        data = packet(destination="10.96.0.11", sport=40002, protocol=protocol)
        verdict, rewritten = runner.run("gr8s_packet_forward", data)
        assert verdict == SHOT and rewritten == data
        cases += 1

    publish(runner, 17)
    data = packet(protocol=17, sport=40003, udp_zero=True)
    rewritten = assert_forward(runner, data)
    assert rewritten[40:42] == bytes(2), "UDP zero checksum changed"
    cases += 1
    if isinstance(runner, Interpreter):
        data = packet(protocol=17, sport=40007, options=bytes.fromhex("01010100"))
        verdict, rewritten = runner.run("gr8s_packet_forward", data, linear_length=34)
        assert verdict == OK and endpoints(rewritten) == (CLIENT, BACKEND, 40007, 8080)
        check_checksums(rewritten)
        cases += 1

    # Native socket LB traffic is already addressed to a real backend and passes
    # without creating another NAT mapping.
    direct = packet(destination=BACKEND, dport=8080, sport=40004)
    verdict, rewritten = runner.run("gr8s_packet_forward", direct)
    assert verdict == OK and rewritten == direct
    cases += 1

    # Slot reuse cannot send a new flow to an unrelated Service's backend.
    publish(runner)
    runner.update("gr8s_backend_v4", struct.pack("<I", 0), backend_value("10.88.3.9"))
    data = packet(sport=40005)
    verdict, rewritten = runner.run("gr8s_packet_forward", data)
    assert verdict == SHOT and rewritten == data
    cases += 1

    # A Service with no endpoints is a known destination and fails closed.
    runner.update("gr8s_service_v4", service_key(), struct.pack("<HHIII", 0, 0, 0, 0, 1))
    data = packet(sport=40006)
    verdict, rewritten = runner.run("gr8s_packet_forward", data)
    assert verdict == SHOT and rewritten == data
    cases += 1
    for data in (b"", bytes(13), packet()[:33], packet()[:40]):
        if isinstance(runner, Kernel) and len(data) < 14:
            continue  # TC test-run requires at least an Ethernet header.
        verdict, _ = runner.run("gr8s_packet_forward", data)
        assert verdict == SHOT
        cases += 1
    # Affinity follows source IP across different connections. Removal of the
    # held endpoint selects a remaining endpoint; existing flows still reply.
    key = service_key()
    first, second = backend_value(), backend_value("10.88.2.4")
    runner.update("gr8s_backend_v4", struct.pack("<I", 0), first)
    runner.update("gr8s_backend_v4", struct.pack("<I", 1), second)
    runner.update("gr8s_backend_index_v4", key + first, struct.pack("<I", 0))
    runner.update("gr8s_backend_index_v4", key + second, struct.pack("<I", 1))
    runner.update("gr8s_service_v4", key, struct.pack("<HHIII", 2, 1, 0, 60, 0))
    client = "10.88.0.20"
    verdict, rewritten = runner.run("gr8s_packet_forward", packet(source=client, sport=41000))
    assert verdict == OK
    selected = endpoints(rewritten)[1]
    for port in (41001, 41002):
        assert_forward(runner, packet(source=client, sport=port), selected)
        cases += 1
    held, remaining = (first, second) if selected == BACKEND else (second, first)
    runner.delete("gr8s_backend_index_v4", key + held)
    runner.update("gr8s_backend_v4", struct.pack("<I", 0), remaining)
    runner.update("gr8s_backend_index_v4", key + remaining, struct.pack("<I", 0))
    runner.update("gr8s_service_v4", key, struct.pack("<HHIII", 1, 1, 0, 60, 0))
    remaining_address = str(ipaddress.ip_address(remaining[:4]))
    assert_forward(runner, packet(source=client, sport=41003), remaining_address)
    cases += 1
    for reason in (0, 1, 2, 3, 4, 6):
        assert struct.unpack("<Q", runner.lookup("gr8s_pkt_stats", struct.pack("<I", reason)))[0] > 0
    assert runner.lookup("gr8s_pkt_stats", struct.pack("<I", 5)) == bytes(8)
    return cases


def capacity_exercise(runner):
    """A real map-capacity failure cannot publish a half-working NAT flow."""
    publish(runner)
    assert_forward(runner, packet())  # Fill the one-entry forward table.
    data = packet(sport=42000)
    verdict, rewritten = runner.run("gr8s_packet_forward", data)
    assert verdict == SHOT and rewritten == data
    reply = packet(BACKEND, CLIENT, 8080, 42000)
    verdict, rewritten = runner.run("gr8s_packet_reverse", reply)
    assert verdict == SHOT and rewritten == reply, "orphan reverse entry translated"
    # Existing traffic keeps working despite the failed new connection.
    assert_forward(runner, packet())
    # Recover after freeing capacity. The abandoned reverse reservation is
    # reusable by its original Service but cannot steal another Service's flow.
    forward = (ipaddress.ip_address(CLIENT).packed + ipaddress.ip_address(VIP).packed +
               struct.pack("!HHBBH", 40000, 80, 6, 0, 0))
    runner.delete("gr8s_pkt_forward", forward)
    assert_forward(runner, data)
    assert struct.unpack("<Q", runner.lookup("gr8s_pkt_stats", struct.pack("<I", 5)))[0] == 2
    return 5


def main():
    programs, ids, descriptors = read_fixture(sys.argv[1])
    runner = (Kernel if "--kernel" in sys.argv[2:] else Interpreter)(programs, ids, descriptors)
    try:
        cases = exercise(runner)
        print(f"Service TC bytecode ({'kernel' if isinstance(runner, Kernel) else 'interpreter'}): "
              f"{cases} packet/flow/checksum cases passed")
    finally:
        runner.close()
    limited = dict(descriptors)
    kind, key_size, value_size, _, flags = limited["gr8s_pkt_forward"]
    limited["gr8s_pkt_forward"] = (kind, key_size, value_size, 1, flags)
    runner = (Kernel if "--kernel" in sys.argv[2:] else Interpreter)(programs, ids, limited)
    try:
        cases = capacity_exercise(runner)
        print(f"Service TC capacity: {cases} publication/recovery cases passed")
    finally:
        runner.close()


if __name__ == "__main__":
    main()
