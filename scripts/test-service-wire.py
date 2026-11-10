#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual standalone Service Geneve codec bytecode.

--kernel requires a disposable root VM. This proves framing, not flow/policy
integration, identity authentication, real tunnel delivery, MTU or GSO behavior.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("nat", Path(__file__).with_name("test-service-nat.py"))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)
p, e = n.packet, n.packet.endpoint
MAP = "gr8s_wire_fixture"
WRAP, UNWRAP = "gr8s_wire_wrap", "gr8s_wire_unwrap"


def metadata(protocol=6, kind=1):
    return (struct.pack("!IBBH4sHBB", 0x47523853, 1, kind, 48,
                        bytes([10, 96, 0, 10]), 80, protocol, 0) +
            struct.pack("<QQQQ", 1, 101, 2, 102))


def checksum_at(data, offset):
    data = bytearray(data)
    size = (data[offset] & 15) * 4
    struct.pack_into("!H", data, offset + 10, 0)
    struct.pack_into("!H", data, offset + 10, p.checksum(bytes(data[offset:offset + size])))
    return bytes(data)


def expected(data, meta):
    length = len(data) + 88
    ip = struct.pack("!BBHHHBBH", 0x45, data[15], length, 0, 0x4000, 64, 17, 0) + data[26:34]
    ip = ip[:10] + struct.pack("!H", p.checksum(ip)) + ip[12:]
    udp = struct.pack("!HHHH", 49152, 6081, length - 20, 0)
    geneve = bytes.fromhex("0d40655867723800fffe800c")
    return data[:14] + ip + udp + geneve + meta + data


class Machine(p.PacketMachine):
    def __init__(self, *args):
        super().__init__(*args)
        self.packet_address = 0x100000
        self.fail_adjust = False

    def call(self, helper):
        r = self.registers
        if helper not in (9, 10, 26, 50):
            return super().call(helper)
        data = self.memory[self.packet_address]
        if helper == 50:
            delta = r[2] & 0xffffffff
            if delta & 0x80000000:
                delta -= 0x100000000
            assert r[3] == 1
            assert (delta, r[4]) in ((102, 0x0e00000000000053), (-102, 1)), (delta, hex(r[4]))
            if self.fail_adjust:
                r[0] = -12 & e.MASK
            else:
                data = (data[:14] + bytearray(delta) + data[14:] if delta > 0
                        else data[:14] + data[14 - delta:])
                del self.memory[self.packet_address]
                self.packet_address += 0x400000  # Invalidate every old packet pointer.
                self.memory[self.packet_address] = data
                struct.pack_into("<I", self.memory[0x200000], 0, len(data))
                struct.pack_into("<II", self.memory[0x200000], 76,
                                 self.packet_address, self.packet_address + len(data))
                r[0] = 0
        elif helper == 9:
            assert r[2] + r[4] <= len(data)
            data[r[2]:r[2] + r[4]] = self.read_bytes(r[3], r[4])
            r[0] = 0
        elif helper == 26:
            if r[2] + r[4] > len(data):
                r[0] = -14 & e.MASK
            else:
                for offset, value in enumerate(data[r[2]:r[2] + r[4]]):
                    self.write(r[3] + offset, 1, value)
                r[0] = 0
        else:
            assert r[5] == 2
            old, = struct.unpack_from("!H", data, r[2])
            before = int.from_bytes((r[3] & 0xffff).to_bytes(2, "little"), "big")
            after = int.from_bytes((r[4] & 0xffff).to_bytes(2, "little"), "big")
            value = (~old & 0xffff) + (~before & 0xffff) + after
            while value >> 16:
                value = (value & 0xffff) + (value >> 16)
            struct.pack_into("!H", data, r[2], ~value & 0xffff)
            r[0] = 0
        r[1:6] = [0xdeadbeef] * 5


class Interpreter(p.Interpreter):
    def run(self, name, data, fail_adjust=False):
        machine = Machine(self.programs[name], self.maps, bytes(data), self.clock)
        machine.fail_adjust = fail_adjust
        verdict = machine.run()
        return verdict, bytes(machine.memory[machine.packet_address])


class Kernel(n.Kernel):
    def run(self, name, data):
        verdict, output, _ = self.stage_raw(name, data)
        return verdict, output


def exercise(runner):
    cases = []
    for protocol in (6, 17):
        for kind in (1, 2):
            meta = metadata(protocol, kind)
            runner.update(MAP, bytes(4), meta)
            for options in (b"", bytes.fromhex("01010100"), bytes([1]) * 40):
                original = p.packet(destination=p.BACKEND, protocol=protocol, options=options,
                                    udp_zero=protocol == 17)
                verdict, wire = runner.run(WRAP, original)
                assert verdict == p.OK
                assert wire == expected(original, meta)
                verdict, restored = runner.run(UNWRAP, wire)
                assert verdict == p.OK and restored == original
                p.check_checksums(restored)
                # Forwarding can change Ethernet/TTL; inner IP/options stay exact.
                routed = bytearray(wire)
                routed[:12] = bytes.fromhex("020000000003020000000004")
                routed[22] -= 1
                struct.pack_into("!H", routed, 18, 1024)
                routed = checksum_at(routed, 14)
                verdict, restored = runner.run(UNWRAP, routed)
                assert verdict == p.OK and restored == routed[:14] + original[14:]
                cases.append(f"protocol{protocol}kind{kind}options{len(options)}")
    meta = metadata(17)
    runner.update(MAP, bytes(4), meta)
    original = p.packet(destination=p.BACKEND, protocol=17)
    wire = expected(original, meta)
    # Each framing field and every byte of both128-bit epochs is independently
    # corrupted. Recompute outer checksum so structural checks, not its checksum,
    # must catch the altered option/identity/length/address.
    for offset in (12, 14, 16, 20, 22, 23, 26, 30, 36, 38, 40, 42, 43, 44,
                   46, 49, 50, 52, 53, *range(54, 102), 114, 116, 118, 122, 125, 128, 132):
        changed = bytearray(wire)
        changed[offset] ^= 0x80 if offset == 20 else 1
        if offset == 22:
            changed[offset] = 0
        changed = checksum_at(changed, 14) if offset != 14 else bytes(changed)
        verdict, _ = runner.run(UNWRAP, changed)
        assert verdict == p.SHOT, ("accepted corruption", offset)
        cases.append(f"corruptByte{offset}")
    corrupt_checksum = bytearray(wire)
    corrupt_checksum[24] ^= 1
    assert runner.run(UNWRAP, corrupt_checksum)[0] == p.SHOT
    cases.append("outerChecksum")
    for length in (14, 33, 53, 101, 115, 135, len(wire) - 1):
        assert runner.run(UNWRAP, wire[:length])[0] == p.SHOT
        cases.append(f"truncated{length}")
    for value in (0, 1, 2, 3):
        inner = bytearray(original)
        inner[15] = 0xa0 | value
        inner = checksum_at(inner, 14)
        encoded = bytearray(expected(inner, meta))
        encoded[15] |= 3
        encoded = checksum_at(encoded, 14)
        verdict, restored = runner.run(UNWRAP, encoded)
        if value == 0:
            assert verdict == p.SHOT
        else:
            assert verdict == p.OK
            assert restored[15] == 0xa3
            p.check_checksums(restored)
        cases.append(f"outerCEinnerECN{value}")
    for offset in (0, 4, 5, 6, 8, 12, 14, 15, 16, 32):
        changed = bytearray(meta)
        if offset in (16, 32):
            changed[offset:offset + 16] = bytes(16)
        elif offset in (8, 12):
            changed[offset:offset + (4 if offset == 8 else 2)] = bytes(4 if offset == 8 else 2)
        else:
            changed[offset] = 0xff
        runner.update(MAP, bytes(4), changed)
        assert runner.run(WRAP, original)[0] == p.SHOT
        cases.append(f"invalidMetadata{offset}")
    runner.update(MAP, bytes(4), meta)
    if isinstance(runner, Interpreter):
        for name, data in ((WRAP, original), (UNWRAP, wire)):
            verdict, output = runner.run(name, data, fail_adjust=True)
            assert verdict == p.SHOT and output == data
            cases.append(name + "AllocationFailure")
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=(WRAP, UNWRAP))
    cls = Kernel if args.kernel else Interpreter
    runner = cls(programs, ids, descriptors)
    try:
        cases = exercise(runner)
        print(json.dumps({"passed": True, "kernel": args.kernel, "cases": cases}))
    finally:
        runner.close()


if __name__ == "__main__":
    main()
