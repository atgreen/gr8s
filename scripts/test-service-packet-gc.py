#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual Service collector bytecode, including reservation races.

Pass the packet fixture then the GC fixture; --kernel runs in a disposable root
VM. Uses the same flow maps and packet bytecode as the attached dataplane.
"""
import importlib.util
from pathlib import Path
import struct
import sys
import threading

spec = importlib.util.spec_from_file_location("packet", Path(__file__).with_name("test-service-packet-program.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def frame(direction, key):
    data = bytearray(52)
    data[:14] = bytes.fromhex("0200000000010200000000020800")
    data[14], data[17], data[22], data[23], data[34] = 0x45, 38, 64, 253, direction
    data[36:] = key
    struct.pack_into("!H", data, 24, p.checksum(bytes(data[14:34])))
    return bytes(data)


def collect(runner, direction, key):
    data = frame(direction, key)
    result, unchanged = runner.run("gr8s_packet_gc", data)
    assert unchanged == data, "collector modified the envelope"
    return result


def pair_keys(port=48000, vip=p.VIP, backend=p.BACKEND, protocol=17):
    return (p.flow_key(sport=port, destination=vip, protocol=protocol),
            p.flow_key(backend, p.CLIENT, 8080, port, protocol))


def exercise(runner):
    cases = 0
    for protocol, lifetime in ((17, 180), (6, 7200)):
        forward, reverse = pair_keys(protocol=protocol)
        p.publish(runner, protocol)
        request = p.packet(sport=48000, protocol=protocol)
        p.assert_forward(runner, request)
        original = runner.lookup("gr8s_pkt_forward", forward)
        assert collect(runner, 0, forward) == collect(runner, 1, reverse) == 0
        assert runner.lookup("gr8s_pkt_forward", forward) == original, "GC refreshed a flow"
        runner.advance(lifetime + 1)
        aged = runner.lookup("gr8s_pkt_forward", forward)
        # A packet owning either key prevents collection; the losing collector
        # must release its partial acquisition without erasing the foreign one.
        for name, held in (("gr8s_pkt_fwd_lock", forward), ("gr8s_pkt_rev_lock", reverse)):
            runner.update(name, held, bytes(8))
            for direction, key in ((0, forward), (1, reverse)):
                assert collect(runner, direction, key) == p.SHOT
                assert runner.lookup(name, held) == bytes(8)
                assert runner.lookup("gr8s_pkt_forward", forward) == aged
            runner.delete(name, held)
            p.assert_unlocked(runner)
            cases += 2
        assert collect(runner, 0, forward) == 1
        assert runner.lookup("gr8s_pkt_forward", forward) is None
        assert runner.lookup("gr8s_pkt_reverse", reverse) is None
        assert collect(runner, 0, forward) == collect(runner, 1, reverse) == 0
        # A different Service can now own the freed return tuple.
        vip = "10.96.0.11"
        p.publish(runner, protocol, vip=vip)
        p.assert_forward(runner, p.packet(sport=48000, destination=vip, protocol=protocol))
        second, _ = pair_keys(vip=vip, protocol=protocol)
        runner.advance(lifetime + 1)
        assert collect(runner, 1, reverse) == 1
        assert runner.lookup("gr8s_pkt_forward", second) is None
        assert runner.lookup("gr8s_pkt_reverse", reverse) is None
        p.assert_unlocked(runner)
        cases += 6
    # Foreground expiry can leave an obsolete reverse key after selecting a
    # different backend. Its collector must preserve the current live backend.
    p.publish(runner, 17)
    forward, old_reverse = pair_keys(port=48001)
    request = p.packet(sport=48001, protocol=17)
    p.assert_forward(runner, request)
    runner.advance(181)
    replacement = "10.88.2.4"
    p.publish(runner, 17, backend=replacement)
    p.assert_forward(runner, request, replacement)
    original = runner.lookup("gr8s_pkt_forward", forward)
    assert collect(runner, 1, old_reverse) == 1
    assert runner.lookup("gr8s_pkt_forward", forward) == original
    _, current_reverse = pair_keys(port=48001, backend=replacement)
    assert runner.lookup("gr8s_pkt_reverse", current_reverse) is not None
    assert collect(runner, 1, current_reverse) == 0
    cases += 3
    # Do not remove a reverse reservation owned by a different Service while
    # retiring this forward entry. The orphan pass validates its own owner.
    # Reverse values encode address then network-order port, rather than VIP keys.
    foreign = p.backend_value("10.96.0.12", 80) + struct.pack("<Q", 0)
    runner.update("gr8s_pkt_reverse", current_reverse, foreign)
    runner.advance(181)
    assert collect(runner, 0, forward) == 1
    assert runner.lookup("gr8s_pkt_reverse", current_reverse) == foreign
    assert collect(runner, 1, current_reverse) == 1
    assert runner.lookup("gr8s_pkt_reverse", current_reverse) is None
    cases += 3
    # Invalid control input cannot touch maps or retain tuple reservations.
    for data in (frame(2, forward), frame(0, bytes(16)), frame(0, forward)[:38]):
        result, unchanged = runner.run("gr8s_packet_gc", data)
        assert result == 3 and unchanged == data
        p.assert_unlocked(runner)
        cases += 1
    return cases


def capacity(runner):
    p.publish(runner, 17)
    first, reverse = pair_keys(port=48100)
    p.assert_forward(runner, p.packet(sport=48100, protocol=17))
    request = p.packet(sport=48101, protocol=17)
    verdict, unchanged = runner.run("gr8s_packet_forward", request)
    assert verdict == p.SHOT and unchanged == request
    second, orphan = pair_keys(port=48101)
    assert runner.lookup("gr8s_pkt_reverse", orphan) is not None
    assert collect(runner, 1, orphan) == 1
    assert runner.lookup("gr8s_pkt_forward", first) is not None
    runner.advance(181)
    assert collect(runner, 0, first) == 1
    p.assert_forward(runner, request)
    assert runner.lookup("gr8s_pkt_forward", second) is not None
    p.assert_unlocked(runner)
    return 5


def concurrent(runner):
    p.publish(runner, 17)
    forward, reverse = pair_keys(port=48200)
    request = p.packet(sport=48200, protocol=17)
    p.assert_forward(runner, request)
    errors, counts = [], []

    def worker(maintenance):
        passed = 0
        try:
            for _ in range(256):
                if maintenance:
                    assert collect(runner, 0, forward) in (0, 2)
                    assert collect(runner, 1, reverse) in (0, 2)
                else:
                    result, data = runner.run("gr8s_packet_forward", request)
                    assert result in (p.OK, p.SHOT)
                    if result == p.OK:
                        assert p.endpoints(data) == (p.CLIENT, p.BACKEND, 48200, 8080)
                        p.check_checksums(data)
                passed += 1
        except BaseException as error:
            errors.append(error)
        counts.append(passed)
    threads = [threading.Thread(target=worker, args=(mode,)) for mode in (False, True)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive(), "GC/traffic coordination stalled"
    assert not errors, errors
    p.assert_unlocked(runner)
    p.assert_forward(runner, request)
    return sum(counts)


def main():
    programs, ids, descriptors = p.read_fixture(sys.argv[1])
    gc, gc_ids, gc_specs = p.read_fixture(sys.argv[2], names=("gr8s_packet_gc",))
    assert gc_ids == ids and gc_specs == descriptors
    programs.update(gc)
    cls = p.Kernel if "--kernel" in sys.argv[3:] else p.Interpreter
    runner = cls(programs, ids, descriptors)
    try:
        print(f"Service GC ({cls.__name__}): {exercise(runner)} ownership/expiry/reservation cases passed")
    finally:
        runner.close()
    limited = dict(descriptors)
    kind, key_size, value_size, _, flags = limited["gr8s_pkt_forward"]
    limited["gr8s_pkt_forward"] = kind, key_size, value_size, 1, flags
    runner = cls(programs, ids, limited)
    try:
        print(f"Service GC capacity recovery: {capacity(runner)} cases passed")
    finally:
        runner.close()
    if cls is p.Kernel:
        runner = cls(programs, ids, descriptors)
        try:
            print(f"Service GC concurrent traffic: {concurrent(runner)} worker iterations passed")
        finally:
            runner.close()


if __name__ == "__main__":
    main()
