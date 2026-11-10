#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise v2 per-key collection. --kernel is disposable-VM root only.

This proves reclamation transactions, not an installed node-agent scanner.
"""
import argparse
import json
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import importlib.util

spec = importlib.util.spec_from_file_location("tcp_adapter", Path(__file__).with_name("test-service-nat-tcp.py"))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
n, p = t.nat, t.nat.packet
TCP, GC = "gr8s_nat_tcp_v2", "gr8s_nat_gc"


def frame(kind, key):
    data = bytearray(36 + len(key))
    data[:14] = bytes.fromhex("0200000000010200000000020800")
    data[14], data[22], data[23], data[34] = 0x45, 64, 253, kind
    struct.pack_into("!H", data, 16, len(data) - 14)
    struct.pack_into("!H", data, 24, p.checksum(bytes(data[14:34])))
    data[36:] = key
    return bytes(data)


def collect(runner, kind, key, check_unlock=True):
    data = frame(kind, key)
    verdict, output, _ = runner.stage(GC, data)
    assert output == data, "collector modified its control envelope"
    if check_unlock:
        n.unlocked(runner)
    return verdict


class Collector:
    collect = staticmethod(collect)

    @staticmethod
    def pair_keys(port=48000, vip=p.VIP, backend=p.BACKEND, protocol=17):
        return (p.flow_key(sport=port, destination=vip, protocol=protocol),
                p.flow_key(backend, p.CLIENT, 8080, port, protocol))


def tcp_key(key, epoch=1):
    return key + struct.pack("<QQ", epoch, epoch + 100)


def create(runner, port=51000, protocol=17, vip=p.VIP, backend=p.BACKEND):
    p.publish(runner, protocol, vip=vip, backend=backend)
    original = p.packet(destination=vip, sport=port, protocol=protocol,
                        seq=1000, tcp_flags=2 if protocol == 6 else 0x18, payload=b"")
    verdict, wire = runner.run("gr8s_packet_forward", original)
    assert verdict == p.OK
    source, destination, sport, dport = p.endpoints(wire)
    forward = n.key(original)
    reverse = p.flow_key(destination, source, dport, sport, protocol)
    return original, wire, forward, reverse


def exercise(runner):
    cases = []
    # Pending UDP publication cannot persist forever if policy never commits.
    p.publish(runner, 17)
    original = p.packet(sport=51000, protocol=17)
    _, _, context = runner.stage(n.NAMES[0], original)
    assert context != n.ZERO
    forward, reverse = Collector.pair_keys(port=51000)
    assert collect(runner, 0, forward) == 0
    runner.advance(6)
    assert collect(runner, 1, reverse) == 1
    assert runner.lookup(n.FWD, forward) is runner.lookup(n.REV, reverse) is None
    cases.append("pendingPolicyClaimExpires")

    for protocol, lifetime in ((17, 180), (6, 120)):
        for direction in (0, 1, 2) if protocol == 6 else (0, 1):
            original, wire, forward, reverse = create(runner, 51010 + direction + protocol, protocol)
            key = (forward, reverse, tcp_key(forward))[direction]
            held = runner.lookup(n.FWD, forward)
            assert collect(runner, direction, key) == 0
            assert runner.lookup(n.FWD, forward) == held
            runner.advance(lifetime + 1)
            aged = runner.lookup(n.FWD, forward)
            for lock, reserved in (("gr8s_nat_fl_v2", forward), ("gr8s_nat_rl_v2", reverse)):
                runner.update(lock, reserved, bytes(8))
                assert collect(runner, direction, key, False) == p.SHOT
                assert runner.lookup(lock, reserved) == bytes(8)
                assert runner.lookup(n.FWD, forward) == aged
                runner.delete(lock, reserved)
                n.unlocked(runner)
                cases.append(f"protocol{protocol}Direction{direction}Preserves{lock}")
            assert collect(runner, direction, key) == 1
            assert runner.lookup(n.FWD, forward) is runner.lookup(n.REV, reverse) is None
            assert runner.lookup(TCP, tcp_key(forward)) is None
            assert collect(runner, direction, key) == 0
            cases.append(f"protocol{protocol}Direction{direction}ExpiryReclaimsPair")

    # An expired forward cannot erase a reverse row carrying another owner.
    _, _, forward, reverse = create(runner, 51100)
    foreign_key = p.flow_key(sport=51100, destination="10.96.0.77")
    foreign = tcp_key(foreign_key)
    runner.update(n.REV, reverse, foreign)
    runner.advance(181)
    assert collect(runner, 0, forward) == 1
    assert runner.lookup(n.REV, reverse) == foreign
    assert collect(runner, 1, reverse) == 1
    cases.append("expiredForwardPreservesForeignReturnOwner")

    # Obsolete reverse rows from a different backend share this source epoch's
    # TCP key with the current generation. Only the obsolete row may be deleted.
    _, _, forward, old_reverse = create(runner, 51101, 6)
    old_return = runner.lookup(n.REV, old_reverse)
    old_tcp = runner.lookup(TCP, tcp_key(forward))
    p.publish(runner, backend="10.88.7.4")
    p.assert_forward(runner, t.tcp.request(51101, 2000), "10.88.7.4")
    current = runner.lookup(n.FWD, forward)
    current_tcp = runner.lookup(TCP, tcp_key(forward))
    new_reverse = p.flow_key("10.88.7.4", p.CLIENT, 8080, 51101, 6)
    current_return = runner.lookup(n.REV, new_reverse)
    runner.update(n.REV, old_reverse, old_return)
    assert collect(runner, 1, old_reverse) == 1
    assert runner.lookup(n.FWD, forward) == current
    assert runner.lookup(TCP, tcp_key(forward)) == current_tcp
    assert runner.lookup(n.REV, new_reverse) == current_return
    cases.append("obsoleteReversePreservesSameEpochReplacementTCP")

    # Orphan metadata with no forward row is independently discoverable.
    orphan = p.flow_key(sport=51102, protocol=6)
    runner.update(TCP, tcp_key(orphan), old_tcp)
    assert collect(runner, 2, tcp_key(orphan)) == 1
    assert runner.lookup(TCP, tcp_key(orphan)) is None
    cases.append("orphanTCPWithoutForwardReclaimed")

    # Previous-incarnation metadata/reverse state must never erase the new one.
    n.owner(runner, n.CLIENT, n.ALIAS, 2)
    p.publish(runner, backend="10.88.8.4")
    p.assert_forward(runner, t.tcp.request(51101, 3000), "10.88.8.4")
    current = runner.lookup(n.FWD, forward)
    current_tcp = runner.lookup(TCP, tcp_key(forward, 2))
    new_reverse = p.flow_key("10.88.8.4", p.CLIENT, 8080, 51101, 6)
    current_return = runner.lookup(n.REV, new_reverse)
    runner.update(TCP, tcp_key(forward), old_tcp)
    runner.update(n.REV, old_reverse, old_return)
    assert collect(runner, 2, tcp_key(forward)) == 1
    assert collect(runner, 1, old_reverse) == 1
    assert runner.lookup(n.FWD, forward) == current
    assert runner.lookup(TCP, tcp_key(forward, 2)) == current_tcp
    assert runner.lookup(n.REV, new_reverse) == current_return
    cases.append("oldEpochOrphansPreserveReplacement")
    n.owner(runner, n.CLIENT, n.ALIAS, 1)

    # Invalid envelopes never acquire reservations or touch legitimate state.
    for kind, key in ((3, forward), (2, forward), (2, forward + bytes(16)),
                      (0, forward[:13] + b"\x01" + forward[14:])):
        assert collect(runner, kind, key) == 3
    cases.append("invalidEnvelopeRefused")
    return cases


def metadata_fence(runner):
    cases = []
    for missing in (True, False):
        port = 51200 + missing
        original, wire, forward, reverse = create(runner, port, 6)
        key = tcp_key(forward)
        if missing:
            runner.delete(TCP, key)
        else:
            wrong = bytearray(runner.lookup(TCP, key))
            wrong[:8] = p.backend_value("10.88.9.9")
            struct.pack_into("<H", wrong, 48, 128)  # Cannot impose a foreign reset lifetime.
            runner.update(TCP, key, wrong)
        before = runner.lookup(n.FWD, forward)
        response = p.packet(p.BACKEND, p.CLIENT, 8080, port, seq=9000, ack=1001,
                            tcp_flags=0x12, payload=b"")
        for name, data in (("gr8s_packet_forward", t.tcp.request(port, 1001, 9001, 0x10)),
                           ("gr8s_packet_forward", original), ("gr8s_packet_reverse", response)):
            verdict, _ = runner.run(name, data)
            assert verdict == p.SHOT
            assert runner.lookup(n.FWD, forward) == before
        runner.advance(11)
        assert collect(runner, 0, forward) == 0
        assert runner.lookup(n.REV, reverse) is not None
        runner.advance(7200)
        assert collect(runner, 0, forward) == 1
        assert runner.lookup(n.FWD, forward) is runner.lookup(n.REV, reverse) is None
        assert runner.lookup(TCP, key) is None
        cases.append("missingMetadataFailsClosed" if missing else "mismatchedMetadataFailsClosed")
    return cases


def capacity(factory):
    cases = []
    runner = factory(1, 1, 1)
    try:
        _, _, first, reverse = create(runner, 51300, 6)
        verdict, _ = runner.run("gr8s_packet_forward", t.tcp.request(51301, 2000))
        assert verdict == p.SHOT
        runner.advance(121)
        assert collect(runner, 0, first) == 1
        assert runner.lookup(n.REV, reverse) is None
        p.assert_forward(runner, t.tcp.request(51301, 2000))
        cases.append("oneEntryMapsRecoverAfterPairCollection")
    finally:
        runner.close()

    runner = factory(1, 2, 1)
    try:
        _, _, first, _ = create(runner, 51310, 6)
        current = runner.lookup(TCP, tcp_key(first))
        verdict, _ = runner.run("gr8s_packet_forward", t.tcp.request(51311, 2000))
        assert verdict == p.SHOT
        second, reverse = Collector.pair_keys(port=51311, protocol=6)
        assert runner.lookup(n.FWD, second) is None
        assert runner.lookup(n.REV, reverse) is not None
        assert collect(runner, 1, reverse) == 1
        assert runner.lookup(n.REV, reverse) is None
        assert runner.lookup(TCP, tcp_key(first)) == current
        cases.append("InterruptedForwardCapacityClaimCollectedWithoutStealingTCP")
    finally:
        runner.close()

    runner = factory(4, 4, 1)
    try:
        orphan = tcp_key(p.flow_key(sport=51320, protocol=6))
        runner.update(TCP, orphan, p.backend_value(p.BACKEND) + bytes(56))
        p.publish(runner)
        verdict, _ = runner.run("gr8s_packet_forward", t.tcp.request(51321, 2000))
        assert verdict == p.SHOT
        forward = p.flow_key(sport=51321, protocol=6)
        assert runner.lookup(n.FWD, forward)[39] == 0
        assert collect(runner, 2, orphan) == 1
        p.assert_forward(runner, t.tcp.request(51321, 2000))
        assert runner.lookup(TCP, tcp_key(forward)) is not None
        cases.append("MetadataCapacityRecoversAfterOrphanCollection")
    finally:
        runner.close()
    return cases


def concurrent_packets(runner, threaded):
    """Race maintenance against live tuple owners; never age state mid-syscall."""
    flows = []
    for destination, dport in ((p.VIP, 80), ("10.96.0.91", 80), (p.BACKEND, 8080)):
        if dport == 80:
            p.publish(runner, 17, vip=destination)
        original = p.packet(destination=destination, dport=dport, sport=51400, protocol=17)
        verdict, wire = runner.run("gr8s_packet_forward", original)
        assert verdict == p.OK
        flows.append((original, wire))
    c, s = t.tcp.establish(runner, 51401)
    original = t.tcp.request(51401, c, s, 0x10)
    verdict, wire = runner.run("gr8s_packet_forward", original)
    assert verdict == p.OK
    flows.append((original, wire))
    barrier = threading.Barrier(6) if threaded else None

    def worker(index):
        if barrier:
            barrier.wait()
        passed = dropped = reclaimed = 0
        for _ in range(64):
            if index < 4:
                original, previous_wire = flows[index]
                verdict, selected, context = runner.stage(n.NAMES[0], original)
                assert verdict in (p.OK, p.SHOT)
                if verdict == p.SHOT:
                    dropped += 1
                    continue
                verdict, wire, context = runner.stage(n.NAMES[1], selected, context)
                assert verdict in (p.OK, p.SHOT)
                if verdict == p.SHOT:
                    dropped += 1
                    continue
                assert context == n.ZERO
                assert p.endpoints(wire) == p.endpoints(previous_wire)
                p.check_checksums(wire)
                source, backend, sport, dport = p.endpoints(wire)
                response = p.packet(backend, source, dport, sport, protocol=wire[23],
                                    seq=s, ack=c, tcp_flags=0x10, payload=b"reply")
                verdict, prepared, context = runner.stage(n.NAMES[2], response)
                assert verdict in (p.OK, p.SHOT)
                if verdict == p.SHOT:
                    dropped += 1
                    continue
                verdict, restored, context = runner.stage(n.NAMES[3], prepared, context)
                assert verdict in (p.OK, p.SHOT)
                if verdict == p.SHOT:
                    dropped += 1
                    continue
                client, destination, original_port, original_dport = p.endpoints(original)
                assert p.endpoints(restored) == (destination, client, original_dport, original_port)
                assert context == n.ZERO
                p.check_checksums(restored)
                passed += 1
            else:
                for original, wire in flows:
                    source, backend, sport, dport = p.endpoints(wire)
                    kind = index - 4
                    key = (n.key(original) if kind == 0 else
                           p.flow_key(backend, source, dport, sport, wire[23]))
                    verdict = collect(runner, kind, key, False)
                    assert verdict in (0, 1, p.SHOT)
                    passed += verdict == 0
                    reclaimed += verdict == 1
                    dropped += verdict == p.SHOT
                if index == 5:
                    verdict = collect(runner, 2, tcp_key(n.key(flows[3][0])), False)
                    assert verdict in (0, 1, p.SHOT)
                    passed += verdict == 0
                    reclaimed += verdict == 1
                    dropped += verdict == p.SHOT
        return dict(worker=index, completed=passed, deferred=dropped, reclaimed=reclaimed)

    if threaded:
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(worker, range(6)))
    else:
        results = [worker(index) for index in range(6)]
    n.unlocked(runner)
    for original, wire in flows:
        verdict, current = runner.run("gr8s_packet_forward", original)
        assert verdict == p.OK and p.endpoints(current) == p.endpoints(wire)
    assert t.tcp.tcp_flags(runner, 51401) & 4
    return dict(threaded=threaded, iterations=64, workers=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=n.NAMES)
    cls = t.Kernel if args.kernel else t.Interpreter
    results = {}
    for name, function in (("ownership", exercise), ("metadataFence", metadata_fence),
                           ("tcpClosure", lambda r: t.tcp.closure_gc(r, Collector)),
                           ("tcpLifetimes", lambda r: t.tcp.gc_exercise(r, Collector))):
        runner = cls(programs, ids, descriptors)
        try:
            results[name] = function(runner)
        finally:
            runner.close()

    def factory(forward, reverse, tcp):
        limited = dict(descriptors)
        for name, count in ((n.FWD, forward), (n.REV, reverse), (TCP, tcp)):
            row = list(limited[name])
            row[3] = count
            limited[name] = tuple(row)
        return cls(programs, ids, limited)

    results["capacity"] = capacity(factory)
    runner = cls(programs, ids, descriptors)
    try:
        results["packetsDuringCollection"] = concurrent_packets(runner, args.kernel)
    finally:
        runner.close()
    print(json.dumps({"passed": True, "kernel": args.kernel, "cases": results}))


if __name__ == "__main__":
    main()
