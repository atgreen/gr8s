#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise SYN generations/handshake metadata in the actual packet bytecode.

Run unprivileged by default; --kernel requires a disposable root VM. Full TCP
Window/timestamp handling and the remainder of TCP lifecycle remain in progress.
"""
import importlib.util
from pathlib import Path
import struct
import sys

spec = importlib.util.spec_from_file_location("packet", Path(__file__).with_name("test-service-packet-program.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def request(port, seq, ack=0, flags=2, **kwargs):
    kwargs.setdefault("payload", b"")
    return p.packet(sport=port, seq=seq, ack=ack, tcp_flags=flags, **kwargs)


def reply(port, seq, ack, flags=0x12, backend=p.BACKEND, payload=b"", **kwargs):
    return p.packet(source=backend, destination=p.CLIENT, sport=8080, dport=port,
                    seq=seq, ack=ack, tcp_flags=flags, payload=payload, **kwargs)


def translate_reply(runner, data, port):
    result, output = runner.run("gr8s_packet_reverse", data)
    assert result == p.OK and p.endpoints(output) == (p.VIP, p.CLIENT, 80, port)
    p.check_checksums(output)


def exercise(runner):
    cases = 0
    for index, start in enumerate((1000, 0xfffffff0, 0)):
        port = 50010 + index
        p.publish(runner)
        syn = request(port, start, options=bytes.fromhex("01010100"), tcp_options=bytes(4))
        p.assert_forward(runner, syn)
        # Slot repacking/endpoint replacement must not retarget a retransmission.
        replacement = "10.88.2.4"
        p.publish(runner, backend=replacement)
        p.assert_forward(runner, syn)
        key = p.flow_key(sport=port, protocol=6)
        state = runner.lookup("gr8s_pkt_tcp", key)
        assert len(state) == 64 and struct.unpack_from("<I", state, 8)[0] == start
        assert struct.unpack_from("<I", state, 48)[0] & 1
        next_client = (start + 1) & 0xffffffff
        server_start = (3000, 0xfffffff0, 0)[index]
        next_server = (server_start + 1) & 0xffffffff
        translate_reply(runner, reply(port, server_start, next_client), port)
        translate_reply(runner, reply(port, server_start, next_client), port)
        p.assert_forward(runner, request(port, next_client, next_server, 0x10))
        state = runner.lookup("gr8s_pkt_tcp", key)
        assert struct.unpack_from("<I", state, 48)[0] & 4, "handshake never established"
        assert struct.unpack_from("<I", state, 28)[0] == next_server
        body = b"reply payload"
        translate_reply(runner, reply(port, next_server, next_client, 0x18, payload=body), port)
        server_end = (next_server + len(body)) & 0xffffffff
        p.assert_forward(runner, p.packet(sport=port, seq=next_client, ack=server_end,
                                         tcp_flags=0x18, payload=b"abc"))
        before = runner.lookup("gr8s_pkt_tcp", key)
        p.assert_forward(runner, syn)
        translate_reply(runner, reply(port, server_start, next_client), port)
        after = runner.lookup("gr8s_pkt_tcp", key)
        assert after[16:32] == before[16:32], "SYN retransmission regressed sequence progress"
        # A new initial sequence reusing the exact tuple must select the current
        # backend, without treating old SYN/SYN-ACK packets as this incarnation.
        new_start = (start + 100) & 0xffffffff
        p.assert_forward(runner, request(port, new_start), replacement)
        current = runner.lookup("gr8s_pkt_tcp", key)
        result, unchanged = runner.run("gr8s_packet_forward", syn)
        assert result == p.SHOT and unchanged == syn
        old_reply = reply(port, server_start, next_client)
        result, unchanged = runner.run("gr8s_packet_reverse", old_reply)
        assert result == p.SHOT and unchanged == old_reply
        assert runner.lookup("gr8s_pkt_tcp", key) == current
        # A stale SYN-ACK from the selected backend has the wrong generation ACK.
        stale = reply(port, 7000, next_client, backend=replacement)
        result, unchanged = runner.run("gr8s_packet_reverse", stale)
        assert result == p.SHOT and unchanged == stale
        translate_reply(runner, reply(port, 7000, (new_start + 1) & 0xffffffff, backend=replacement), port)
        p.assert_forward(runner, request(port, (new_start + 1) & 0xffffffff, 7001, 0x10), replacement)
        p.assert_unlocked(runner)
        cases += 17
    # Pending SYN state has its own shorter lifetime; normal established traffic
    # remains pinned beyond that timeout.
    port = 50020
    p.publish(runner)
    p.assert_forward(runner, request(port, 10000))
    runner.advance(121)
    p.publish(runner, backend="10.88.3.9")
    p.assert_forward(runner, request(port, 10000), "10.88.3.9")
    p.assert_forward(runner, request(50011, 85, 7001, 0x10), "10.88.2.4")
    cases += 3
    if isinstance(runner, p.Interpreter):
        p.publish(runner)
        data = request(50025, 20000, options=bytes(4), tcp_options=bytes(40))
        result, output = runner.run("gr8s_packet_forward", data, linear_length=34)
        assert result == p.OK and p.endpoints(output) == (p.CLIENT, p.BACKEND, 50025, 8080)
        p.check_checksums(output)
        cases += 1
    p.publish(runner)
    p.assert_forward(runner, request(50026, 5000))
    translate_reply(runner, reply(50026, 9000, 5001), 50026)
    p.assert_forward(runner, request(50026, 5001, 9001, 0x14))
    state = runner.lookup("gr8s_pkt_tcp", p.flow_key(sport=50026, protocol=6))
    assert not struct.unpack_from("<I", state, 48)[0] & 4, "RST/ACK falsely completed the handshake"
    cases += 1
    # Illegal data offset and SYN control combinations cannot publish state.
    for flags in (3, 6):
        data = request(50030 + flags, 100, flags=flags)
        result, unchanged = runner.run("gr8s_packet_forward", data)
        assert result == p.SHOT and unchanged == data
        assert runner.lookup("gr8s_pkt_tcp", p.flow_key(sport=50030 + flags, protocol=6)) is None
        cases += 1
    data = bytearray(request(50040, 100))
    data[46] = 0x40  # TCP data offset shorter than the minimum header.
    result, _ = runner.run("gr8s_packet_forward", data)
    assert result == p.SHOT
    p.assert_unlocked(runner)
    return cases + 1



def tcp_state(runner, port):
    return runner.lookup("gr8s_pkt_tcp", p.flow_key(sport=port, protocol=6))


def tcp_flags(runner, port):
    return struct.unpack_from("<I", tcp_state(runner, port), 48)[0]


def establish(runner, port, client=1000, server=9000):
    p.publish(runner)
    p.assert_forward(runner, request(port, client))
    translate_reply(runner, reply(port, server, (client + 1) & 0xffffffff), port)
    p.assert_forward(runner, request(port, (client + 1) & 0xffffffff,
                                     (server + 1) & 0xffffffff, 0x10))
    return (client + 1) & 0xffffffff, (server + 1) & 0xffffffff


def closure(runner):
    cases = 0
    for index, start in enumerate((1000, 0xffffffff, 0)):
        for server_first in (False, True):
            port = 50400 + index * 2 + server_first
            c, s = establish(runner, port, start, start)
            key = p.flow_key(sport=port, protocol=6)
            if server_first:
                translate_reply(runner, reply(port, s, c, 0x11), port)
                s = (s + 1) & 0xffffffff
                p.assert_forward(runner, request(port, c, s, 0x10))
                # A half-close still permits application data in the other direction.
                runner.advance(121)
                p.assert_forward(runner, request(port, c, s, 0x18, payload=b"abc"))
                c = (c + 3) & 0xffffffff
                translate_reply(runner, reply(port, s, c, 0x10), port)
                p.assert_forward(runner, request(port, c, s, 0x11))
                c = (c + 1) & 0xffffffff
                assert not tcp_flags(runner, port) & 256
                translate_reply(runner, reply(port, s, c, 0x10), port)
            else:
                # FIN can carry the final data bytes; retransmission must retain it.
                fin = request(port, c, s, 0x11, payload=b"abc")
                p.assert_forward(runner, fin)
                p.assert_forward(runner, fin)
                c = (c + 4) & 0xffffffff
                translate_reply(runner, reply(port, s, c, 0x10), port)
                runner.advance(121)
                translate_reply(runner, reply(port, s, c, 0x18, payload=b"last reply"), port)
                s = (s + len(b"last reply")) & 0xffffffff
                p.assert_forward(runner, request(port, c, s, 0x10))
                translate_reply(runner, reply(port, s, c, 0x11), port)
                s = (s + 1) & 0xffffffff
                assert not tcp_flags(runner, port) & 256
                p.assert_forward(runner, request(port, c, s, 0x10))
            assert tcp_flags(runner, port) & 256, "both FINs acknowledged but state not closed"
            state = tcp_state(runner, port)
            runner.advance(60)
            forward = runner.lookup("gr8s_pkt_forward", key)
            p.assert_forward(runner, request(port, c, s, 0x10))
            translate_reply(runner, reply(port, (s - 1) & 0xffffffff, c, 0x11), port)
            assert tcp_state(runner, port) == state
            assert runner.lookup("gr8s_pkt_forward", key) == forward, "late traffic refreshed tombstone"
            # A new stream can choose the current plan while the old tombstone lives.
            replacement = "10.88.2.4"
            p.publish(runner, backend=replacement)
            new_c = (c + 100) & 0xffffffff
            p.assert_forward(runner, request(port, new_c), replacement)
            translate_reply(runner, reply(port, 7000, (new_c + 1) & 0xffffffff,
                                         backend=replacement), port)
            p.assert_forward(runner, request(port, (new_c + 1) & 0xffffffff, 7001, 0x10), replacement)
            # Old FIN/RST from the same selected backend cannot close the new state.
            for flag in (0x11, 0x14):
                translate_reply(runner, reply(port, s, c, flag, backend=replacement), port)
                assert not tcp_flags(runner, port) & 384
            cases += 16
    for reverse in (False, True):
        port = 50420 + reverse
        c, s = establish(runner, port)
        # A future or old reset cannot poison sequence progress or shorten state.
        before = tcp_state(runner, port)
        for seq in ((s if reverse else c) - 1, (s if reverse else c) + 10000):
            if reverse:
                translate_reply(runner, reply(port, seq, c, 0x14), port)
            else:
                p.assert_forward(runner, request(port, seq, s, 0x14))
            assert not tcp_flags(runner, port) & 128
            assert tcp_state(runner, port)[16:32] == before[16:32]
        # ACK beyond the peer's sent bytes must not change the reset evidence.
        p.assert_forward(runner, request(port, c, s + 10000, 0x10))
        assert tcp_state(runner, port)[24:32] == before[24:32]
        if reverse:
            translate_reply(runner, reply(port, s, c, 0x14), port)
        else:
            p.assert_forward(runner, request(port, c, s, 0x14))
        assert tcp_flags(runner, port) & 128
        key = p.flow_key(sport=port, protocol=6)
        runner.advance(6)
        forward = runner.lookup("gr8s_pkt_forward", key)
        p.assert_forward(runner, request(port, c, s, 0x18, payload=b"late"))
        assert runner.lookup("gr8s_pkt_forward", key) == forward
        runner.advance(5)
        p.publish(runner, backend="10.88.2.4")
        p.assert_forward(runner, request(port, 1000), "10.88.2.4")
        cases += 9
    # Delayed controls from the prior incarnation on the same backend must not
    # teach a new receiver-ACK edge and make an old reset appear current.
    port = 50432
    c, s = establish(runner, port)
    p.assert_forward(runner, request(port, 2000))
    translate_reply(runner, reply(port, 7000, 2001), port)
    p.assert_forward(runner, request(port, 2001, 7001, 0x10))
    translate_reply(runner, reply(port, s, c, 0x11), port)
    p.assert_forward(runner, request(port, c, s + 1, 0x10))
    translate_reply(runner, reply(port, s + 1, 0, 0x04), port)
    assert not tcp_flags(runner, port) & 384, "old FIN/ACK/RST retired the replacement generation"
    cases += 4
    # Refusal in SYN-SENT: ACK identifies the SYN even with an arbitrary RST seq.
    p.publish(runner)
    p.assert_forward(runner, request(50430, 0xffffffff))
    translate_reply(runner, reply(50430, 0, 0, 0x14), 50430)
    assert tcp_flags(runner, 50430) & 128
    p.assert_unlocked(runner)
    return cases + 2




def reordered_closure(runner):
    cases = 0
    for index, start in enumerate((1000, 0xfffffffc, 0)):
        for server_first in (False, True):
            port = 50500 + index * 2 + server_first
            c, s = establish(runner, port, start, start)
            # The FIN arrives before the preceding data. The endpoint's later
            # cumulative ACK proves the gap filled; it must complete the close.
            if server_first:
                translate_reply(runner, reply(port, (s + 3) & 0xffffffff, c, 0x11), port)
                translate_reply(runner, reply(port, s, c, 0x18, payload=b"abc"), port)
                s = (s + 4) & 0xffffffff
                p.assert_forward(runner, request(port, c, s, 0x11))
                c = (c + 1) & 0xffffffff
                assert not tcp_flags(runner, port) & 256
                translate_reply(runner, reply(port, s, c, 0x10), port)
            else:
                p.assert_forward(runner, request(port, (c + 3) & 0xffffffff, s, 0x11))
                p.assert_forward(runner, request(port, c, s, 0x18, payload=b"abc"))
                c = (c + 4) & 0xffffffff
                translate_reply(runner, reply(port, s, c, 0x11), port)
                s = (s + 1) & 0xffffffff
                assert not tcp_flags(runner, port) & 256
                p.assert_forward(runner, request(port, c, s, 0x10))
            assert tcp_flags(runner, port) & 256, "reordered FIN never reached closed state"
            p.assert_unlocked(runner)
            cases += 6
    return cases


def closure_gc(runner, gc):
    cases = 0
    for reverse_gc in (False, True):
        for reset in (False, True):
            port = 50450 + reverse_gc * 2 + reset
            c, s = establish(runner, port)
            if reset:
                translate_reply(runner, reply(port, s, c, 0x14), port)
                lifetime = 10
            else:
                p.assert_forward(runner, request(port, c, s, 0x11))
                translate_reply(runner, reply(port, s, c + 1, 0x11), port)
                p.assert_forward(runner, request(port, c + 1, s + 1, 0x10))
                lifetime = 120
            assert tcp_flags(runner, port) & (128 if reset else 256)
            forward, reverse = gc.pair_keys(port=port, protocol=6)
            key = reverse if reverse_gc else forward
            runner.advance(lifetime - 1)
            assert gc.collect(runner, int(reverse_gc), key) == 0
            runner.advance(2)
            assert gc.collect(runner, int(reverse_gc), key) == 1
            assert runner.lookup("gr8s_pkt_forward", forward) is None
            assert runner.lookup("gr8s_pkt_reverse", reverse) is None
            assert runner.lookup("gr8s_pkt_tcp", forward) is None
            cases += 6
    p.assert_unlocked(runner)
    return cases


def capacity(runner):
    p.publish(runner)
    p.assert_forward(runner, request(50100, 1000))
    data = request(50101, 2000)
    result, unchanged = runner.run("gr8s_packet_forward", data)
    assert result == p.SHOT and unchanged == data
    assert runner.lookup("gr8s_pkt_forward", p.flow_key(sport=50101, protocol=6)) is None
    result, unchanged = runner.run("gr8s_packet_reverse", reply(50101, 4000, 2001))
    assert result == p.SHOT, "missing TCP metadata published a reverse-translatable connection"
    p.assert_forward(runner, request(50100, 1000))
    p.assert_unlocked(runner)
    return 4


def gc_exercise(runner, gc):
    p.publish(runner)
    forward, reverse = gc.pair_keys(port=50200, protocol=6)
    p.assert_forward(runner, request(50200, 1000))
    runner.advance(121)
    assert gc.collect(runner, 0, forward) == 1
    assert runner.lookup("gr8s_pkt_tcp", forward) is None
    assert runner.lookup("gr8s_pkt_reverse", reverse) is None
    forward, reverse = gc.pair_keys(port=50201, protocol=6)
    p.assert_forward(runner, request(50201, 3000))
    translate_reply(runner, reply(50201, 4000, 3001), 50201)
    p.assert_forward(runner, request(50201, 3001, 4001, 0x10))
    state = runner.lookup("gr8s_pkt_tcp", forward)
    runner.advance(121)
    assert gc.collect(runner, 1, reverse) == 0
    assert runner.lookup("gr8s_pkt_tcp", forward) == state
    runner.advance(7200)
    assert gc.collect(runner, 1, reverse) == 1
    assert runner.lookup("gr8s_pkt_tcp", forward) is None
    p.assert_unlocked(runner)
    return 6


def gc_capacity(runner, gc):
    p.publish(runner)
    first, _ = gc.pair_keys(port=50300, protocol=6)
    second, reverse = gc.pair_keys(port=50301, protocol=6)
    p.assert_forward(runner, request(50300, 1000))
    state = runner.lookup("gr8s_pkt_tcp", first)
    result, _ = runner.run("gr8s_packet_forward", request(50301, 2000))
    assert result == p.SHOT
    assert runner.lookup("gr8s_pkt_tcp", second) is not None
    assert runner.lookup("gr8s_pkt_forward", second) is None
    assert gc.collect(runner, 1, reverse) == 1
    assert runner.lookup("gr8s_pkt_tcp", second) is None
    assert runner.lookup("gr8s_pkt_tcp", first) == state
    runner.advance(121)
    assert gc.collect(runner, 0, first) == 1
    p.assert_forward(runner, request(50301, 2000))
    p.assert_unlocked(runner)
    return 6


def main():
    programs, ids, descriptors = p.read_fixture(sys.argv[1])
    gc = None
    if len(sys.argv) > 2 and not sys.argv[2].startswith("--"):
        spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("test-service-packet-gc.py"))
        gc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gc)
        maintenance, gc_ids, gc_specs = p.read_fixture(sys.argv[2], names=("gr8s_packet_gc",))
        assert gc_ids == ids and gc_specs == descriptors
        programs.update(maintenance)
    cls = p.Kernel if "--kernel" in sys.argv[2:] else p.Interpreter
    runner = cls(programs, ids, descriptors)
    try:
        print(f"Service TCP generations ({cls.__name__}): {exercise(runner)} cases passed")
    finally:
        runner.close()
    runner = cls(programs, ids, descriptors)
    try:
        print(f"Service TCP closure ({cls.__name__}): {closure(runner)} cases passed")
        print(f"Service TCP reordered close: {reordered_closure(runner)} cases passed")
    finally:
        runner.close()
    limited = dict(descriptors)
    kind, key_size, value_size, _, flags = limited["gr8s_pkt_tcp"]
    limited["gr8s_pkt_tcp"] = kind, key_size, value_size, 1, flags
    runner = cls(programs, ids, limited)
    try:
        print(f"Service TCP metadata capacity: {capacity(runner)} cases passed")
    finally:
        runner.close()
    if gc:
        runner = cls(programs, ids, descriptors)
        try:
            print(f"Service TCP closure GC: {closure_gc(runner, gc)} cases passed")
        finally:
            runner.close()
        runner = cls(programs, ids, descriptors)
        try:
            print(f"Service TCP metadata GC: {gc_exercise(runner, gc)} cases passed")
        finally:
            runner.close()
        limited = dict(descriptors)
        kind, key_size, value_size, _, flags = limited["gr8s_pkt_forward"]
        limited["gr8s_pkt_forward"] = kind, key_size, value_size, 1, flags
        runner = cls(programs, ids, limited)
        try:
            print(f"Service TCP orphan/capacity GC: {gc_capacity(runner, gc)} cases passed")
        finally:
            runner.close()


if __name__ == "__main__":
    main()
