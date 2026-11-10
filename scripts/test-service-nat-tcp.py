#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Run the existing TCP evidence through the staged v2 NAT graph.

Identities and receiver capability are supplied by this fixture. No agent,
NetworkPolicy, CNI, guest or real TCP socket integration is claimed.
"""
import argparse
import importlib.util
import ipaddress
import json
import struct
from pathlib import Path


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nat = load("nat", "test-service-nat.py")
tcp = load("tcp", "test-service-tcp-state.py")
tcp.p = nat.packet


class Adapter:
    aliases = {"gr8s_pkt_tcp": "gr8s_nat_tcp_v2", "gr8s_pkt_forward": nat.FWD,
               "gr8s_pkt_reverse": nat.REV, "gr8s_pkt_stats": "gr8s_nat_st_v2",
               "gr8s_pkt_fwd_lock": "gr8s_nat_fl_v2", "gr8s_pkt_rev_lock": "gr8s_nat_rl_v2"}

    def __init__(self, *args):
        super().__init__(*args)
        nat.owner(self, nat.CLIENT, nat.ALIAS, 1)
        if isinstance(self, nat.Interpreter):
            for name in ("gr8s_pkt_fwd_lock", "gr8s_pkt_rev_lock"):
                self.maps.entries[name] = self.maps.entries[self.aliases[name]]

    def lookup(self, name, key):
        if name == "gr8s_pkt_tcp":
            key += struct.pack("<QQ", 1, 101)
        value = super().lookup(self.aliases.get(name, name), key)
        return value[:16] if name == "gr8s_pkt_forward" and value else value

    def update(self, name, key, value):
        if name == "gr8s_pkt_tcp":
            key += struct.pack("<QQ", 1, 101)
        if name == "gr8s_backend_v4":
            backend = str(ipaddress.ip_address(value[:4]))
            number = int(ipaddress.ip_address(backend))
            alias = str(ipaddress.ip_address(0xac1f0000 | (number & 0xffff)))
            if backend != nat.CLIENT:
                nat.owner(self, backend, alias, number)
        return super().update(self.aliases.get(name, name), key, value)

    def keys(self, name):
        return super().keys(self.aliases.get(name, name))

    def run(self, name, data, linear_length=None):
        self.linear_length = linear_length
        try:
            first, second = ((nat.NAMES[0], nat.NAMES[1]) if name == "gr8s_packet_forward"
                             else (nat.NAMES[2], nat.NAMES[3]))
            verdict, output, context = self.stage(first, data)
            if verdict == nat.packet.OK:
                verdict, output, _ = self.stage(second, output, context)
            nat.unlocked(self)
            return verdict, output
        finally:
            self.linear_length = None


class Interpreter(Adapter, nat.Interpreter):
    pass


class Kernel(Adapter, nat.Kernel):
    pass


def translated_streams(runner):
    """Independent live TCP generations behind colliding and hairpin tuples."""
    p = nat.packet
    port = 50900
    streams = []

    def stage(name, data, context=nat.ZERO, verdict=p.OK):
        result, output, outgoing = runner.stage(name, data, context)
        assert result == verdict, (name, result, p.endpoints(data))
        nat.unlocked(runner)
        if result == p.OK:
            p.check_checksums(output)
        return output, outgoing

    def forward(data):
        selected, context = stage(nat.NAMES[0], data)
        wire, context = stage(nat.NAMES[1], selected, context)
        assert context == nat.ZERO
        return wire

    def reply(stream, seq, ack, flags, timestamp):
        request = stream["wire"]
        source, backend, sport, dport = p.endpoints(request)
        response = p.packet(backend, source, dport, sport, seq=seq, ack=ack,
                            tcp_flags=flags, payload=b"",
                            tcp_options=tcp.options(timestamp, echo=stream["stamp"]))
        # A local backend must not classify its reply as a new direct request.
        outgoing, context = stage(nat.NAMES[0], response)
        assert outgoing == response and context == nat.ZERO
        outgoing, context = stage(nat.NAMES[1], outgoing, context)
        assert outgoing == response and context == nat.ZERO
        prepared, context = stage(nat.NAMES[2], response)
        restored, context = stage(nat.NAMES[3], prepared, context)
        assert p.endpoints(restored) == (stream["destination"], nat.CLIENT, stream["dport"], port)
        assert context == nat.ZERO
        return response

    for index, (destination, dport, backend) in enumerate((
            (p.VIP, 80, nat.BACKEND), ("10.96.0.61", 80, nat.BACKEND),
            (nat.BACKEND, 8080, nat.BACKEND), ("10.96.0.62", 80, nat.CLIENT))):
        if dport == 80:
            p.publish(runner, vip=destination, backend=backend)
        start, server, stamp = 1000 + index * 100, 9000 + index * 100, 100 + index * 10
        syn = p.packet(destination=destination, dport=dport, sport=port, seq=start,
                       tcp_flags=2, payload=b"", tcp_options=tcp.options(stamp, 7))
        wire = forward(syn)
        assert (p.endpoints(wire)[0] == nat.ALIAS) == bool(index)
        stream = dict(destination=destination, dport=dport, wire=wire, stamp=stamp,
                      start=start, server=server, key=nat.key(syn))
        streams.append(stream)
        reply(stream, server, start + 1, 0x12, 300 + index)
        ack = p.packet(destination=destination, dport=dport, sport=port, seq=start + 1,
                       ack=server + 1, tcp_flags=0x10, payload=b"",
                       tcp_options=tcp.options(stamp + 1, echo=300 + index))
        assert p.endpoints(forward(ack)) == p.endpoints(wire)
        state = runner.lookup("gr8s_pkt_tcp", stream["key"])
        assert struct.unpack_from("<H", state, 48)[0] & 4

    # Interleave all four streams; the shared original source port must not mix
    # endpoint/timestamp/sequence metadata between separate Service/direct keys.
    for index, stream in enumerate(streams):
        reply(stream, stream["server"] + 1, stream["start"] + 1, 0x10, 310 + index)
        state = runner.lookup("gr8s_pkt_tcp", stream["key"])
        assert struct.unpack_from("<II", state, 8) == (stream["start"], stream["server"])

    # A fresh SYN can move one alias-backed stream to a replacement backend;
    # the old alias reply must lose its claim while other streams stay valid.
    stream = streams[1]
    old_reply = reply(stream, stream["server"] + 1, stream["start"] + 1, 0x10, 320)
    p.publish(runner, vip=stream["destination"], backend="10.88.7.4")
    fresh = p.packet(destination=stream["destination"], sport=port, seq=5000,
                     tcp_flags=2, payload=b"", tcp_options=tcp.options(500, 7))
    wire = forward(fresh)
    assert p.endpoints(wire)[1] == "10.88.7.4"
    stage(nat.NAMES[2], old_reply, verdict=p.SHOT)
    for survivor in (streams[0], streams[2], streams[3]):
        reply(survivor, survivor["server"] + 1, survivor["start"] + 1, 0x10, 330)
    return 22


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = nat.packet.read_fixture(args.fixture, names=nat.NAMES)
    cls = Kernel if args.kernel else Interpreter
    results = {}
    for name in ("exercise", "closure", "early_data_refusal", "early_data_handshake",
                 "reordered_closure", "option_exercise", "simultaneous_open",
                 "retained_option_compatibility", "translated_streams"):
        runner = cls(programs, ids, descriptors)
        try:
            if name == "exercise":
                results[name] = tcp.exercise(runner, unclaimed_reply_verdict=nat.packet.OK)
            else:
                results[name] = (translated_streams if name == "translated_streams"
                                 else getattr(tcp, name))(runner)
        finally:
            runner.close()
    limited = dict(descriptors)
    values = list(limited["gr8s_nat_tcp_v2"])
    values[3] = 1
    limited["gr8s_nat_tcp_v2"] = tuple(values)
    runner = cls(programs, ids, limited)
    try:
        p = nat.packet
        p.publish(runner)
        p.assert_forward(runner, tcp.request(50100, 1000))
        first_key = p.flow_key(sport=50100, protocol=6)
        first = runner.lookup("gr8s_pkt_tcp", first_key)
        second_key = p.flow_key(sport=50101, protocol=6)
        verdict, _ = runner.run("gr8s_packet_forward", tcp.request(50101, 2000))
        assert verdict == p.SHOT
        assert runner.lookup("gr8s_pkt_tcp", second_key) is None
        pending = runner.lookup(nat.FWD, second_key)
        assert pending[39] == 0, "failed metadata publication activated pending claim"
        verdict, _ = runner.run("gr8s_packet_reverse", tcp.reply(50101, 4000, 2001))
        assert verdict == p.SHOT, "metadata capacity failure authorized a reply"
        assert runner.lookup("gr8s_pkt_tcp", first_key) == first
        p.assert_forward(runner, tcp.request(50100, 1000))
        results["metadata_capacity"] = 6
    finally:
        runner.close()
    print(json.dumps({"passed": True, "kernel": args.kernel, "cases": results}))


if __name__ == "__main__":
    main()
