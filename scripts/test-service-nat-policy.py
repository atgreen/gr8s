#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Test standalone alias-aware authorization; --kernel requires a disposable VM.

Identity rows, managed CIDRs and local epochs are fixture-supplied. No CNI or
receiver-ack integration is claimed. Authorization must never rewrite/redirect.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("nat", Path(__file__).with_name("test-service-nat.py"))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)
p, e = n.packet, n.packet.endpoint
NAMES = ("gr8s_egress_guard", "gr8s_ingress_guard")
LOCAL, LOCAL_ALIAS = "10.88.1.2", "10.88.1.9"
PEER, ALIAS = "10.88.2.3", "10.88.2.9"
FLOWS, PODS = "netpol_flows_v2", "gr8s_nat_pod_v2"


def address(value):
    return ipaddress.ip_address(value).packed


def identity(epoch=1, mode=1, mac=e.MAC):
    return (struct.pack("<IIII", int(ipaddress.ip_address(LOCAL)),
                        int.from_bytes(mac[:4], "big"), int.from_bytes(mac[4:], "big"), mode)
            + e.IP6 + struct.pack("<QQ", epoch, epoch + 100))


def setup(runner):
    n.owner(runner, LOCAL, LOCAL_ALIAS, 1)
    n.owner(runner, PEER, ALIAS, 2)
    runner.update("endpoint_identity", bytes(4), identity())
    runner.update(PODS, e.cidr_key("10.88.0.0/16"), b"\x01")


def isolated(runner, egress=1, ingress=1):
    runner.update("netpol_mode", struct.pack("<I", 0), struct.pack("<I", egress))
    runner.update("netpol_mode", struct.pack("<I", 1), struct.pack("<I", ingress))


def allow(runner, direction, cidr, group=1, protocol=None, port=None):
    runner.update(f"netpol_{direction}_cidr", e.cidr_key(cidr), struct.pack("<I", group))
    runner.update(f"netpol_{direction}_ports", e.port_key(group, protocol, port), b"\x01")


def v4(source=LOCAL, destination=PEER, sport=40000, dport=8080, protocol=6, mac=e.MAC):
    data = p.packet(source, destination, sport, dport, protocol, payload=b"policy")
    return data[:6] + mac + data[12:]


def check(runner, direction, data, expected):
    verdict, output = runner.run(NAMES[direction], data)
    assert verdict == expected, (NAMES[direction], verdict, expected, data[26:34].hex())
    assert output == data, "authorization rewrote or redirected the packet"
    if data[12:14] == b"\x08\x00":
        p.check_checksums(output)


def flow_key(peer, pod_port, peer_port, protocol=6, epoch=2):
    return (address(peer) + struct.pack("!HHBBH", pod_port, peer_port, protocol, 0, 0)
            + bytes(4) + (struct.pack("<QQ", epoch, epoch + 100) if epoch else bytes(16)))


def canonical_rules(runner):
    cases = []
    isolated(runner)
    allow(runner, "ingress", PEER + "/32", protocol=6, port=8080)
    incoming = v4(ALIAS, LOCAL, 50000, 8080)
    check(runner, 1, incoming, p.OK)
    key = flow_key(ALIAS, 8080, 50000)
    assert runner.lookup(FLOWS, key) is not None
    assert runner.lookup(FLOWS, flow_key(PEER, 8080, 50000)) is None
    cases.append("selectorPrimaryMatchesAliasButStateKeepsWirePeer")
    check(runner, 0, v4(LOCAL, ALIAS, 8080, 50000), p.OK)
    check(runner, 0, v4(LOCAL, PEER, 8080, 50000), p.SHOT)
    check(runner, 0, v4(LOCAL, ALIAS, 8080, 50001), p.SHOT)
    cases.append("replyExceptionDoesNotAuthorizeOtherWireAddressOrPort")

    # A missing owner must fail before an old reply exception or broad CIDR can
    # classify the alias as an unrelated external address.
    runner.delete(n.IDENT, address(ALIAS))
    allow(runner, "egress", "0.0.0.0/0")
    check(runner, 0, v4(LOCAL, ALIAS, 8080, 50000), p.SHOT)
    check(runner, 1, incoming, p.SHOT)
    assert runner.lookup(FLOWS, key) is not None
    cases.append("missingManagedAliasCannotBypassRulesOrInheritException")
    n.owner(runner, PEER, ALIAS, 2)
    return cases


def exceptions(runner):
    cases = []
    isolated(runner)
    for direction in ("egress", "ingress"):
        allow(runner, direction, "0.0.0.0/0")
        # Longest-prefix group0 has no port entries: IPBlock except Pod IP.
        runner.update(f"netpol_{direction}_cidr", e.cidr_key(PEER + "/32"), bytes(4))
    for protocol in (6, 17):
        check(runner, 0, v4(LOCAL, ALIAS, 41000 + protocol, 8080, protocol), p.SHOT)
        check(runner, 1, v4(ALIAS, LOCAL, 51000 + protocol, 8080, protocol), p.SHOT)
        check(runner, 0, v4(LOCAL, PEER, 42000 + protocol, 8080, protocol), p.SHOT)
        cases.append(f"protocol{protocol}IPBlockExceptUsesCanonicalPod")
    # Allowing the alias CIDR alone cannot manufacture permission for its owner.
    allow(runner, "ingress", ALIAS + "/32", group=2)
    check(runner, 1, v4(ALIAS, LOCAL, 52000, 8080), p.SHOT)
    cases.append("aliasCIDRDoesNotOverridePrimaryException")
    # Unknown addresses outside the managed pool retain external IPBlock semantics.
    check(runner, 0, v4(LOCAL, "203.0.113.8", 43000, 443), p.OK)
    assert runner.lookup(FLOWS, flow_key("203.0.113.8", 43000, 443, epoch=0)) is not None
    check(runner, 1, v4("203.0.113.9", LOCAL, 53000, 8080), p.OK)
    check(runner, 0, v4(LOCAL, "10.88.4.99", 44000, 443), p.SHOT)
    check(runner, 1, v4("10.88.4.99", LOCAL, 54000, 8080), p.SHOT)
    cases.append("unknownManagedPeerDropsWhileExternalCIDRsStillWork")
    return cases


def reuse(runner):
    isolated(runner)
    allow(runner, "ingress", PEER + "/32")
    incoming = v4(ALIAS, LOCAL, 50000, 8080)
    reply = v4(LOCAL, ALIAS, 8080, 50000)
    check(runner, 1, incoming, p.OK)
    check(runner, 0, reply, p.OK)
    old_key = flow_key(ALIAS, 8080, 50000)
    old_stamp = runner.lookup(FLOWS, old_key)
    n.owner(runner, "10.88.3.4", ALIAS, 3)
    check(runner, 0, reply, p.SHOT)
    check(runner, 1, incoming, p.SHOT)
    assert runner.lookup(FLOWS, old_key) == old_stamp
    allow(runner, "ingress", "10.88.3.4/32", group=3)
    check(runner, 1, incoming, p.OK)
    check(runner, 0, reply, p.OK)
    new_key = flow_key(ALIAS, 8080, 50000, epoch=3)
    assert runner.lookup(FLOWS, new_key) is not None
    assert runner.lookup(FLOWS, old_key) == old_stamp
    n.owner(runner, "10.88.3.4", ALIAS, 4)
    check(runner, 0, reply, p.SHOT)
    assert runner.lookup(FLOWS, flow_key(ALIAS, 8080, 50000, epoch=4)) is None
    return ["aliasReuseCannotInheritOldReplyPermission", "primaryAndAliasReuseWithSameIPChangesEpoch"]


def invalid_owners(runner):
    isolated(runner)
    allow(runner, "egress", "0.0.0.0/0")
    allow(runner, "ingress", "0.0.0.0/0")
    original = runner.lookup(n.IDENT, address(ALIAS))
    cases = []
    for name, offset, value, fmt in (("disabled", 4, 0x20000, "<I"),
                                   ("wrongABI", 4, 0x30007, "<I"),
                                   ("wrongRole", 28, 3, "<I"),
                                   ("differentEpoch", 8, 999, "<Q"),
                                   ("differentAlias", 0, 0, "<I")):
        bad = bytearray(original)
        struct.pack_into(fmt, bad, offset, value)
        runner.update(n.IDENT, address(ALIAS), bad)
        check(runner, 1, v4(ALIAS, LOCAL, 50000, 8080), p.SHOT)
        check(runner, 0, v4(LOCAL, ALIAS, 40000, 8080), p.SHOT)
        cases.append(name + "AliasDropsBothDirections")
    runner.update(n.IDENT, address(ALIAS), original)
    runner.delete(n.IDENT, address(PEER))
    check(runner, 1, v4(ALIAS, LOCAL, 50000, 8080), p.SHOT)
    check(runner, 0, v4(LOCAL, ALIAS, 40000, 8080), p.SHOT)
    cases.append("missingPrimaryPairDropsBothDirections")
    return cases


def local_fence_and_legacy(runner):
    cases = []
    packet = v4()
    check(runner, 0, packet, p.OK)
    check(runner, 0, v4(mac=bytes(6)), p.SHOT)
    check(runner, 0, v4(source=PEER), p.SHOT)
    check(runner, 0, e.arp(), p.OK)
    check(runner, 0, e.arp(sender_mac=bytes(6)), p.SHOT)
    ipv6 = e.datagram6(e.IP6, ipaddress.ip_address("fd42::3").packed, 6, 40000, 443)
    incoming6 = e.datagram6(ipaddress.ip_address("fd42::3").packed, e.IP6, 6, 50000, 443)
    check(runner, 0, ipv6, p.OK)
    check(runner, 1, incoming6, p.OK)
    cases.append("canonicalSourceMACIPv4AndARPChecksRemain")
    for bad in (identity(epoch=2), identity(mode=0), identity(mode=3), bytes(48)):
        runner.update("endpoint_identity", bytes(4), bad)
        check(runner, 0, packet, p.SHOT)
        check(runner, 1, v4(PEER, LOCAL), p.SHOT)
        check(runner, 0, e.arp(), p.SHOT)
        check(runner, 0, ipv6, p.SHOT)
        check(runner, 1, incoming6, p.SHOT)
    cases.append("localEpochAndInitializedIdentityFenceAllFamilies")
    runner.update("endpoint_identity", bytes(4), identity())
    n.owner(runner, LOCAL, LOCAL_ALIAS, 9)
    check(runner, 0, packet, p.SHOT)
    check(runner, 1, v4(PEER, LOCAL), p.SHOT)
    n.owner(runner, LOCAL, LOCAL_ALIAS, 1)
    isolated(runner)
    # Egress to node DNS and host-local destinations answers to egress policy
    # (podster-5hv.10): refused under isolation until a rule allows it, and then
    # authorized without any redirect or L2 mutation before the eventual NAT
    # commit/delivery stage. Ingress from the Pod's node stays exempt.
    runner.update("host_redirect_v4", address("192.0.2.1"), b"\x01")
    check(runner, 0, v4(destination="169.254.1.1", dport=53, protocol=17), p.SHOT)
    check(runner, 0, v4(destination="192.0.2.1", dport=443), p.SHOT)
    check(runner, 1, v4("192.0.2.1", LOCAL, 53000, 443), p.OK)
    check(runner, 1, v4("192.0.2.2", LOCAL, 53000, 443), p.SHOT)
    cases.append("nodeDestinationsAnswerToEgressPolicy")
    allow(runner, "egress", "169.254.1.1/32")
    allow(runner, "egress", "192.0.2.1/32")
    check(runner, 0, v4(destination="169.254.1.1", dport=53, protocol=17), p.OK)
    check(runner, 0, v4(destination="192.0.2.1", dport=443), p.OK)
    cases.append("allowedNodeDestinationsAuthorizeWithoutEarlyRedirect")
    allow(runner, "egress", PEER + "/32")
    runner.update("local_pod_v4", e.cidr_key(PEER + "/32"),
                  struct.pack("<I", 12345) + bytes.fromhex("020000000001020000000002"))
    check(runner, 0, v4(), p.OK)
    cases.append("sameNodeAuthorizationDoesNotRewriteOrDeliverBeforeCommit")
    for direction in ("egress", "ingress"):
        runner.update(f"netpol_{direction}_cidr_v6", e.cidr_key6("fd42::/64"), struct.pack("<I", 5))
        runner.update(f"netpol_{direction}_ports_v6", e.port_key(5, 6, 443), b"\x01")
    check(runner, 0, ipv6, p.OK)
    check(runner, 1, incoming6, p.OK)
    check(runner, 0, e.datagram6(e.IP6, ipaddress.ip_address("fd43::3").packed, 6, 40000, 443), p.SHOT)
    cases.append("canonicalIPv6PolicyRemainsSeparateFromIPv4Aliases")
    return cases


def self_traffic(runner):
    isolated(runner)
    for protocol in (6, 17):
        check(runner, 0, v4(LOCAL, LOCAL, 40000, 8080, protocol), p.OK)
        check(runner, 1, v4(LOCAL, LOCAL, 40000, 8080, protocol), p.OK)
        check(runner, 1, v4(LOCAL_ALIAS, LOCAL, 50000, 8080, protocol), p.OK)
        check(runner, 0, v4(LOCAL, LOCAL_ALIAS, 8080, 50000, protocol), p.OK)
    # The same address is not this endpoint when its peer record has a different
    # epoch; even a broad allow rule cannot turn a stale local identity into self.
    allow(runner, "egress", "0.0.0.0/0")
    allow(runner, "ingress", "0.0.0.0/0")
    local = bytearray(runner.lookup(n.IDENT, address(LOCAL_ALIAS)))
    struct.pack_into("<QQ", local, 8, 2, 102)
    runner.update(n.IDENT, address(LOCAL_ALIAS), local)
    check(runner, 1, v4(LOCAL_ALIAS, LOCAL, 50000, 8080), p.SHOT)
    check(runner, 0, v4(LOCAL, LOCAL_ALIAS, 8080, 50000), p.SHOT)
    return ["selfPrimaryAndHairpinAliasesPassDefaultDeny", "selfExceptionRequiresMatchingIncarnation"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    programs, ids, descriptors = p.read_fixture(args.fixture, names=NAMES)
    assert descriptors["endpoint_identity"][2] == 48
    assert descriptors[FLOWS][1:3] == (32, 8)
    assert "netpol_flows" not in descriptors
    assert descriptors[PODS][-1] == 129
    results = {}
    for function in (canonical_rules, exceptions, reuse, invalid_owners, local_fence_and_legacy, self_traffic):
        runner = (p.Kernel if args.kernel else p.Interpreter)(programs, ids, descriptors)
        try:
            setup(runner)
            results[function.__name__] = function(runner)
        finally:
            runner.close()
    print(json.dumps({"passed": True, "kernel": args.kernel, "cases": results}))


if __name__ == "__main__":
    main()
