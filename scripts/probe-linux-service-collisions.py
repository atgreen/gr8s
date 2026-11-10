#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Compare crossed UDP Services with ordinary Linux/nft NAT in a disposable VM.

Four network namespaces model two Pods and two routing nodes. This is a Linux
reference experiment, not a Cilium/Calico or kube-proxy conformance test.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys


def command(*args, input=None, check=True):
    return subprocess.run(args, input=input, text=True, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def app(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))
    sock.settimeout(5)
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        try:
            if request["op"] == "send":
                sock.sendto(request["body"].encode(), (request["destination"], 80))
                result = {"sent": True}
            else:
                body, peer = sock.recvfrom(4096)
                result = {"body": body.decode(), "peer": peer}
        except (TimeoutError, OSError) as error:
            result = {"error": type(error).__name__, "errno": getattr(error, "errno", None)}
        print(json.dumps(result), flush=True)


def request(process, payload):
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("UDP probe process exited: " + process.stderr.read())
    return json.loads(line)


def scenario(simultaneous, masquerade):
    token = str(os.getpid())
    namespaces = {role: "gr8s-collision-" + role + "-" + token for role in ("na", "nb", "pa", "pb")}
    created, processes = [], []
    names = ["wa" + token, "wb" + token, "ha" + token, "pa" + token, "hb" + token, "pb" + token]

    def ns(role, *args, **kwargs):
        return command("ip", "netns", "exec", namespaces[role], *args, **kwargs)

    def pair(first, second, left, right):
        command("ip", "link", "add", first, "type", "veth", "peer", "name", second)
        command("ip", "link", "set", first, "netns", namespaces[left])
        command("ip", "link", "set", second, "netns", namespaces[right])
        ns(left, "ip", "link", "set", first, "up")
        ns(right, "ip", "link", "set", second, "up")

    try:
        for name in namespaces.values():
            command("ip", "netns", "add", name)
            created.append(name)
        for role in namespaces:
            ns(role, "ip", "link", "set", "lo", "up")
            ns(role, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0",
               "net.ipv4.conf.default.rp_filter=0")
        pair(names[0], names[1], "na", "nb")
        pair(names[2], names[3], "na", "pa")
        pair(names[4], names[5], "nb", "pb")
        for role, link, address in (("na", names[0], "192.0.2.1/30"),
                                     ("nb", names[1], "192.0.2.2/30"),
                                     ("na", names[2], "10.88.0.1/24"),
                                     ("pa", names[3], "10.88.0.2/24"),
                                     ("nb", names[4], "10.88.1.1/24"),
                                     ("pb", names[5], "10.88.1.3/24")):
            ns(role, "ip", "address", "add", address, "dev", link)
        ns("pa", "ip", "route", "add", "default", "via", "10.88.0.1")
        ns("pb", "ip", "route", "add", "default", "via", "10.88.1.1")
        ns("na", "ip", "route", "add", "10.88.1.0/24", "via", "192.0.2.2")
        ns("nb", "ip", "route", "add", "10.88.0.0/24", "via", "192.0.2.1")
        # Initial Service routing occurs before DNAT on some paths. Keep both
        # frontend ranges routable toward the other node without owning them.
        ns("na", "ip", "route", "add", "10.96.0.0/16", "via", "192.0.2.2")
        ns("nb", "ip", "route", "add", "10.96.0.0/16", "via", "192.0.2.1")
        for left, left_link, left_ip, right, right_link, right_ip in (
                ("na", names[0], "192.0.2.1", "nb", names[1], "192.0.2.2"),
                ("na", names[2], "10.88.0.1", "pa", names[3], "10.88.0.2"),
                ("nb", names[4], "10.88.1.1", "pb", names[5], "10.88.1.3")):
            left_mac = json.loads(ns(left, "ip", "-j", "link", "show", left_link).stdout)[0]["address"]
            right_mac = json.loads(ns(right, "ip", "-j", "link", "show", right_link).stdout)[0]["address"]
            ns(left, "ip", "neigh", "replace", right_ip, "lladdr", right_mac, "nud", "permanent", "dev", left_link)
            ns(right, "ip", "neigh", "replace", left_ip, "lladdr", left_mac, "nud", "permanent", "dev", right_link)
        for role, link, vip, backend in (("na", names[0], "10.96.0.10", "10.88.1.3:8080"),
                                         ("nb", names[1], "10.96.0.99", "10.88.0.2:5000")):
            ns(role, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            ns(role, "tc", "qdisc", "add", "dev", link, "root", "netem", "delay", "3000ms")
            mark = "meta mark set 1 " if masquerade else ""
            post = "meta mark 1 masquerade" if masquerade else ""
            rules = ("table ip services {\n"
                     " chain pre { type nat hook prerouting priority dstnat; policy accept;\n"
                     f" ip daddr {vip} udp dport 80 {mark}dnat to {backend}\n"
                     " }\n chain post { type nat hook postrouting priority srcnat; policy accept;\n"
                     f" {post}\n }}\n}}\n")
            ns(role, "nft", "-f", "-", input=rules)
        for role, address, port in (("pa", "10.88.0.2", 5000), ("pb", "10.88.1.3", 8080)):
            processes.append(subprocess.Popen(
                ["ip", "netns", "exec", namespaces[role], sys.executable,
                 str(Path(__file__).resolve()), "--app", address, str(port)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        a, b = processes
        for process in processes:
            assert json.loads(process.stdout.readline()) == {"ready": True}
        first_send = request(a, {"op": "send", "destination": "10.96.0.10", "body": "request-from-A"})
        first_receive = None if simultaneous else request(b, {"op": "receive"})
        second_send = request(b, {"op": "send", "destination": "10.96.0.99", "body": "request-from-B"})
        queues = []
        if simultaneous:
            for role, link in (("na", names[0]), ("nb", names[1])):
                stats = ns(role, "tc", "-s", "qdisc", "show", "dev", link).stdout
                match = re.search(r"backlog \S+ (\d+)p", stats)
                queues.append(int(match[1]) if match else None)
        if simultaneous:
            first_receive = request(b, {"op": "receive"})
        second_receive = request(a, {"op": "receive"})
        return {"simultaneous": simultaneous, "masquerade": masquerade,
                "wireQueueLengthsBeforeReceive": queues,
                "bothQueuedBeforeDelivery": all(value is not None and value > 0 for value in queues) if queues else None,
                "firstSend": first_send, "secondSend": second_send,
                "firstReceive": first_receive, "secondReceive": second_receive,
                "firstLooksLikeServiceReply": first_receive.get("peer", [None])[0] == "10.96.0.99",
                "secondLooksLikeServiceReply": second_receive.get("peer", [None])[0] == "10.96.0.10"}
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for name in reversed(created):
            command("ip", "netns", "del", name, check=False)
        # Handles a setup failure between creating a pair and moving its links.
        for name in names:
            command("ip", "link", "del", name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", nargs=2, metavar=("ADDRESS", "PORT"))
    parser.add_argument("--disposable-vm", action="store_true")
    args = parser.parse_args()
    if args.app:
        app(args.app[0], int(args.app[1]))
        return
    if not args.disposable_vm or os.geteuid() != 0:
        parser.error("run --disposable-vm as root inside a disposable VM")
    cases = [scenario(simultaneous, masquerade) for masquerade in (False, True)
             for simultaneous in (False, True)]
    print(json.dumps({"kernel": command("uname", "-r").stdout.strip(),
                      "nft": command("nft", "--version").stdout.strip(), "cases": cases}))


if __name__ == "__main__":
    main()
