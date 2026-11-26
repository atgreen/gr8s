#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Execute the actual Whistler socket bytecode through Service map updates.

Build the fixture with:
  sbcl --script scripts/compile-endpoint-policy-fixture.lisp OUTPUT service-lb
This uses the endpoint-policy interpreter's stack/bounds checks and deliberately
clobbers helper argument registers, just as Linux does. It needs no privileges.
Pass --kernel only inside a disposable root VM to load and attach the same
programs and exercise real TCP and UDP sockets, including UDP source restoration.
"""

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys


spec = importlib.util.spec_from_file_location(
    "endpoint_policy", Path(__file__).with_name("test-endpoint-policy.py"))
endpoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(endpoint)


class SocketMachine(endpoint.Machine):
    def __init__(self, code, maps, address, port, protocol=6, after_membership=None):
        super().__init__(code, maps, b"", [1_000_000_000])
        self.address = ipaddress.ip_address(address)
        self.retval = None
        self.after_membership = after_membership
        context = self.memory[0x200000]
        offset = 4 if self.address.version == 4 else 8
        context[offset:offset + len(self.address.packed)] = self.address.packed
        context[24:28] = struct.pack("!H", port) + b"\0\0"
        struct.pack_into("<I", context, 36, protocol)

    def call(self, helper):
        membership_lookup = (helper == 1 and
                             "backend_index" in self.maps.names[self.registers[1]])
        if helper in (7, 46, 122, 187):
            if helper == 187:
                self.retval = self.registers[1] & 0xffffffff
            self.registers[0] = {7: 0, 46: 123, 122: 456, 187: 0}[helper]
            self.registers[1:6] = [0xdeadbeef] * 5
        else:
            super().call(helper)
        if membership_lookup and self.after_membership is not None:
            action, self.after_membership = self.after_membership, None
            action()

    def destination(self):
        context = self.memory[0x200000]
        offset, size = (4, 4) if self.address.version == 4 else (8, 16)
        return (str(ipaddress.ip_address(bytes(context[offset:offset + size]))),
                struct.unpack_from("!H", context, 24)[0])


def fixture(path):
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
        programs[program["section"]] = bytes(code)
    return programs, endpoint.Maps(ids, descriptors, {})


def service_key(address, port, protocol=6):
    address = ipaddress.ip_address(address)
    if address.version == 4:
        return struct.pack("!H", port) + address.packed + bytes([protocol, 0])
    return address.packed + struct.pack("!HBB", port, protocol, 0)


def backend_value(address, port):
    return ipaddress.ip_address(address).packed + struct.pack("!H", port) + b"\0\0"


def check(programs, maps, address, backend, protocol, section, expected):
    machine = SocketMachine(programs[section], maps, address, 80, protocol)
    result = machine.run()
    if expected:
        assert result == 1 and machine.destination() == backend, (
            section, result, machine.destination(), backend)
    else:
        assert result == 0 and machine.destination() == (address, 80), (
            section, result, machine.destination())
        assert machine.retval == (-111 & 0xffffffff), machine.retval


def test_repacking(programs, maps, family, protocol, affinity):
    """Visit every write boundary of a slot move, including failed publication."""
    suffix = f"v{family}"
    address = "10.96.0.10" if family == 4 else "fd96::a"
    original = ("10.88.1.5" if family == 4 else "fd88::5", 8080)
    unrelated = ("10.88.2.7" if family == 4 else "fd88::7", 9090)
    key = service_key(address, 80, protocol)
    original_value = backend_value(*original)
    index = f"gr8s_backend_index_{suffix}"
    backend_map = f"gr8s_backend_{suffix}"
    service_map = f"gr8s_service_{suffix}"
    slot0, slot1 = struct.pack("<I", 0), struct.pack("<I", 1)
    maps.update(backend_map, slot0, original_value)
    maps.update(index, key + original_value, slot0)
    maps.update(service_map, key, struct.pack("<HHIII", 1, affinity, 0, 60, 0))
    sections = [f"cgroup/connect{family}"]
    if protocol == 17:
        sections.append(f"cgroup/sendmsg{family}")
    for section in sections:
        check(programs, maps, address, original, protocol, section, True)

    # A helper may race a later update too: the destination must come from the
    # identity we checked, not a fresh read of a now-repurposed backend slot.
    if not affinity:
        for section in sections:
            maps.update(backend_map, slot0, original_value)
            machine = SocketMachine(
                programs[section], maps, address, 80, protocol,
                after_membership=lambda: maps.update(backend_map, slot0,
                                                     backend_value(*unrelated)))
            assert machine.run() == 1
            assert machine.destination() == original, (section, machine.destination())

    # Another Service takes our old slot before our base slot is published.
    # An interrupted reconciliation can leave this state indefinitely.
    maps.update(backend_map, slot0, backend_value(*unrelated))
    for section in sections:
        check(programs, maps, address, original, protocol, section, False)
    maps.update(backend_map, slot1, original_value)
    maps.update(index, key + original_value, slot1)
    for section in sections:
        check(programs, maps, address, original, protocol, section, False)
    maps.update(service_map, key, struct.pack("<HHIII", 1, affinity, 1, 60, 0))
    for section in sections:
        check(programs, maps, address, original, protocol, section, True)


def test_egress_capture(programs, maps):
    """A captured Pod's TCP outside the cluster goes to the egress proxy with its port
    kept; QUIC's UDP 443 is refused; cluster addresses and Services are untouched
    (podster-wv1w.2). The interpreter's netns cookie is 456."""
    def run(section, address, port, protocol):
        machine = SocketMachine(programs[section], maps, address, port, protocol)
        return machine.run(), machine.destination(), machine.retval

    cookie = struct.pack("<Q", 456)
    assert run("cgroup/connect4", "203.0.113.5", 443, 6) == (1, ("203.0.113.5", 443), None)
    maps.update("gr8s_egress_capture", cookie, b"\x01")
    maps.update("gr8s_egress_exempt_v4", endpoint.cidr_key("10.0.0.0/8"), b"\x01")
    assert run("cgroup/connect4", "203.0.113.5", 443, 6) == (1, ("169.254.1.2", 443), None)
    assert run("cgroup/connect4", "198.51.100.9", 8443, 6) == (1, ("169.254.1.2", 8443), None)
    assert run("cgroup/connect4", "10.1.2.3", 5432, 6) == (1, ("10.1.2.3", 5432), None)
    for section in ("cgroup/connect4", "cgroup/sendmsg4"):
        assert run(section, "203.0.113.5", 443, 17) == (0, ("203.0.113.5", 443), 0xffffffff)
        assert run(section, "1.1.1.1", 53, 17) == (1, ("1.1.1.1", 53), None)
    # DNS to the node gateway goes to the egress DNS gate, and a UDP reply from the
    # gate is shown as the gateway's.
    for section, protocol in (("cgroup/sendmsg4", 17), ("cgroup/connect4", 17), ("cgroup/connect4", 6)):
        assert run(section, "169.254.1.1", 53, protocol) == (1, ("169.254.1.2", 53), None), (section, protocol)
    reverse = struct.pack("<QQ", 123, 0x35000201fea9)
    assert maps.lookup("gr8s_reverse_v4", reverse) != 0
    reply = SocketMachine(programs["cgroup/recvmsg4"], maps, "169.254.1.2", 53, 17)
    assert reply.run() == 1 and reply.destination() == ("169.254.1.1", 53), reply.destination()
    # A Service is still load-balanced for a captured Pod.
    key = service_key("10.96.0.10", 80, 6)
    backend = backend_value("10.88.1.5", 8080)
    maps.update("gr8s_backend_v4", struct.pack("<I", 0), backend)
    maps.update("gr8s_backend_index_v4", key + backend, struct.pack("<I", 0))
    maps.update("gr8s_service_v4", key, struct.pack("<HHIII", 1, 0, 0, 60, 0))
    assert run("cgroup/connect4", "10.96.0.10", 80, 6) == (1, ("10.88.1.5", 8080), None)
    # Mode 2, a hostname allowlist (podster-wv1w.8): a synthetic address passes as dialled,
    # for the proxy to read; a real public address is refused; the rest is as in mode 1.
    maps.update("gr8s_egress_capture", cookie, b"\x02")
    for address in ("198.18.0.7", "198.19.255.254"):
        assert run("cgroup/connect4", address, 6379, 6) == (1, (address, 6379), None), address
    for address in ("203.0.113.5", "198.20.0.7", "198.17.255.255"):
        assert run("cgroup/connect4", address, 443, 6) == (0, (address, 443), 0xffffffff), address
    assert run("cgroup/connect4", "10.1.2.3", 5432, 6) == (1, ("10.1.2.3", 5432), None)
    assert run("cgroup/connect4", "169.254.1.1", 53, 17) == (1, ("169.254.1.2", 53), None)
    assert run("cgroup/sendmsg4", "203.0.113.5", 443, 17) == (0, ("203.0.113.5", 443), 0xffffffff)
    assert run("cgroup/connect4", "10.96.0.10", 80, 6) == (1, ("10.88.1.5", 8080), None)


def main():
    if "--kernel" in sys.argv[2:]:
        test_kernel(sys.argv[1])
        return
    for family in (4, 6):
        for protocol in (6, 17):
            for affinity in (0, 1):
                programs, maps = fixture(sys.argv[1])
                test_repacking(programs, maps, family, protocol, affinity)
    programs, maps = fixture(sys.argv[1])
    test_egress_capture(programs, maps)
    print("Service socket bytecode: slot-repacking isolation passed "
          "for IPv4/IPv6, TCP/UDP, with/without affinity; egress capture passed")


def test_kernel_egress_capture(kernel):
    """A captured netns's TCP outside the exempt prefixes reaches the egress proxy address
    with its port kept, UDP 443 is refused, and DNS to the node gateway reaches the DNS
    gate while its reply shows the gateway's address (podster-wv1w.2)."""
    addresses = ("169.254.1.1/32", "169.254.1.2/32", "10.99.0.1/32")
    for address in addresses:
        subprocess.run(["ip", "addr", "add", address, "dev", "lo"], check=False, capture_output=True)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            cookie = probe.getsockopt(socket.SOL_SOCKET, 71, 8)  # SO_NETNS_COOKIE
        kernel.update("gr8s_egress_capture", cookie, b"\x01")
        kernel.update("gr8s_egress_exempt_v4", endpoint.cidr_key("10.0.0.0/8"), b"\x01")
        with socket.socket() as proxy, socket.socket() as internal:
            proxy.bind(("169.254.1.2", 0))
            proxy.listen()
            port = proxy.getsockname()[1]
            internal.bind(("10.99.0.1", port))
            internal.listen()
            with socket.socket() as client:
                client.settimeout(2)
                client.connect(("203.0.113.5", port))
                accepted, _ = proxy.accept()
                assert accepted.getsockname() == ("169.254.1.2", port), accepted.getsockname()
                accepted.close()
            with socket.socket() as client:
                client.settimeout(2)
                client.connect(("10.99.0.1", port))
                accepted, _ = internal.accept()
                accepted.close()
            assert not select.select([proxy], [], [], 0)[0], "an exempt address went to the proxy"
            # Mode 2 (podster-wv1w.8): a synthetic address is dialled as it is, and a
            # real public one is refused.
            kernel.update("gr8s_egress_capture", cookie, b"\x02")
            synthetic = socket.socket()
            synthetic.setblocking(False)
            try:
                try:
                    synthetic.connect(("198.18.0.7", port))
                except (BlockingIOError, ConnectionRefusedError, OSError) as error:
                    assert not isinstance(error, PermissionError), "a synthetic address was refused"
            finally:
                synthetic.close()
            with socket.socket() as client:
                try:
                    client.connect(("203.0.113.5", port))
                except PermissionError:
                    pass
                else:
                    raise AssertionError("mode 2 reached a real public address")
            assert not select.select([proxy], [], [], 0)[0], "mode 2 went to the proxy address"
            kernel.update("gr8s_egress_capture", cookie, b"\x01")
        for send in ("connect", "sendto"):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                try:
                    if send == "connect":
                        client.connect(("203.0.113.5", 443))
                    else:
                        client.sendto(b"quic", ("203.0.113.5", 443))
                except PermissionError:
                    pass
                else:
                    raise AssertionError(f"UDP 443 by {send} was not refused")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as gate, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            gate.bind(("169.254.1.2", 53))
            client.settimeout(2)
            client.sendto(b"query", ("169.254.1.1", 53))
            assert select.select([gate], [], [], 2)[0], "the DNS gate got no query"
            payload, peer = gate.recvfrom(256)
            assert payload == b"query"
            gate.sendto(b"answer", peer)
            payload, peer = client.recvfrom(256)
            assert payload == b"answer" and peer == ("169.254.1.1", 53), peer
    finally:
        for address in addresses:
            subprocess.run(["ip", "addr", "del", address, "dev", "lo"], check=False, capture_output=True)


def test_kernel(path):
    """Attach all six socket hooks and exercise real sockets in a disposable VM."""
    programs, maps = fixture(path)
    hooks = {"cgroup/connect4": 10, "cgroup/connect6": 11,
             "cgroup/sendmsg4": 14, "cgroup/sendmsg6": 15,
             "cgroup/recvmsg4": 19, "cgroup/recvmsg6": 20}
    kernel = endpoint.Kernel(programs, maps.ids, maps.descriptors,
                             program_types={name: (18, hooks[name]) for name in programs})
    original_cgroup = next(line.strip().split(":", 2)[2]
                           for line in open("/proc/self/cgroup") if line.startswith("0::"))
    root = Path("/sys/fs/cgroup")
    group = root / f"gr8s-service-bytecode-{os.getpid()}"
    links = []
    try:
        group.mkdir()
        target = os.open(group, os.O_RDONLY)
        try:
            for name, program_fd in kernel.program_fds.items():
                links.append(kernel.bpf(28, struct.pack("<IIII", program_fd, target,
                                                        hooks[name], 0)))
        finally:
            os.close(target)
        (group / "cgroup.procs").write_text(str(os.getpid()))
        for family, af, address, loopback in (
                (4, socket.AF_INET, "10.96.0.10", "127.0.0.1"),
                (6, socket.AF_INET6, "fd96::a", "::1")):
            for protocol, kind in ((6, socket.SOCK_STREAM), (17, socket.SOCK_DGRAM)):
                with socket.socket(af, kind) as backend, socket.socket(af, kind) as unrelated:
                    backend.bind((loopback, 0))
                    unrelated.bind((loopback, 0))
                    if protocol == 6:
                        backend.listen()
                        unrelated.listen()
                    suffix = f"v{family}"
                    key = service_key(address, 80, protocol)
                    value = backend_value(loopback, backend.getsockname()[1])
                    slot0, slot1 = struct.pack("<I", 0), struct.pack("<I", 1)
                    kernel.update(f"gr8s_backend_{suffix}", slot0, value)
                    kernel.update(f"gr8s_backend_index_{suffix}", key + value, slot0)
                    kernel.update(f"gr8s_service_{suffix}", key, struct.pack("<HHIII", 1, 0, 0, 60, 0))

                    def successful_request():
                        with socket.socket(af, kind) as client:
                            client.settimeout(2)
                            if protocol == 6:
                                client.connect((address, 80))
                                accepted, _ = backend.accept()
                                accepted.close()
                            else:
                                client.sendto(b"request", (address, 80))
                                assert select.select([backend], [], [], 2)[0], "no UDP request"
                                payload, peer = backend.recvfrom(256)
                                assert payload == b"request"
                                backend.sendto(b"reply", peer)
                                payload, peer = client.recvfrom(256)
                                assert payload == b"reply" and peer[:2] == (address, 80), peer

                    successful_request()
                    kernel.update(f"gr8s_backend_{suffix}", slot0,
                                  backend_value(loopback, unrelated.getsockname()[1]))
                    with socket.socket(af, kind) as client:
                        client.settimeout(2)
                        try:
                            if protocol == 6:
                                client.connect((address, 80))
                            else:
                                client.sendto(b"must-not-arrive", (address, 80))
                        except ConnectionRefusedError:
                            pass
                        else:
                            raise AssertionError(f"IPv{family}/{protocol}: foreign backend accepted")
                    assert not select.select([unrelated], [], [], 0)[0], "foreign backend received traffic"
                    kernel.update(f"gr8s_backend_{suffix}", slot1, value)
                    kernel.update(f"gr8s_backend_index_{suffix}", key + value, slot1)
                    kernel.update(f"gr8s_service_{suffix}", key, struct.pack("<HHIII", 1, 0, 1, 60, 0))
                    successful_request()
        test_kernel_egress_capture(kernel)
        print("Service socket kernel hooks: IPv4/IPv6 TCP/UDP translation, UDP replies, "
              "slot-repacking isolation and recovery, egress capture passed")
    finally:
        if group.exists():
            (root / original_cgroup.lstrip("/") / "cgroup.procs").write_text(str(os.getpid()))
        for link in links:
            os.close(link)
        if group.exists():
            group.rmdir()
        kernel.close()


if __name__ == "__main__":
    main()
