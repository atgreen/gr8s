#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Inspect or install historical Service stages for a disposable-VM agent upgrade test.

Installation requires a reaped/stopped agent PID. Drop guards drain both TCX
hooks before replacing stages; on failure their pins remain for agent recovery.
No maps or entry links are replaced. --inspect performs no mutations.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import struct


class Kernel:
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.number = {"x86_64": 321, "aarch64": 280}[platform.machine()]
        self.fds = []

    def bpf(self, command, data):
        attr = ctypes.create_string_buffer(data, len(data))
        result = self.libc.syscall(self.number, command, ctypes.byref(attr), len(data))
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return result

    def own(self, fd):
        self.fds.append(fd)
        return fd

    def open(self, path):
        name = ctypes.create_string_buffer(os.fsencode(path))
        return self.own(self.bpf(7, struct.pack("<QII", ctypes.addressof(name), 0, 0)))

    def info(self, fd):
        info = ctypes.create_string_buffer(256)
        self.bpf(15, struct.pack("<IIQ", fd, 256, ctypes.addressof(info)))
        return info.raw

    def map_ids(self, fd):
        count = struct.unpack_from("<I", self.info(fd), 52)[0]
        # A returned info record contains nonzero code/BTF output lengths.
        # Request only map IDs; do not reuse those lengths with null pointers.
        info = ctypes.create_string_buffer(256)
        ids = ctypes.create_string_buffer(max(4, count * 4))
        struct.pack_into("<I", info, 52, count)
        struct.pack_into("<Q", info, 56, ctypes.addressof(ids))
        self.bpf(15, struct.pack("<IIQ", fd, 256, ctypes.addressof(info)))
        return list(struct.unpack_from(f"<{count}I", ids.raw))

    def lookup(self, fd, index):
        key, value = ctypes.create_string_buffer(struct.pack("<I", index)), ctypes.create_string_buffer(4)
        self.bpf(1, struct.pack("<IIQQQ", fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
        return struct.unpack("<I", value.raw)[0]

    def load(self, code):
        instructions, license = ctypes.create_string_buffer(bytes(code)), ctypes.create_string_buffer(b"GPL")
        log = ctypes.create_string_buffer(1024 * 1024)
        try:
            return self.own(self.bpf(5, struct.pack("<IIQQIIQ", 3, len(code) // 8,
                ctypes.addressof(instructions), ctypes.addressof(license), 1, len(log), ctypes.addressof(log))))
        except OSError as error:
            raise RuntimeError(f"legacy classifier rejected: {error}: {log.value.decode()}") from error

    def pin(self, fd, path):
        name = ctypes.create_string_buffer(os.fsencode(path))
        self.bpf(6, struct.pack("<QII", ctypes.addressof(name), fd, 0))

    def snapshot(self, endpoint, shared):
        stages = self.open(endpoint / "gr8s_pkt_stages")
        result = {"stages": [], "links": {}, "requiredMapIds": {}, "endpointMapIds": {},
                  "blockerPins": sorted(p.name for p in endpoint.glob("gr8s_pkt_upgrade_*"))}
        for path in sorted(endpoint.glob("*")):
            if path.name.startswith(("tcx-", "gr8s_pkt_upgrade_")):
                continue
            result["endpointMapIds"][path.name] = struct.unpack_from("<I", self.info(self.open(path)), 4)[0]
        for index in range(3):
            try:
                identity = self.lookup(stages, index)
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
                identity = 0
            if not identity:
                result["stages"].append({"id": 0, "mapIds": [], "tag": None})
                continue
            fd = self.own(self.bpf(13, struct.pack("<III", identity, 0, 0)))
            result["stages"].append({"id": identity, "mapIds": self.map_ids(fd),
                                      "tag": self.info(fd)[8:16].hex()})
        for direction in ("ingress", "egress"):
            info = self.info(self.open(endpoint / ("tcx-" + direction)))
            kind, identity, program = struct.unpack_from("<III", info)
            assert kind == 11
            result["links"][direction] = {"id": identity, "programId": program}
        for name in ("gr8s_pkt_forward", "gr8s_pkt_reverse", "gr8s_pkt_fwd_lock", "gr8s_pkt_rev_lock", "gr8s_pkt_tcp"):
            result["requiredMapIds"][name] = struct.unpack_from("<I", self.info(self.open(shared / name)), 4)[0]
        return result

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--fixture", type=Path)
    group.add_argument("--validate-fixture", type=Path,
                       help="load historical programs against real maps without publishing them")
    group.add_argument("--inspect", action="store_true")
    group.add_argument("--interrupt", action="store_true",
                       help="leave pinned drop guards and a missing reverse stage for restart recovery")
    parser.add_argument("--endpoint-directory", type=Path, required=True)
    parser.add_argument("--service-root", type=Path, required=True)
    parser.add_argument("--stopped-agent-pid", type=int)
    parser.add_argument("--tcp-key", help="remove this metadata entry to model a pre-TCP-tracker flow")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root in a disposable VM")
    kernel, blockers = Kernel(), []
    try:
        if args.inspect:
            print(json.dumps(kernel.snapshot(args.endpoint_directory, args.service_root)))
            return
        if not args.validate_fixture and (not args.stopped_agent_pid or Path(f"/proc/{args.stopped_agent_pid}").exists()):
            parser.error("the agent must be stopped and reaped before installing historical stages")
        if args.interrupt and args.tcp_key:
            parser.error("--interrupt preserves existing TCP metadata")
        fixture = args.fixture or args.validate_fixture
        document = json.loads(fixture.read_text()) if fixture else {"maps": [], "programs": []}
        specs, maps = document["maps"], []
        for spec in specs:
            path = args.endpoint_directory / spec["name"]
            fd = kernel.open(path if path.exists() else args.service_root / spec["name"])
            info = kernel.info(fd)
            assert struct.unpack_from("<II", info, 8) == (spec["key_size"], spec["value_size"]), spec["name"]
            maps.append(fd)
        before = kernel.snapshot(args.endpoint_directory, args.service_root)
        replacements = {}
        for program in document["programs"]:
            if program["name"] not in ("gr8s_packet_forward", "gr8s_packet_reverse"):
                continue
            code = bytearray(program["code"])
            for offset, index in program["relocations"]:
                struct.pack_into("<I", code, offset + 4, maps[index])
            replacements[program["name"]] = kernel.load(code)
        assert args.interrupt or len(replacements) == 2
        if args.validate_fixture:
            print(json.dumps({"fixtureSHA256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                              "legacyPrograms": {name: {"mapIds": kernel.map_ids(fd),
                                  "tag": kernel.info(fd)[8:16].hex()} for name, fd in replacements.items()},
                              "published": False}))
            return
        drop = kernel.load(bytes.fromhex("b7000000020000009500000000000000"))
        for direction, attach_type in (("ingress", 46), ("egress", 47)):
            path = args.endpoint_directory / ("gr8s_pkt_upgrade_" + direction)
            assert not path.exists(), "a previous upgrade is already incomplete"
            entry = kernel.open(args.endpoint_directory / ("tcx-" + direction))
            info = kernel.info(entry)
            kind = struct.unpack_from("<I", info)[0]
            index, actual_type = struct.unpack_from("<II", info, 16)
            assert kind == 11 and index > 0 and actual_type == attach_type
            block = kernel.own(kernel.bpf(28, struct.pack("<IIIIQQ", drop, index, attach_type, 8, 0, 0)))
            kernel.pin(block, path)
            blockers.append(path)
        stages = kernel.open(args.endpoint_directory / "gr8s_pkt_stages")
        for index, name in ((0, "gr8s_packet_forward"), (2, "gr8s_packet_reverse")):
            key = ctypes.create_string_buffer(struct.pack("<I", index))
            if args.interrupt:
                if index == 2:
                    kernel.bpf(3, struct.pack("<IIQ", stages, 0, ctypes.addressof(key)))
            else:
                value = ctypes.create_string_buffer(struct.pack("<I", replacements[name]))
                kernel.bpf(2, struct.pack("<IIQQQ", stages, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
        if args.tcp_key:
            raw = bytes.fromhex(args.tcp_key)
            assert len(raw) == 16
            key = ctypes.create_string_buffer(raw)
            fd = kernel.open(args.service_root / "gr8s_pkt_tcp")
            kernel.bpf(3, struct.pack("<IIQ", fd, 0, ctypes.addressof(key)))
        after = kernel.snapshot(args.endpoint_directory, args.service_root)
        assert after["links"] == before["links"]
        assert after["requiredMapIds"] == before["requiredMapIds"]
        if args.interrupt:
            assert after["stages"][2]["id"] == 0 and len(after["blockerPins"]) == 2
            print(json.dumps({"before": before, "interrupted": after, "tcpMetadataRemoved": False}))
            return  # Keep both blockers pinned after every descriptor closes.
        required = set(after["requiredMapIds"].values())
        for index in (0, 2):
            assert after["stages"][index]["id"] != before["stages"][index]["id"]
            assert not required.issubset(after["stages"][index]["mapIds"]), "fixture is not a legacy pipeline"
        for path in blockers:
            path.unlink()
        blockers.clear()
        print(json.dumps({"before": before, "legacy": after,
                          "fixtureSHA256": hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
                          "tcpMetadataRemoved": bool(args.tcp_key)}))
    finally:
        # Failed installation deliberately leaves pinned drop guards for recovery.
        kernel.close()


if __name__ == "__main__":
    main()
