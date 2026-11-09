#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify the running native agent reclaims pinned packet Service state.

Run as root in a disposable VM with test-service-traffic.py alongside this file.
No test images or Pods are needed: seed retained flow/orphan state directly,
then observe the agent's ordinary bounded reconciliation worker clean it up.
"""
import argparse
import ctypes
import errno
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
import time

spec = importlib.util.spec_from_file_location("traffic", Path(__file__).with_name("test-service-traffic.py"))
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)


class PinnedMap:
    def __init__(self, path, value_size):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.number = {"x86_64": 321, "aarch64": 280}[platform.machine()]
        name = ctypes.create_string_buffer(os.fsencode(path))
        self.fd = self.bpf(7, struct.pack("<QII", ctypes.addressof(name), 0, 0))
        info = ctypes.create_string_buffer(256)
        self.bpf(15, struct.pack("<IIQ", self.fd, 256, ctypes.addressof(info)))
        kind, self.identity, key_size, actual_value_size = struct.unpack_from("<IIII", info.raw)
        assert (kind, key_size, actual_value_size) == (1, 16, value_size)
        self.value_size = value_size

    def bpf(self, command, attr):
        data = ctypes.create_string_buffer(attr)
        result = self.libc.syscall(self.number, command, ctypes.byref(data), len(attr))
        if result < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return result

    def update(self, key, value):
        assert len(key) == 16 and len(value) == self.value_size
        key, value = ctypes.create_string_buffer(key), ctypes.create_string_buffer(value)
        self.bpf(2, struct.pack("<IIQQQ", self.fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))

    def lookup(self, key):
        key = ctypes.create_string_buffer(key)
        value = ctypes.create_string_buffer(self.value_size)
        try:
            self.bpf(1, struct.pack("<IIQQQ", self.fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
        except OSError as error:
            if error.errno == errno.ENOENT:
                return None
            raise
        return value.raw

    def close(self):
        os.close(self.fd)


def key(source, destination, sport, dport):
    return (ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed +
            struct.pack("!HHBBH", sport, dport, 17, 0, 0))


def value(address, port, stamp):
    return (ipaddress.ip_address(address).packed + struct.pack("!H", port) + bytes(2) +
            struct.pack("<Q", stamp & ((1 << 64) - 1)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--report-directory", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in a disposable VM")
    os.environ["GR8S_ENABLE_PACKET_SERVICES"] = "1"
    cluster = traffic.Cluster(args.gr8s.resolve(), Path("/var/tmp"), 18195, 17455)
    args.report_directory.mkdir(parents=True, exist_ok=True)
    report = {"root": str(cluster.root), "checks": []}
    maps = {}

    def save():
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def check(name, passed, observed):
        report["checks"].append({"name": name, "passed": bool(passed), "observed": observed})
        save()
        print(f"{name}: {'passed' if passed else 'failed'}", flush=True)
        if not passed:
            raise AssertionError(name)

    try:
        cluster.start()
        directory = cluster.root / "state/agent/containerd/bpf/service-lb"
        names = {"gr8s_pkt_forward": 16, "gr8s_pkt_reverse": 16,
                 "gr8s_pkt_fwd_lock": 8, "gr8s_pkt_rev_lock": 8}
        traffic.wait_for("packet state pins", 180, lambda: all((directory / name).exists() for name in names))
        for name, size in names.items():
            maps[name] = PinnedMap(directory / name, size)
        identities = {name: item.identity for name, item in maps.items()}
        check("canonicalPacketMapsPinned", True, identities)
        forward, reverse = maps["gr8s_pkt_forward"], maps["gr8s_pkt_reverse"]
        client, vip, backend = "10.88.0.2", "10.96.0.10", "10.88.1.3"
        now = time.monotonic_ns()
        fresh_key = key(client, vip, 49000, 80)
        fresh_reverse = key(backend, client, 8080, 49000)
        fresh = value(backend, 8080, now)
        fresh_reply = value(vip, 80, 0)  # reverse creation age cannot expire a live forward owner
        forward.update(fresh_key, fresh)
        reverse.update(fresh_reverse, fresh_reply)
        aged = now - 181_000_000_000
        expired = []
        for port in range(48000, 48300):
            fwd, rev = key(client, vip, port, 80), key(backend, client, 8080, port)
            forward.update(fwd, value(backend, 8080, aged))
            reverse.update(rev, value(vip, 80, aged))
            expired.append((fwd, rev))
        orphan = key(backend, client, 8080, 49999)
        reverse.update(orphan, value(vip, 80, now))
        report["seededExpiredPairs"] = len(expired)
        report["batchBudgetPerMap"] = 128
        started = time.monotonic()

        def reclaimed():
            assert forward.lookup(fresh_key) == fresh, "collector altered fresh forward state"
            assert reverse.lookup(fresh_reverse) == fresh_reply, "collector removed live reverse owner"
            return (all(forward.lookup(fwd) is None and reverse.lookup(rev) is None for fwd, rev in expired)
                    and reverse.lookup(orphan) is None)

        traffic.wait_for("agent background flow reclamation", 90, reclaimed)
        check("backgroundReclaimsMoreThanOneBatch", True,
              {"pairs": len(expired), "seconds": round(time.monotonic() - started, 3)})
        check("abandonedReverseReservationWithdrawn", reverse.lookup(orphan) is None, orphan.hex())
        check("freshForwardAndReverseSurvive", forward.lookup(fresh_key) == fresh and
              reverse.lookup(fresh_reverse) == fresh_reply, {"forward": fresh.hex(), "reverse": fresh_reply.hex()})
        # Retained maps may not be replaced as a shortcut for garbage collection.
        current = {}
        for name, size in names.items():
            reopened = PinnedMap(directory / name, size)
            current[name] = reopened.identity
            reopened.close()
        check("mapIdsPreserved", current == identities, current)
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}")
    finally:
        for item in maps.values():
            item.close()
        try:
            cluster.stop()
            report["cleanupCompleted"] = True
        except Exception as error:
            report.update(passed=False, cleanupError=str(error))
        log = cluster.root / "gr8s.log"
        if log.exists():
            shutil.copyfile(log, args.report_directory / "gr8s.log")
            failures = [line for line in log.read_text(errors="replace").splitlines()
                        if any(message in line for message in ("Service flow GC failed:",
                            "Service flow GC deferred:", "Service LB convergence failed:"))]
            report["checks"].append({"name": "noServiceMaintenanceErrors", "passed": not failures,
                                     "observed": failures})
            if failures:
                report["passed"] = False
        save()
        if report.get("cleanupCompleted"):
            cluster.remove()
    print(json.dumps({"passed": report.get("passed", False), "reportDirectory": str(args.report_directory)}))
    sys.exit(0 if report.get("passed") else 1)


if __name__ == "__main__":
    main()
