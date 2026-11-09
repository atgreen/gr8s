#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise TC ClusterIP translation from a real Kata guest in a disposable VM.

Requires test-service-traffic.py alongside this file, root, nested KVM, kubectl,
and a checksum-pinned official Kata bundle. --ctr optionally preloads agnhost
directly into the test containerd when testing independently of the OCI mirror.
Evidence remains in --report-directory; the cluster is stopped and removed.
"""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import urllib.parse

spec = importlib.util.spec_from_file_location(
    "service_traffic", Path(__file__).with_name("test-service-traffic.py"))
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)


def read_packet_counters(path):
    """Read the actual shared TC counters without creating another dataplane."""
    libc = ctypes.CDLL(None, use_errno=True)
    number = {"x86_64": 321, "aarch64": 280}[platform.machine()]

    def bpf(command, attr):
        buffer = ctypes.create_string_buffer(attr)
        result = libc.syscall(number, command, ctypes.byref(buffer), len(attr))
        if result < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return result

    name = ctypes.create_string_buffer(os.fsencode(path))
    fd = bpf(7, struct.pack("<QII", ctypes.addressof(name), 0, 0))
    try:
        values = []
        for index in range(7):
            key = ctypes.create_string_buffer(struct.pack("<I", index))
            value = ctypes.create_string_buffer(8)
            bpf(1, struct.pack("<IIQQQ", fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
            values.append(struct.unpack("<Q", value.raw)[0])
        return values
    finally:
        os.close(fd)


def packet_counters(cluster):
    return read_packet_counters(cluster.root / "state/agent/containerd/bpf/service-lb/gr8s_pkt_stats")


def dial(address, destination, port, protocol, request):
    query = urllib.parse.urlencode({"host": destination, "port": port,
                                   "protocol": protocol, "request": request, "tries": 1})
    status, body = traffic.http_get(address, 8080, "/dial?" + query, timeout=15)
    try:
        body = json.loads(body)
    except (ValueError, TypeError):
        pass
    return status, body


def configure_test_kata(cluster, timeout_ms, *, addon_root=None):
    """Allow slow nested boots and retain guest diagnostics in this test only."""
    root = addon_root or cluster.root / "state/runtime-addons/kata"
    descriptor = root / "addon.json"
    addon = json.loads(descriptor.read_text())
    config = Path(addon["options"]["ConfigPath"])
    relative = str(config.relative_to(root))
    text, count = re.subn(r"(?m)^reconnect_timeout_ms\s*=\s*\d+\s*$",
                          f"reconnect_timeout_ms = {timeout_ms}", config.read_text())
    if count != 1:
        raise RuntimeError("Kata agent timeout configuration changed")
    text = text.replace("enable_debug = false", "enable_debug = true")
    asset = next(a for a in addon["assets"] if a["path"] == relative)
    config.write_text(text)
    asset["sha512"] = hashlib.sha512(config.read_bytes()).hexdigest()
    descriptor.write_text(json.dumps(addon, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--kata-bundle", required=True, type=Path)
    parser.add_argument("--kata-sha256", required=True)
    parser.add_argument("--report-directory", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--ctr", type=Path)
    parser.add_argument("--kata-agent-timeout-ms", type=int, default=120000,
                        help="test-only agent connection budget for slow nested KVM boots")
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/dev/kvm").exists():
        sys.exit("run as root in a disposable VM with nested KVM")
    os.environ["GR8S_ENABLE_PACKET_SERVICES"] = "1"
    args.report_directory.mkdir(parents=True, exist_ok=True)
    cluster = traffic.Cluster(args.gr8s.resolve(), args.state_parent, 18194, 17451)
    report = {"clusterRoot": str(cluster.root), "checks": [], "kataSHA256": args.kata_sha256}
    report["kataTestConfig"] = {"agentReconnectTimeoutMs": args.kata_agent_timeout_ms,
                                "debug": True}

    def check(name, passed, observed):
        report["checks"].append({"name": name, "passed": bool(passed), "observed": observed})
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if not passed:
            raise AssertionError(name)

    try:
        with (args.report_directory / "install.log").open("w") as log:
            subprocess.run([str(cluster.binary), "runtime", "install", "kata",
                            "--state-directory", str(cluster.root / "state"),
                            "--bundle", str(args.kata_bundle.resolve()),
                            "--sha256", args.kata_sha256], stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=600)
        configure_test_kata(cluster, args.kata_agent_timeout_ms)
        cluster.start()
        # Node registration precedes managed-containerd startup. Do not race
        # the image preload against creation of its gRPC socket.
        socket_path = cluster.root / "state/agent/containerd/run/containerd.sock"
        traffic.wait_for("managed containerd socket", 180, socket_path.exists)
        config = cluster.root / "state/agent/containerd/config.toml"
        check("kataHandlerConfigured", "containerd.runtimes.kata" in config.read_text(),
              str(config))
        if args.ctr:
            with (args.report_directory / "image-pull.log").open("w") as log:
                subprocess.run([str(args.ctr), "--address",
                                str(socket_path),
                                "--namespace", "k8s.io", "images", "pull", traffic.AGNHOST],
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
        guest = traffic.server_pod("guest")
        guest["spec"]["runtimeClassName"] = "kata"
        guest["metadata"]["labels"]["app"] = "guest"
        cluster.apply({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
                       "metadata": {"name": "kata"}, "handler": "kata"},
                      traffic.server_pod("backend"), guest,
                      traffic.service("packet-web", [traffic.HTTP, traffic.UDP],
                                      selector={"test.gr8s.io/pod": "backend"}))
        traffic.wait_for("Kata guest and native backend ready", 600, lambda: all(
            any(c["type"] == "Ready" and c["status"] == "True"
                for c in cluster.get("pod", name).get("status", {}).get("conditions", []))
            for name in ("guest", "backend")))
        guest_ip = cluster.get("pod", "guest")["status"]["podIP"]
        vip = cluster.get("service", "packet-web")["spec"]["clusterIP"]
        guest_kernel = cluster.kubectl("exec", "guest", "--", "uname", "-r").strip()
        qemus = []
        for cmdline in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                command = cmdline.read_bytes()
                words = command.split(b"\0")
                if words and b"qemu-system" in words[0] and os.fsencode(cluster.root) in command:
                    qemus.append({"pid": int(cmdline.parent.name),
                                  "command": b" ".join(words).decode(errors="replace")})
            except (OSError, ProcessLookupError):
                pass
        check("realGuestKernel", guest_kernel != platform.release() and qemus,
              {"guest": guest_kernel, "host": platform.release(), "qemu": qemus})
        for protocol, port, request in (("http", 80, "hostname"), ("udp", 81, "hostname")):
            before = packet_counters(cluster)
            answer = dial(guest_ip, vip, port, protocol, request)
            after = packet_counters(cluster)
            check(protocol + "ClusterIP", answer[0] == 200 and
                  isinstance(answer[1], dict) and answer[1].get("responses") == ["backend"],
                  {"answer": answer, "countersBefore": before, "countersAfter": after})
            check(protocol + "UsesTCBothDirections", after[0] > before[0] and after[1] > before[1],
                  {"before": before, "after": after})
            answer = dial(guest_ip, vip, port, protocol, "clientip")
            responses = answer[1].get("responses", []) if isinstance(answer[1], dict) else []
            check(protocol + "PreservesGuestSource", answer[0] == 200 and len(responses) == 1 and
                  responses[0].rsplit(":", 1)[0] == guest_ip, answer)
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["passed"] = False
        report["error"] = f"{type(error).__name__}: {error}"
        try:
            (args.report_directory / "pods.json").write_text(cluster.kubectl("get", "pods", "-o", "json"))
            (args.report_directory / "events.json").write_text(cluster.kubectl("get", "events", "-o", "json"))
        except Exception:
            pass
    finally:
        try:
            cluster.stop()
        except subprocess.TimeoutExpired as error:
            report["passed"] = False
            report["shutdownError"] = str(error)
            # Only the process this test started; never leave it using a state
            # directory that the following cleanup is about to remove.
            cluster.process.kill()
            cluster.process.wait(timeout=30)
            cluster.process = None
        finally:
            for source, target in ((cluster.root / "gr8s.log", "gr8s.log"),
                                   (cluster.root / "state/agent/containerd/containerd.log", "containerd.log")):
                if source.exists():
                    shutil.copyfile(source, args.report_directory / target)
            (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            cluster.remove()
            kata_link = Path("/opt/kata")
            if kata_link.is_symlink() and str(kata_link.readlink()).startswith(str(cluster.root) + "/"):
                kata_link.unlink()
    print(json.dumps({"reportDirectory": str(args.report_directory), "passed": report.get("passed", False)}))
    sys.exit(0 if report.get("passed") else 1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--read-packet-counters":
        print(json.dumps(read_packet_counters(Path(sys.argv[2]))))
    else:
        main()
