#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify retained Service map cleanup and workload identity through agent restart.

Run as root in a disposable VM. Copy smoke-two-node.py and
test-service-traffic.py alongside this file. Uses two native nodes in separate
mount/network namespaces; optional ctr preloads isolate image-mirror faults.
"""
import argparse
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import struct
import sys


def inspect_maps(directory, seed=False):
    """Read map IDs/keys, optionally modeling orphaned interrupted writes."""
    libc = ctypes.CDLL(None, use_errno=True)
    number = {"x86_64": 321, "aarch64": 280}[platform.machine()]

    def bpf(command, attr):
        buffer = ctypes.create_string_buffer(attr)
        result = libc.syscall(number, command, ctypes.byref(buffer), len(attr))
        if result < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return result

    result = {}
    for path in sorted(directory.glob("gr8s_*")):
        if not any(part in path.name for part in ("service_v", "backend_", "pkt_")):
            continue
        name = ctypes.create_string_buffer(os.fsencode(path))
        fd = bpf(7, struct.pack("<QII", ctypes.addressof(name), 0, 0))
        try:
            info = ctypes.create_string_buffer(256)
            bpf(15, struct.pack("<IIQ", fd, 256, ctypes.addressof(info)))
            _kind, identity, key_size, value_size = struct.unpack_from("<IIII", info.raw)
            control = any(part in path.name for part in ("service_v", "backend_"))
            if seed and control:
                key = ctypes.create_string_buffer(b"\xee" * key_size)
                value = ctypes.create_string_buffer(value_size)
                bpf(2, struct.pack("<IIQQQ", fd, 0, ctypes.addressof(key), ctypes.addressof(value), 0))
            keys, previous = [], None
            if control:
                while True:
                    key = ctypes.create_string_buffer(previous) if previous is not None else None
                    following = ctypes.create_string_buffer(key_size)
                    try:
                        bpf(4, struct.pack("<IIQQ", fd, 0, ctypes.addressof(key) if key else 0,
                                           ctypes.addressof(following)))
                    except OSError as error:
                        if error.errno == errno.ENOENT:
                            break
                        raise
                    previous = following.raw
                    keys.append(previous.hex())
            result[path.name] = {"id": identity, "keySize": key_size, "valueSize": value_size,
                                 "keys": sorted(keys)}
        finally:
            os.close(fd)
    return result


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path)
    parser.add_argument("--ctr", type=Path)
    parser.add_argument("--report-directory", type=Path)
    parser.add_argument("--inspect", type=Path)
    parser.add_argument("--seed-orphans", action="store_true")
    args = parser.parse_args()
    if args.inspect:
        print(json.dumps(inspect_maps(args.inspect, args.seed_orphans)))
        return
    if os.geteuid() != 0 or not args.gr8s or not args.report_directory:
        parser.error("root, --gr8s and --report-directory are required")
    overlay = module("two_node", "smoke-two-node.py")
    traffic = module("service_traffic", "test-service-traffic.py")
    os.environ["GR8S_ENABLE_PACKET_SERVICES"] = "1"
    os.environ["GR8S_SMOKE_KEEP_WORKDIR"] = "1"
    smoke = overlay.Smoke(binary=args.gr8s, startup_timeout=240, state_parent=Path("/var/tmp"),
                          shutdown_timeout=180, pod_cleanup_timeout=180)
    args.report_directory.mkdir(parents=True, exist_ok=True)
    report = {"root": str(smoke.root), "checks": []}

    def save():
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def check(name, passed, observed):
        report["checks"].append({"name": name, "passed": bool(passed), "observed": observed})
        save()
        print(f"{name}: {'passed' if passed else 'failed'}", flush=True)
        if not passed:
            raise AssertionError(name)

    def apply(*objects):
        smoke.kubectl("apply", "-f", "-", input=json.dumps(
            {"apiVersion": "v1", "kind": "List", "items": list(objects)}))

    def maps(seed=False):
        command = ["python3", Path(__file__).resolve(), "--inspect",
                   smoke.root / "agent-0/containerd/bpf/service-lb"]
        if seed:
            command.append("--seed-orphans")
        return json.loads(smoke.in_node(0, *command).stdout)

    def fetch(vip):
        return smoke.kubectl("exec", "two-node-0", "--", "curl", "-fsS", "--max-time", "5",
                             f"http://{vip}/hostname", check=False, timeout=20).stdout.strip()

    try:
        smoke.setup()
        for index in range(2):
            socket_path = smoke.root / f"agent-{index}/containerd/run/containerd.sock"
            overlay.wait_for("managed containerd", socket_path.exists, timeout=180)
            if args.ctr:
                pulled = smoke.in_node(index, args.ctr, "--address", socket_path, "--namespace", "k8s.io",
                                       "images", "pull", traffic.AGNHOST, check=False, timeout=300)
                (args.report_directory / f"image-pull-{index}.log").write_text(pulled.stdout + pulled.stderr)
                if pulled.returncode:
                    raise RuntimeError("direct image preload failed")
        pods = [traffic.server_pod(f"two-node-{index}") for index in range(2)]
        for index, pod in enumerate(pods):
            pod["spec"]["nodeName"] = f"worker-{index}"
        apply(*pods, *(traffic.service(name, [traffic.HTTP], selector={"test.gr8s.io/pod": "two-node-1"})
                      for name in ("kept", "removed")))
        overlay.wait_for("workloads", smoke.check_pods, timeout=300)
        identities = smoke.check_pods()
        services = {name: json.loads(smoke.kubectl("get", "service", name, "-o", "json").stdout)
                    for name in ("kept", "removed")}
        vips = {name: service["spec"]["clusterIP"] for name, service in services.items()}
        for name, vip in vips.items():
            overlay.wait_for("initial Service traffic", lambda vip=vip: fetch(vip) == "two-node-1", timeout=120)
        before = maps()
        check("sixControlMaps", sum("pkt_" not in name for name in before) == 6, before)
        smoke.agents[0].send_signal(signal.SIGTERM)
        smoke.agents[0].wait(timeout=180)
        smoke.agents[0] = None
        # API exec requires the agent being deliberately stopped. Probe from
        # the retained client network namespace instead, directly to the remote
        # Pod, so this check measures surviving workload connectivity.
        namespaces = smoke.in_node(0, "find", smoke.root /
            "agent-0/containerd/run/io.containerd.grpc.v1.cri/netns",
            "-mindepth", "1", "-maxdepth", "1").stdout.splitlines()
        client_namespace = None
        for namespace in namespaces:
            addresses = json.loads(smoke.in_node(0, "nsenter", f"--net={namespace}", "--",
                                                 "ip", "-j", "addr", "show").stdout)
            if any(address.get("local") == identities[0][2]
                   for link in addresses for address in link.get("addr_info", [])):
                client_namespace = namespace
                break
        if client_namespace is None:
            raise RuntimeError("retained client network namespace not found")
        probe = smoke.in_node(0, "nsenter", f"--net={client_namespace}", "--", "python3", "-c",
            "import urllib.request; print(urllib.request.urlopen(" +
            repr(f"http://{identities[1][2]}:8080/hostname") + ",timeout=5).read().decode())",
            check=False, timeout=15)
        check("existingWorkloadWhileAgentDown", probe.returncode == 0 and
              probe.stdout.strip() == "two-node-1",
              {"identities": identities, "probe": probe.stdout + probe.stderr})
        smoke.kubectl("delete", "service", "removed", "--wait=true")
        retained = maps(seed=True)
        check("retainedMapsBeforeRestart", {k: v["id"] for k, v in before.items()} ==
              {k: v["id"] for k, v in retained.items()}, retained)
        check("allControlMapsContainOrphans", all("ee" * value["keySize"] in value["keys"]
              for name, value in retained.items() if "pkt_" not in name), retained)
        smoke.start_agent(0)
        overlay.wait_for("unchanged Pod identities", lambda: smoke.check_pods(identities), timeout=180)
        overlay.wait_for("Service after restart", lambda: fetch(vips["kept"]) == "two-node-1", timeout=180)
        check("serviceAfterRestart", fetch(vips["kept"]) == "two-node-1", vips["kept"])
        def converged():
            current = maps()
            return current if all("ee" * value["keySize"] not in value["keys"]
                                  for name, value in current.items() if "pkt_" not in name) else None
        after = overlay.wait_for("orphan withdrawal", converged, timeout=90)
        check("orphanKeysWithdrawn", True, after)
        check("mapIdsPreserved", {k: v["id"] for k, v in before.items()} ==
              {k: v["id"] for k, v in after.items()}, after)
        # Service VIP key ABI: network address/port bytes, protocol at offset6.
        removed_key = (struct.pack("!H", 80) + socket.inet_aton(vips["removed"]) + b"\x06\x00").hex()
        check("deletedServiceWithdrawn", removed_key in before["gr8s_service_v4"]["keys"] and
              removed_key not in after["gr8s_service_v4"]["keys"], removed_key)
        check("podIdentityPreserved", smoke.check_pods(identities) == identities, identities)
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}")
        save()
        # Restore the deliberately stopped agent so ordinary Pod deletion can
        # clean up even when an assertion in the offline interval fails.
        if smoke.agents[0] is None and smoke.server and smoke.server.poll() is None:
            try:
                smoke.start_agent(0)
            except Exception as restart_error:
                report["cleanupRestartError"] = str(restart_error)
    finally:
        smoke.success = report.get("passed", False)
        try:
            smoke.cleanup()
            report.update(passed=smoke.success, cleanupCompleted=True)
        except Exception as error:
            report.update(passed=False, cleanupError=str(error))
        for path in smoke.root.glob("*.log"):
            shutil.copyfile(path, args.report_directory / path.name)
        errors = []
        for path in args.report_directory.glob("agent-*.log"):
            errors.extend(line for line in path.read_text(errors="replace").splitlines()
                          if "Service LB convergence failed:" in line)
        report["convergenceErrors"] = errors
        if errors:
            report["passed"] = False
        save()
        if report.get("cleanupCompleted"):
            traffic.Cluster.remove(smoke)
    print(json.dumps({"passed": report.get("passed", False), "reportDirectory": str(args.report_directory)}))
    sys.exit(0 if report.get("passed") else 1)


if __name__ == "__main__":
    main()
