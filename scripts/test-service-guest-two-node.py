#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify real guest TC Services and policy over a two-node overlay.

Run as root in a disposable VM with nested KVM. Copy smoke-two-node.py,
test-service-guest.py and test-service-traffic.py alongside this script.
Two agents run in distinct mount/network namespaces, joined by a routed
underlay. A Kata guest on worker-0 reaches a native backend on worker-1.
This tests cross-node routing, not two physical hosts or NIC offloads.
"""

import argparse
import base64
import gzip
import hashlib
import ipaddress
import struct
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import urllib.parse


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


guest = module("service_guest", "test-service-guest.py")
overlay = module("two_node", "smoke-two-node.py")
traffic = guest.traffic
CLIENT, BACKEND = "two-node-0", "two-node-1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--kata-bundle", type=Path, required=True)
    parser.add_argument("--kata-sha256", required=True)
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--ctr", type=Path)
    parser.add_argument("--tcp-client", type=Path,
                        help="optional static service-tcp-client probe for real guest source-port reuse")
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--kata-agent-timeout-ms", type=int, default=120000)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/dev/kvm").exists():
        sys.exit("run as root in a disposable VM with nested KVM")
    os.environ["GR8S_ENABLE_PACKET_SERVICES"] = "1"
    os.environ["GR8S_SMOKE_KEEP_WORKDIR"] = "1"
    smoke = overlay.Smoke(binary=args.gr8s, startup_timeout=240, state_parent=args.state_parent,
                          shutdown_timeout=180, pod_cleanup_timeout=180)
    args.report_directory.mkdir(parents=True, exist_ok=True)
    report = {"root": str(smoke.root), "checks": [], "overlay": smoke.overlay,
              "kataSHA256": args.kata_sha256, "agentReconnectTimeoutMs": args.kata_agent_timeout_ms}

    def save():
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def check(name, passed, observed):
        report["checks"].append({"name": name, "passed": bool(passed), "observed": observed})
        save()
        if not passed:
            raise AssertionError(name)

    def get(kind, name):
        return json.loads(smoke.kubectl("get", kind, name, "-o", "json").stdout)

    def apply(*objects):
        smoke.kubectl("apply", "-f", "-", input=json.dumps(
            {"apiVersion": "v1", "kind": "List", "items": list(objects)}))

    def counters(index):
        path = smoke.root / f"agent-{index}/containerd/bpf/service-lb/gr8s_pkt_stats"
        return json.loads(smoke.in_node(index, "python3", Path(guest.__file__).resolve(),
                                       "--read-packet-counters", path).stdout)

    def dial(destination, port, protocol, request="hostname"):
        query = urllib.parse.urlencode({"host": destination, "port": port,
                                       "protocol": protocol, "request": request, "tries": 1})
        # The control request stays inside the guest. The dialed socket also
        # belongs to the guest kernel; host cgroup socket hooks cannot rewrite it.
        result = smoke.kubectl("exec", CLIENT, "--request-timeout=30s", "--", "curl",
                               "-sS", "--max-time", "12", "http://127.0.0.1:8080/dial?" + query,
                               check=False, timeout=40)
        try:
            body = json.loads(result.stdout)
        except ValueError:
            body = {"controlError": result.stdout + result.stderr}
        return {"returncode": result.returncode, "body": body}

    def succeeds(answer):
        return answer["returncode"] == 0 and answer["body"].get("responses") == [BACKEND]

    def denied(answer):
        return (answer["returncode"] == 0 and bool(answer["body"].get("errors"))
                and not answer["body"].get("responses"))

    def observed_when(description, probe, predicate):
        last = None

        def attempt():
            nonlocal last
            last = probe()
            return last if predicate(last) else None

        try:
            return overlay.wait_for(description, attempt, timeout=90)
        except RuntimeError as error:
            raise RuntimeError(f"{error}; last observation: {last}") from error

    def client_policy(rules):
        return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                "metadata": {"name": "guest-policy", "namespace": "default"},
                "spec": {"podSelector": {"matchLabels": {"app": "guest"}},
                         "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": rules}}

    try:
        with (args.report_directory / "install.log").open("w") as log:
            subprocess.run([str(smoke.binary), "runtime", "install", "kata", "--state-directory",
                            str(smoke.root / "agent-0"), "--bundle", str(args.kata_bundle.resolve()),
                            "--sha256", args.kata_sha256], stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=600)
        guest.configure_test_kata(smoke, args.kata_agent_timeout_ms,
                                  addon_root=smoke.root / "agent-0/runtime-addons/kata")
        smoke.setup()
        for index in range(2):
            socket_path = smoke.root / f"agent-{index}/containerd/run/containerd.sock"
            overlay.wait_for(f"worker-{index} managed containerd", socket_path.exists, timeout=180)
            if args.ctr:
                with (args.report_directory / f"image-pull-{index}.log").open("w") as log:
                    result = smoke.in_node(index, args.ctr, "--address", socket_path,
                                           "--namespace", "k8s.io", "images", "pull", traffic.AGNHOST,
                                           check=False, timeout=300)
                    log.write(result.stdout + result.stderr)
                    if result.returncode:
                        raise RuntimeError(f"worker-{index} image preload failed; see image-pull log")
        client = traffic.server_pod(CLIENT)
        client["spec"].update(nodeName="worker-0", runtimeClassName="kata")
        client["metadata"]["labels"]["app"] = "guest"
        backend = traffic.server_pod(BACKEND)
        backend["spec"]["nodeName"] = "worker-1"
        apply({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
               "metadata": {"name": "kata"}, "handler": "kata"}, client, backend,
              traffic.service("guest-remote", [traffic.HTTP, traffic.UDP],
                              selector={"test.gr8s.io/pod": BACKEND}))
        overlay.wait_for("both workloads ready", lambda: all(
            any(c["type"] == "Ready" and c["status"] == "True"
                for c in get("pod", name).get("status", {}).get("conditions", []))
            for name in (CLIENT, BACKEND)), timeout=600)
        client, backend = get("pod", CLIENT), get("pod", BACKEND)
        client_ip, backend_ip = client["status"]["podIP"], backend["status"]["podIP"]
        check("differentNodes", client["spec"]["nodeName"] == "worker-0" and
              backend["spec"]["nodeName"] == "worker-1",
              {"client": client_ip, "backend": backend_ip,
               "nodes": [client["spec"]["nodeName"], backend["spec"]["nodeName"]]})
        kernel = smoke.kubectl("exec", CLIENT, "--", "uname", "-r").stdout.strip()
        qemus = []
        for path in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                command = path.read_bytes()
                if b"qemu-system" in command.split(b"\0")[0] and os.fsencode(smoke.root) in command:
                    qemus.append({"pid": int(path.parent.name), "command": command.replace(b"\0", b" ").decode()})
            except OSError:
                pass
        check("realGuestKernel", kernel != platform.release() and qemus,
              {"guest": kernel, "host": platform.release(), "qemu": qemus})
        for index, peer in ((0, backend_ip), (1, client_ip)):
            route = json.loads(smoke.in_node(index, "ip", "-j", "route", "get", peer).stdout)
            check(f"worker{index}UsesOverlay", route[0].get("dev") == smoke.overlay_interface, route)
        vip = get("service", "guest-remote")["spec"]["clusterIP"]
        for protocol, target, port in (("http", 8080, 80), ("udp", 8081, 81)):
            answer = observed_when(f"direct {protocol} backend", lambda: dial(backend_ip, target, protocol), succeeds)
            check(protocol + "DirectBackend", succeeds(answer), answer)
            before = counters(0)
            answer = observed_when(f"{protocol} ClusterIP", lambda: dial(vip, port, protocol), succeeds)
            after = counters(0)
            check(protocol + "CrossNodeClusterIP", succeeds(answer), answer)
            check(protocol + "TCBothDirections", after[0] > before[0] and after[1] > before[1],
                  {"before": before, "after": after})
            answer = dial(vip, port, protocol, "clientip")
            replies = answer["body"].get("responses", [])
            check(protocol + "PreservesSource", len(replies) == 1 and
                  replies[0].rsplit(":", 1)[0] == client_ip, answer)
        before = [counters(i) for i in range(2)]
        native = smoke.kubectl("exec", BACKEND, "--", "curl", "-fsS", "--max-time", "10",
                               f"http://{vip}/hostname").stdout
        after = [counters(i) for i in range(2)]
        check("nativeSocketAcceleration", native == BACKEND and
              all(a[:2] == b[:2] for a, b in zip(before, after)),
              {"response": native, "before": before, "after": after})
        if args.tcp_client:
            alternate = "tcp-alternate"
            probe_path = "/tmp/gr8s-service-tcp-client"
            payload = args.tcp_client.read_bytes()
            encoded = base64.b64encode(gzip.compress(payload)).decode()
            smoke.kubectl("exec", CLIENT, "--request-timeout=120s", "-i", "--", "sh", "-c",
                           f"base64 -d | gzip -d > {probe_path} && chmod 755 {probe_path}",
                           input=encoded, timeout=130)
            actual = smoke.kubectl("exec", CLIENT, "--", "sha256sum", probe_path).stdout.split()[0]
            check("guestTcpProbeVerified", actual == hashlib.sha256(payload).hexdigest(), actual)
            alternate_pod = traffic.server_pod(alternate)
            alternate_pod["spec"]["nodeName"] = "worker-1"
            apply(alternate_pod, traffic.service("guest-tcp-reuse", [traffic.HTTP],
                                               selector={"test.gr8s.io/pod": BACKEND}))
            overlay.wait_for("alternate backend ready", lambda: any(
                c["type"] == "Ready" and c["status"] == "True"
                for c in get("pod", alternate).get("status", {}).get("conditions", [])), timeout=300)
            reuse_vip = get("service", "guest-tcp-reuse")["spec"]["clusterIP"]
            local_port = 25090  # outside the default ephemeral range used by ordinary probes

            def fixed_connection(mode="reset"):
                answer = smoke.kubectl("exec", CLIENT, "--request-timeout=30s", "--", probe_path,
                                       reuse_vip, str(local_port), *(["fin"] if mode == "fin" else []),
                                       check=False, timeout=40)
                try:
                    return json.loads(answer.stdout)
                except ValueError:
                    return {"error": answer.stdout + answer.stderr, "returncode": answer.returncode}

            def tcp_state():
                key = (ipaddress.ip_address(client_ip).packed + ipaddress.ip_address(reuse_vip).packed +
                       struct.pack("!HHBBH", local_port, 80, 6, 0, 0)).hex()
                path = smoke.root / "agent-0/containerd/bpf/service-lb/gr8s_pkt_tcp"
                return json.loads(smoke.in_node(0, "python3", Path(guest.__file__).resolve(),
                                               "--read-tcp-state", path, key).stdout)

            first = observed_when("fixed-port initial guest connection", fixed_connection,
                                  lambda answer: answer.get("body") == BACKEND)
            state_before = tcp_state()
            check("guestTcpInitialGeneration", state_before["backend"] == backend_ip and
                  bool(state_before["flags"] & 4), {"connection": first, "state": state_before})
            check("guestTcpResetObserved", bool(state_before["flags"] & 128), state_before)
            check("guestTcpOptionsTracked", state_before["flags"] & 15360 == 15360 and
                  state_before["flags"] & 49152 == 49152 and
                  0 <= state_before["clientScale"] <= 14 and 0 <= state_before["serverScale"] <= 14,
                  state_before)
            apply(traffic.service("guest-tcp-reuse", [traffic.HTTP],
                                  selector={"test.gr8s.io/pod": alternate}))
            second = observed_when("same guest source port reaches replacement", fixed_connection,
                                   lambda answer: answer.get("body") == alternate)
            state_after = tcp_state()
            alternate_ip = get("pod", alternate)["status"]["podIP"]
            identity = ("localIP", "localPort", "peerIP", "peerPort")
            check("guestTcpSourcePortReused", all(first[k] == second[k] for k in identity) and
                  first["localIP"] == client_ip and first["localPort"] == local_port and
                  first["peerIP"] == reuse_vip and first["peerPort"] == 80,
                  {"before": first, "after": second})
            check("guestTcpNewGenerationSelectsReplacement", state_after["backend"] == alternate_ip and
                  state_after["clientISN"] != state_before["clientISN"] and bool(state_after["flags"] & 4),
                  {"before": state_before, "after": state_after, "replacement": alternate_ip})
            # A second tuple exercises a graceful half-close and the final reply FIN.
            local_port = 25091
            graceful = observed_when("graceful guest connection", lambda: fixed_connection("fin"),
                                     lambda answer: answer.get("body") == alternate)
            closed = tcp_state()
            check("guestTcpGracefulCloseObserved", bool(closed["flags"] & 256) and
                  closed["backend"] == alternate_ip, {"connection": graceful, "state": closed})
            local_port = 25090
            old_service = get("service", "guest-tcp-reuse")
            smoke.kubectl("delete", "service", "guest-tcp-reuse", "--wait=true")
            recreated = traffic.service("guest-tcp-reuse", [traffic.HTTP],
                                        selector={"test.gr8s.io/pod": BACKEND})
            recreated["spec"]["clusterIP"] = reuse_vip
            apply(recreated)
            current_service = get("service", "guest-tcp-reuse")
            check("guestTcpServiceIdentityReplaced", current_service["metadata"]["uid"] !=
                  old_service["metadata"]["uid"] and current_service["spec"]["clusterIP"] == reuse_vip,
                  {"beforeUID": old_service["metadata"]["uid"],
                   "afterUID": current_service["metadata"]["uid"], "vip": reuse_vip})
            third = observed_when("recreated Service on the same guest tuple", fixed_connection,
                                  lambda answer: answer.get("body") == BACKEND)
            replaced_state = tcp_state()
            check("guestTcpRecreatedServiceUsesCurrentBackend", all(third[k] == first[k] for k in identity) and
                  replaced_state["backend"] == backend_ip and
                  replaced_state["clientISN"] != state_after["clientISN"] and
                  bool(replaced_state["flags"] & 4), {"connection": third, "state": replaced_state})
        apply(client_policy([]))
        for protocol, port in (("http", 80), ("udp", 81)):
            answer = observed_when(f"default-deny {protocol}", lambda: dial(vip, port, protocol), denied)
            check(protocol + "GuestEgressDenied", denied(answer), answer)
        ports = [{"protocol": "TCP", "port": 8080}, {"protocol": "UDP", "port": 8081}]
        rules = [{"to": [{"ipBlock": {"cidr": backend_ip + "/32"}}], "ports": ports}]
        apply(client_policy(rules))
        for protocol, port in (("http", 80), ("udp", 81)):
            answer = observed_when(f"backend-only {protocol} policy", lambda: dial(vip, port, protocol), succeeds)
            check(protocol + "PolicySeesBackendAndAllowsReplies", succeeds(answer), answer)
        remote_policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                         "metadata": {"name": "backend-policy", "namespace": "default"},
                         "spec": {"podSelector": {"matchLabels": {"test.gr8s.io/pod": BACKEND}},
                                  "policyTypes": ["Ingress"], "ingress": []}}
        apply(remote_policy)
        for protocol, port in (("http", 80), ("udp", 81)):
            answer = observed_when(f"backend ingress deny {protocol}", lambda: dial(vip, port, protocol), denied)
            check(protocol + "RemoteIngressDenied", denied(answer), answer)
        remote_policy["spec"]["ingress"] = [{"from": [{"podSelector": {"matchLabels": {"app": "guest"}}}],
                                                "ports": ports}]
        apply(remote_policy)
        for protocol, port in (("http", 80), ("udp", 81)):
            answer = observed_when(f"backend ingress allow {protocol}", lambda: dial(vip, port, protocol), succeeds)
            check(protocol + "RemoteIngressRecovers", succeeds(answer), answer)
        cni_timeouts = {str(i): (smoke.root / f"agent-{i}.log").read_text().count(
            "failed (add): timed out waiting for the gr8s agent CNI service") for i in range(2)}
        check("coldCniAddsMeetDeadline", not any(cni_timeouts.values()), cni_timeouts)
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["passed"] = False
        report["error"] = f"{type(error).__name__}: {error}"
        for resource in ("pods", "events", "endpointslices", "networkpolicies"):
            try:
                (args.report_directory / (resource + ".json")).write_text(
                    smoke.kubectl("get", resource, "-o", "json", check=False).stdout)
            except Exception:
                pass
    finally:
        if args.tcp_client and smoke.server and smoke.server.poll() is None:
            try:
                smoke.kubectl("delete", "pod", "tcp-alternate", "--ignore-not-found", "--wait=false", check=False)
            except Exception as error:
                report["extraPodCleanupError"] = str(error)
                report["passed"] = False
        smoke.success = report.get("passed", False)
        try:
            smoke.cleanup()
            report["passed"] = smoke.success
            report["cleanupCompleted"] = True
        except Exception as error:
            report["passed"] = False
            report["cleanupError"] = str(error)
        for path in smoke.root.glob("*.log"):
            shutil.copyfile(path, args.report_directory / path.name)
        for index in range(2):
            source = smoke.root / f"agent-{index}/containerd/containerd.log"
            if source.exists():
                shutil.copyfile(source, args.report_directory / f"containerd-{index}.log")
        save()
        if report.get("cleanupCompleted"):
            traffic.Cluster.remove(smoke)
            link = Path("/opt/kata")
            if link.is_symlink() and str(link.readlink()).startswith(str(smoke.root) + "/"):
                link.unlink()
    print(json.dumps({"reportDirectory": str(args.report_directory), "passed": report.get("passed", False)}))
    sys.exit(0 if report.get("passed") else 1)


if __name__ == "__main__":
    main()
