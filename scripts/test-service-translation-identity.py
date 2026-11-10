#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify private Service translation identities with two real managed agents.

Root disposable VM only. Provisions a private IPAM lease while its agent is
stopped; no packet source-NAT claim. Requires smoke-two-node.py and
test-service-traffic.py alongside this file.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import sys


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def provision_lease(path, primary, remove=False):
    """Model the validated allocator's file format only with the owner stopped."""
    state = json.loads(path.read_text())
    cidrs = state.get("cidrs", [state.get("cidr")])
    rows = state["allocations"]
    for row in rows:
        if "addresses" not in row:
            row["addresses"] = [row.pop("address")]
    owners = [row for row in rows if primary in row["addresses"]]
    if len(owners) != 1:
        raise RuntimeError("expected one durable lease for the observed client IP")
    owner = owners[0]
    aliases = state.setdefault("serviceSNATAllocations", [])
    if remove:
        state["serviceSNATAllocations"] = [x for x in aliases if
            (x["sandboxID"], x["interfaceName"]) != (owner["sandboxID"], owner["interfaceName"])]
        alias = None
    else:
        used = {ip for row in rows for ip in row["addresses"]} | {x["address"] for x in aliases}
        pool = next(ipaddress.ip_network(c) for c in cidrs if ipaddress.ip_network(c).version == 4)
        alias = next(str(ip) for ip in pool.hosts() if str(ip) not in used)
        aliases.append({"sandboxID": owner["sandboxID"], "interfaceName": owner["interfaceName"],
                        "address": alias})
    state["version"] = 3
    state["cidrs"] = cidrs
    state.pop("cidr", None)
    temporary = path.with_suffix(".identity-test.tmp")
    temporary.write_text(json.dumps(state) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    return {"podIP": primary, "address": alias, "sandboxID": owner["sandboxID"],
            "interfaceName": owner["interfaceName"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--ctr", type=Path)
    parser.add_argument("--report-directory", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root in a disposable VM")
    overlay = module("identity_overlay", "smoke-two-node.py")
    traffic = module("identity_traffic", "test-service-traffic.py")
    os.environ["GR8S_SMOKE_KEEP_WORKDIR"] = "1"
    os.environ["GR8S_ENABLE_PACKET_SERVICES"] = "1"
    smoke = overlay.Smoke(binary=args.gr8s, startup_timeout=240, shutdown_timeout=180,
                          pod_cleanup_timeout=180, state_parent=Path("/var/tmp"))
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

    def identities():
        return [{"uid": smoke.pod(i)["metadata"]["uid"], "ip": smoke.pod(i)["status"]["podIP"],
                 "containers": [c["containerID"] for c in smoke.pod(i)["status"]["containerStatuses"]]}
                for i in range(2)]

    def inventory(i):
        return json.loads((smoke.root / f"agent-{i}/runtime/network.json").read_text()).get("serviceTranslations", [])

    def all_inventory(expected):
        current = [inventory(i) for i in range(2)]
        return current if all(len(rows) == expected for rows in current) else None

    def stop_client():
        smoke.agents[0].send_signal(signal.SIGTERM)
        smoke.agents[0].wait(timeout=180)
        smoke.agents[0] = None

    try:
        smoke.setup()
        for i in range(2):
            socket = smoke.root / f"agent-{i}/containerd/run/containerd.sock"
            overlay.wait_for("managed containerd", socket.exists, timeout=180)
            if args.ctr:
                answer = smoke.in_node(i, args.ctr, "--address", socket, "--namespace", "k8s.io",
                                       "images", "pull", traffic.AGNHOST, check=False, timeout=300)
                (args.report_directory / f"image-pull-{i}.log").write_text(answer.stdout + answer.stderr)
                if answer.returncode:
                    raise RuntimeError("direct image preload failed")
            pod = traffic.server_pod(f"two-node-{i}")
            pod["spec"]["nodeName"] = f"worker-{i}"
            smoke.kubectl("apply", "-f", "-", input=json.dumps(pod))
        overlay.wait_for("native workloads", smoke.check_pods, timeout=300)
        before = identities()
        check("noPrivateIdentitiesBeforeLease", all_inventory(0), [inventory(i) for i in range(2)])
        primary = before[0]["ip"]
        stop_client()
        lease = provision_lease(smoke.root / "agent-0/runtime/ipam/allocations.json", primary)
        report["lease"] = lease
        smoke.start_agent(0)
        rows = overlay.wait_for("private identity on both nodes", lambda: all_inventory(1), timeout=120)
        check("authenticatedIdentityProjected", all(
            row[0]["address"] == lease["address"] and row[0]["podIP"] == primary and
            row[0]["podUID"] == before[0]["uid"] and row[0]["sandboxID"] == lease["sandboxID"] and
            row[0]["nodeName"] == "worker-0" and bool(row[0]["nodeID"]) for row in rows), rows)
        public = smoke.pod(0)
        check("privateIdentityHiddenFromPodStatus", "gr8sServiceTranslation" not in public["status"] and
              lease["address"] not in [x["ip"] for x in public["status"]["podIPs"]], public["status"])
        check("workloadsUnchangedAfterLease", identities() == before, identities())
        checkpoint = list((smoke.root / "control").rglob(f"observations/{before[0]['uid']}.json"))
        if len(checkpoint) != 1:
            raise RuntimeError("expected one private observation checkpoint")
        private = json.loads(checkpoint[0].read_text())["status"]["gr8sServiceTranslation"]
        check("privateIdentityCheckpointed", private["address"] == lease["address"] and
              private["podUID"] == before[0]["uid"], private)
        stop_client()
        smoke.start_agent(0)
        restored = overlay.wait_for("identity after owner restart", lambda: all_inventory(1), timeout=120)
        check("identityRetainedAcrossOwnerRestart", restored == rows and identities() == before, restored)
        stop_client()
        provision_lease(smoke.root / "agent-0/runtime/ipam/allocations.json", primary, remove=True)
        smoke.start_agent(0)
        withdrawn = overlay.wait_for("identity withdrawal on both nodes", lambda: all_inventory(0), timeout=120)
        check("identityWithdrawnOnBothNodes", bool(withdrawn) and identities() == before, withdrawn)
        check("publicStatusStillPrivate", "gr8sServiceTranslation" not in smoke.pod(0)["status"], smoke.pod(0)["status"])
        responses = [smoke.kubectl("exec", f"two-node-{i}", "--", "curl", "-fsS", "--max-time", "5",
                                  f"http://{before[1-i]['ip']}:8080/hostname").stdout.strip()
                     for i in range(2)]
        check("nativeTrafficAfterWithdrawal", responses == ["two-node-1", "two-node-0"], responses)
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        if smoke.agents[0] is None and smoke.server and smoke.server.poll() is None:
            try:
                smoke.start_agent(0)
            except Exception as error:
                report["cleanupRestartError"] = str(error)
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
        save()
        if report.get("cleanupCompleted"):
            traffic.Cluster.remove(smoke)
    print(json.dumps({"passed": report.get("passed"), "reportDirectory": str(args.report_directory)}))
    sys.exit(0 if report.get("passed") else 1)


if __name__ == "__main__":
    main()
