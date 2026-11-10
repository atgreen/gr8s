#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify private Service translation identities with two real managed agents.

Root disposable VM only. Exercises actual CNI allocation and private return
route/neighbor lifecycle; no packet source-NAT claim. Requires smoke-two-node.py and
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


ENDPOINT_IDENTITY_PROBE = """
import ctypes,json,os,platform,struct,sys
libc=ctypes.CDLL(None,use_errno=True)
number={"x86_64":321,"aarch64":280}[platform.machine()]
def bpf(command,data):
    attr=ctypes.create_string_buffer(data,len(data))
    result=libc.syscall(number,command,ctypes.byref(attr),len(data))
    if result<0:
        e=ctypes.get_errno();raise OSError(e,os.strerror(e))
    return result
name=ctypes.create_string_buffer(os.fsencode(sys.argv[1]))
fd=bpf(7,struct.pack("<QII",ctypes.addressof(name),0,0))
try:
    key=ctypes.create_string_buffer(struct.pack("<I",0))
    value=ctypes.create_string_buffer(32)
    bpf(1,struct.pack("<IIQQQ",fd,0,ctypes.addressof(key),ctypes.addressof(value),0))
    print(json.dumps({"ipv4":struct.unpack_from("<I",value.raw)[0],"bytes":value.raw.hex()}))
finally:
    os.close(fd)
"""


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

    def ipam_state(i):
        return json.loads((smoke.root / f"agent-{i}/runtime/ipam/allocations.json").read_text())

    def lease_for(i, primary):
        state = ipam_state(i)
        owner = next(x for x in state["allocations"] if primary in x.get("addresses", [x.get("address")]))
        alias = next(x for x in state["serviceSNATAllocations"] if
                     (x["sandboxID"], x["interfaceName"]) == (owner["sandboxID"], owner["interfaceName"]))
        return {**alias, "podIP": primary}

    def sandbox_netns(i):
        state = smoke.root / f"agent-{i}/containerd"
        namespaces = smoke.in_node(i, "find", state / "run/io.containerd.grpc.v1.cri/netns",
                                   "-mindepth", "1", "-maxdepth", "1").stdout.splitlines()
        if len(namespaces) != 1:
            raise RuntimeError("expected one actual sandbox namespace")
        return namespaces[0]

    def cni(i, command):
        state = smoke.root / f"agent-{i}/containerd"
        config = json.loads((state / "cni/net.d/10-gr8s.conflist").read_text())
        plugin = {**config["plugins"][0], "name": config["name"], "cniVersion": config["cniVersion"]}
        lease = lease_for(i, smoke.pod(i)["status"]["podIP"])
        return smoke.in_node(i, "env", f"CNI_COMMAND={command}", f"CNI_CONTAINERID={lease['sandboxID']}",
                             f"CNI_NETNS={sandbox_netns(i)}", "CNI_IFNAME=eth0", args.gr8s,
                             input=json.dumps(plugin), check=False, timeout=60)

    def return_path(i, lease):
        routes = json.loads(smoke.in_node(i, "ip", "-j", "-4", "route", "show", "exact",
                                          f"{lease['address']}/32").stdout)
        if len(routes) != 1:
            raise RuntimeError(f"expected one private return route: {routes}")
        host = routes[0]["dev"]
        links = json.loads(smoke.in_node(i, "ip", "-j", "link", "show", "dev", host).stdout)
        neighbors = json.loads(smoke.in_node(i, "ip", "-j", "neigh", "show", "to", lease["address"],
                                            "dev", host).stdout)
        public_addresses = json.loads(smoke.in_node(i, "nsenter", f"--net={sandbox_netns(i)}", "--",
                                                   "ip", "-j", "address", "show", "dev", lease["interfaceName"]).stdout)
        identity = json.loads(smoke.in_node(i, "python3", "-c", ENDPOINT_IDENTITY_PROBE,
                                           smoke.root / f"agent-{i}/containerd/bpf/{lease['sandboxID']}/endpoint_identity").stdout)
        return {"route": routes[0], "link": links[0], "neighbors": neighbors,
                "podAddresses": [x["local"] for link in public_addresses for x in link.get("addr_info", [])],
                "peerMAC": public_addresses[0]["address"],
                "endpointIdentity": identity}

    def healthy_path(lease, path):
        return (path["route"].get("prefsrc") == "169.254.1.1" and
                path["link"].get("ifalias") == f"gr8s:{lease['sandboxID']}/{lease['interfaceName']}" and
                len(path["neighbors"]) == 1 and "PERMANENT" in path["neighbors"][0].get("state", []) and
                path["neighbors"][0].get("lladdr") == path["peerMAC"] and
                lease["address"] not in path["podAddresses"] and lease["podIP"] in path["podAddresses"] and
                path["endpointIdentity"]["ipv4"] == int(ipaddress.ip_address(lease["podIP"])))

    def native_traffic():
        current = identities()
        return [smoke.kubectl("exec", f"two-node-{i}", "--", "curl", "-fsS", "--max-time", "5",
                              f"http://{current[1-i]['ip']}:8080/hostname").stdout.strip() for i in range(2)]

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
        leases = [lease_for(i, before[i]["ip"]) for i in range(2)]
        lease = leases[0]
        report["leases"] = leases
        rows = overlay.wait_for("automatic CNI identity on both nodes", lambda: all_inventory(2), timeout=120)
        check("authenticatedAutomaticIdentitiesProjected", all(
            any(record["address"] == leases[i]["address"] and record["podIP"] == before[i]["ip"] and
                record["podUID"] == before[i]["uid"] and record["sandboxID"] == leases[i]["sandboxID"] and
                record["nodeName"] == f"worker-{i}" and bool(record["nodeID"]) for record in row)
            for row in rows for i in range(2)), rows)
        check("privateIdentitiesHiddenFromPodStatus", all(
            "gr8sServiceTranslation" not in smoke.pod(i)["status"] and
            leases[i]["address"] not in [x["ip"] for x in smoke.pod(i)["status"]["podIPs"]] for i in range(2)),
            [smoke.pod(i)["status"] for i in range(2)])
        paths = [return_path(i, leases[i]) for i in range(2)]
        check("privateKernelReturnPathsAndPrimaryOnlyGuardIdentity", all(
            healthy_path(leases[i], paths[i]) for i in range(2)), paths)
        answers = [cni(i, "CHECK") for i in range(2)]
        check("cniCheckBothEndpoints", all(x.returncode == 0 for x in answers), [x.stdout + x.stderr for x in answers])
        host = paths[0]["route"]["dev"]
        smoke.in_node(0, "ip", "neigh", "del", lease["address"], "dev", host)
        answer = cni(0, "CHECK")
        check("missingNeighborFailsCheck", answer.returncode != 0, answer.stdout + answer.stderr)
        answer = cni(0, "ADD")
        check("addRepairsNeighbor", answer.returncode == 0 and healthy_path(lease, return_path(0, lease)),
              answer.stdout + answer.stderr)
        result = json.loads(answer.stdout)
        check("cniResultExcludesPrivateAddress", all(
            str(ipaddress.ip_interface(x["address"]).ip) != lease["address"] for x in result["ips"]), result)
        smoke.in_node(0, "ip", "route", "del", f"{lease['address']}/32", "dev", host)
        answer = cni(0, "CHECK")
        check("missingRouteFailsCheck", answer.returncode != 0, answer.stdout + answer.stderr)
        answer = cni(0, "ADD")
        check("addRepairsRoute", answer.returncode == 0 and healthy_path(lease, return_path(0, lease)), answer.stdout)
        smoke.in_node(0, "ip", "route", "replace", f"{lease['address']}/32", "dev", "lo")
        answer = cni(0, "ADD")
        conflict = json.loads(smoke.in_node(0, "ip", "-j", "-4", "route", "show", "exact",
                                           f"{lease['address']}/32").stdout)
        check("conflictingRouteAddFailsWithoutStealing", answer.returncode != 0 and
              len(conflict) == 1 and conflict[0]["dev"] == "lo" and lease_for(0, lease["podIP"]) == lease,
              {"result": answer.stdout + answer.stderr, "route": conflict})
        smoke.in_node(0, "ip", "route", "del", f"{lease['address']}/32", "dev", "lo")
        answer = cni(0, "ADD")
        check("addRecoversAfterConflictRemoval", answer.returncode == 0 and healthy_path(lease, return_path(0, lease)),
              answer.stdout + answer.stderr)
        checkpoint = list((smoke.root / "control").rglob(f"observations/{before[0]['uid']}.json"))
        if len(checkpoint) != 1:
            raise RuntimeError("expected one private observation checkpoint")
        private = json.loads(checkpoint[0].read_text())["status"]["gr8sServiceTranslation"]
        check("privateIdentityCheckpointed", private["address"] == lease["address"] and
              private["podUID"] == before[0]["uid"], private)
        stop_client()
        smoke.start_agent(0)
        restored = overlay.wait_for("identity after owner restart", lambda: all_inventory(2), timeout=120)
        check("identityRetainedAcrossOwnerRestart", restored == rows and identities() == before, restored)
        path = return_path(0, lease)
        check("returnPathSurvivesOwnerRestart", healthy_path(lease, path), path)
        responses = native_traffic()
        check("nativeTrafficAfterRepairsAndRestart", responses == ["two-node-1", "two-node-0"], responses)
        smoke.kubectl("delete", "pod", "two-node-0", "--wait=false")
        withdrawn = overlay.wait_for("CNI identity withdrawal on both nodes", lambda: all_inventory(1), timeout=180)
        check("identityWithdrawnOnBothNodes", all(all(x["podUID"] != before[0]["uid"] for x in row)
                                                  for row in withdrawn), withdrawn)
        overlay.wait_for("Pod deletion", lambda: not smoke.kubectl("get", "pod", "two-node-0",
                         "--ignore-not-found", "-o", "json").stdout.strip(), timeout=180)
        def released():
            state = ipam_state(0)
            gone = smoke.in_node(0, "ip", "link", "show", "dev", host, check=False)
            routes = json.loads(smoke.in_node(0, "ip", "-j", "-4", "route", "show", "exact",
                                             f"{lease['address']}/32").stdout)
            return state if (gone.returncode != 0 and not routes and
                not any(x["sandboxID"] == lease["sandboxID"] for x in state.get("serviceSNATAllocations", [])) and
                not any(x["sandboxID"] == lease["sandboxID"] for x in state["allocations"])) else None
        state = overlay.wait_for("private lease and owned return-link deletion", released, timeout=180)
        check("deleteReleasesPrivateLeaseAndOwnedReturnLink", True, state)
        pod = traffic.server_pod("two-node-0")
        pod["spec"]["nodeName"] = "worker-0"
        smoke.kubectl("apply", "-f", "-", input=json.dumps(pod))
        overlay.wait_for("replacement native workload", smoke.check_pods, timeout=180)
        current = identities()
        replacement = lease_for(0, current[0]["ip"])
        path = return_path(0, replacement)
        check("releasedAliasReusedByNewEndpointOwner", current[0]["uid"] != before[0]["uid"] and
              replacement["sandboxID"] != lease["sandboxID"] and replacement["address"] == lease["address"] and
              path["route"]["dev"] != host and healthy_path(replacement, path), {"lease": replacement, "path": path})
        overlay.wait_for("replacement identity on both nodes", lambda: all_inventory(2), timeout=120)
        responses = native_traffic()
        check("nativeTrafficAfterAliasReuse", responses == ["two-node-1", "two-node-0"], responses)
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
