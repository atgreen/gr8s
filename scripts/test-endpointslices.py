#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Validate actual EndpointSlice and selectorless Service forwarding in an owned native guest."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import socket
import struct
import tempfile
import time
import traceback
import urllib.error
import urllib.request
import uuid


def main():
    """Run actual HTTP backend, readiness, restart and terminating-endpoint scenarios."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--api-port", type=int, default=18207)
    parser.add_argument("--node-port", type=int, default=17464)
    parser.add_argument("--verify-dns", action="store_true", help="also verify actual UDP/TCP Service and headless DNS")
    parser.add_argument("--verify-dns-records", action="store_true", help="also verify actual SRV/PTR, Pod hostname/hosts and escaped command execution")
    args = parser.parse_args()
    if args.verify_dns_records:
        args.verify_dns = True
    root = Path(tempfile.mkdtemp(prefix="gr8s-endpointslices.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    namespace = "slices-" + uuid.uuid4().hex[:8]
    base = f"http://127.0.0.1:{args.api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    log = (root / "gr8s.log").open("w")
    process = None
    seen = {}
    report = {"directory": str(root), "stateDirectory": str(state), "namespace": namespace,
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(),
              "scenarios": {}, "nativeExitCodes": [], "passed": False}
    print(json.dumps({"directory": str(root), "namespace": namespace}), flush=True)

    def request(path, method="GET", obj=None, content_type="application/json"):
        """Read an actual API response while retaining server failure status."""
        data = None if obj is None else json.dumps(obj).encode()
        req = urllib.request.Request(base + path, method=method, data=data, headers={"Content-Type": content_type})
        try:
            with opener.open(req, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def wait(predicate, description, timeout=300):
        """Observe one ongoing operation without restarting it on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except OSError as error:
                report.setdefault("observationErrors", []).append(str(error))
            time.sleep(.2)
        raise TimeoutError(description)

    def stop():
        """Stop only this test's native process and require a clean exit."""
        nonlocal process
        if process:
            process.terminate()
            code = process.wait(timeout=45)
            report["nativeExitCodes"].append(code)
            process = None
            assert code == 0, code

    def start():
        """Start the same durable state and wait for actual worker readiness."""
        nonlocal process
        process = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                    "--port", str(args.api_port), "--node-port", str(args.node_port),
                                    "--kubeconfig", str(root / "kubeconfig")], stdout=log, stderr=subprocess.STDOUT)
        def ready():
            """Detect an early native exit while observing readiness."""
            if process.poll() is not None:
                raise RuntimeError(f"native exited {process.returncode}")
            with opener.open(base + "/metrics", timeout=2) as response:
                return 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in response.read().decode()
        wait(ready, "native worker readiness", 90)

    def path(resource, name=None):
        """Return a resource endpoint confined to the owned namespace."""
        prefix = "/apis/discovery.k8s.io/v1" if resource == "endpointslices" else "/api/v1"
        return f"{prefix}/namespaces/{namespace}/{resource}" + ("/" + name if name else "")

    def create(resource, obj):
        """Require creation of the actual API object."""
        code, value = request(path(resource), "POST", obj)
        assert code == 201, (code, value)
        return value

    def pods():
        """Retain actual Pod and container identities for evidence even after deletion."""
        code, value = request(path("pods"))
        assert code == 200, (code, value)
        for pod in value["items"]:
            seen[pod["metadata"]["uid"]] = pod
        return value["items"]

    def slices(service):
        """Read actual slices selected by the standard Service label."""
        code, value = request(path("endpointslices"))
        assert code == 200, (code, value)
        return [s for s in value["items"] if s["metadata"].get("labels", {}).get("kubernetes.io/service-name") == service]

    def identities():
        """Record real CRI container IDs under their actual Pod UIDs."""
        return {p["metadata"]["uid"]: p["status"]["containerStatuses"][0]["containerID"] for p in pods()}

    def http(address, port=8080, path="/"):
        """Require an actual HTTP response from the addressed backend or Service proxy."""
        with opener.open(f"http://{address}:{port}{path}", timeout=2) as response:
            return response.read().decode().strip()

    def service(name, selector=None):
        """Create a real TCP Service with an optional Pod selector."""
        spec = {"ports": [{"port": 8080, "targetPort": "http"}]}
        if selector is not None:
            spec["selector"] = selector
        return create("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": spec})

    def dns_query(name, tcp=False, qtype=1):
        """Query the actual agent resolver and decode only genuine IPv4 answers."""
        wire_name = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
        packet = struct.pack("!6H", 19101, 256, 1, 0, 0, 0) + wire_name + struct.pack("!2H", qtype, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect(("169.254.1.1", 53))
            if tcp:
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                def read_exact(size):
                    """Read a complete DNS frame without mistaking a partial read for EOF."""
                    result = b""
                    while len(result) < size:
                        part = sock.recv(size - len(result))
                        if not part:
                            raise EOFError("DNS TCP frame ended early")
                        result += part
                    return result
                response = read_exact(struct.unpack("!H", read_exact(2))[0])
            else:
                sock.send(packet)
                response = sock.recv(65535)
        ident, flags, questions, count, _, _ = struct.unpack_from("!6H", response)
        assert ident == 19101 and flags & 32768, (ident, flags)
        def read_name(offset, visited=None):
            """Decode a real DNS name, following bounded packet-relative compression pointers."""
            visited = set() if visited is None else visited
            labels, end = [], None
            while response[offset]:
                if offset in visited:
                    raise ValueError("looping DNS compression pointer")
                visited.add(offset)
                length = response[offset]
                if length & 192 == 192:
                    target = ((length & 63) << 8) | response[offset + 1]
                    tail, _ = read_name(target, visited)
                    labels.append(tail)
                    end = offset + 2
                    break
                offset += 1
                labels.append(response[offset:offset + length].decode())
                offset += length
            return ".".join(labels).lower(), end if end is not None else offset + 1
        offset = 12
        for _ in range(questions):
            _, offset = read_name(offset)
            offset += 4
        records = []
        for _ in range(count):
            owner, offset = read_name(offset)
            kind, cls, ttl, size = struct.unpack_from("!HHIH", response, offset)
            offset += 10
            record = {"type": kind, "owner": owner, "ttl": ttl}
            if kind == 1 and cls == 1 and size == 4:
                record["address"] = socket.inet_ntoa(response[offset:offset + size])
            elif kind in (5, 12):
                record["target"], _ = read_name(offset)
            elif kind == 16:
                cursor, end = offset, offset + size
                record["strings"] = []
                while cursor < end:
                    length = response[cursor]
                    cursor += 1
                    record["strings"].append(response[cursor:cursor + length].decode())
                    cursor += length
            elif kind == 33:
                record["priority"], record["weight"], record["port"] = struct.unpack_from("!3H", response, offset)
                record["target"], _ = read_name(offset + 6)
            records.append(record)
            offset += size
        return flags & 15, records

    def dns(name, tcp=False):
        """Inspect actual IPv4 DNS addresses while retaining the authoritative result code."""
        code, records = dns_query(name, tcp)
        return code, {record["address"] for record in records if record["type"] == 1}

    def dns_targets(name, qtype=5, tcp=False):
        """Observe actual alias targets without indexing a legitimately empty transitional answer."""
        code, records = dns_query(name, tcp, qtype)
        return code, {record["target"] for record in records if record["type"] == qtype and "target" in record}

    def shims():
        """Inspect only runtime shims belonging to this explicitly owned state."""
        return [l for l in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if l.startswith("containerd-shim") and str(state) in l]

    try:
        start()
        code, value = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, value)
        selected = service("selected", {"app": "web"})
        for name in ("one", "two"):
            marker = namespace + "-" + name
            command = f"mkdir -p /www; echo {marker} > /www/index.html; trap '' TERM; while :; do httpd -f -p 8080 -h /www; done"
            obj = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": "web"}},
                   "spec": {"restartPolicy": "Always", "terminationGracePeriodSeconds": 30,
                            "containers": [{"name": "main", "image": "docker.io/library/busybox:1.36.1", "imagePullPolicy": "IfNotPresent",
                                            "command": ["sh", "-c", command], "ports": [{"name": "http", "containerPort": 8080}]}]}}
            if args.verify_dns_records:
                obj["spec"].update(hostname="custom-" + name, subdomain="dns-headless")
                container = obj["spec"]["containers"][0]
                container["env"] = [{"name": "NATIVE_VALUE", "value": "resolved-native-env"}]
                prefix = "mkdir -p /www; hostname > /www/hostname; cat /etc/hosts > /www/hosts; echo \"$$(printf actual-native-command)\" > /www/command; printf '%s' '$(NATIVE_VALUE)' > /www/env; "
                container["command"][2] = prefix + command
            create("pods", obj)
        def observed():
            """Require actual ready containers and matching slice target UIDs and addresses."""
            children = pods()
            current = slices("selected")
            endpoints = [e for s in current for e in s["endpoints"]]
            good = len(children) == len(endpoints) == 2 and all(p.get("status", {}).get("containerStatuses") for p in children)
            good &= all(e["conditions"].get("ready") and e["conditions"].get("serving") and not e["conditions"].get("terminating") for e in endpoints)
            good &= {e["targetRef"]["uid"] for e in endpoints} == {p["metadata"]["uid"] for p in children}
            good &= {e["addresses"][0] for e in endpoints} == {p.get("status", {}).get("podIP") for p in children}
            good &= all(len(s["ports"]) == 1 and s["ports"][0]["port"] == 8080 for s in current)
            return (children, current) if good else None
        children, current = wait(observed, "actual selector Service EndpointSlices")
        expected = {namespace + "-one", namespace + "-two"}
        responses = {http(selected["spec"]["clusterIP"]) for _ in range(6)}
        assert responses == expected, responses
        before_ids = identities()
        before_slices = {s["metadata"]["uid"] for s in current}
        report["scenarios"]["selectorServiceActualEndpoints"] = {"passed": True, "identities": before_ids,
                                                                  "sliceUIDs": sorted(before_slices), "actualHTTPResponses": sorted(responses)}
        if args.verify_dns_records:
            observed_pod = children[0]
            proxy_url = base + path("pods", observed_pod["metadata"]["name"]) + "/proxy/"
            with opener.open(proxy_url, timeout=5) as response:
                proxy_body = response.read().decode().strip()
                assert response.status == 200
            assert proxy_body == namespace + "-" + observed_pod["metadata"]["name"], proxy_body
            report["scenarios"]["actualPodHTTPProxy"] = {"passed": True, "podUID": observed_pod["metadata"]["uid"],
                                                       "actualObservedPodIP": observed_pod["status"]["podIP"], "implicitFirstDeclaredPort": 8080,
                                                       "apiProxyHTTPResponse": proxy_body}
        if args.verify_dns:
            create("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "dns-headless"},
                                "spec": {"clusterIP": "None", "selector": {"app": "web"},
                                         "ports": [{"name": "http", "port": 8082, "targetPort": "http"}]}})
            create("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "dns-empty"},
                                "spec": {"clusterIP": "None", "ports": [{"port": 8080}]}})
            actual_ips = {pod["status"]["podIP"] for pod in children}
            wait(lambda: dns(f"dns-headless.{namespace}.svc.cluster.local") == (0, actual_ips), "actual headless DNS addresses")
            for tcp in (False, True):
                assert dns(f"selected.{namespace}.svc.cluster.local", tcp) == (0, {selected["spec"]["clusterIP"]})
            assert dns(f"dns-empty.{namespace}.svc.cluster.local")[0] == 3
            report["scenarios"]["actualServiceDNS"] = {"passed": True, "udpAndTCPClusterIP": selected["spec"]["clusterIP"], "headlessActualPodIPs": sorted(actual_ips), "emptyHeadlessNXDOMAIN": True}
        if args.verify_dns_records:
            named = create("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "named"},
                           "spec": {"selector": {"app": "web"}, "ports": [{"name": "http", "port": 8081, "targetPort": "http"}]}})
            normal_owner = f"_http._tcp.named.{namespace}.svc.cluster.local"
            headless_owner = f"_http._tcp.dns-headless.{namespace}.svc.cluster.local"
            expected_targets = {f"custom-{pod['metadata']['name']}.dns-headless.{namespace}.svc.cluster.local" for pod in children}
            wait(lambda: dns_query(normal_owner, qtype=33)[0] == 0, "actual named Service SRV publication")
            for tcp in (False, True):
                code, records = dns_query(normal_owner, tcp, 33)
                assert code == 0 and {(r["port"], r["target"]) for r in records} == {(8081, f"named.{namespace}.svc.cluster.local")}, records
                code, headless_records = dns_query(headless_owner, tcp, 33)
                assert code == 0 and {(r["port"], r["target"]) for r in headless_records} == {(8080, name) for name in expected_targets}, headless_records
            reverse = ".".join(reversed(named["spec"]["clusterIP"].split("."))) + ".in-addr.arpa"
            assert dns_query(reverse, qtype=12)[1][0]["target"] == f"named.{namespace}.svc.cluster.local"
            for pod in children:
                address = pod["status"]["podIP"]
                hostname = "custom-" + pod["metadata"]["name"]
                fqdn = f"{hostname}.dns-headless.{namespace}.svc.cluster.local"
                assert http(address, path="/hostname") == hostname
                assert address in http(address, path="/hosts") and fqdn in http(address, path="/hosts")
                assert http(address, path="/command") == "actual-native-command"
                assert http(address, path="/env") == "resolved-native-env"
                assert dns(fqdn) == (0, {address})
            report["scenarios"]["actualDNSRecords"] = {"passed": True, "normalServiceSRV": records, "headlessActualTargetSRV": headless_records,
                                                       "realPodHostnamesAndHosts": True, "escapedCommandActuallyExecuted": True, "resolvedCommandEnvironment": True}
        if args.verify_dns_records:
            alias = create("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "alias"},
                           "spec": {"type": "ExternalName", "externalName": "foo.example.org"}})
            alias_owner = f"alias.{namespace}.svc.cluster.local"
            wait(lambda: dns_targets(alias_owner) == (0, {"foo.example.org"}), "actual ExternalName CNAME publication")
            for tcp in (False, True):
                assert dns_query(alias_owner, tcp, 5)[1][0]["target"] == "foo.example.org"
                assert dns_query("dns-version.cluster.local", tcp, 16)[1][0]["strings"] == ["1.1.0"]
            code, value = request(path("services", "alias"), "PATCH", {"spec": {"externalName": "bar.example.org"}},
                                  content_type="application/merge-patch+json")
            assert code == 200, (code, value)
            wait(lambda: dns_targets(alias_owner) == (0, {"bar.example.org"}), "actual changed ExternalName CNAME")
            code, cluster_alias = request(path("services", "alias"), "PATCH",
                                  {"spec": {"type": "ClusterIP", "selector": {"app": "web"},
                                            "ports": [{"name": "http", "port": 8083, "targetPort": "http"}]}},
                                  content_type="application/merge-patch+json")
            assert code == 200, (code, cluster_alias)
            alias_ip = cluster_alias["spec"]["clusterIP"]
            wait(lambda: dns(alias_owner) == (0, {alias_ip}), "actual ExternalName to ClusterIP DNS conversion")
            actual_alias_http = wait(lambda: http(alias_ip, 8083), "actual forwarding after ExternalName to ClusterIP conversion")
            assert actual_alias_http in expected, actual_alias_http
            code, external_alias = request(path("services", "alias"), "PATCH",
                                  {"spec": {"type": "ExternalName", "externalName": "final.example.org"}},
                                  content_type="application/merge-patch+json")
            assert code == 200 and not external_alias["spec"].get("clusterIP"), (code, external_alias)
            wait(lambda: dns_targets(alias_owner) == (0, {"final.example.org"}), "actual restored ExternalName CNAME")
            assert alias["metadata"]["uid"] == external_alias["metadata"]["uid"]
            report["scenarios"]["actualExternalNameDNS"] = {"passed": True, "initialTarget": "foo.example.org", "mutatedTarget": "bar.example.org",
                                                          "allocatedClusterIP": alias_ip, "actualConvertedServiceHTTPResponse": actual_alias_http,
                                                          "finalTarget": "final.example.org", "sameServiceUID": alias["metadata"]["uid"] == external_alias["metadata"]["uid"],
                                                          "actualSchemaTXT": "1.1.0"}
        target = children[0]
        manual_service = service("manual")
        manual = create("endpointslices", {"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": "manual", "labels": {"kubernetes.io/service-name": "manual"}}, "addressType": "IPv4",
            "ports": [{"name": "", "protocol": "TCP", "port": 8080}],
            "endpoints": [{"addresses": [target["status"]["podIP"]], "conditions": {"ready": True}}]})
        body = wait(lambda: http(manual_service["spec"]["clusterIP"]), "manual EndpointSlice forwarding")
        assert body == namespace + "-" + target["metadata"]["name"], body
        code, value = request(path("endpointslices", "manual"), "PATCH",
                              {"endpoints": [{"addresses": [target["status"]["podIP"]], "conditions": {"ready": False}}]},
                              content_type="application/merge-patch+json")
        assert code == 200, (code, value)
        try:
            http(manual_service["spec"]["clusterIP"])
        except OSError:
            pass
        else:
            raise AssertionError("unready manual endpoint still forwarded HTTP")
        code, manual = request(path("endpointslices", "manual"))
        manual["endpoints"][0]["conditions"]["ready"] = True
        code, value = request(path("endpointslices", "manual"), "PUT", manual)
        assert code == 200, (code, value)
        assert http(manual_service["spec"]["clusterIP"]) == body
        report["scenarios"]["manualSliceForwardingAndReadiness"] = {"passed": True, "sliceUID": manual["metadata"]["uid"], "actualHTTPResponse": body}
        stop()
        start()
        wait(observed, "actual endpoint recovery after restart")
        assert identities() == before_ids
        assert {s["metadata"]["uid"] for s in slices("selected")} == before_slices
        assert request(path("endpointslices", "manual"))[1]["metadata"]["uid"] == manual["metadata"]["uid"]
        report["stage"] = "restart-selected-service-http"
        assert {http(selected["spec"]["clusterIP"]) for _ in range(6)} == expected
        assert http(manual_service["spec"]["clusterIP"]) == body
        report["scenarios"]["restartPersistence"] = {"passed": True, "unchangedIdentities": before_ids}
        if args.verify_dns:
            wait(lambda: dns(f"dns-headless.{namespace}.svc.cluster.local") == (0, actual_ips), "headless DNS recovery after process restart")
            report["scenarios"]["actualServiceDNS"]["restartRecovered"] = True
            if args.verify_dns_records:
                assert {r["target"] for r in dns_query(headless_owner, True, 33)[1]} == expected_targets
                report["scenarios"]["actualDNSRecords"]["restartRecovered"] = True
                assert dns_query(alias_owner, True, 5)[1][0]["target"] == "final.example.org"
                report["scenarios"]["actualExternalNameDNS"]["restartRecovered"] = True
        code, value = request(path("pods", target["metadata"]["name"]), "DELETE", {"gracePeriodSeconds": 30, "preconditions": {"uid": target["metadata"]["uid"]}})
        assert code == 200, (code, value)
        def terminating():
            """Observe a real deleting Pod while its actual HTTP process still serves."""
            endpoints = [e for s in slices("selected") for e in s["endpoints"]]
            endpoint = next((e for e in endpoints if e["targetRef"]["uid"] == target["metadata"]["uid"]), None)
            return endpoint if endpoint and endpoint["conditions"].get("terminating") and not endpoint["conditions"].get("ready") else None
        endpoint = wait(terminating, "terminating EndpointSlice condition", 25)
        assert endpoint["conditions"].get("serving")
        report["stage"] = "terminating-direct-http"
        assert wait(lambda: http(target["status"]["podIP"]), "actual HTTP serving during termination", 10) == body
        survivor = (expected - {body}).pop()
        report["stage"] = "terminating-service-withdrawal"
        assert {http(selected["spec"]["clusterIP"]) for _ in range(4)} == {survivor}
        if args.verify_dns:
            surviving_ips = actual_ips - {target["status"]["podIP"]}
            wait(lambda: dns(f"dns-headless.{namespace}.svc.cluster.local") == (0, surviving_ips), "terminating address withdrawal from actual DNS")
            report["scenarios"]["actualServiceDNS"]["terminatingAddressWithdrawn"] = True
            if args.verify_dns_records:
                target_name = f"custom-{target['metadata']['name']}.dns-headless.{namespace}.svc.cluster.local"
                wait(lambda: {r["target"] for r in dns_query(headless_owner, qtype=33)[1]} == expected_targets - {target_name}, "actual terminating SRV target withdrawal")
                report["scenarios"]["actualDNSRecords"]["terminatingSRVTargetWithdrawn"] = True
        wait(lambda: request(path("pods", target["metadata"]["name"]))[0] == 404, "actual deleting Pod removal", 60)
        wait(lambda: all(e["targetRef"]["uid"] != target["metadata"]["uid"] for s in slices("selected") for e in s["endpoints"]), "deleted endpoint removal")
        try:
            remaining_body = http(target["status"]["podIP"])
        except OSError:
            remaining_body = None
        assert remaining_body != body, "deleted actual Pod still served its original HTTP response"
        report["scenarios"]["terminatingEndpoint"] = {"passed": True, "servedDirectHTTPWhileWithdrawn": True, "survivingHTTPResponse": survivor}
        report["passed"] = True
    except Exception as error:
        report["error"] = repr(error)
        report["traceback"] = traceback.format_exc()
        if process and process.poll() is None:
            try:
                diagnostic_pods = pods()
                report["failureSnapshot"] = {"pods": diagnostic_pods,
                    "services": request(path("services"))[1],
                    "endpointSlices": request(path("endpointslices"))[1],
                    "nodes": request("/api/v1/nodes")[1], "directHTTP": {}}
                for pod in diagnostic_pods:
                    address = pod.get("status", {}).get("podIP")
                    if address:
                        try:
                            report["failureSnapshot"]["directHTTP"][pod["metadata"]["name"]] = http(address)
                        except Exception as failure:
                            report["failureSnapshot"]["directHTTP"][pod["metadata"]["name"]] = repr(failure)
            except Exception as failure:
                report["diagnosticError"] = repr(failure)
    finally:
        try:
            if process:
                for resource in ("services", "endpointslices"):
                    code, listing = request(path(resource))
                    if code == 200:
                        for obj in listing["items"]:
                            request(path(resource, obj["metadata"]["name"]), "DELETE", {"preconditions": {"uid": obj["metadata"]["uid"]}})
                for pod in pods():
                    request(path("pods", pod["metadata"]["name"]), "DELETE", {"gracePeriodSeconds": 0, "preconditions": {"uid": pod["metadata"]["uid"]}})
                wait(lambda: not pods() and not shims(), "owned Pod and runtime cleanup", 120)
                request("/api/v1/namespaces/" + namespace, "DELETE")
        except Exception as error:
            report["cleanupError"] = repr(error)
            report["passed"] = False
        try:
            stop()
        except Exception as error:
            report["shutdownError"] = repr(error)
            report["passed"] = False
        log.close()
        report["ownedShimsRemaining"] = shims()
        if report["ownedShimsRemaining"]:
            report["passed"] = False
        report["pods"] = list(seen.values())
        for uid, pod in seen.items():
            for container in pod["spec"]["containers"]:
                source = Path("/var/log/gr8s/pods") / uid / (container["name"] + ".log")
                if source.exists():
                    (root / (uid + "-" + container["name"] + ".log")).write_bytes(source.read_bytes())
        report["artifactSHA256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob("*.log")}
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"directory": str(root), "passed": report["passed"], "error": report.get("error"), "cleanupError": report.get("cleanupError")}), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
