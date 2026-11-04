#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Validate actual EndpointSlice and selectorless Service forwarding in an owned native guest."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
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
    args = parser.parse_args()
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

    def http(address, port=8080):
        """Require an actual HTTP response from the addressed backend or Service proxy."""
        with opener.open(f"http://{address}:{port}/", timeout=2) as response:
            return response.read().decode().strip()

    def service(name, selector=None):
        """Create a real TCP Service with an optional Pod selector."""
        spec = {"ports": [{"port": 8080, "targetPort": "http"}]}
        if selector is not None:
            spec["selector"] = selector
        return create("services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": spec})

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
            command = f"mkdir -p /www; echo {marker} > /www/index.html; trap '' TERM; httpd -f -p 8080 -h /www & wait"
            create("pods", {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": "web"}},
                            "spec": {"restartPolicy": "Always", "terminationGracePeriodSeconds": 30,
                                     "containers": [{"name": "main", "image": "docker.io/library/busybox:1.36.1", "imagePullPolicy": "IfNotPresent",
                                                     "command": ["sh", "-c", command], "ports": [{"name": "http", "containerPort": 8080}]}]}})
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
        assert http(manual_service["spec"]["clusterIP"]) == body
        report["scenarios"]["restartPersistence"] = {"passed": True, "unchangedIdentities": before_ids}
        code, value = request(path("pods", target["metadata"]["name"]), "DELETE", {"gracePeriodSeconds": 30, "preconditions": {"uid": target["metadata"]["uid"]}})
        assert code == 200, (code, value)
        def terminating():
            """Observe a real deleting Pod while its actual HTTP process still serves."""
            endpoints = [e for s in slices("selected") for e in s["endpoints"]]
            endpoint = next((e for e in endpoints if e["targetRef"]["uid"] == target["metadata"]["uid"]), None)
            return endpoint if endpoint and endpoint["conditions"].get("terminating") and not endpoint["conditions"].get("ready") else None
        endpoint = wait(terminating, "terminating EndpointSlice condition", 25)
        assert endpoint["conditions"].get("serving")
        assert http(target["status"]["podIP"]) == body
        survivor = (expected - {body}).pop()
        assert {http(selected["spec"]["clusterIP"]) for _ in range(4)} == {survivor}
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
