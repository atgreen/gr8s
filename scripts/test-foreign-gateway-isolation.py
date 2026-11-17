#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise foreign Gateway isolation through real Service IPs in a disposable VM.

Requires an existing Kubernetes cluster, Gateway API CRDs, and incumbent CNI and
Service forwarding. Runs gr8s with CNI and Service LB disabled. Never run on a
shared cluster: this starts a node Gateway controller and creates test resources.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time


def run(args):
    root = Path(tempfile.mkdtemp(prefix="gr8s-foreign-gateway-", dir=args.parent))
    suffix = root.name.rsplit("-", 1)[-1]
    namespaces = [f"gw-{suffix}-a", f"gw-{suffix}-b"]
    gateway_class = f"gr8s-{suffix}"
    report = {"root": str(root), "checks": [], "observations": []}
    process = None
    starts = 0

    def kube(*argv, obj=None, required=True):
        result = subprocess.run(
            ["kubectl", "--kubeconfig", args.kubeconfig, "--request-timeout=10s", *argv],
            input=json.dumps(obj) if obj is not None else None,
            capture_output=True, text=True, timeout=30)
        if required and result.returncode:
            raise AssertionError(f"kubectl {argv}: {result.stderr}")
        return result.stdout if result.returncode == 0 else ""

    def apply(obj):
        kube("apply", "-f", "-", obj=obj)

    def get(kind, name, namespace):
        value = kube("get", kind, name, "-n", namespace, "-o", "json", required=False)
        return json.loads(value) if value else None

    def check(description, ok):
        if not ok:
            raise AssertionError(description)
        report["checks"].append(description)
        print(description, flush=True)

    def wait(description, predicate, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise AssertionError(f"Gateway process exited {process.returncode}; see agent-{starts}.log")
            value = predicate()
            if value:
                return value
            time.sleep(.3)
        raise AssertionError(f"Timed out: {description}")

    def start():
        nonlocal process, starts
        starts += 1
        with (root / f"agent-{starts}.log").open("wb") as log:
            process = subprocess.Popen(
                [str(Path(args.binary).resolve()), "net-agent", "--kubeconfig", args.kubeconfig,
                 "--node-name", args.node, "--state-directory", str(root / "state"),
                 "--cni", "false", "--service-lb", "false", "--gateway", "true"],
                stdout=log, stderr=subprocess.STDOUT)

    def stop():
        nonlocal process
        if process is not None:
            process.terminate()
            try:
                code = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("Gateway agent did not stop gracefully")
            finally:
                process = None
            check("Gateway agent stopped gracefully", code == 0)

    def gateway(ns, protocol="HTTP", tls=False):
        listener = {"name": "listener", "protocol": protocol, "port": 443 if tls else 80,
                    "hostname": "app.example.com"}
        if protocol == "TCP":
            listener.pop("hostname")
        if tls:
            listener["tls"] = {"mode": "Terminate", "certificateRefs": [{"name": "gateway-tls"}]}
        return {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
                "metadata": {"name": "web", "namespace": ns},
                "spec": {"gatewayClassName": gateway_class, "listeners": [listener]}}

    def request(address, port=80, tls=False):
        connection = None
        try:
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = http.client.HTTPSConnection(address, port, timeout=2, context=context)
            else:
                connection = http.client.HTTPConnection(address, port, timeout=2)
            connection.connect()
            certificate = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() if tls else None
            connection.request("GET", "/app", headers={"Host": "app.example.com", "Connection": "close"})
            response = connection.getresponse()
            result = {"status": response.status, "tenant": response.getheader("x-tenant"), "certificate": certificate}
            response.read(1024)
            return result
        except (OSError, http.client.HTTPException):
            return {"status": 0, "tenant": None, "certificate": None}
        finally:
            if connection is not None:
                connection.close()

    def service(ns):
        return get("service", "gr8s-gateway-web", ns)

    def leased_port(ns):
        page = json.loads(kube("get", "endpointslices", "-n", ns,
                              "-l", "kubernetes.io/service-name=gr8s-gateway-web", "-o", "json"))
        for item in page["items"]:
            for endpoint in item.get("endpoints", []):
                if endpoint.get("nodeName") == args.node and endpoint.get("conditions", {}).get("ready"):
                    return item["ports"][0]["port"]
        return None

    def serving(ns, tls=False, certificate=None):
        value = service(ns)
        if not value:
            return None
        address = value["spec"]["clusterIP"]
        result = request(address, 443 if tls else 80, tls)
        if result["tenant"] is not None and result["tenant"] != ns:
            raise AssertionError(f"Cross-tenant routing at {address}: {result}")
        if result["status"] == 200 and result["tenant"] == ns:
            if certificate is not None and result["certificate"] != certificate:
                raise AssertionError(f"Wrong tenant certificate at {address}: {result}")
            return address
        return None

    def verify_pair(label, tls=False, certificates=None):
        addresses = [wait(f"{ns} serves {label}", lambda ns=ns: serving(
            ns, tls, certificates.get(ns) if certificates else None)) for ns in namespaces]
        check(f"{label}: distinct Gateway Service IPs", len(set(addresses)) == 2)
        for ns in namespaces:
            for _ in range(10):
                check_result = serving(ns, tls, certificates.get(ns) if certificates else None)
                if not check_result:
                    raise AssertionError(f"{label}: {ns} stopped serving")
        check(f"{label}: both same-hostname Gateways route only their own tenant", True)
        ports = {ns: wait(f"{ns} EndpointSlice", lambda ns=ns: leased_port(ns)) for ns in namespaces}
        check(f"{label}: distinct private sockets", len(set(ports.values())) == 2)
        report["observations"].append({"phase": label, "addresses": addresses, "ports": ports})
        return ports

    try:
        if os.geteuid() != 0:
            raise AssertionError("Run inside a disposable root-capable VM")
        for ns in namespaces:
            apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}})
            apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "backend", "namespace": ns},
                   "spec": {"selector": {"matchLabels": {"app": "backend"}}, "template": {
                       "metadata": {"labels": {"app": "backend"}}, "spec": {"containers": [
                           {"name": "backend", "image": args.image, "imagePullPolicy": "IfNotPresent"}]}}}})
            apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "backend", "namespace": ns},
                   "spec": {"selector": {"app": "backend"}, "ports": [{"port": 80, "targetPort": 8080}]}})
        apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
               "metadata": {"name": gateway_class}, "spec": {"controllerName": "gr8s.io/gateway-controller"}})
        for index, ns in enumerate(namespaces):
            wait(f"{ns} backend ready", lambda ns=ns: (get("deployment", "backend", ns) or {}).get(
                "status", {}).get("availableReplicas", 0) == 1)
            apply(gateway(ns))
            apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                   "metadata": {"name": "app", "namespace": ns}, "spec": {
                       "parentRefs": [{"name": "web"}], "hostnames": ["app.example.com"], "rules": [{
                           "matches": [{"path": {"type": "PathPrefix", "value": "/app" if index else "/"}}],
                           "backendRefs": [{"name": "backend", "port": 80}], "filters": [{
                               "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                                   "set": [{"name": "x-tenant", "value": ns}]}}]}]}})
        start()
        ports = verify_pair("initial HTTP")
        first = namespaces[0]
        apply(gateway(first, "TCP"))
        wait("HTTP socket retired for TCP", lambda: request(service(first)["spec"]["clusterIP"])["status"] == 0)
        apply(gateway(first))
        after = verify_pair("TCP to HTTP")
        check("Protocol replacement retains both leases", after == ports)
        old_uid = get("gateway", "web", first)["metadata"]["uid"]
        kube("delete", "gateway", "web", "-n", first, "--wait=true")
        wait("Deleted Gateway Service garbage collected", lambda: service(first) is None)
        apply(gateway(first))
        recreated = verify_pair("Gateway recreation")
        check("Recreated Gateway receives a new UID", get("gateway", "web", first)["metadata"]["uid"] != old_uid)
        check("Retired lease is not reused", recreated[first] != ports[first])
        check("Neighbor retains its lease", recreated[namespaces[1]] == ports[namespaces[1]])
        node = json.loads(kube("get", "node", args.node, "-o", "json"))
        node_ip = next(a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP" and ":" not in a["address"])
        wait("Retired private socket closed", lambda: request(node_ip, ports[first])["status"] == 0)
        stop()
        for ns in namespaces:
            check(f"{ns}: shutdown withdraws endpoint", leased_port(ns) is None)
        start()
        restarted = verify_pair("agent restart")
        check("Agent restart preserves active leases", restarted == recreated)
        check("Old destination remains closed after restart", request(node_ip, ports[first])["status"] == 0)
        certificates = {}
        for ns in namespaces:
            cert, key = root / f"{ns}.crt", root / f"{ns}.key"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=app.example.com", "-keyout", str(key), "-out", str(cert)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            certificates[ns] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "gateway-tls", "namespace": ns},
                   "type": "kubernetes.io/tls", "data": {
                       "tls.crt": base64.b64encode(cert.read_bytes()).decode(),
                       "tls.key": base64.b64encode(key.read_bytes()).decode()}})
            apply(gateway(ns, "HTTPS", tls=True))
        tls_ports = verify_pair("HTTPS certificate isolation", tls=True, certificates=certificates)
        stop()
        start()
        check("HTTPS restart preserves leases", verify_pair(
            "HTTPS restart", tls=True, certificates=certificates) == tls_ports)
        stop()
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = str(error)
        raise
    finally:
        try:
            stop()
        finally:
            for ns in namespaces:
                snapshot = kube("get", "gateway,httproute,service,endpointslice,pod", "-n", ns, "-o", "json", required=False)
                (root / f"{ns}.json").write_text(snapshot)
                kube("delete", "namespace", ns, "--wait=false", "--ignore-not-found", required=False)
            kube("delete", "gatewayclass", gateway_class, "--wait=false", "--ignore-not-found", required=False)
            (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"Evidence: {root}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--kubeconfig", default="/etc/rancher/k3s/k3s.yaml")
    parser.add_argument("--node", required=True)
    parser.add_argument("--image", default="howardjohn/hyper-server")
    parser.add_argument("--parent", default="/var/tmp")
    run(parser.parse_args())
