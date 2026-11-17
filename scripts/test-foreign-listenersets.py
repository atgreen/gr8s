#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Small ListenerSet acceptance test, for a disposable Kubernetes VM only.

Creates two Gateways, at most six routes and five ListenerSets. No scale workload.
Requires the selected ListenerSet CRD and existing CNI/Service forwarding.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time


def run(args):
    if os.geteuid() != 0:
        raise RuntimeError("Run in a disposable root-capable VM")
    root = Path(tempfile.mkdtemp(prefix="gr8s-listenersets-", dir=args.parent))
    suffix = hashlib.sha256(str(root).encode()).hexdigest()[:12]
    namespaces = [f"ls-{suffix}-a", f"ls-{suffix}-b"]
    gateway_class = f"ls-{suffix}"
    report = {"root": str(root), "checks": [], "passed": False}
    process = None
    starts = 0
    fingerprints = {}
    experimental = args.listenerset_api == "experimental"
    listener_group = "gateway.networking.x-k8s.io" if experimental else "gateway.networking.k8s.io"
    listener_version = "v1alpha1" if experimental else "v1"
    listener_kind = "XListenerSet" if experimental else "ListenerSet"
    listener_resource = ("xlistenersets" if experimental else "listenersets") + "." + listener_group
    report["listenerset_api"] = listener_group + "/" + listener_version
    hosts = {"a": "a.example.test", "b": "web.apps.example.test"}

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

    def get(kind, name, ns):
        data = kube("get", kind, name, "-n", ns, "-o", "json", required=False)
        return json.loads(data) if data else None

    def check(label, value):
        if not value:
            raise AssertionError(label)
        report["checks"].append(label)
        print(label, flush=True)

    def wait(label, predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise AssertionError(f"Agent exited {process.returncode}; see agent-{starts}.log")
            result = predicate()
            if result:
                return result
            time.sleep(.3)
        raise AssertionError(f"Timed out: {label}")

    def start():
        nonlocal process, starts
        starts += 1
        with (root / f"agent-{starts}.log").open("wb") as log:
            process = subprocess.Popen(
                [str(Path(args.binary).resolve()), "net-agent", "--kubeconfig", args.kubeconfig,
                 "--node-name", args.node, "--state-directory", str(root / "state"),
                 "--cni", "false", "--service-lb", "false", "--gateway", "true",
                 "--listenerset-api-group", listener_group],
                stdout=log, stderr=subprocess.STDOUT)

    def stop():
        nonlocal process
        if process is not None:
            child, process = process, None
            child.terminate()
            try:
                code = child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise AssertionError("Agent did not stop gracefully")
            check("Agent stopped gracefully", code == 0)

    def gateway(ns, admission="Same"):
        return {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
                "metadata": {"name": "web", "namespace": ns},
                "spec": {"gatewayClassName": gateway_class, "listeners": [
                            {"name": "http", "port": 8080, "protocol": "HTTP"}],
                         "allowedListeners": {"namespaces": {"from": admission}}}}

    def listener_set(ns, name):
        return {"apiVersion": listener_group + "/" + listener_version, "kind": listener_kind,
                "metadata": {"name": name, "namespace": ns}, "spec": {
                    "parentRef": {"name": "web"}, "listeners": [{
                        "name": "https", "port": 443, "protocol": "HTTPS",
                        "hostname": hosts[name] if name == "a" else "*.apps.example.test",
                        "tls": {"mode": "Terminate", "certificateRefs": [{"name": name}]}}]}}

    def route(ns, name, tenant=None):
        return {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                "metadata": {"name": name, "namespace": ns}, "spec": {
                    "parentRefs": [{"group": listener_group, "kind": listener_kind, "name": name}],
                    "hostnames": [hosts[name]], "rules": [{
                        "backendRefs": [{"name": "backend", "port": 80}],
                        "filters": [{"type": "ResponseHeaderModifier", "responseHeaderModifier": {
                            "set": [{"name": "x-tenant", "value": tenant or f"{ns}/{name}"}]}}]}]}}

    def secret(ns, name):
        cert, key = root / f"{ns}-{name}.crt", root / f"{ns}-{name}.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", f"/CN={hosts[name]}", "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fingerprints[ns, name] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": ns},
               "type": "kubernetes.io/tls", "data": {
                   "tls.crt": base64.b64encode(cert.read_bytes()).decode(),
                   "tls.key": base64.b64encode(key.read_bytes()).decode()}})

    def address(ns):
        service = get("service", "gr8s-gateway-web", ns)
        return service and service["spec"]["clusterIP"]

    def probe(ns, host, sni=True):
        connection = None
        raw = None
        try:
            ip = address(ns)
            if not ip:
                return None
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((ip, 443), timeout=2)
            tls = context.wrap_socket(raw, server_hostname=host if sni is True else (sni or None))
            certificate = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            connection = http.client.HTTPConnection(ip, 443, timeout=2)
            connection.sock = tls
            connection.request("GET", "/", headers={"Host": host, "Connection": "close"})
            response = connection.getresponse()
            result = (response.status, response.getheader("x-tenant"), certificate)
            response.read(4096)
            return result
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if connection is not None:
                connection.close()
            elif raw is not None:
                raw.close()

    def serves(ns, name, tenant=None):
        return probe(ns, hosts[name]) == (200, tenant or f"{ns}/{name}", fingerprints[ns, name])

    def probe_http(ns, host, path):
        connection = http.client.HTTPConnection(address(ns), 8080, timeout=2)
        try:
            connection.request("GET", path, headers={"Host": host, "Connection": "close"})
            response = connection.getresponse()
            result = response.status, response.getheader("x-tenant")
            response.read(4096)
            return result
        except (OSError, http.client.HTTPException):
            return None
        finally:
            connection.close()

    def condition(obj, kind, expected="True"):
        return obj and any(c.get("type") == kind and c.get("status") == expected
                           and c.get("observedGeneration") == obj["metadata"].get("generation")
                           for c in obj.get("status", {}).get("conditions", []))

    def ports(ns):
        result = json.loads(kube("get", "endpointslices", "-n", ns, "-o", "json",
                                 "-l", "kubernetes.io/service-name=gr8s-gateway-web"))
        return sorted({port["port"] for item in result["items"] for port in item.get("ports", [])
                       if port.get("name") == "p-443"
                       and any(e.get("nodeName") == args.node and e.get("conditions", {}).get("ready")
                              for e in item.get("endpoints", []))})

    def route_ready(ns, name):
        obj = get("httproute", name, ns)
        if not obj:
            return False
        return any(parent.get("controllerName") == "gr8s.io/gateway-controller"
                   and parent.get("parentRef", {}).get("kind") == listener_kind
                   and parent.get("parentRef", {}).get("group") == listener_group
                   and parent.get("parentRef", {}).get("name") == name
                   and condition({"metadata": obj["metadata"], "status": parent}, "Accepted")
                   for parent in obj.get("status", {}).get("parents", []))

    try:
        apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
               "metadata": {"name": gateway_class}, "spec": {"controllerName": "gr8s.io/gateway-controller"}})
        for ns in namespaces:
            apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}})
            apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "backend", "namespace": ns},
                   "spec": {"selector": {"matchLabels": {"app": "backend"}}, "template": {
                       "metadata": {"labels": {"app": "backend"}}, "spec": {"containers": [
                           {"name": "backend", "image": args.image, "imagePullPolicy": "IfNotPresent"}]}}}})
            apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "backend", "namespace": ns},
                   "spec": {"selector": {"app": "backend"}, "ports": [{"port": 80, "targetPort": 8080}]}})
            apply(gateway(ns))
            for name in hosts:
                secret(ns, name)
                apply(listener_set(ns, name))
                apply(route(ns, name))
        start()
        for ns in namespaces:
            for name in hosts:
                wait(f"{ns}/{name} HTTPS routing", lambda ns=ns, name=name: serves(ns, name))
                check(f"{ns}/{name}: correct backend and distinct certificate", True)
                wait(f"{ns}/{name} Programmed", lambda ns=ns, name=name: condition(get(listener_resource, name, ns), "Programmed"))
                wait(f"{ns}/{name} route Accepted", lambda ns=ns, name=name: route_ready(ns, name))
            wait(f"{ns} attached count", lambda ns=ns: (get("gateway", "web", ns) or {}).get("status", {}).get("attachedListenerSets") == 2)
            check(f"{ns}: ListenerSet status and Gateway count", True)
            check(f"{ns}: unmatched SNI rejected", probe(ns, "unknown.example.test") is None)
            check(f"{ns}: absent SNI rejected", probe(ns, hosts["a"], False) is None)
            mismatch = probe(ns, hosts["b"], hosts["a"])
            check(f"{ns}: sibling Host cannot cross SNI listener", mismatch and mismatch[0] == 404)
        initial_ports = {ns: wait(f"{ns} private port", lambda ns=ns: ports(ns)) for ns in namespaces}
        check("One shared socket per Gateway, distinct between Gateways",
              all(len(p) == 1 for p in initial_ports.values()) and len({p[0] for p in initial_ports.values()}) == 2)
        ns = namespaces[0]
        secret(ns, "a")
        wait("Rotated certificate active", lambda: serves(ns, "a"))
        check("Certificate rotation preserves sibling routing", serves(ns, "b"))
        check("Certificate rotation preserves socket lease", ports(ns) == initial_ports[ns])
        apply(route(ns, "a", "updated"))
        wait("Route update active", lambda: serves(ns, "a", "updated"))
        check("Route update reaches HTTPS snapshot", True)
        apply(gateway(ns, "None"))
        wait("Admission revocation withdraws HTTPS", lambda: probe(ns, hosts["a"]) is None and probe(ns, hosts["b"]) is None)
        wait("Admission revocation status", lambda: condition(get(listener_resource, "a", ns), "Accepted", "False"))
        check("Admission revocation withdraws traffic and status", True)
        apply(gateway(ns))
        wait("Admission restored", lambda: serves(ns, "a", "updated") and serves(ns, "b"))
        before = get(listener_resource, "b", ns)["metadata"]["uid"]
        kube("delete", listener_resource, "b", "-n", ns, "--wait=true")
        wait("Deleted listener withdrawn", lambda: probe(ns, hosts["b"]) is None)
        check("Deleting one ListenerSet preserves its sibling", serves(ns, "a", "updated"))
        apply(listener_set(ns, "b"))
        wait("Recreated ListenerSet serving", lambda: serves(ns, "b"))
        check("Recreated ListenerSet has a new UID", get(listener_resource, "b", ns)["metadata"]["uid"] != before)

        # An otherwise identical, newer listener must lose deterministically.
        conflict = listener_set(ns, "a")
        conflict["metadata"]["name"] = "conflict"
        conflict["spec"]["listeners"][0]["tls"]["certificateRefs"][0]["name"] = "b"
        apply(conflict)
        def conflicted():
            obj = get(listener_resource, "conflict", ns)
            return obj and any(condition({"metadata": obj["metadata"], "status": listener}, "Conflicted")
                               for listener in obj.get("status", {}).get("listeners", []))
        wait("Newer conflicting listener rejected", conflicted)
        check("Conflict preserves older listener certificate and routing", serves(ns, "a", "updated"))
        kube("delete", listener_resource, "conflict", "-n", ns, "--wait=true")

        if experimental:
            dynamic = listener_set(ns, "a")
            dynamic["metadata"]["name"] = "dynamic"
            dynamic_listener = dynamic["spec"]["listeners"][0]
            dynamic_listener["hostname"] = "dynamic.example.test"
            for omitted in (False, True):
                if omitted:
                    dynamic_listener.pop("port", None)
                else:
                    dynamic_listener["port"] = 0
                apply(dynamic)
                def unsupported_port():
                    obj = get(listener_resource, "dynamic", ns)
                    return (obj and condition(obj, "Accepted", "False")
                            and any(c["type"] == "Accepted" and c["reason"] == "UnsupportedPort"
                                    for c in obj.get("status", {}).get("conditions", []))
                            and not obj.get("status", {}).get("listeners", []))
                wait("Dynamic port rejected with schema-valid status", unsupported_port)
                service = get("service", "gr8s-gateway-web", ns)
                check("Omitted dynamic port rejected" if omitted else "Zero dynamic port rejected",
                      serves(ns, "a", "updated") and serves(ns, "b")
                      and all(p["port"] > 0 for p in service["spec"]["ports"]))
            fixed = json.loads(json.dumps(dynamic_listener))
            fixed.update(name="fixed", port=8443, hostname="fixed.example.test")
            dynamic["spec"]["listeners"].append(fixed)
            apply(dynamic)
            def fixed_sibling_ready():
                obj = get(listener_resource, "dynamic", ns)
                listeners = obj.get("status", {}).get("listeners", []) if obj else []
                return (condition(obj, "Programmed") and len(listeners) == 1
                        and listeners[0]["name"] == "fixed" and listeners[0]["port"] == 8443)
            wait("Fixed sibling survives unsupported dynamic port", fixed_sibling_ready)
            check("Valid fixed-port sibling remains programmed", True)
            kube("delete", listener_resource, "dynamic", "-n", ns, "--wait=true")
            wait("Fixed sibling port withdrawn",
                 lambda: all(p["port"] != 8443 for p in get("service", "gr8s-gateway-web", ns)["spec"]["ports"]))

        # Authorize a cross-namespace Secret using the child's identity.
        other_ns = namespaces[1]
        foreign_secret = listener_set(ns, "a")
        foreign_secret["spec"]["listeners"][0]["tls"]["certificateRefs"][0]["namespace"] = other_ns
        apply(foreign_secret)
        wait("Cross-namespace Secret denied without grant", lambda: probe(ns, hosts["a"]) is None)
        grant = {"apiVersion": "gateway.networking.k8s.io/v1beta1", "kind": "ReferenceGrant",
                 "metadata": {"name": "listener-secret", "namespace": other_ns}, "spec": {
                     "from": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "namespace": ns}],
                     "to": [{"group": "", "kind": "Secret", "name": "a"}]}}
        apply(grant)
        check("Gateway grant cannot authorize child Secret", probe(ns, hosts["a"]) is None)
        grant["spec"]["from"][0]["kind"] = listener_kind
        grant["spec"]["from"][0]["group"] = listener_group
        apply(grant)
        wait("ListenerSet grant enables foreign Secret", lambda: probe(ns, hosts["a"]) ==
             (200, "updated", fingerprints[other_ns, "a"]))
        kube("delete", "referencegrant", "listener-secret", "-n", other_ns, "--wait=true")
        wait("Grant revocation withdraws listener", lambda: probe(ns, hosts["a"]) is None)
        check("Grant revocation preserves sibling", serves(ns, "b"))
        apply(listener_set(ns, "a"))
        wait("Local Secret restored", lambda: serves(ns, "a", "updated"))
        check("Child Secret authorization and revocation", True)

        kube("label", "namespace", ns, "listenerset-allowed=yes", "--overwrite")
        selected = gateway(ns)
        selected["spec"]["allowedListeners"]["namespaces"] = {
            "from": "Selector", "selector": {"matchLabels": {"listenerset-allowed": "yes"}}}
        apply(selected)
        wait("Selector admission acknowledged", lambda: condition(get("gateway", "web", ns), "Programmed"))
        check("Matching namespace selector admits children", serves(ns, "a", "updated") and serves(ns, "b"))
        kube("label", "namespace", ns, "listenerset-allowed-")
        wait("Namespace relabel withdraws children", lambda: probe(ns, hosts["a"]) is None and probe(ns, hosts["b"]) is None)
        wait("Namespace relabel updates status", lambda: condition(get(listener_resource, "a", ns), "Accepted", "False"))
        kube("label", "namespace", ns, "listenerset-allowed=yes", "--overwrite")
        wait("Namespace relabel restores children", lambda: serves(ns, "a", "updated") and serves(ns, "b"))
        check("Namespace selector revocation and restoration", True)
        stop()
        start()
        for current_ns in namespaces:
            for name in hosts:
                tenant = "updated" if current_ns == ns and name == "a" else None
                wait("Agent restart routing", lambda ns=current_ns, name=name, tenant=tenant: serves(ns, name, tenant))
        check("Agent restart restores all four TLS routes", True)
        for name, hostname, path in (("a", "*.http.example.test", "/private"),
                                     ("b", "app.http.example.test", "/public")):
            owner = get(listener_resource, name, ns)
            owner = {"apiVersion": owner["apiVersion"], "kind": owner["kind"],
                     "metadata": {"name": name, "namespace": ns}, "spec": owner["spec"]}
            owner["spec"]["listeners"].append({"name": "http", "port": 8080,
                                               "protocol": "HTTP", "hostname": hostname})
            apply(owner)
            http_route = route(ns, name, "http-" + name)
            http_route["metadata"]["name"] = "http-" + name
            http_route["spec"]["hostnames"] = [hostname]
            http_route["spec"]["parentRefs"][0]["sectionName"] = "http"
            http_route["spec"]["rules"][0]["matches"] = [{"path": {"type": "PathPrefix", "value": path}}]
            apply(http_route)
        wait("HTTP exact listener active", lambda: probe_http(ns, "app.http.example.test", "/public") == (200, "http-b"))
        wait("HTTP wildcard listener active", lambda: probe_http(ns, "other.http.example.test", "/private") == (200, "http-a"))
        check("HTTP exact listener cannot fall through to wildcard routes",
              probe_http(ns, "app.http.example.test", "/private") == (404, None))
        http_route = get("httproute", "http-a", ns)
        http_route["spec"]["rules"][0]["matches"][0]["path"]["value"] = "/changed"
        apply({"apiVersion": http_route["apiVersion"], "kind": http_route["kind"],
               "metadata": {"name": "http-a", "namespace": ns}, "spec": http_route["spec"]})
        wait("HTTP wildcard route update", lambda: probe_http(ns, "other.http.example.test", "/changed") == (200, "http-a"))
        check("HTTP route updates preserve listener isolation",
              probe_http(ns, "app.http.example.test", "/changed") == (404, None)
              and probe_http(ns, "other.http.example.test", "/private") == (404, None))
        parent_route = route(ns, "b", "http-parent")
        parent_route["metadata"]["name"] = "http-b"
        parent_route["spec"]["parentRefs"] = [{"group": "gateway.networking.k8s.io",
                                                "kind": "Gateway", "name": "web", "sectionName": "http"}]
        parent_route["spec"]["hostnames"] = ["parent.example.test"]
        apply(parent_route)
        wait("Parent HTTP route active", lambda: probe_http(ns, "parent.example.test", "/") == (200, "http-parent"))
        for name in hosts:
            owner = get(listener_resource, name, ns)
            owner["spec"]["listeners"] = [listener for listener in owner["spec"]["listeners"]
                                          if listener["protocol"] != "HTTP"]
            apply({"apiVersion": owner["apiVersion"], "kind": owner["kind"],
                   "metadata": {"name": name, "namespace": ns}, "spec": owner["spec"]})
            wait("HTTP child removal acknowledged",
                 lambda name=name: condition(get(listener_resource, name, ns), "Programmed"))
        check("Removing final HTTP child preserves parent Gateway route",
              probe_http(ns, "parent.example.test", "/") == (200, "http-parent"))
        stop()
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        try:
            stop()
        finally:
            for ns in namespaces:
                snapshot = kube("get", f"gateway,{listener_resource},httproute,service,endpointslice,pod", "-n", ns, "-o", "json", required=False)
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
    parser.add_argument("--listenerset-api", choices=("stable", "experimental"), default="stable")
    parser.add_argument("--parent", default="/var/tmp")
    run(parser.parse_args())
