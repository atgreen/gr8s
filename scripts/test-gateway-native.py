#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify Gateway status and listener lifecycle in a disposable, root-capable VM.

Uses a native gr8s binary, real containerd networking and kubectl. No synthetic
status or warm-up route is installed: Programmed must mean the advertised
address accepts requests, including when the Gateway has zero attached routes.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def wait_for(description, predicate, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            print(description, flush=True)
            return result
        time.sleep(0.2)
    raise AssertionError(f"Timed out waiting for {description}")


def condition(object_, name):
    return next((entry for entry in object_.get("status", {}).get("conditions", [])
                 if entry["type"] == name), {})


def http_status(address, port):
    request = urllib.request.Request(
        f"http://{address}:{port}/", headers={"Host": "gateway-test.example.com"})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as error:
        error.close()
        return error.code
    except urllib.error.URLError:
        return None


def run(args):
    root = Path(tempfile.mkdtemp(prefix="gr8s-gateway.", dir=args.parent))
    kubeconfig = root / "kubeconfig"
    evidence = {"root": str(root), "checks": []}
    process = None

    def kubectl(*arguments, object_=None, check=True):
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(kubeconfig), "--request-timeout=5s", *arguments],
            input=None if object_ is None else json.dumps(object_), text=True,
            capture_output=True, check=False)
        if check and result.returncode:
            raise AssertionError(f"kubectl {' '.join(arguments)}: {result.stderr}")
        return result.stdout if result.returncode == 0 else ""

    def get_gateway(name="web"):
        return json.loads(kubectl("get", "gateway", name, "-o", "json"))

    def apply(object_):
        kubectl("apply", "-f", "-", object_=object_)

    def check(description, assertion):
        if not assertion:
            raise AssertionError(description)
        evidence["checks"].append(description)

    def serving_gateway(generation=1):
        gateway = get_gateway()
        programmed = condition(gateway, "Programmed")
        addresses = gateway.get("status", {}).get("addresses", [])
        if (programmed.get("status") == "True"
                and programmed.get("observedGeneration") == generation and addresses):
            return gateway
        return None

    try:
        with (root / "gr8s.log").open("wb") as log:
            process = subprocess.Popen(
                [str(Path(args.binary).resolve()), "serve", "--runtime", "containerd",
                 "--state-directory", str(root / "state"), "--port", str(args.port),
                 "--node-port", str(args.node_port), "--containerd-log-root", str(root / "pods"),
                 "--kubeconfig", str(kubeconfig)], stdout=log, stderr=subprocess.STDOUT)
        wait_for("node enrolled", lambda: kubectl("get", "nodes", "-o", "name", check=False))
        apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayClass",
               "metadata": {"name": "gr8s-test"},
               "spec": {"controllerName": "gr8s.io/gateway-controller"}})
        # Force a real bind failure, then change only the actual socket state.
        # The desired Gateway stays unchanged: deduplication must not lose its retry.
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", args.gateway_port))
            occupied.listen(1)
            apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
                   "metadata": {"name": "web"},
                   "spec": {"gatewayClassName": "gr8s-test", "listeners": [
                       {"name": "http", "protocol": "HTTP", "port": args.gateway_port}]}})
            wait_for("listener bind failure observed",
                     lambda: "Gateway convergence failed:" in (root / "gr8s.log").read_text(), timeout=60)
            time.sleep(2)
            check("failed listener is not programmed",
                  condition(get_gateway(), "Programmed").get("status") != "True")
        gateway = wait_for("Gateway retries unchanged desired listener", serving_gateway, timeout=30)
        check("listener recovery preserves desired generation", gateway["metadata"]["generation"] == 1)
        address = gateway["status"]["addresses"][0]["value"]
        evidence["address"] = address
        check("zero-route listener returns HTTP 404", http_status(address, args.gateway_port) == 404)
        check("initial attachedRoutes is zero", gateway["status"]["listeners"][0]["attachedRoutes"] == 0)
        class_ = json.loads(kubectl("get", "gatewayclass", "gr8s-test", "-o", "json"))
        check("GatewayClass is accepted", condition(class_, "Accepted").get("status") == "True")
        kubectl("get", "--raw", "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/web/status")
        revision = get_gateway()["metadata"]["resourceVersion"]
        time.sleep(3)
        check("unchanged readiness does not churn resourceVersion",
              get_gateway()["metadata"]["resourceVersion"] == revision)
        apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
               "metadata": {"name": "missing-tls"},
               "spec": {"gatewayClassName": "gr8s-test", "listeners": [
                   {"name": "https", "protocol": "HTTPS", "port": 18443,
                    "tls": {"certificateRefs": [{"name": "missing-certificate"}]}}]}})

        def unresolved_tls():
            gateway = get_gateway("missing-tls")
            listeners = gateway.get("status", {}).get("listeners", [])
            if not listeners:
                return False
            unresolved = next((entry for entry in listeners[0].get("conditions", [])
                               if entry["type"] == "ResolvedRefs"), {})
            return (unresolved.get("status") == "False"
                    and condition(gateway, "Programmed").get("status") == "False"
                    and not gateway["status"].get("addresses"))

        wait_for("missing TLS certificate is not advertised as ready", unresolved_tls)
        evidence["checks"].append("unresolved TLS references prevent readiness and address publication")
        kubectl("delete", "gateway", "missing-tls")
        apply({"apiVersion": "v1", "kind": "Pod", "metadata": {
            "name": "gateway-backend", "labels": {"app": "gateway-backend"}},
            "spec": {"containers": [{"name": "backend", "image": "howardjohn/hyper-server"}]}})
        apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "gateway-backend"},
               "spec": {"selector": {"app": "gateway-backend"},
                        "ports": [{"port": 80, "targetPort": 8080}]}})
        kubectl("wait", "--for=condition=Ready", "pod/gateway-backend", "--timeout=180s")
        apply({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
               "metadata": {"name": "app"}, "spec": {
                   "parentRefs": [{"name": "web"}], "hostnames": ["gateway-test.example.com"],
                   "rules": [{"backendRefs": [{"name": "gateway-backend", "port": 80}]}]}})
        wait_for("first route serves HTTP 200", lambda: http_status(address, args.gateway_port) == 200)
        wait_for("attachedRoutes becomes one", lambda: get_gateway()["status"]["listeners"][0]["attachedRoutes"] == 1)
        evidence["checks"].append("first route propagates without a warm-up route")
        kubectl("delete", "httproute", "app")
        wait_for("last route removal returns HTTP 404", lambda: http_status(address, args.gateway_port) == 404)
        wait_for("attachedRoutes returns to zero", lambda: get_gateway()["status"]["listeners"][0]["attachedRoutes"] == 0)
        check("listener remains programmed after last route removal",
              condition(get_gateway(), "Programmed").get("status") == "True")
        kubectl("patch", "gateway", "web", "--type=merge", "-p", json.dumps({
            "spec": {"listeners": [{"name": "http", "protocol": "HTTP", "port": args.gateway_port + 1}]}}))
        wait_for("new Gateway generation programmed", lambda: serving_gateway(2))
        check("new listener returns HTTP 404", http_status(address, args.gateway_port + 1) == 404)
        check("old listener is closed", http_status(address, args.gateway_port) is None)
        evidence["checks"].append("Gateway status follows the current spec generation")
        evidence["status"] = "passed"
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = str(error)
        raise
    finally:
        (root / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, indent=2), flush=True)
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--parent", default="/var/tmp")
    parser.add_argument("--port", type=int, default=18191)
    parser.add_argument("--node-port", type=int, default=17448)
    parser.add_argument("--gateway-port", type=int, default=18088)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run only as root in a disposable test VM")
    run(arguments)
