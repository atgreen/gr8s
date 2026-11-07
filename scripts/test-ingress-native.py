#!/usr/bin/env python3
"""Prove native Ingress HTTP/TLS routing through every advertised node."""

import argparse
import http.client
import json
import ssl
import subprocess
import tempfile
import time
from pathlib import Path


MANIFEST = """
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: {name: gr8s-native-test}
spec: {controller: gr8s.io/ingress-controller}
---
apiVersion: v1
kind: Pod
metadata:
  name: ingress-native-backend
  labels: {run: ingress-native-backend}
spec:
  containers:
  - name: backend
    image: registry.k8s.io/e2e-test-images/agnhost:2.57
    args: [netexec, --http-port=8080]
    ports: [{name: http, containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: ingress-native-backend}
spec:
  selector: {run: ingress-native-backend}
  ports: [{name: web, port: 80, targetPort: http}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: ingress-native-test}
spec:
  ingressClassName: gr8s-native-test
  tls: [{hosts: [ingress-native.test], secretName: ingress-native-tls}]
  rules:
  - host: ingress-native.test
    http:
      paths:
      - path: /echo
        pathType: Exact
        backend:
          service:
            name: ingress-native-backend
            port: {name: web}
"""


def run(*argv, input_text=None, check=True):
    return subprocess.run(argv, input=input_text, text=True, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def kubectl(kubeconfig, *args, input_text=None, check=True):
    return run("kubectl", "--kubeconfig", kubeconfig, *args,
               input_text=input_text, check=check)


def request(address, tls, message):
    cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    kwargs = {"timeout": 5}
    if tls:
        kwargs["context"] = ssl._create_unverified_context()
    connection = cls(address, 443 if tls else 80, **kwargs)
    try:
        connection.request("GET", f"/echo?msg={message}", headers={"Host": "ingress-native.test"})
        response = connection.getresponse()
        body = response.read().decode()
        if response.status != 200 or body != message:
            raise RuntimeError(f"{address}: unexpected {response.status} {body!r}")
    finally:
        connection.close()


def wait_for_addresses(kubeconfig, count, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = kubectl(kubeconfig, "get", "ingress", "ingress-native-test", "-o", "json")
        ingress = json.loads(result.stdout)
        entries = ingress.get("status", {}).get("loadBalancer", {}).get("ingress", [])
        addresses = sorted(entry.get("ip") or entry.get("hostname") for entry in entries)
        addresses = [address for address in addresses if address]
        if len(addresses) == count:
            return addresses
        time.sleep(2)
    raise TimeoutError(f"Ingress did not advertise {count} nodes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expected-nodes", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="gr8s-ingress-") as directory:
        certificate = Path(directory) / "tls.crt"
        key = Path(directory) / "tls.key"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=ingress-native.test", "-keyout", str(key), "-out", str(certificate))
        secret = kubectl(args.kubeconfig, "create", "secret", "tls", "ingress-native-tls",
                         f"--cert={certificate}", f"--key={key}", "--dry-run=client", "-o", "yaml").stdout
        try:
            kubectl(args.kubeconfig, "apply", "-f", "-", input_text=secret + "\n---\n" + MANIFEST)
            kubectl(args.kubeconfig, "wait", "--for=condition=Ready",
                    "pod/ingress-native-backend", f"--timeout={args.timeout}s")
            addresses = wait_for_addresses(args.kubeconfig, args.expected_nodes, args.timeout)
            for index, address in enumerate(addresses, 1):
                request(address, False, f"http-node-{index}")
                request(address, True, f"https-node-{index}")
                print(f"ok {address}: HTTP and HTTPS")
        finally:
            kubectl(args.kubeconfig, "delete", "ingress", "ingress-native-test",
                    "--ignore-not-found", check=False)
            kubectl(args.kubeconfig, "delete", "service", "ingress-native-backend",
                    "--ignore-not-found", check=False)
            kubectl(args.kubeconfig, "delete", "pod", "ingress-native-backend",
                    "--ignore-not-found", check=False)
            kubectl(args.kubeconfig, "delete", "secret", "ingress-native-tls",
                    "--ignore-not-found", check=False)
            kubectl(args.kubeconfig, "delete", "ingressclass", "gr8s-native-test",
                    "--ignore-not-found", check=False)


if __name__ == "__main__":
    main()
