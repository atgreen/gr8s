#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Purpose: Verify native CSR APIs and genuine approved certificates with strict kubectl and Go TLS.

Use an isolated fake workload runtime because this test creates no Pods. API,
PKI, durable state, watches and independent certificate verification are real.
The unmodified upstream Certificates API family is validated separately.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def run(command):
    """Execute a real client and retain stderr when verification fails."""
    return subprocess.run([str(item) for item in command], check=True, text=True, capture_output=True).stdout


def request(base, path, method="GET", obj=None, expected=200):
    """Issue a JSON API request and check its actual status, including negative cases."""
    data = json.dumps(obj).encode() if obj is not None else None
    message = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(message, timeout=10) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    if status != expected:
        raise AssertionError(f"{method} {path}: expected {expected}, got {status}: {body!r}")
    return json.loads(body)


def wait_for(predicate, timeout=30):
    """Wait only for observed state, propagating the last actual client failure."""
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, urllib.error.URLError) as error:
            last = error
        time.sleep(0.1)
    raise RuntimeError(f"observed-state timeout; last client failure: {last}")


def watch(base, revision, name, timeout=1, ready=None):
    """Read actual durable watch events from the server, including replayed mutations."""
    query = urllib.parse.urlencode({"watch": "true", "resourceVersion": revision, "fieldSelector": "metadata.name=" + name, "timeoutSeconds": timeout})
    with urllib.request.urlopen(base + "/apis/certificates.k8s.io/v1/certificatesigningrequests?" + query, timeout=timeout + 5) as response:
        if ready is not None:
            ready.set()
        return [json.loads(line) for line in response if line.strip()]


def main():
    """Verify real native create/approve/sign/watch/restart/deletion and clean shutdown."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18195)
    parser.add_argument("--node-port", type=int, default=17495)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-csr-api-"))
    state, kubeconfig = root / "state", root / "kubeconfig"
    base, collection = f"http://127.0.0.1:{args.port}", "/apis/certificates.k8s.io/v1/certificatesigningrequests"
    client = [shutil.which("kubectl") or "kubectl", "--kubeconfig", kubeconfig]
    command = [args.executable.resolve(), "serve", "--runtime", "fake", "--state-directory", state, "--port", args.port, "--node-port", args.node_port, "--kubeconfig", kubeconfig]
    log = (root / "native.log").open("w")
    process, exits = None, []
    report = {"stateDirectory": str(root), "binarySHA256": hashlib.sha256(args.executable.read_bytes()).hexdigest(), "workloadRuntime": "fake; no Pods created", "isCertificationResult": False}

    def start():
        """Start the actual native control plane against its durable directory."""
        child = subprocess.Popen([str(item) for item in command], stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_for(lambda: request(base, "/version"))
        except Exception:
            if child.poll() is None:
                child.terminate()
            exits.append(child.wait(timeout=30))
            raise
        return child

    def stop(child):
        """Require a clean owned process exit and retain every exit code."""
        child.send_signal(signal.SIGTERM)
        code = child.wait(timeout=30)
        exits.append(code)
        if code:
            raise RuntimeError(f"native process exited {code}; see {root / 'native.log'}")

    def create(name, signer):
        """Create through strict kubectl server validation without bypass flags."""
        manifest = {"apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest", "metadata": {"name": name}, "spec": {"request": base64.b64encode((root / "request.pem").read_bytes()).decode(), "signerName": signer, "expirationSeconds": 3600, "usages": ["digital signature", "client auth"]}}
        path = root / (name + ".json")
        path.write_text(json.dumps(manifest))
        run(client + ["create", "--validate=strict", "-f", path])
        return request(base, collection + "/" + name)

    print(f"CSR native state: {root}", flush=True)
    try:
        process = start()
        run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=native-csr-client/O=api-users", "-keyout", root / "client.key", "-out", root / "request.pem"])
        group = request(base, "/apis/certificates.k8s.io/v1")
        assert {entry["name"] for entry in group["resources"]} == {"certificatesigningrequests", "certificatesigningrequests/approval", "certificatesigningrequests/status"}
        initial = request(base, collection)["metadata"]["resourceVersion"]
        # RV=0 denotes an initial snapshot, so observe future mutations rather
        # than mistaking a current snapshot for historical replay.
        watch_ready, observed_events, watch_errors = threading.Event(), [], []

        def collect_watch():
            """Retain the real stream started before the create/approve mutations."""
            try:
                observed_events.extend(watch(base, initial, "native-client", timeout=10, ready=watch_ready))
            except Exception as error:
                watch_errors.append(error)

        watch_thread = threading.Thread(target=collect_watch, daemon=True)
        watch_thread.start()
        assert watch_ready.wait(5), "native watch did not establish before mutations"
        created = create("native-client", "kubernetes.io/kube-apiserver-client")
        uid = created["metadata"]["uid"]
        assert not created["status"].get("certificate") and not created["status"].get("conditions")
        run(client + ["certificate", "approve", "native-client"])
        issued = wait_for(lambda: (lambda obj: obj if obj["status"].get("certificate") else None)(request(base, collection + "/native-client")))
        certificate = base64.b64decode(issued["status"]["certificate"])
        (root / "client.crt").write_bytes(certificate)
        ca = next((state / "pki").rglob("cluster-ca.crt"))
        server_certificate = next((state / "pki").rglob("server.crt"))
        server_key = server_certificate.with_name("server.key")
        ca_digest = hashlib.sha256(ca.read_bytes()).hexdigest()
        run(["openssl", "verify", "-purpose", "sslclient", "-CAfile", ca, root / "client.crt"])
        helper = Path(__file__).resolve().parent / "verify-csr-certificate.go"
        external = json.loads(run([args.go, "run", helper, "--certificate", root / "client.crt", "--ca", ca, "--key", root / "client.key", "--purpose", "client", "--dns-name", "gr8s-control", "--server-certificate", server_certificate, "--server-key", server_key]))
        assert external["verified"] and external["singleLeaf"] and external["ordinaryTLSHandshakeVerified"]
        report["externalGoVerification"] = external
        watch_thread.join(timeout=15)
        assert not watch_thread.is_alive() and not watch_errors, f"watch stream failed: {watch_errors}"
        events = observed_events
        assert {entry["type"] for entry in events} >= {"ADDED", "MODIFIED"}, f"missing live watch mutations: {events}"
        assert all(entry["object"]["metadata"]["uid"] == uid for entry in events)
        report["creationWatchTypes"] = [entry["type"] for entry in events]
        create("native-denied", "kubernetes.io/kube-apiserver-client")
        run(client + ["certificate", "deny", "native-denied"])
        denied = request(base, collection + "/native-denied")
        assert any(condition["type"] == "Denied" and condition["status"] == "True" for condition in denied["status"]["conditions"])
        assert not denied["status"].get("certificate")
        create("native-custom", "example.test/custom")
        run(client + ["certificate", "approve", "native-custom"])
        invalid = json.loads((root / "native-custom.json").read_text())
        invalid["metadata"]["name"] = "invalid-signature"
        pem = (root / "request.pem").read_text()
        payload = base64.b64decode("".join(line for line in pem.splitlines() if not line.startswith("---")))
        payload = payload[:-1] + bytes([payload[-1] ^ 1])
        invalid_pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(payload).decode() + "-----END CERTIFICATE REQUEST-----\n"
        invalid["spec"]["request"] = base64.b64encode(invalid_pem.encode()).decode()
        report["invalidSignatureResponse"] = request(base, collection, "POST", invalid, expected=422)
        report["invalidCertificateResponse"] = request(base, collection + "/native-custom/status", "PUT", {**request(base, collection + "/native-custom"), "status": {"certificate": base64.b64encode(b"not a certificate").decode(), "conditions": request(base, collection + "/native-custom")["status"]["conditions"]}}, expected=422)
        stop(process)
        process = None
        process = start()
        reopened = request(base, collection + "/native-client")
        assert reopened["metadata"]["uid"] == uid and reopened["status"]["certificate"] == issued["status"]["certificate"]
        assert hashlib.sha256(ca.read_bytes()).hexdigest() == ca_digest
        assert not request(base, collection + "/native-custom")["status"].get("certificate")
        revision = request(base, collection)["metadata"]["resourceVersion"]
        run(client + ["delete", "csr", "native-client"])
        deleted = watch(base, revision, "native-client")
        assert any(event["type"] == "DELETED" and event["object"]["metadata"]["uid"] == uid for event in deleted)
        report.update(deletionWatchTypes=[event["type"] for event in deleted], restartPreservedUIDAndCertificate=True, caSHA256=ca_digest, passed=True)
        print("strict kubectl CSR create/approve/deny, actual Go TLS certificate, watch and durable restart passed", flush=True)
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        try:
            if process is not None:
                stop(process)
        finally:
            log.close()
            report["nativeExitCodes"] = exits
            (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("clean native exits: " + str(exits), flush=True)


if __name__ == "__main__":
    main()
