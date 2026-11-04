#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Verify real Pod resolver files and custom UDP/TCP queries in an owned native guest."""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid


class CustomDNS:
    """Serve a test DNS name pointing to the actual observed HTTP backend Pod IP."""

    def __init__(self, address, backend, port=53):
        """Bind exact owned UDP/TCP listeners and record genuine queries from clients."""
        self.backend = backend
        self.queries = []
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((address, port))
        self.port = self.udp.getsockname()[1]
        self.udp.settimeout(0.25)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((address, self.port))
        self.tcp.listen(8)
        self.tcp.settimeout(0.25)
        self.threads = [threading.Thread(target=self.serve_udp), threading.Thread(target=self.serve_tcp)]
        for thread in self.threads:
            thread.start()

    def answer(self, packet, protocol):
        """Answer only backend.custom.test using its real Pod IP; unknown names are NXDOMAIN."""
        offset, labels = 12, []
        while packet[offset]:
            length = packet[offset]
            offset += 1
            labels.append(packet[offset:offset + length].decode())
            offset += length
        offset += 1
        qtype, qclass = struct.unpack_from("!HH", packet, offset)
        end = offset + 4
        name = ".".join(labels).lower()
        known = name == "backend.custom.test"
        with self.lock:
            self.queries.append({"transport": protocol, "name": name, "type": qtype})
        answer = b""
        if known and qtype == 1 and qclass == 1:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton(self.backend)
        flags = 0x8400 | (struct.unpack_from("!H", packet, 2)[0] & 0x0100) | (0 if known else 3)
        return packet[:2] + struct.pack("!5H", flags, 1, bool(answer), 0, 0) + packet[12:end] + answer

    def serve_udp(self):
        """Handle actual UDP requests until explicit fixture shutdown."""
        while not self.stopped.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                self.udp.sendto(self.answer(packet, "udp"), peer)
            except socket.timeout:
                continue
            except OSError:
                if not self.stopped.is_set():
                    raise

    @staticmethod
    def read_exact(stream, size):
        """Read a complete TCP DNS frame or fail on a genuine premature close."""
        result = b""
        while len(result) < size:
            data = stream.recv(size - len(result))
            if not data:
                raise EOFError("custom DNS TCP frame closed early")
            result += data
        return result

    def serve_tcp(self):
        """Handle actual framed TCP requests on the separate configured resolver IP."""
        while not self.stopped.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.stopped.is_set():
                    raise
                break
            with client:
                client.settimeout(2)
                try:
                    size = struct.unpack("!H", self.read_exact(client, 2))[0]
                    answer = self.answer(self.read_exact(client, size), "tcp")
                    client.sendall(struct.pack("!H", len(answer)) + answer)
                except (OSError, EOFError):
                    pass

    def close(self):
        """Stop and join both owned listeners before removing their fixture IP."""
        self.stopped.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=3)
            assert not thread.is_alive(), "custom DNS listener did not stop"


def main():
    """Create real backend/client Pods, prove custom resolution and recover without changing identities."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--api-port", type=int, default=18209)
    parser.add_argument("--node-port", type=int, default=17466)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-pod-dns-config.", dir="/var/tmp"))
    state = args.state_directory or root / "state"
    namespace = "resolver-" + uuid.uuid4().hex[:8]
    base = f"http://127.0.0.1:{args.api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    report = {"directory": str(root), "stateDirectory": str(state), "namespace": namespace,
              "nativeSHA256": hashlib.sha256(args.gr8s.read_bytes()).hexdigest(), "passed": False, "nativeExitCodes": []}
    process, custom_dns, added_address = None, None, False
    custom_address = "169.254.1.2"
    log = (root / "gr8s.log").open("w")
    print(json.dumps({"directory": str(root), "namespace": namespace}), flush=True)

    def request(path, method="GET", obj=None):
        """Read actual API status and objects, retaining rejected request bodies."""
        data = None if obj is None else json.dumps(obj).encode()
        try:
            with opener.open(urllib.request.Request(base + path, data=data, method=method,
                              headers={"Content-Type": "application/json"}), timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def path(resource, name=None):
        """Confine every mutation to the namespace owned by this test."""
        return f"/api/v1/namespaces/{namespace}/{resource}" + ("/" + name if name else "")

    def wait(predicate, description, timeout=180):
        """Poll an ongoing observation without rerunning the action being observed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, TimeoutError):
                pass
            if process and process.poll() is not None:
                raise RuntimeError(f"native exited {process.returncode}: {description}")
            time.sleep(0.25)
        raise TimeoutError(description)

    def pods():
        """Read actual Pod observations from this test's namespace."""
        code, listing = request(path("pods"))
        return listing.get("items", []) if code == 200 else []

    def observed(name):
        """Require actual container IDs and a real assigned Pod address before using a backend."""
        pod = next((pod for pod in pods() if pod["metadata"]["name"] == name), None)
        if pod and pod.get("status", {}).get("podIP") and all(c.get("ready") for c in pod["status"].get("containerStatuses", [])):
            if len(pod["status"].get("containerStatuses", [])) == len(pod["spec"]["containers"]):
                return pod
        return None

    def create(obj):
        """Require creation of a real desired Pod with server-assigned identity."""
        code, pod = request(path("pods"), "POST", obj)
        assert code == 201, (code, pod)
        return pod

    def read_proxy(name, filename):
        """Read actual files served by the Pod HTTP process through the public proxy API."""
        with opener.open(base + path("pods", name) + "/proxy/results/" + filename, timeout=5) as response:
            assert response.status == 200
            return response.read().decode().strip()

    def identities():
        """Keep every container identity, including both containers in the resolver client Pod."""
        return {pod["metadata"]["uid"]: {c["name"]: c["containerID"] for c in pod["status"]["containerStatuses"]} for pod in pods()}

    def shims():
        """Inspect only shims belonging to this explicitly owned runtime state."""
        return [line for line in subprocess.check_output(["ps", "-eo", "comm=,args="], text=True).splitlines()
                if line.startswith("containerd-shim") and str(state) in line]

    def start():
        """Start only the supplied binary/state and require its actual node readiness."""
        nonlocal process
        process = subprocess.Popen([str(args.gr8s), "serve", "--runtime", "containerd", "--state-directory", str(state),
                                    "--port", str(args.api_port), "--node-port", str(args.node_port)], stdout=log, stderr=subprocess.STDOUT)
        def ready():
            """Inspect real metrics while distinguishing a stopped native process."""
            with opener.open(base + "/metrics", timeout=2) as response:
                return 'gr8s_dataplane_node_ready{node="gr8s-local"} 1' in response.read().decode()
        wait(ready, "native worker readiness", 90)

    def stop():
        """Stop and join only this test's native process, recording its true exit status."""
        nonlocal process
        if process:
            process.terminate()
            code = process.wait(timeout=45)
            report["nativeExitCodes"].append(code)
            process = None
            assert code == 0, code

    try:
        assert not shims(), "the supplied owned state is still running"
        start()
        code, value = request("/api/v1/namespaces", "POST", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}})
        assert code == 201, (code, value)
        marker = namespace + "-actual-backend"
        create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "backend"},
                "spec": {"terminationGracePeriodSeconds": 0, "containers": [{"name": "http", "image": "docker.io/library/busybox:1.36.1",
                         "command": ["sh", "-c", f"mkdir -p /www; echo {marker} >/www/index.html; httpd -f -p 8080 -h /www"],
                         "ports": [{"containerPort": 8080}]}]}})
        backend = wait(lambda: observed("backend"), "actual HTTP backend readiness")
        addresses = json.loads(subprocess.check_output(["ip", "-j", "address", "show", "dev", "gr8s-gateway"], text=True))
        assert not any(address.get("local") == custom_address for link in addresses for address in link.get("addr_info", [])), "fixture address is already owned"
        subprocess.run(["ip", "address", "add", custom_address + "/32", "dev", "gr8s-gateway"], check=True)
        added_address = True
        custom_dns = CustomDNS(custom_address, backend["status"]["podIP"])
        command = ("cat /etc/resolv.conf >/results/resolv.conf; for i in `seq 1 600`; do "
                   "dig +time=1 +tries=1 +notcp +short backend.custom.test A >/results/udp; "
                   "dig +time=1 +tries=1 +tcp +short backend.custom.test A >/results/tcp; "
                   "wget -qO /results/http http://backend:8080/; sleep 1; done")
        create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "client"},
                "spec": {"terminationGracePeriodSeconds": 0, "dnsPolicy": "None",
                         "dnsConfig": {"nameservers": [custom_address], "searches": ["custom.test"], "options": [{"name": "ndots", "value": "2"}]},
                         "volumes": [{"name": "results", "emptyDir": {}}], "containers": [
                            {"name": "web", "image": "registry.k8s.io/e2e-test-images/agnhost:2.63.0", "args": ["test-webserver"],
                             "volumeMounts": [{"name": "results", "mountPath": "/results"}]},
                            {"name": "queries", "image": "registry.k8s.io/e2e-test-images/agnhost:2.63.0", "command": ["sh", "-c", command],
                             "volumeMounts": [{"name": "results", "mountPath": "/results"}]}]}})
        client = wait(lambda: observed("client"), "actual custom resolver client readiness")
        wait(lambda: read_proxy("client", "http") == marker, "actual HTTP reached using the custom search path")
        resolver = read_proxy("client", "resolv.conf")
        assert f"nameserver {custom_address}" in resolver and "search custom.test" in resolver and "ndots:2" in resolver, resolver
        assert "svc.cluster.local" not in resolver and "169.254.1.1" not in resolver, resolver
        assert backend["status"]["podIP"] in read_proxy("client", "udp")
        assert backend["status"]["podIP"] in read_proxy("client", "tcp")
        assert {query["transport"] for query in custom_dns.queries if query["name"] == "backend.custom.test"} == {"udp", "tcp"}
        before = identities()
        report["customDNS"] = {"address": custom_address, "backendUID": backend["metadata"]["uid"], "backendIP": backend["status"]["podIP"],
                               "clientUID": client["metadata"]["uid"], "resolverContents": resolver, "actualHTTPResponse": marker,
                               "actualUDPAnswer": read_proxy("client", "udp"), "actualTCPAnswer": read_proxy("client", "tcp")}
        stop()
        start()
        wait(lambda: observed("backend") and observed("client"), "actual Pod recovery after restart")
        assert identities() == before, (identities(), before)
        assert read_proxy("client", "http") == marker
        assert read_proxy("client", "resolv.conf") == resolver
        report["unchangedContainerIdentitiesAfterRestart"] = before
        report["passed"] = True
    except Exception as error:
        report["error"] = repr(error)
    finally:
        if custom_dns:
            try:
                custom_dns.close()
            except Exception as error:
                report["fixtureCleanupError"] = repr(error)
                report["passed"] = False
            report["actualCustomResolverQueries"] = custom_dns.queries
        if added_address:
            subprocess.run(["ip", "address", "del", custom_address + "/32", "dev", "gr8s-gateway"], check=False)
        try:
            if process and process.poll() is None:
                for pod in pods():
                    request(path("pods", pod["metadata"]["name"]), "DELETE",
                            {"gracePeriodSeconds": 0, "preconditions": {"uid": pod["metadata"]["uid"]}})
                wait(lambda: not pods() and not shims(), "actual owned Pod/runtime cleanup", 120)
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
        report["artifactSHA256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob("*.log")}
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"directory": str(root), "passed": report["passed"], "error": report.get("error"), "cleanupError": report.get("cleanupError")}), flush=True)
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
