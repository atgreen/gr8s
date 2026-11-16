#!/usr/bin/env python3
"""Validate staged certificate rotation against a disposable three-voter cluster.

The harness needs no root: every control plane and the remote agent use the fake
runtime.  It retains logs and a machine-readable report on failure and removes
them after success unless --keep is requested.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*arguments, check=True, **keywords):
    result = subprocess.run([str(item) for item in arguments], text=True,
                            capture_output=True, **keywords)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, arguments))}\n"
                           f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result


def wait_for(description, function, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (OSError, RuntimeError, json.JSONDecodeError) as error:
            last = error
        time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for {description}: {last}")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def certificate_fingerprint(path):
    pem = path.read_text(encoding="utf-8")
    begin = pem.index("-----BEGIN CERTIFICATE-----")
    end_marker = "-----END CERTIFICATE-----"
    end = pem.index(end_marker, begin) + len(end_marker)
    der = ssl.PEM_cert_to_DER_cert(pem[begin:end])
    return hashlib.sha256(der).hexdigest().upper()


class Cluster:
    def __init__(self, binary, kubectl, root):
        self.binary = binary.resolve()
        self.kubectl = kubectl
        self.root = root
        self.children = []
        self.logs = []
        self.nodes = [dict(id=f"cp{index}", state=root / f"cp{index}",
                           api=free_port(), raft=free_port(), node=free_port())
                      for index in range(1, 4)]
        self.agent = dict(id="worker-a", state=root / "worker-a")

    def command(self, *arguments, check=True):
        return run(self.binary, *arguments, check=check)

    def launch_control_plane(self, node, join=None, join_via=None):
        log = (self.root / f"{node['id']}.log").open("a", encoding="utf-8")
        self.logs.append(log)
        arguments = ["serve", "--runtime", "fake", "--disable-agent",
                     "--state-directory", node["state"], "--listen", "127.0.0.1",
                     "--port", node["api"], "--node-port", node["node"],
                     "--node-name", node["id"], "--raft-id", node["id"],
                     "--raft-port", node["raft"], "--kubeconfig", node["state"] / "kubeconfig"]
        if join:
            arguments += ["--join", f"127.0.0.1:{join_via['raft']}",
                          "--token", join["token"],
                          "--ca-pin", join["caPin"]]
        else:
            arguments += ["--raft-init"]
        child = subprocess.Popen([str(self.binary), *map(str, arguments)], stdout=log,
                                 stderr=subprocess.STDOUT, text=True)
        self.children.append(child)
        node["process"] = child
        return child

    def kubectl_get(self, node, resource="nodes"):
        result = run(self.kubectl, "--kubeconfig", node["state"] / "kubeconfig",
                     "--request-timeout=5s", "get", resource, "-o", "json", check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def wait_api(self, node):
        return wait_for(f"{node['id']} Kubernetes API", lambda: self.kubectl_get(node))

    def join_token(self, name, role="control-plane", source=None):
        source = source or self.live_node()
        result = self.command("join-token", "--state-directory", source["state"],
                              "--node-name", name, "--role", role)
        return json.loads(result.stdout)

    def launch_agent(self, token):
        log = (self.root / "worker-a.log").open("a", encoding="utf-8")
        self.logs.append(log)
        endpoints = ",".join(f"127.0.0.1:{node['node']}" for node in self.nodes)
        child = subprocess.Popen(
            [str(self.binary), "agent", "--runtime", "fake", "--server", endpoints,
             "--state-directory", str(self.agent["state"]), "--node-name", self.agent["id"],
             "--token", token["token"], "--ca-pin", token["caPin"]],
            stdout=log, stderr=subprocess.STDOUT, text=True)
        self.children.append(child)
        self.agent["process"] = child
        return child

    def wait_node(self, issuer=None):
        def ready():
            document = self.kubectl_get(self.live_node(), "nodes")
            if not document:
                return None
            node = next((item for item in document["items"]
                         if item["metadata"]["name"] == self.agent["id"]), None)
            if not node or issuer is None:
                return node
            records = list(self.live_node()["state"].glob("nodes/*.json"))
            if not records:
                return None
            persisted = next((json.loads(path.read_text(encoding="utf-8"))
                              for path in records
                              if json.loads(path.read_text(encoding="utf-8")).get("name")
                              == self.agent["id"]), None)
            return node if (persisted and
                            persisted.get("certificateIssuerFingerprint") == issuer) else None
        description = "remote agent registration"
        if issuer:
            description = f"remote agent reconnect under CA {issuer}"
        return wait_for(description, ready)

    def live_node(self):
        return next(node for node in self.nodes if node["process"].poll() is None)

    def rotate(self, kind, stage, node=None, check=True):
        node = node or self.live_node()
        command = "rotate-ca" if kind == "ca" else "service-account-key"
        return self.command("certificate", command, stage, "--kubeconfig",
                            node["state"] / "kubeconfig", check=check)

    def rotate_eventually(self, kind, stage, node=None, timeout=90):
        def attempt():
            result = self.rotate(kind, stage, node, check=False)
            return result if result.returncode == 0 else None
        return wait_for(f"{kind} {stage} after leader election", attempt, timeout=timeout)

    def stop(self, target):
        child = target["process"]
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            child.wait(timeout=30)

    def restart_control_plane(self, node):
        self.stop(node)
        # Existing members rejoin with their durable Raft identity and credentials.
        # If the stopped member was leader, its first attempt can race the next
        # election; retry from a live survivor with a fresh one-time token.
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            survivor = self.live_node()
            token = self.join_token(node["id"], source=survivor)
            child = self.launch_control_plane(node, token, survivor)
            attempt_deadline = min(deadline, time.monotonic() + 25)
            while time.monotonic() < attempt_deadline:
                if self.kubectl_get(node):
                    return
                if child.poll() is not None:
                    break
                time.sleep(0.25)
            if child.poll() is None:
                self.stop(node)
        raise RuntimeError(f"timed out restarting {node['id']} after leader election")

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for log in self.logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="gr8s-certificate-ha-"))
    cluster = Cluster(arguments.gr8s, arguments.kubectl, root)
    report = {"passed": False, "runtime": "fake", "members": 3,
              "evidenceDirectory": str(root), "checks": {}}
    passed = False
    try:
        founder = cluster.nodes[0]
        cluster.launch_control_plane(founder)
        cluster.wait_api(founder)
        for node in cluster.nodes[1:]:
            token = cluster.join_token(node["id"])
            cluster.launch_control_plane(node, token, founder)
            cluster.wait_api(node)
        report["checks"]["initialCluster"] = True

        old_ca = founder["state"] / "pki/pki/cluster-ca.crt"
        old_ca_digest = digest(old_ca)
        cluster.rotate("ca", "prepare", founder)
        prepared = [node["state"] / "pki/pki/cluster-ca-next.crt" for node in cluster.nodes]
        wait_for("prepared CA extraction", lambda: all(path.exists() for path in prepared))
        report["checks"]["preparedOnEveryVoter"] = True

        # Lose the member that initiated prepare. A survivor must promote the
        # durable transition, proving recovery at an interrupted stage boundary.
        cluster.stop(founder)
        survivor = cluster.nodes[1]
        cluster.wait_api(survivor)
        cluster.rotate_eventually("ca", "promote", survivor)
        retiring = [node["state"] / "pki/pki/cluster-ca-retiring.crt"
                    for node in cluster.nodes[1:]]
        wait_for("promoted CA extraction", lambda: all(path.exists() for path in retiring))
        assert all(digest(path) == old_ca_digest for path in retiring)
        report["checks"]["prepareSurvivedLeaderLoss"] = True
        report["checks"]["dualTrustPromoted"] = True

        # Restart each voter separately. The surviving pair retains quorum; each
        # restarted member reloads the active CA and renews its local leaves.
        cluster.restart_control_plane(founder)
        for node in (cluster.nodes[2], survivor):
            cluster.restart_control_plane(node)
            assert cluster.kubectl_get(cluster.live_node())
        report["checks"]["rollingControlPlaneRenewal"] = True

        active = cluster.live_node()
        cluster.rotate("ca", "finalize", active)
        wait_for("retiring CA removal", lambda: all(
            not (node["state"] / "pki/pki/cluster-ca-retiring.crt").exists()
            for node in cluster.nodes))
        cluster.wait_api(active)
        report["checks"]["safeFinalize"] = True

        for stage in ("prepare", "promote", "finalize"):
            cluster.rotate("service-account-key", stage, active)
        signer_files = [node["state"] / "pki/service-account-signing-key.json"
                        for node in cluster.nodes]
        wait_for("signing-key convergence", lambda: all(path.exists() for path in signer_files)
                 and len({digest(path) for path in signer_files}) == 1)
        report["checks"]["serviceAccountSignerRotation"] = True

        report["passed"] = all(report["checks"].values())
        passed = report["passed"]
    except Exception as error:
        report["error"] = str(error)
    finally:
        cluster.close()
        destination = arguments.output or (root / "report.json")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, sort_keys=True))
        if passed and not arguments.keep and arguments.output:
            shutil.rmtree(root)
        elif not passed or arguments.keep:
            print(f"Evidence retained: {root}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
