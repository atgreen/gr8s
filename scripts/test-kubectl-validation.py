#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Validate a real manifest of every built-in kind with real kubectl against native gr8s.

kubectl checks a List's items on the client against the server's OpenAPI documents,
and single objects on the server when its OpenAPI says it validates fields. This
applies tests/fixtures/builtin-manifests.json both ways under --validate=strict and
--validate=warn, creates the review kinds, and runs kubectl explain for every kind.
It also fails when discovery serves a creatable kind of a Kubernetes group version
that the fixture has no manifest for. The fake runtime is enough: nothing runs.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures/builtin-manifests.json"
# Group versions whose schemas gr8s publishes as Kubernetes does (schema/openapi-v1.json).
UPSTREAM = set(json.loads((ROOT / "schema/openapi-v1.json").read_text())["documents"])


def free_port():
    """Choose a currently free loopback TCP port for this isolated server."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    """Own one native API process and its state directory."""
    def __init__(self, executable):
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-kubectl-validation-"))
        self.executable = str(Path(executable).resolve())
        self.port, self.node_port = free_port(), free_port()
        self.env = dict(os.environ, KUBECONFIG=str(self.root / "kubeconfig"),
                        KUBECACHEDIR=str(self.root / "kube-cache"))
        self.process = None
        self.log = (self.root / "server.log").open("ab")
        print(f"kubectl validation state: {self.root}", flush=True)

    def start(self):
        self.process = subprocess.Popen(
            [self.executable, "serve", "--runtime", "fake", "--disable-agent",
             "--port", str(self.port), "--node-port", str(self.node_port),
             "--state-directory", str(self.root / "state"),
             "--kubeconfig", str(self.root / "kubeconfig")],
            stdout=self.log, stderr=subprocess.STDOUT, env=self.env)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"native API exited {self.process.returncode}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/readyz", timeout=1):
                    if (self.root / "kubeconfig").exists():
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.1)
        raise AssertionError("native API did not become ready")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            assert self.process.wait(timeout=30) == 0
        self.process = None

    def kubectl(self, *arguments):
        """Run kubectl; return (code, stdout, stderr)."""
        result = subprocess.run(["kubectl", *arguments], env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        return result.returncode, result.stdout, result.stderr


def discovered_kinds(server):
    """Map (groupVersion, kind) -> (resource, verbs) for every top-level resource discovery serves."""
    code, out, err = server.kubectl("get", "--raw", "/api/v1")
    assert code == 0, err
    documents = [("v1", json.loads(out))]
    code, out, err = server.kubectl("get", "--raw", "/apis")
    assert code == 0, err
    for group in json.loads(out)["groups"]:
        for version in group["versions"]:
            code, out, err = server.kubectl("get", "--raw", f"/apis/{version['groupVersion']}")
            assert code == 0, err
            documents.append((version["groupVersion"], json.loads(out)))
    kinds = {}
    for group_version, document in documents:
        for resource in document["resources"]:
            if "/" not in resource["name"]:
                kinds[(group_version, resource["kind"])] = (resource["name"], resource["verbs"])
    return kinds


def document_key(group_version):
    return f"api/{group_version}" if "/" not in group_version else f"apis/{group_version}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", nargs="?", default=str(ROOT / "build/gr8s"))
    arguments = parser.parse_args()
    manifests = json.loads(FIXTURE.read_text())["items"]
    server = Server(arguments.executable)
    failures = []

    def check(label, code, out, err, warn=False):
        problem = code != 0 or (warn and "Warning" in err) or "error validating" in err
        print(f"{'FAIL' if problem else 'ok  '} {label}", flush=True)
        if problem:
            failures.append(f"{label}: exit {code}\n{out}{err}")

    try:
        server.start()
        kinds = discovered_kinds(server)
        covered = {(item["apiVersion"], item["kind"]) for item in manifests}
        for (group_version, kind), (resource, verbs) in sorted(kinds.items()):
            if document_key(group_version) in UPSTREAM and "create" in verbs and (group_version, kind) not in covered:
                failures.append(f"no fixture manifest for creatable {group_version} {kind} ({resource})")
        applyable = [item for item in manifests if "get" in kinds.get((item["apiVersion"], item["kind"]), ("", []))[1]]
        reviews = [item for item in manifests if item not in applyable]
        directory = server.root / "manifests"
        directory.mkdir()
        list_path = directory / "list.json"
        list_path.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": applyable}))
        # A List is validated on the client against the published schemas.
        for mode in ("strict", "warn"):
            check(f"apply List of {len(applyable)} kinds --validate={mode}",
                  *server.kubectl("apply", "--dry-run=server", f"--validate={mode}", "-f", str(list_path)), warn=True)
        reviews_path = directory / "reviews.json"
        reviews_path.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": reviews}))
        check(f"create List of {len(reviews)} review kinds --validate=strict",
              *server.kubectl("create", "--validate=strict", "-o", "name", "-f", str(reviews_path)))
        # A single object is validated by the server when its document offers fieldValidation.
        for index, item in enumerate(manifests):
            path = directory / f"{index:02d}-{item['kind']}.json"
            path.write_text(json.dumps(item))
            verb = ["apply", "--dry-run=server"] if item in applyable else ["create", "-o", "name"]
            check(f"{verb[0]} {item['apiVersion']} {item['kind']} --validate=strict",
                  *server.kubectl(*verb, "--validate=strict", "-f", str(path)), warn=True)
        # explain reads the v3 documents.
        for (group_version, kind), (resource, verbs) in sorted(kinds.items()):
            if document_key(group_version) in UPSTREAM:
                code, out, err = server.kubectl("explain", f"{resource}", f"--api-version={group_version}")
                if code == 0 and f"KIND:       {kind}" not in out:
                    code, err = 1, err + f"explain did not describe {kind}"
                check(f"explain {group_version} {resource}", code, out, err)
        for field, expected in (("pod.spec.containers.imagePullPolicy", "imagePullPolicy"),
                                ("pod.spec.containers.readinessProbe.exec", "command"),
                                ("deployment.spec.template.spec.initContainers.resources", "limits"),
                                ("networkpolicy.spec.ingress.from.ipBlock", "except")):
            code, out, err = server.kubectl("explain", field)
            if code == 0 and expected not in out:
                code, err = 1, err + f"explain {field} does not mention {expected}"
            check(f"explain {field}", code, out, err)
        code, out, err = server.kubectl("explain", "pods", "--recursive")
        check("explain pods --recursive", code, out, err)
    finally:
        server.stop()
    if failures:
        print("\n".join(["", "FAILURES:"] + failures))
        raise SystemExit(1)
    print("kubectl validation passed")


if __name__ == "__main__":
    main()
