#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise real kubectl/HTTP CRD behavior against an isolated native API.

The fake workload runtime is intentional: this test creates no containers and
verifies actual API discovery, schema admission, watches and durable storage.
Every server and resource belongs to a fresh state directory retained as evidence.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def free_port():
    """Choose a currently free loopback TCP port for this isolated server."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CRDSmoke:
    """Own one native API process and its persistent custom-resource state."""
    def __init__(self, executable):
        """Allocate this smoke's isolated state, ports and process log."""
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-crd-api-"))
        self.executable = str(Path(executable).resolve())
        self.port, self.node_port = free_port(), free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.env = dict(os.environ, KUBECONFIG=str(self.root / "kubeconfig"))
        self.process = None
        self.log = (self.root / "server.log").open("ab")
        self.namespace = "crd-smoke"
        self.group = "widgets.smoke.example.test"
        self.definition_name = f"widgets.{self.group}"
        self.collection = f"/apis/{self.group}/v1/namespaces/{self.namespace}/widgets"
        print(f"CRD smoke state: {self.root}", flush=True)

    def start(self):
        """Start the actual dumped executable against this run's own durable state."""
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
                with urllib.request.urlopen(self.base + "/readyz", timeout=1):
                    return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise AssertionError("native API did not become ready")

    def stop(self):
        """Stop only this run's process and require a clean native shutdown."""
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            assert self.process.wait(timeout=30) == 0
        self.process = None

    def kubectl(self, *arguments, fail=False):
        """Run actual kubectl, preserving stderr when an expected operation fails."""
        result = subprocess.run(["kubectl", *arguments], env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if fail:
            assert result.returncode != 0, result.stdout
        elif result.returncode:
            raise AssertionError(f"kubectl {arguments}: {result.stderr}")
        return result.stdout

    def read(self, path):
        """Read actual API JSON, returning None only for a genuine 404."""
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def create(self, name, finalizers=None):
        """Create a custom instance through kubectl with strict schema validation."""
        value = {"apiVersion": self.group + "/v1", "kind": "Widget",
                 "metadata": {"name": name, "namespace": self.namespace}, "spec": {}}
        if finalizers:
            value["metadata"]["finalizers"] = finalizers
        path = self.root / f"{name}.json"
        path.write_text(json.dumps(value))
        self.kubectl("create", "--validate=strict", "-f", str(path))
        return self.read(self.collection + "/" + name)

    def watch(self):
        """Observe actual create/update/delete events after an exact resource revision."""
        revision = self.read(self.collection)["metadata"]["resourceVersion"]
        query = urllib.parse.urlencode({"watch": "true", "resourceVersion": revision,
                                        "timeoutSeconds": "2", "fieldSelector": "metadata.name=watched"})
        events, failures = [], []
        opened = threading.Event()

        def receive():
            """Read the actual streamed JSON watch rather than inferred mutations."""
            try:
                with urllib.request.urlopen(self.base + self.collection + "?" + query, timeout=10) as response:
                    opened.set()
                    for line in response:
                        if line.strip():
                            events.append(json.loads(line))
            except Exception as error:
                failures.append(repr(error))
                opened.set()

        thread = threading.Thread(target=receive)
        thread.start()
        assert opened.wait(10), "watch did not establish"
        self.create("watched")
        self.kubectl("-n", self.namespace, "patch", "widgets", "watched", "--type=merge",
                     "-p", '{"spec":{"count":3}}')
        self.kubectl("-n", self.namespace, "delete", "widgets", "watched", "--wait=false")
        thread.join(timeout=15)
        assert not thread.is_alive() and not failures, failures
        assert [event["type"] for event in events] == ["ADDED", "MODIFIED", "DELETED"], events
        assert all(event["object"]["apiVersion"] == self.group + "/v1" for event in events)
        print("actual create/update/delete watch events passed", flush=True)

    def run(self):
        """Prove lifecycle, schema, status, version conversion and cleanup end to end."""
        schema = {"type": "object", "properties": {
            "spec": {"type": "object", "properties": {
                "count": {"type": "integer", "minimum": 1, "maximum": 5, "default": 2}}},
            "status": {"type": "object", "properties": {"ready": {"type": "boolean"}}}}}
        definition = {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                      "metadata": {"name": self.definition_name}, "spec": {
                          "group": self.group, "scope": "Namespaced",
                          "names": {"plural": "widgets", "kind": "Widget"},
                          "versions": [{"name": name, "served": True, "storage": index == 0,
                                        "schema": {"openAPIV3Schema": schema}, "subresources": {"status": {}}}
                                       for index, name in enumerate(["v1", "v2"])]}}
        path = self.root / "definition.json"
        path.write_text(json.dumps(definition))
        self.start()
        self.kubectl("create", "namespace", self.namespace)
        self.kubectl("create", "--validate=strict", "-f", str(path))
        self.kubectl("wait", "--for=condition=Established", "crd/" + self.definition_name, "--timeout=20s")
        assert "widgets" in self.kubectl("api-resources", "--api-group=" + self.group)
        created = self.create("one")
        assert created["spec"]["count"] == 2
        uid = created["metadata"]["uid"]
        self.kubectl("-n", self.namespace, "patch", "widgets", "one", "--type=merge", "-p", '{"spec":{"count":0}}', fail=True)
        self.kubectl("-n", self.namespace, "patch", "widgets", "one", "--subresource=status", "--type=merge",
                     "-p", '{"status":{"ready":true},"spec":{"count":999}}')
        value = self.read(self.collection + "/one")
        assert value["spec"]["count"] == 2 and value["status"]["ready"] is True
        other_version = self.read(self.collection.replace("/v1/", "/v2/") + "/one")
        assert other_version["metadata"]["uid"] == uid and other_version["apiVersion"] == self.group + "/v2"
        self.watch()
        self.stop()
        self.start()
        recovered = self.read(self.collection + "/one")
        assert recovered["metadata"]["uid"] == uid and recovered["status"]["ready"] is True
        print("strict kubectl discovery/schema/status/versions and native restart passed", flush=True)
        self.create("retained", ["example.test/cleanup"])
        self.kubectl("delete", "crd/" + self.definition_name, "--wait=false")
        retained = self.read(self.collection + "/retained")
        assert retained["metadata"]["deletionTimestamp"]
        assert self.read("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + self.definition_name)["metadata"]["deletionTimestamp"]
        assert self.read(self.collection + "/one") is None
        self.kubectl("-n", self.namespace, "patch", "widgets", "retained", "--type=merge", "-p", '{"metadata":{"finalizers":[]}}')
        self.kubectl("wait", "--for=delete", "crd/" + self.definition_name, "--timeout=20s")
        assert self.read(self.collection) is None
        self.kubectl("create", "--validate=strict", "-f", str(path))
        assert self.read(self.collection + "/one") is None
        self.kubectl("delete", "crd/" + self.definition_name, "--wait=true", "--timeout=20s")
        self.stop()
        print("durable finalizer cleanup, route withdrawal, clean recreation and native exit 0 passed", flush=True)


def main():
    """Run the isolated smoke and always stop its own process on failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    smoke = CRDSmoke(parser.parse_args().executable)
    try:
        smoke.run()
    finally:
        smoke.stop()
        smoke.log.close()


if __name__ == "__main__":
    main()
