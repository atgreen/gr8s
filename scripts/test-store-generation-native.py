#!/usr/bin/env python3
"""Check native generation selection, application writes/reopen and member-root preservation.
Uses loopback HTTP, a fake runtime and no agent; requires no root or containers.
The fixture is a completed generation, not an artifact-restore implementation.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def private_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(value, stream)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", default="build/gr8s")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    evidence = Path(tempfile.mkdtemp(prefix="gr8s-generation-native-"))
    state = evidence / "state"
    generation_id = "01234567-89ab-4cde-8fab-0123456789ab"
    generation = state / "application-generations" / generation_id
    generation.mkdir(mode=0o700, parents=True)
    os.chmod(generation.parent, 0o700)
    descriptor = dict(format="gr8s-store-generation", version=1, generation=generation_id,
                      index=42, term=7, artifactSha256="a" * 64)
    private_json(generation / "generation.meta", descriptor)
    private_json(state / "metadata" / "application-generation.json", descriptor)
    namespace = dict(apiVersion="v1", kind="Namespace", metadata=dict(
        name="default", uid="11111111-1111-4111-8111-111111111111", resourceVersion="1"))
    config = dict(apiVersion="v1", kind="ConfigMap", metadata=dict(
        name="generation-config", namespace="default", uid="22222222-2222-4222-8222-222222222222",
        resourceVersion="1"), data=dict(source="generation"))
    private_json(generation / "objects" / "state.json", dict(
        version=2, revision=1, workloadDeletions={}, jobControllerStates={},
        templateHistory=[], templateHistoryFloor=1, resourceHistoryStart=1,
        templateTokenKey=base64.b64encode(bytes(32)).decode(), eventExpirations={},
        items=[namespace, config], customResourceItems=[]))
    published_uid = "44444444-4444-4444-8444-444444444444"
    private_json(generation / (published_uid + ".json"), dict(
        apiVersion="v1", kind="Pod", metadata=dict(name="published-pod", namespace="default",
                                                   uid=published_uid, resourceVersion="3"),
        spec=dict(nodeName="external-worker", containers=[dict(name="main", image="busybox")])))
    legacy_uid = "33333333-3333-4333-8333-333333333333"
    private_json(state / (legacy_uid + ".json"), dict(
        apiVersion="v1", kind="Pod", metadata=dict(name="legacy-pod", namespace="default",
                                                   uid=legacy_uid, resourceVersion="1"),
        spec=dict(containers=[dict(name="main", image="busybox")])) )
    sentinel = state / "pki" / "generation-test-private.key"
    private_json(sentinel, dict(memberPrivate="preserve"))
    sentinel_digest = hashlib.sha256(sentinel.read_bytes()).hexdigest()
    api_port, node_port = free_port(), free_port()
    command = [str(Path(args.gr8s).resolve()), "serve", "--runtime", "fake", "--disable-agent",
               "--state-directory", str(state), "--listen", "127.0.0.1", "--port", str(api_port),
               "--node-port", str(node_port), "--node-name", "generation-native-check",
               "--kubeconfig", str(evidence / "kubeconfig")]
    process = None
    published_before_restart = None
    result = dict(passed=False, native=True, runtime="fake", evidence=str(evidence))

    def request(path, value=None):
        data = None if value is None else json.dumps(value).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{api_port}" + path, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.load(response)

    try:
        for cycle in range(2):
            with (evidence / f"serve-{cycle}.log").open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 60
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("native server exited before readiness")
                    try:
                        request("/version")
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("native server did not become ready")
                        time.sleep(0.1)
                found = request("/api/v1/namespaces/default/configmaps/generation-config")
                assert found["data"]["source"] == "generation", "selected generation was not loaded"
                try:
                    request("/api/v1/namespaces/default/pods/legacy-pod")
                    raise AssertionError("legacy root Pod leaked into selected generation")
                except urllib.error.HTTPError as error:
                    assert error.code == 404
                published = request("/api/v1/namespaces/default/pods/published-pod")
                if cycle == 0:
                    published_before_restart = published
                    saved = json.loads((generation / "publications" / (published_uid + ".json")).read_text())
                    assert saved["status"] == published["status"], "API status was not checkpointed"
                    assert saved["resourceVersion"] == published["metadata"]["resourceVersion"]
                else:
                    assert published["status"] == published_before_restart["status"], "published status changed on restart"
                    assert published["metadata"]["resourceVersion"] == published_before_restart["metadata"]["resourceVersion"], "publication revision changed on restart"
                if cycle == 0:
                    request("/api/v1/namespaces/default/configmaps", dict(
                        apiVersion="v1", kind="ConfigMap", metadata=dict(name="native-write"),
                        data=dict(persisted="generation")))
                else:
                    found = request("/api/v1/namespaces/default/configmaps/native-write")
                    assert found["data"]["persisted"] == "generation", "write did not survive reopen"
                assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == sentinel_digest
                assert not (generation / "pki").exists(), "member PKI moved into application generation"
                assert not (state / "objects").exists(), "application core writes escaped to member root"
                process.terminate()
                process.wait(timeout=20)
                assert process.returncode == 0, f"shutdown returned {process.returncode}"
        result.update(passed=True, generationLoaded=True, legacyPodExcluded=True,
                      applicationWriteSurvivesRestart=True, podPublicationSurvivesRestart=True,
                      memberPrivateFilePreserved=True,
                      gracefulShutdown=True)
    except Exception as error:
        result["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
    print(json.dumps(result))
    if result["passed"] and not args.keep:
        shutil.rmtree(evidence)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
