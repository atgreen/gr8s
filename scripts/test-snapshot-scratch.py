#!/usr/bin/env python3
"""Verify native HA startup reaps abandoned transfer scratch and preserves a live owner.
Uses a fake runtime with the agent disabled; requires no root or containers.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_ports(count):
    ports = set()
    while len(ports) < count:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            ports.add(listener.getsockname()[1])
    return list(ports)


def scratch(namespace, live):
    root = namespace / (".raft-transfer-v2-" + secrets.token_hex(3))
    root.mkdir(mode=0o700)
    owner = os.open(root / ".owner", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with os.fdopen(os.open(root / "in-fixture.snapshot", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(b"x" * (1024 * 1024))
    if not live:
        os.close(owner)
        owner = None
    return root, owner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", default="build/gr8s")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    binary = Path(args.gr8s).resolve()
    evidence = Path(tempfile.mkdtemp(prefix="gr8s-native-scratch-"))
    state = evidence / "state"
    namespace = state / "raft" / "transfers" / (".gr8s-raft-transfers-v2-" + str(os.geteuid()))
    namespace.mkdir(mode=0o700, parents=True)
    dead_root, _ = scratch(namespace, False)
    live_root, owner = scratch(namespace, True)
    live_payload = live_root / "in-fixture.snapshot"
    digest = hashlib.sha256(live_payload.read_bytes()).hexdigest()
    api_port, node_port, raft_port = free_ports(3)
    process = None
    result = {"passed": False, "native": True, "runtime": "fake", "evidence": str(evidence)}
    try:
        with (evidence / "serve.log").open("wb") as log:
            process = subprocess.Popen([
                str(binary), "serve", "--runtime", "fake", "--disable-agent",
                "--state-directory", str(state), "--listen", "127.0.0.1", "--port", str(api_port),
                "--node-port", str(node_port), "--raft-init", "--raft-id", "scratch-check",
                "--node-name", "scratch-check", "--raft-port", str(raft_port),
                "--kubeconfig", str(evidence / "kubeconfig"),
            ], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 60
            ready = False
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("native control plane exited before readiness")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{api_port}/version", timeout=0.5) as response:
                        ready = response.status == 200
                except (OSError, urllib.error.URLError):
                    pass
                if ready:
                    break
                time.sleep(0.1)
            if not ready:
                raise RuntimeError("native control plane did not become ready")
            if dead_root.exists():
                raise AssertionError("abandoned snapshot root was not reaped at startup")
            if not live_root.exists() or hashlib.sha256(live_payload.read_bytes()).hexdigest() != digest:
                raise AssertionError("startup touched a live owner's snapshot")
            process.terminate()
            process.wait(timeout=20)
            if process.returncode != 0:
                raise AssertionError(f"native control plane shutdown returned {process.returncode}")
            result.update(passed=True, reclaimedPayloadBytes=1024 * 1024,
                          liveOwnerPreserved=True, gracefulShutdown=True)
    except Exception as error:
        result["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        os.close(owner)
    print(json.dumps(result))
    if result["passed"] and not args.keep:
        shutil.rmtree(evidence)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
