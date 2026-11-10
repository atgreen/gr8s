#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Native internal admission probe: slow artifact transfer, SIGKILL/rejoin, writes.
No root, containers or BPF. Uses the instrumented native harness, not serve.
VM and leader-handoff acceptance remain separate; this probe never certifies them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def publish(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as out:
        json.dump(value, out)
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def read(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def await_value(check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError("native acceptance condition did not become true")


class Node:
    def __init__(self, binary, base, name, records, delay, tls=False):
        self.binary, self.name, self.records, self.delay = binary, name, records, delay
        self.tls = tls
        self.root = base / name
        self.control = self.root / "harness"
        self.control.mkdir(parents=True, mode=0o700)
        self.root.chmod(0o700)
        self.port = port()
        self.process = None
        self.cycle = 0

    def launch(self, mode):
        for name in ("ready.json", "request.json", "response.json"):
            (self.control / name).unlink(missing_ok=True)
        self.cycle += 1
        self.log = (self.root.parent / f"{self.name}-{self.cycle}.log").open("wb")
        self.process = subprocess.Popen([
            str(self.binary), "--dynamic-space-size", "384", str(self.root), self.name,
            mode, str(self.port), str(self.records), str(self.delay),
            *(["--tls"] if self.tls else [])], stdout=self.log, stderr=subprocess.STDOUT)
        def ready():
            self.live()
            return read(self.control / "ready.json")
        await_value(ready)

    def live(self):
        if self.process.poll() is not None:
            raise RuntimeError(f"{self.name} exited {self.process.returncode}; see {self.log.name}")

    def rpc(self, command, **fields):
        self.live()
        nonce = uuid.uuid4().hex
        publish(self.control / "request.json", dict(nonce=nonce, command=command, **fields))
        def response():
            self.live()
            value = read(self.control / "response.json")
            return value if value and value.get("nonce") == nonce else None
        result = await_value(response, timeout=45)
        if "error" in result:
            raise RuntimeError(f"{self.name} {command}: {result['error']}")
        return result

    def stop(self, kill=False):
        if self.process is None:
            return
        if self.process.poll() is None:
            if kill:
                self.process.kill()
            else:
                try:
                    self.rpc("stop")
                except Exception:
                    self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        result = self.process.returncode
        self.log.close()
        self.process = None
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/gr8s-learner-acceptance")
    parser.add_argument("--records", type=int, default=1024)
    parser.add_argument("--chunk-delay", type=float, default=0.02)
    args = parser.parse_args()
    if args.records < 64 or args.chunk_delay <= 0:
        parser.error("at least 64 records and a positive chunk delay are required")
    binary = Path(args.binary).resolve()
    base = Path(tempfile.mkdtemp(prefix="gr8s-learner-native-"))
    result = dict(passed=False, nativeHarness=True, productionServe=False,
                  vmAcceptance=False, fullAcceptanceComplete=False, evidence=str(base),
                  records=args.records, payloadBytes=args.records * 65536,
                  heapLimitMiB=384, chunkDelay=args.chunk_delay,
                  binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    source = Node(binary, base, "source", args.records, args.chunk_delay)
    sink = Node(binary, base, "sink", args.records, 0)
    try:
        source.launch("founder")
        await_value(lambda: (lambda s: s if s["role"] == "leader" and not s["blocked"] else None)(source.rpc("status")))
        sink.launch("learner")
        assert sink.rpc("join", port=source.port)["accepted"]
        progress = await_value(lambda: (lambda p: p if p and 1048576 <= p["offset"] < p["total"] // 2 else None)(read(source.control / "transfer.json")))
        assert progress["total"] >= args.records * 65536, progress
        result["partialTransfer"] = progress
        before = source.rpc("status")
        assert before["heapLimitMiB"] == 384, before
        assert before["quorumMembers"] == 1, before
        assert next(m for m in before["members"] if m["id"] == "sink")["role"] == "learner"
        assert source.rpc("write", name="during-transfer", value="committed")["committed"]
        interrupted = sink.rpc("status")
        assert interrupted["blocked"], interrupted
        partial_files = [dict(path=str(path.relative_to(sink.root)), bytes=path.stat().st_size)
                         for path in sink.root.rglob("*.snapshot")]
        assert any(0 < item["bytes"] < progress["total"] for item in partial_files), partial_files
        result.update(beforeInterruption=before, interruptedReceiver=interrupted, partialFilesBeforeSigkill=partial_files)
        killed = sink.stop(kill=True)
        assert killed == -9, killed
        assert source.rpc("write", name="while-disconnected", value="committed")["committed"]
        disconnected = source.rpc("status")
        assert disconnected["quorumMembers"] == 1, disconnected
        result.update(disconnected=disconnected, sigkillExit=killed)
        sink.launch("recover")
        assert sink.rpc("join", port=source.port)["accepted"]
        def promotion():
            sink.live()
            status = source.rpc("status")
            return status if status["quorumMembers"] == 2 else None
        promoted = await_value(promotion, timeout=180)
        restored = await_value(lambda: (lambda s: s if s["selfRole"] == "voter" and not s["blocked"] else None)(sink.rpc("status")))
        assert restored["lastPayloadBytes"] == 65536
        assert restored["heapLimitMiB"] == 384, restored
        assert restored["resources"] >= args.records + 3, restored
        for name in ("during-transfer", "while-disconnected"):
            assert sink.rpc("read", name=name)["value"] == "committed"
        last = promoted["lastIndex"]
        assert sink.rpc("join", port=source.port)["accepted"]
        repeated = source.rpc("status")
        assert repeated["lastIndex"] == last, (last, repeated)
        assert sink.rpc("status")["selfRole"] == "voter"
        result.update(passed=True, partialTransfer=progress, interruptedReceiver=interrupted,
                      partialFilesBeforeSigkill=partial_files, beforeInterruption=before,
                      disconnected=disconnected, promoted=promoted, restored=restored,
                      repeatedJoin=repeated, sigkillExit=killed,
                      largePayloadAcceptance=args.records >= 1024,
                      remaining=["VM execution", "leader handoff during catch-up", "production serve recovery integration"])
    except Exception as error:
        result["error"] = str(error)
    finally:
        result["sinkExit"] = sink.stop()
        result["sourceExit"] = source.stop()
        if result["passed"] and (result["sinkExit"] != 0 or result["sourceExit"] != 0):
            result.update(passed=False, error="native harness failed during shutdown")
        publish(base / "result.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
