#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Repeatedly kill real publishers; verify exclusive startup reclaims their scratch."""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def main():
    base = Path(tempfile.mkdtemp(prefix="gr8s-snapshot-startup-scratch-"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = ["sbcl", "--noinform", "--non-interactive", "--load",
               "scripts/snapshot-startup-scratch-harness.lisp", "--end-toplevel-options"]
    result = dict(passed=False, evidence=str(base), productionServe=False, vmAcceptance=False, cycles=[])
    process = None
    try:
        for iteration in range(1, 4):
            control = base / f"attempt-{iteration}"
            control.mkdir()
            arguments = [str(base), str(port), str(iteration)]
            cycle = dict(iteration=iteration, passed=False)
            result["cycles"].append(cycle)
            with (control / "hold.log").open("w") as out:
                process = subprocess.Popen(command + ["hold"] + arguments, stdout=out, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 120
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"Publisher exited before readiness: {process.returncode}")
                    try:
                        ready = json.loads((control / "ready.json").read_text())
                        break
                    except (FileNotFoundError, json.JSONDecodeError):
                        if time.monotonic() > deadline:
                            raise TimeoutError("Paused publishers did not become ready")
                        time.sleep(0.1)
                assert ready["pid"] == process.pid
                orphans = [Path(path) for path in ready["orphans"]]
                assert len(orphans) == 3 and all(path.is_file() for path in orphans)
                stats = [(os.lstat(path).st_ino, os.lstat(path).st_size) for path in orphans]
                artifacts = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in ready["artifacts"]}
                assert artifacts
                with (control / "blocked-owner.log").open("w") as blocked_out:
                    blocked = subprocess.run(command + ["recover"] + arguments, stdout=blocked_out,
                                             stderr=subprocess.STDOUT, timeout=120)
                assert blocked.returncode != 0
                assert "Another serve process owns state directory" in (control / "blocked-owner.log").read_text()
                assert process.poll() is None
                assert [(os.lstat(path).st_ino, os.lstat(path).st_size) for path in orphans] == stats
                cycle["liveOwnerProtected"] = True
                process.send_signal(signal.SIGKILL)
                assert process.wait(timeout=15) == -signal.SIGKILL
                cycle["killedExitCode"] = process.returncode
            with (control / "recover.log").open("w") as out:
                subprocess.run(command + ["recover"] + arguments, stdout=out,
                               stderr=subprocess.STDOUT, check=True, timeout=120)
            assert all(not path.exists() for path in orphans)
            assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in artifacts.items())
            cycle.update(recovery=json.loads((control / "recovered.json").read_text()),
                         publishedArtifactsPreserved=True, orphanPaths=[str(path) for path in orphans], passed=True)
        result["passed"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        (base / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
