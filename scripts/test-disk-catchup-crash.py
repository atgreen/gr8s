#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""SIGKILL a real file-Raft-storage cache owner, then recover its durable WAL."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    root = Path(tempfile.mkdtemp(prefix="gr8s-disk-catchup-crash-"))
    command = ["sbcl", "--noinform", "--non-interactive", "--load",
               "scripts/disk-catchup-crash-harness.lisp", "--end-toplevel-options"]
    result = {"passed": False, "evidence": str(root), "productionServe": False}
    process = None
    try:
        with (root / "hold.log").open("w") as out:
            process = subprocess.Popen(command + ["hold", str(root)], stdout=out, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 120
            while not (root / "ready.json").exists():
                if process.poll() is not None:
                    raise RuntimeError(f"Cache owner exited early: {process.returncode}")
                if time.monotonic() > deadline:
                    raise TimeoutError("Cache owner readiness timed out")
                time.sleep(0.1)
            ready = json.loads((root / "ready.json").read_text())
            assert ready["pid"] == process.pid and ready["bytes"] > 0
            fd_path = Path(f"/proc/{process.pid}/fd/{ready['fd']}")
            assert fd_path.exists() and os.stat(fd_path).st_nlink == 0
            result["anonymousTarget"] = os.readlink(fd_path)
            before = sorted(p.name for p in root.iterdir())
            process.send_signal(signal.SIGKILL)
            assert process.wait(timeout=15) == -signal.SIGKILL
            assert not fd_path.exists()
            assert sorted(p.name for p in root.iterdir()) == before
            result.update(cacheBeforeKill=ready, killedExitCode=process.returncode,
                          descriptorGone=True, noNamedCacheFiles=True)
        with (root / "recover.log").open("w") as out:
            subprocess.run(command + ["recover", str(root)], stdout=out, stderr=subprocess.STDOUT,
                           check=True, timeout=120)
        result.update(recovery=json.loads((root / "recovered.json").read_text()), passed=True)
    except Exception as error:
        result["error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
