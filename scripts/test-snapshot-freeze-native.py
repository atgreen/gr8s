#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Freeze and stream a copied full-history core store at a 384 MiB dynamic heap.

Only checkpoint/journal files are imported, not member identity, credentials or
Raft state. This is standalone application memory evidence, not HA acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/gr8s-snapshot-freeze-acceptance"))
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--history-clock", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args()
    if args.history_clock <= 0 or args.timeout <= 0:
        parser.error("require a positive clock and timeout")
    binary = args.binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="gr8s-snapshot-freeze-native-"))
    state = root / "state"
    state.mkdir(mode=0o700)
    objects = state / "objects"
    objects.mkdir(mode=0o700)
    result = {"passed": False, "evidence": str(root), "binarySha256": digest(binary),
              "historyClock": args.history_clock, "inputs": {}, "timeoutSeconds": args.timeout}
    print(f"Evidence: {root}", flush=True)
    started = time.monotonic()
    try:
        for name, source in (("state.json", args.checkpoint), ("journal.jsonl", args.journal)):
            source = source.resolve(strict=True)
            before = digest(source)
            target = objects / name
            shutil.copyfile(source, target)
            target.chmod(0o600)
            if digest(target) != before or digest(source) != before:
                raise OSError("Input changed during fixture copy")
            result["inputs"][name] = {"source": str(source), "bytes": target.stat().st_size, "sha256": before}
        (root / "launch.json").write_text(json.dumps(result, indent=2) + "\n")
        with (root / "stdout.log").open("w") as out, (root / "stderr.log").open("w") as err:
            child = subprocess.run([str(binary), "--dynamic-space-size", "384", str(state),
                                    str(args.history_clock)], stdout=out, stderr=err, timeout=args.timeout)
        result["exitCode"] = child.returncode
        result["report"] = json.loads((root / "stdout.log").read_text().splitlines()[-1])
        if digest(binary) != result["binarySha256"]:
            raise OSError("Native executable changed during probe")
        if child.returncode != 0 or result["report"].get("passed") is not True:
            raise RuntimeError("Native snapshot freeze probe failed")
        result["passed"] = True
    except Exception as error:
        result["error"] = str(error)
    finally:
        result["elapsedSeconds"] = time.monotonic() - started
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
