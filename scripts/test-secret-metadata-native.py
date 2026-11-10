#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Rotate keys against a copied full-history checkpoint/journal, then cold-reopen.

Requires an unencrypted, quiescent core checkpoint/journal and its frozen history
clock. Only these application files are copied; no member identity or Raft files
are imported. Internal standalone-store memory evidence, not serve/HA/VM evidence.
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
    parser.add_argument("--binary", type=Path, default=Path("build/gr8s-secret-metadata-acceptance"))
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--history-clock", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=900)
    args = parser.parse_args()
    if args.history_clock <= 0 or args.timeout <= 0:
        parser.error("require a positive clock and timeout")
    binary = args.binary.resolve(strict=True)
    binary_digest = digest(binary)
    root = Path(tempfile.mkdtemp(prefix="gr8s-secret-metadata-native-"))
    state = root / "state"
    objects = state / "objects"
    objects.mkdir(mode=0o700, parents=True)
    state.chmod(0o700)
    result = {"passed": False, "evidence": str(root), "binarySha256": binary_digest,
              "historyClock": args.history_clock, "timeoutSeconds": args.timeout, "inputs": {}}
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
        reports = {}
        for mode in ("rotate", "verify"):
            if digest(binary) != binary_digest:
                raise OSError("Native executable changed between phases")
            with (root / f"{mode}-stdout.log").open("w") as out, (root / f"{mode}-stderr.log").open("w") as err:
                process = subprocess.run(
                    [str(binary), "--dynamic-space-size", "384", str(state), str(args.history_clock), mode],
                    stdout=out, stderr=err, check=False,
                    timeout=max(0.001, args.timeout - (time.monotonic() - started)))
            result[f"{mode}ExitCode"] = process.returncode
            report = json.loads((root / f"{mode}-stdout.log").read_text())
            if not isinstance(report, dict):
                raise ValueError("Native report is not an object")
            reports[mode] = report
            result["reports"] = reports
            if not (process.returncode == 0 and report.get("passed") is True
                    and report.get("heapLimitMiB") == 384
                    and report.get("secretBoundaryRecovered") is True
                    and report.get("sentinelRecovered") is True):
                raise ValueError(f"Native {mode} phase failed")
        result["passed"] = (reports["rotate"].get("metadataJournalPreserved") is True
                            and reports["rotate"].get("rotationCompleted") is True)
    except subprocess.TimeoutExpired:
        result["timedOut"] = True
        result["error"] = "Runtime deadline exceeded; acceptance unproven"
    except (OSError, ValueError, UnicodeError) as error:
        result["error"] = str(error)
    result["elapsedSeconds"] = time.monotonic() - started
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
