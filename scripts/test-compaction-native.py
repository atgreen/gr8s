#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Run the internal 384 MiB retention/recovery probe and preserve failure evidence.

No root, containers or BPF. This does not certify production serve, multiple
members, VM execution, or consensus availability during capture.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/gr8s-compaction-acceptance"))
    parser.add_argument("--rounds", type=int, default=2048)
    parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args()
    if args.rounds < 2048 or args.timeout <= 0:
        parser.error("require at least 2048 rounds and a positive timeout")
    binary = args.binary.resolve(strict=True)
    # Record before launching: another build may atomically replace the pathname.
    with binary.open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    root = Path(tempfile.mkdtemp(prefix="gr8s-compaction-native-"))
    state = root / "state"
    state.mkdir(mode=0o700)
    result = {"passed": False, "evidence": str(root), "binarySha256": digest,
              "requestedRounds": args.rounds, "timeoutSeconds": args.timeout}
    print(f"Evidence: {root}", flush=True)
    started = time.monotonic()
    try:
        with (root / "stdout.log").open("w") as out, (root / "stderr.log").open("w") as err:
            process = subprocess.run(
                [str(binary), "--dynamic-space-size", "384", str(state), str(args.rounds)],
                stdout=out, stderr=err, timeout=args.timeout, check=False)
        result["exitCode"] = process.returncode
        try:
            report = json.loads((root / "stdout.log").read_text())
            if not isinstance(report, dict):
                raise ValueError("native report is not an object")
            result["nativeReport"] = report
            result["passed"] = (process.returncode == 0 and report.get("passed") is True
                                and report.get("heapLimitMiB") == 384
                                and report.get("historyClockFrozen") is True
                                and report.get("sentinelRecovered") is True
                                and report.get("inPlaceMemberRecovery") is True)
        except (ValueError, UnicodeError) as error:
            result["error"] = f"Invalid or absent native report: {error}"
        if result["passed"]:
            result["passed"] = False
            remaining = args.timeout - (time.monotonic() - started)
            with binary.open("rb") as executable:
                if hashlib.file_digest(executable, "sha256").hexdigest() != digest:
                    raise OSError("Native executable changed before cold recovery")
            with (root / "cold-stdout.log").open("w") as out, (root / "cold-stderr.log").open("w") as err:
                cold = subprocess.run(
                    [str(binary), "--dynamic-space-size", "384", str(root / "cold-state"), "--recover-only",
                     str(report["memberPort"]), str(report["historyClock"])],
                    stdout=out, stderr=err, timeout=max(0.001, remaining), check=False)
            result["coldExitCode"] = cold.returncode
            try:
                cold_report = json.loads((root / "cold-stdout.log").read_text())
                if not isinstance(cold_report, dict):
                    raise ValueError("cold recovery report is not an object")
                result["coldRecoveryReport"] = cold_report
                result["passed"] = (cold.returncode == 0 and cold_report.get("passed") is True
                                    and cold_report.get("coldRecovery") is True
                                    and cold_report.get("sentinelRecovered") is True
                                    and cold_report.get("heapLimitMiB") == 384)
            except (ValueError, UnicodeError) as error:
                result["error"] = f"Invalid or absent cold recovery report: {error}"
    except subprocess.TimeoutExpired:
        # subprocess.run kills and joins the child. Timeout is inconclusive for
        # heap correctness; retain its progress/diagnostics rather than restarting.
        result["timedOut"] = True
        result["error"] = "Native probe exceeded its runtime deadline; acceptance unproven"
    except OSError as error:
        result["error"] = str(error)
    result["elapsedSeconds"] = time.monotonic() - started
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
