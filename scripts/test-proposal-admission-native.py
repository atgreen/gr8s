#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise bounded pending writes, forwarded overload, quorum return and durable reopen.

Four real loopback members share one 384 MiB process. No root, containers, BPF,
TLS or production serve. Production proposal timeouts remain unchanged.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/gr8s-proposal-admission-acceptance"))
    parser.add_argument("--rounds", type=int, default=2048)
    parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args()
    if args.rounds < 2048 or args.timeout <= 0:
        parser.error("require at least 2048 rounds and a positive timeout")
    binary = args.binary.resolve(strict=True)
    with binary.open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    root = Path(tempfile.mkdtemp(prefix="gr8s-proposal-admission-native-"))
    state = root / "state"
    state.mkdir(mode=0o700)
    result = {"passed": False, "evidence": str(root), "binarySha256": digest,
              "requestedRounds": args.rounds, "timeoutSeconds": args.timeout,
              "startedUtc": datetime.now(timezone.utc).isoformat()}
    (root / "launch.json").write_text(json.dumps(result, indent=2) + "\n")
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
                                and report.get("largeSecretBoundary") is True
                                and report.get("capacityRefusals", 0) > 1000
                                and report.get("timedOutProposals", 0) > 0
                                and report.get("forwardedCapacityRefusal") is True
                                and report.get("sentinelRecovered") is True
                                and report.get("newWritesAfterRecovery") is True
                                and report.get("durableReopen") is True)
        except (ValueError, UnicodeError) as error:
            result["error"] = f"Invalid or absent native report: {error}"
    except subprocess.TimeoutExpired:
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
