#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Internal three-process mTLS compaction availability and recovery probe.

Uses offline credentials and instrumented HCP workers, not production serve,
VMs, containers, BPF or conformance. Smoke runs are explicitly partial evidence.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("learner_probe", Path(__file__).with_name("test-learner-native.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/gr8s-compaction-cluster-acceptance"))
    parser.add_argument("--rounds", type=int, default=2048)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--timeout", type=float, default=2400)
    args = parser.parse_args()
    if args.rounds < 128 or (args.rounds < 2048 and not args.smoke) or args.timeout <= 0:
        parser.error("require at least 2048 rounds, or --smoke with at least 128, and a positive timeout")
    binary = args.binary.resolve(strict=True)
    base = Path(tempfile.mkdtemp(prefix="gr8s-compaction-cluster-native-"))
    nodes = [probe.Node(binary, base, name, args.rounds, 0, tls=True) for name in ("cp-a", "cp-b", "cp-c")]
    result = dict(passed=False, evidence=str(base), binarySha256=digest(binary),
                  nativeHarness=True, productionServe=False, vmAcceptance=False,
                  mutualTls=True, processes=3, heapLimitMiB=384,
                  rounds=args.rounds, payloadBytes=args.rounds * 65536,
                  historyByteBudget=96 * 1024 * 1024, historyClock=4000000000,
                  fullChurnAcceptance=False, fullChurnRequested=not args.smoke, timeoutSeconds=args.timeout)
    result["asymmetricCaptureAcceptance"] = False
    started = time.monotonic()
    print(f"Evidence: {base}", flush=True)

    def states():
        values = {node.name: node.rpc("status") for node in nodes}
        for value in values.values():
            assert value["mutualTls"] and value["heapLimitMiB"] == 384, value
            assert not value["churnError"] and not value["compactionError"], value
        return values

    def established(candidates):
        values = {node.name: node.rpc("status") for node in candidates}
        return values if all(value["quorumMembers"] == len(candidates) and
                             value["selfRole"] == "voter" and not value["blocked"]
                             for value in values.values()) else None

    def leader(candidates):
        for node in candidates:
            value = node.rpc("status")
            if value["role"] == "leader" and not value["blocked"]:
                return node
        return None

    def identities():
        return {str(path.relative_to(base)): digest(path)
                for node in nodes for path in (node.root / "tls").rglob("*")
                if path.is_file() and path.suffix in (".key", ".crt")}

    try:
        (base / "launch.json").write_text(json.dumps(result, indent=2) + "\n")
        setup = subprocess.run([str(binary), "--dynamic-space-size", "384", "--prepare-tls", str(base),
                                *[node.name for node in nodes]], capture_output=True, text=True, timeout=120)
        (base / "tls-setup.log").write_text(setup.stdout + setup.stderr)
        if setup.returncode:
            raise RuntimeError("TLS setup failed")
        assert not any((node.root / "tls/pki/cluster-ca.key").exists() for node in nodes[1:])
        original_identities = identities()
        nodes[0].launch("founder")
        current = probe.await_value(lambda: leader(nodes[:1]))
        for index, node in enumerate(nodes[1:], 1):
            node.launch("learner")
            assert node.rpc("join", port=current.port)["accepted"]
            probe.await_value(lambda: established(nodes[:index + 1]), timeout=240)
            current = probe.await_value(lambda: leader(nodes[:index + 1]))
        result["established"] = states()
        current.rpc("namespace")
        current.rpc("write", name="sentinel", value="preserved")
        for node in nodes:
            node.rpc("hold-capture")
        current.rpc("start-churn")

        def held():
            values = states()
            return values if all(value["captureHeld"] for value in values.values()) else None

        before = probe.await_value(held, timeout=240)
        terms = {name: value["term"] for name, value in before.items()}
        # All three snapshot writers are stopped beyond an election timeout.
        # Neither producers nor background captures can fake the marker commit.
        time.sleep(2)
        current.rpc("write", name="while-held", value="committed-with-all-captures-held")
        target = current.rpc("status")["commit"]

        def marker_applied():
            values = held()
            return values if values and all(value["applied"] >= target for value in values.values()) else None

        during = probe.await_value(marker_applied)
        assert {name: value["term"] for name, value in during.items()} == terms
        assert during[current.name]["role"] == "leader"
        assert all(value["heldIndex"] < target and not value["blocked"] for value in during.values())
        result.update(heldBefore=before, heldAfterMarker=during, heldMarkerCommit=target)
        # Keep one follower's writer held while leader + other voter continue.
        # Its own compactor cannot rescue it; replication must respect the limit.
        slow = next(node for node in nodes if node is not current)
        start_round = current.rpc("status")["completedRounds"]
        for node in nodes:
            if node is not slow:
                node.rpc("release-capture")

        def asymmetric_progress():
            values = states()
            # Advance the leader checkpoint past the stalled follower so release
            # must exercise archived-prefix replication, not only the live tail.
            return values if (values[current.name]["completedRounds"] >= start_round + 32 and
                              values[current.name]["snapshot"] > values[slow.name]["applied"]) else None

        asymmetric = probe.await_value(asymmetric_progress, timeout=240)
        assert asymmetric[slow.name]["captureHeld"]
        assert asymmetric[slow.name]["replicationCapacityRefusals"] > 0
        assert asymmetric[slow.name]["retainedEstimatedBytes"] <= asymmetric[slow.name]["retainedBudgetBytes"]
        assert {name: value["term"] for name, value in asymmetric.items()} == terms
        result.update(asymmetricHeldFollower=slow.name, asymmetricCapture=asymmetric,
                      asymmetricCaptureAcceptance=True)
        slow.rpc("release-capture")

        deadline = time.monotonic() + args.timeout
        samples = 0
        with (base / "samples.jsonl").open("w") as out:
            while True:
                values = states()
                result["lastChurnSample"] = values
                out.write(json.dumps(values) + "\n")
                out.flush()
                samples += 1
                if values[current.name]["churnFinished"]:
                    result["churnCompleted"] = True
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("Full churn did not complete")
                time.sleep(1)
        final_commit = current.rpc("status")["commit"]
        final = probe.await_value(lambda: (lambda values: values if all(
            value["applied"] >= final_commit and not value["blocked"] and
            value["checkpoints"] >= (1 if args.smoke else 2)
            for value in values.values()) else None)(states()), timeout=240)
        result.update(beforeRestart=final, samples=samples)
        result["diskCatchupAcceptance"] = any(value["catchupCacheBatches"] > 0 for value in final.values())
        assert result["diskCatchupAcceptance"], "No archived-prefix batch was read for replication"
        result["catchupHistoryContinuous"] = (final[slow.name]["historyEstimatedBytes"] >=
                                              final[current.name]["historyEstimatedBytes"] - 2 * 65536)
        assert result["catchupHistoryContinuous"], "Delayed follower reset history instead of replaying the missing prefix"
        assert all(value["catchupCacheBytes"] <= 128 * 1024 * 1024 and
                   value["catchupCacheSegments"] <= 128 for value in final.values()), final
        if not args.smoke:
            histories = {name: value["historyEstimatedBytes"] for name, value in final.items()}
            assert all(value >= 96 * 1024 * 1024 - 2 * 65536 for value in histories.values()), \
                f"Full retained history missing before restart: {histories}"
        for node in nodes:
            assert node.rpc("read", name="while-held")["value"] == "committed-with-all-captures-held"
            assert node.rpc("read", name="sentinel")["value"] == "preserved"
        result["stopExitCodes"] = {node.name: node.stop() for node in nodes}
        assert all(code == 0 for code in result["stopExitCodes"].values())
        if digest(binary) != result["binarySha256"]:
            raise RuntimeError("Binary changed before cold restart")
        for node in nodes:
            node.launch("recover")
        probe.await_value(lambda: established(nodes), timeout=240)
        probe.await_value(lambda: leader(nodes), timeout=240)
        recovered = states()
        if not args.smoke:
            histories = {name: value["loadedHistoryEstimatedBytes"] for name, value in recovered.items()}
            assert all(value >= 96 * 1024 * 1024 - 2 * 65536 for value in histories.values()), \
                f"Full retained history missing on cold load: {histories}"
        for node in nodes:
            assert node.rpc("read", name="while-held")["value"] == "committed-with-all-captures-held"
            assert node.rpc("read", name="sentinel")["value"] == "preserved"
        assert identities() == original_identities
        result.update(afterRestart=recovered, identitiesPreserved=True,
                      fullChurnAcceptance=not args.smoke, passed=True)
    except Exception as error:
        result["error"] = str(error)
    finally:
        result["cleanupExitCodes"] = {}
        for node in nodes:
            try:
                result["cleanupExitCodes"][node.name] = node.stop()
            except Exception as error:
                result["cleanupExitCodes"][node.name] = str(error)
        if any(code not in (None, 0) for code in result["cleanupExitCodes"].values()):
            result["passed"] = False
        result["elapsedSeconds"] = time.monotonic() - started
        (base / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
