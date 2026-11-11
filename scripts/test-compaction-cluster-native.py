#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Internal three-process mTLS compaction availability and recovery probe.

Uses offline credentials and instrumented HCP workers, not production serve,
VMs, containers, BPF or conformance. Smoke runs are explicitly partial evidence.
"""
import argparse
import traceback
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


def status_samples_fresh(values, expected_terms=None):
    """Validate fresh partial samples; a busy observation proves no progress."""
    fresh = True
    for name, value in values.items():
        if value.get("busy"):
            assert value["blocked"] and "applied" not in value and "term" not in value, value
            fresh = False
            continue
        assert value["mutualTls"] and value["heapLimitMiB"] == 384, value
        assert not value["churnError"] and not value["compactionError"], value
        if expected_terms is not None:
            assert value["term"] == expected_terms[name], f"Unforced term change on {name}: {value}"
    return fresh


def artifact_samples_reclaimed(values):
    return bool(values) and all(not value.get("busy") and
                               value["artifactReclaimableCount"] == 0 and
                               value["artifactTrashCount"] == 0 and
                               value["artifactCanonicalCount"] <= value["artifactProtectedCount"] and
                               value["maintenanceWorkerUp"] and not value["artifactMaintenanceError"] for value in values.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/gr8s-compaction-cluster-acceptance"))
    parser.add_argument("--rounds", type=int, default=2048)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--require-generation-reclamation", action="store_true",
                        help="Require retired application generations to be reclaimed before cold restart")
    parser.add_argument("--require-artifact-reclamation", action="store_true",
                        help="Require obsolete registry artifacts to be reclaimed before cold restart")
    parser.add_argument("--require-stable-leadership", action="store_true",
                        help="Fail on any unforced term change during churn; restart elections remain allowed")
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
                  fullChurnAcceptance=False, fullChurnRequested=not args.smoke, timeoutSeconds=args.timeout,
                  requireStableLeadership=args.require_stable_leadership,
                  leadershipStabilityAcceptance=False)
    result["asymmetricCaptureAcceptance"] = False
    result["generationReclamationRequested"] = args.require_generation_reclamation
    result["generationReclamationAcceptance"] = False
    result["artifactReclamationRequested"] = args.require_artifact_reclamation
    result["artifactReclamationAcceptance"] = False
    started = time.monotonic()
    print(f"Evidence: {base}", flush=True)

    expected_terms = None

    def fresh_status(node):
        value = node.rpc("status")
        return None if value.get("busy") else value

    def states():
        values = {}
        for node in nodes:
            started_poll = time.monotonic()
            try:
                values[node.name] = node.rpc("status")
            except Exception as error:
                result["failedStatusPoll"] = dict(member=node.name,
                                                  elapsedSeconds=time.monotonic() - started_poll,
                                                  error=f"{type(error).__name__}: {error}",
                                                  partialSamples=values)
                raise
        if not status_samples_fresh(values, expected_terms if args.require_stable_leadership else None):
            result["statusBusyPolls"] = result.get("statusBusyPolls", 0) + 1
            result["lastBusyStatusSample"] = values
            return None
        return values

    def established(candidates):
        values = {node.name: node.rpc("status") for node in candidates}
        return values if all(not value.get("busy") and value["quorumMembers"] == len(candidates) and
                             value["selfRole"] == "voter" and not value["blocked"]
                             for value in values.values()) else None

    def leader(candidates):
        for node in candidates:
            value = node.rpc("status")
            if not value.get("busy") and value["role"] == "leader" and not value["blocked"]:
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
        result["established"] = probe.await_value(states)
        current.rpc("namespace")
        current.rpc("write", name="sentinel", value="preserved")
        # First exercise a genuine archived-prefix gap below the receiver's
        # retention budget. The later saturation phase may correctly prefer an
        # artifact snapshot, so it cannot deterministically cover both paths.
        archive_before = probe.await_value(states)
        archive_peer = next(node for node in nodes if node is not current)
        archive_index = archive_before[archive_peer.name]["applied"]
        archive_terms = {name: value["term"] for name, value in archive_before.items()}
        archive_batches = sum(value["catchupCacheBatches"] for value in archive_before.values())
        result["archivedPrefixStoppedMember"] = archive_peer.name
        result["archivedPrefixStopExitCode"] = archive_peer.stop()
        assert result["archivedPrefixStopExitCode"] == 0
        result["archivedPrefixFixture"] = current.rpc("prefix-churn", rounds=36)
        archive_checkpoint = probe.await_value(
            lambda: (lambda value: value if value and value["snapshot"] > archive_index and
                     value["catchupCacheBytes"] > 0 else None)(fresh_status(current)), timeout=240)
        result["archivedPrefixCheckpoint"] = archive_checkpoint
        archive_commit = archive_checkpoint["commit"]
        archive_peer.launch("recover")
        archive_after = probe.await_value(
            lambda: (lambda values: values if values and all(value["applied"] >= archive_commit and
                     not value["blocked"] and value["checkpoints"] >= 1 for value in values.values()) and
                     sum(value["catchupCacheBatches"] for value in values.values()) > archive_batches
                     else None)(states()), timeout=240)
        result["archivedPrefixRecovered"] = archive_after
        assert {name: value["term"] for name, value in archive_after.items()} == archive_terms
        assert all(value["configMaps"] == archive_after[current.name]["configMaps"]
                   for value in archive_after.values())
        generation = probe.read(archive_peer.root / "metadata/application-generation.json")
        result["archivedPrefixReceiverGenerationIndex"] = generation["index"]
        assert generation["index"] <= archive_index, "Archive fixture recovered through a newer application snapshot"
        result["archivedPrefixReplayAcceptance"] = True
        for node in nodes:
            node.rpc("hold-capture")
        # Even a member compacted exactly through its current applied index
        # needs a new committed suffix to capture. Do this before the producer,
        # which deliberately pauses as soon as the leader's capture is held.
        result["captureArmFixture"] = current.rpc("prefix-churn", rounds=1)
        current.rpc("start-churn")

        def held():
            values = states()
            return values if values and all(value["captureHeld"] for value in values.values()) else None

        before = probe.await_value(held, timeout=240)
        assert all(value["compactionEntryThreshold"] == 100000 for value in before.values()), before
        terms = {name: value["term"] for name, value in before.items()}
        expected_terms = terms

        def check_churn_leadership(values):
            actual = {name: value["term"] for name, value in values.items()}
            stable = actual == terms
            if args.require_stable_leadership and not stable:
                raise AssertionError(f"Unforced leadership term changed during churn: {terms} -> {actual}")
            return stable

        # All three snapshot writers are stopped beyond an election timeout.
        # Neither producers nor background captures can fake the marker commit.
        time.sleep(2)
        current.rpc("write", name="while-held", value="committed-with-all-captures-held")
        target = probe.await_value(lambda: fresh_status(current))["commit"]

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
        start_round = probe.await_value(lambda: fresh_status(current))["completedRounds"]
        for node in nodes:
            if node is not slow:
                node.rpc("release-capture")

        def asymmetric_progress():
            values = states()
            if values is None:
                return None
            result["lastAsymmetricSample"] = values
            check_churn_leadership(values)
            # Advance the leader checkpoint past the stalled follower so release
            # must exercise archived-prefix replication, not only the live tail.
            return values if (values[current.name]["completedRounds"] >= start_round + 32 and
                              values[current.name]["snapshot"] > values[slow.name]["applied"] and
                              values[slow.name]["replicationCapacityRefusals"] > 0) else None

        asymmetric = probe.await_value(asymmetric_progress, timeout=240)
        result.update(asymmetricHeldFollower=slow.name, asymmetricCapture=asymmetric)
        assert asymmetric[slow.name]["captureHeld"], "Delayed follower capture unexpectedly released"
        assert asymmetric[slow.name]["replicationCapacityRefusals"] > 0, "Delayed follower never refused excess retained-log capacity"
        assert asymmetric[slow.name]["retainedEstimatedBytes"] <= asymmetric[slow.name]["retainedBudgetBytes"], "Delayed follower exceeded retained-log budget"
        actual_terms = {name: value["term"] for name, value in asymmetric.items()}
        assert actual_terms == terms, f"Leadership term changed during asymmetric capture: {terms} -> {actual_terms}"
        result.update(asymmetricHeldFollower=slow.name, asymmetricCapture=asymmetric,
                      asymmetricCaptureAcceptance=True)
        slow.rpc("release-capture")

        deadline = time.monotonic() + args.timeout
        samples = 0
        with (base / "samples.jsonl").open("w") as out:
            while True:
                values = states()
                if values is None:
                    if time.monotonic() > deadline:
                        raise TimeoutError("Full churn did not complete with fresh observations")
                    time.sleep(1)
                    continue
                result["lastChurnSample"] = values
                out.write(json.dumps(values) + "\n")
                out.flush()
                samples += 1
                check_churn_leadership(values)
                if values[current.name]["churnFinished"]:
                    result["churnCompleted"] = True
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("Full churn did not complete")
                time.sleep(1)
        final_commit = probe.await_value(lambda: fresh_status(current))["commit"]
        def converged():
            values = states()
            if values is None:
                return None
            result["lastConvergenceSample"] = values
            check_churn_leadership(values)
            return values if all(value["applied"] >= final_commit and not value["blocked"] and
                                 value["checkpoints"] >= (1 if args.smoke else 2)
                                 for value in values.values()) else None

        final = probe.await_value(converged, timeout=240)
        if args.require_generation_reclamation:
            def generations_reclaimed():
                values = states()
                if values is None:
                    return None
                result["lastReclamationSample"] = values
                check_churn_leadership(values)
                return values if (all(value["applicationGenerationCount"] <= 1 and
                                      value["retiredGenerationCount"] == 0 and
                                      value["generationTrashCount"] == 0 and
                                      value["maintenanceWorkerUp"] and not value["maintenanceError"]
                                      for value in values.values()) and
                                  any(value["generationFilesReaped"] > 0 for value in values.values())) else None
            final = probe.await_value(generations_reclaimed, timeout=120)
            result["generationReclamationAcceptance"] = True
        if args.require_artifact_reclamation:
            def artifacts_reclaimed():
                values = states()
                if values is None:
                    return None
                result["lastArtifactReclamationSample"] = values
                check_churn_leadership(values)
                return values if (artifact_samples_reclaimed(values) and
                                  any(value["artifactFilesReaped"] > 0 for value in values.values())) else None
            final = probe.await_value(artifacts_reclaimed, timeout=120)
            result["artifactReclamationAcceptance"] = True
        result.update(beforeRestart=final, samples=samples)
        result["leadershipStabilityAcceptance"] = check_churn_leadership(final)
        expected_maps = final[current.name]["configMaps"]
        assert [row[0] for row in expected_maps] == ["sentinel", "while-held"], expected_maps
        assert all(value["configMaps"] == expected_maps for value in final.values()), final

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
        expected_terms = None  # Cold restart explicitly permits a new election term.
        for node in nodes:
            node.launch("recover")
        probe.await_value(lambda: established(nodes), timeout=240)
        probe.await_value(lambda: leader(nodes), timeout=240)
        if args.require_artifact_reclamation:
            def cold_artifacts_reclaimed():
                values = states()
                if values is None:
                    return None
                result["lastColdArtifactReclamationSample"] = values
                return values if artifact_samples_reclaimed(values) else None
            recovered = probe.await_value(cold_artifacts_reclaimed, timeout=120)
            result["coldArtifactReclamationAcceptance"] = True
        else:
            recovered = probe.await_value(states)
        assert all(value["configMaps"] == expected_maps for value in recovered.values()), recovered

        result["historyPreservedAcrossRestart"] = all(
            value["historyEstimatedBytes"] >= final[name]["historyEstimatedBytes"] - 2 * 65536
            for name, value in recovered.items())
        assert result["historyPreservedAcrossRestart"], "Retained history lost during cold Raft recovery"
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
        result["error"] = f"{type(error).__name__}: {error}"
        result["traceback"] = traceback.format_exc()
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
