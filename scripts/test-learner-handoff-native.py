#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Kill an established leader during native large-snapshot learner catch-up.
Instrumented internal harness, optionally mTLS; no VM, containers, BPF or production serve.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location("learner_probe", Path(__file__).with_name("test-learner-native.py"))
probe = module_from_spec(spec)
spec.loader.exec_module(probe)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/gr8s-learner-acceptance")
    parser.add_argument("--records", type=int, default=1024)
    parser.add_argument("--chunk-delay", type=float, default=0.02)
    parser.add_argument("--tls", action="store_true", help="require mutual TLS with offline per-member fixtures")
    args = parser.parse_args()
    if args.records < 64 or args.chunk_delay <= 0:
        parser.error("at least 64 records and a positive delay required")
    binary = Path(args.binary).resolve()
    base = Path(tempfile.mkdtemp(prefix="gr8s-learner-handoff-"))
    voters = [probe.Node(binary, base, name, args.records, args.chunk_delay, tls=args.tls)
              for name in ("source", "peer1", "peer2")]
    sink = probe.Node(binary, base, "sink", args.records, 0, tls=args.tls)
    nodes = [*voters, sink]
    result = dict(passed=False, evidence=str(base), nativeHarness=True,
                  productionServe=False, mutualTls=args.tls, vmAcceptance=False,
                  heapLimitMiB=384, records=args.records, payloadBytes=args.records * 65536,
                  binarySha256=hashlib.sha256(binary.read_bytes()).hexdigest())

    def status(node):
        value = node.rpc("status")
        assert value["heapLimitMiB"] == 384, value
        assert value["mutualTls"] == args.tls, value
        return value

    def leader(candidates):
        for node in candidates:
            value = status(node)
            if value["role"] == "leader" and not value["blocked"]:
                return node
        return None

    def all_voters(candidates, expected):
        states = {node.name: status(node) for node in candidates}
        return states if all(value["quorumMembers"] == expected and
                             value["selfRole"] == "voter" and not value["blocked"]
                             for value in states.values()) else None

    try:
        if args.tls:
            setup = subprocess.run([str(binary), "--dynamic-space-size", "384", "--prepare-tls",
                                    str(base), *[node.name for node in nodes]],
                                   capture_output=True, text=True, timeout=120)
            if setup.returncode:
                raise RuntimeError("TLS fixture preparation failed: " + setup.stderr[-2000:])
            assert not any((node.root / "tls/pki/cluster-ca.key").exists() for node in nodes[1:])
            identities = {str(path.relative_to(base)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for node in nodes for path in (node.root / "tls").rglob("*")
                          if path.is_file()}
        voters[0].launch("founder")
        current = probe.await_value(lambda: leader(voters[:1]))
        for peer in voters[1:]:
            peer.launch("learner")
            assert peer.rpc("join", port=current.port)["accepted"]
            established = voters[:voters.index(peer) + 1]
            probe.await_value(lambda: all_voters(established, len(established)), timeout=240)
            current = probe.await_value(lambda: leader(established))
        result["establishedVoters"] = all_voters(voters, 3)
        for node in voters:
            (node.control / "transfer.json").unlink(missing_ok=True)
        sink.launch("learner")
        assert sink.rpc("join", port=current.port)["accepted"]
        progress = probe.await_value(lambda: (lambda p: p if p and
            1048576 <= p["offset"] < p["total"] // 2 else None)(
                probe.read(current.control / "transfer.json")))
        assert progress["total"] >= args.records * 65536, progress
        before = status(current)
        unfinished = status(sink)
        assert before["quorumMembers"] == 3, before
        assert next(m for m in before["members"] if m["id"] == "sink")["role"] == "learner"
        assert unfinished["blocked"] and unfinished["selfRole"] == "learner", unfinished
        partial = [dict(path=str(p.relative_to(sink.root)), bytes=p.stat().st_size)
                   for p in sink.root.rglob("*.snapshot")]
        assert any(0 < p["bytes"] < progress["total"] for p in partial), partial
        result.update(killedLeader=current.name, partialTransfer=progress,
                      receiverAtLeaderLoss=unfinished, partialFilesAtLeaderLoss=partial,
                      membershipAtLeaderLoss=before)
        assert current.stop(kill=True) == -9
        survivors = [node for node in voters if node is not current]
        replacement = probe.await_value(lambda: leader(survivors))
        after_election = status(replacement)
        assert after_election["term"] > before["term"], after_election
        assert after_election["quorumMembers"] == 3, after_election
        assert next(m for m in after_election["members"] if m["id"] == "sink")["role"] == "learner"
        assert replacement.rpc("write", name="after-leader-loss", value="committed")["committed"]
        result.update(replacementLeader=replacement.name, membershipAfterElection=after_election)
        # Admission and promotion intent were replicated before the old leader died.
        # No repeated Join is needed for the replacement to resume catch-up.
        resumed = probe.await_value(lambda: probe.read(replacement.control / "transfer.json"))
        result["replacementTransfer"] = resumed
        probe.await_value(lambda: all_voters([*survivors, sink], 4), timeout=240)
        restored = status(sink)
        assert restored["lastPayloadBytes"] == 65536, restored
        assert restored["resources"] >= args.records + 2, restored
        assert sink.rpc("read", name="after-leader-loss")["value"] == "committed"
        result["promotedLearner"] = restored
        current.launch("recover")
        result["finalMembership"] = probe.await_value(lambda: all_voters(nodes, 4), timeout=240)
        for node in nodes:
            assert node.rpc("read", name="after-leader-loss")["value"] == "committed"
        if args.tls:
            assert all(hashlib.sha256((base / path).read_bytes()).hexdigest() == digest
                       for path, digest in identities.items())
            result["identitiesPreserved"] = identities
        result.update(passed=True, largePayloadAcceptance=args.records >= 1024,
                      noRejoinNeeded=True)
    except Exception as error:
        result["error"] = str(error)
    finally:
        result["shutdown"] = {node.name: node.stop() for node in reversed(nodes)}
        if result["passed"] and any(code != 0 for code in result["shutdown"].values()):
            result.update(passed=False, error="native harness shutdown failed")
        probe.publish(base / "result.json", result)
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
