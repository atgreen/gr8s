#!/usr/bin/env python3
"""Unprivileged native production serve acceptance, with agents disabled.

Runs the real CLI and mTLS Raft endpoints. No containers, BPF, host networking
changes, debug server or modified entrypoint. WAL inspection is read-only and
requires SBCL on the development host. This is not VM/conformance acceptance.
"""
import argparse
import hashlib
import json
import signal
import socket
import ssl
import traceback
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PORTS = set()


def port():
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            value = sock.getsockname()[1]
        if value not in PORTS:
            PORTS.add(value)
            return value


def wait_for(check, timeout=120):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            last = error
        time.sleep(0.15)
    raise TimeoutError(f"native HA condition did not become true: {last}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


class Node:
    def __init__(self, binary, base, name, heap, compaction=False, default_compaction=False):
        self.binary, self.name, self.heap = binary, name, heap
        self.compaction, self.http = compaction, None
        self.default_compaction = default_compaction
        self.root = base / name
        self.root.mkdir(mode=0o700)
        self.api, self.grpc, self.raft = port(), port(), port()
        self.process, self.log, self.cycle = None, None, 0

    @property
    def wal(self):
        return self.root / "raft/control-plane.log"

    def start(self, seed=1, enrollment=None):
        self.cycle += 1
        self.log_path = self.root.parent / f"{self.name}-{self.cycle}.log"
        self.log = self.log_path.open("wb")
        args = [str(self.binary), "--dynamic-space-size", str(self.heap), "serve",
                "--disable-agent", "--runtime", "fake", "--state-directory", str(self.root),
                "--listen", "127.0.0.1", "--port", str(self.api),
                "--node-listen", "127.0.0.1", "--node-port", str(self.grpc),
                "--node-name", self.name, "--raft-id", self.name,
                "--raft-listen", "127.0.0.1", "--raft-port", str(self.raft)]
        if self.name == "cp1":
            args += ["--raft-init"]
        else:
            args += ["--raft-join", f"127.0.0.1:{seed}"]
        if enrollment:
            args += ["--raft-node-name", self.name, "--raft-token", enrollment["token"],
                     "--raft-ca-pin", enrollment["caPin"]]
        if self.compaction and not self.default_compaction:
            args += ["--raft-compaction"]
        self.http = None
        self.process = subprocess.Popen(args, cwd=REPO, stdout=self.log, stderr=subprocess.STDOUT)

    def live(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError(f"{self.name} exited; see {self.log_path}")

    def request(self, path, body=None, method=None):
        self.live()
        data = None if body is None else json.dumps(body).encode()
        if self.http is None:
            context = ssl.create_default_context(cafile=str(self.root / "pki/pki/cluster-ca.crt"))
            context.load_cert_chain(str(self.root / "pki/admin.crt"), str(self.root / "pki/admin.key"))
            self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                   urllib.request.HTTPSHandler(context=context))
        req = urllib.request.Request(f"https://127.0.0.1:{self.api}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            response = self.http.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, json.loads(raw) if raw.startswith(b"{") else raw.decode()

    def ready(self):
        return self.request("/readyz")[0] == 200

    def metrics(self):
        status, body = self.request("/metrics")
        assert status == 200 and isinstance(body, str), f"{self.name} metrics unavailable: {status}"
        return {parts[0]: float(parts[1]) for line in body.splitlines()
                if line and not line.startswith("#") and "{" not in line
                and len(parts := line.split()) == 2}

    def stop(self, kill=False):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL if kill else signal.SIGTERM)
            self.process.wait(timeout=40)
        if self.log:
            self.log.close()
        return self.process.returncode if self.process else None

    def identities(self):
        return {str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob("*") if p.is_file() and p.suffix in (".key", ".crt")}


class Witness(Node):
    @property
    def wal(self):
        return self.root / "raft/witness.log"

    def start(self, seed=1, enrollment=None):
        self.cycle += 1
        self.log_path = self.root.parent / f"{self.name}-{self.cycle}.log"
        self.log = self.log_path.open("wb")
        args = [str(self.binary), "--dynamic-space-size", str(self.heap), "witness",
                "--state-directory", str(self.root), "--member-id", self.name,
                "--node-name", self.name, "--listen", "127.0.0.1", "--port", str(self.raft),
                "--join", f"127.0.0.1:{seed}"]
        if enrollment:
            args += ["--token", enrollment["token"], "--ca-pin", enrollment["caPin"]]
        self.process = subprocess.Popen(args, cwd=REPO, stdout=self.log, stderr=subprocess.STDOUT)


def membership_with_witness(nodes, witness):
    all_nodes = [*nodes, witness]
    for node in all_nodes:
        node.live()
    states = inspect(all_nodes)
    expected = {n.name: "voter" for n in nodes} | {witness.name: "witness"}
    return states if all({m["id"]: m["role"] for m in state["members"]} == expected for state in states) else None


def inspect(nodes):
    result = subprocess.run(["sbcl", "--noinform", "--non-interactive", "--load",
                             str(REPO / "scripts/ha-native-inspect.lisp"), "--",
                             *[str(n.wal) for n in nodes]], cwd=REPO, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise ValueError("WAL read raced an append, or inspection failed: " + result.stderr[-500:])
    return json.loads(result.stdout)


def voters_ready(nodes):
    for node in nodes:
        node.live()
    states = inspect(nodes)
    expected = {n.name for n in nodes}
    return states if all({m["id"] for m in s["members"] if m["role"] == "voter"} == expected
                         and len(s["members"]) == len(expected) for s in states) else None


def current_leader(nodes):
    samples = [(node, node.metrics()) for node in nodes]
    leaders = [node for node, values in samples if values.get("gr8s_raft_is_leader") == 1]
    terms = {values.get("gr8s_raft_term") for _, values in samples}
    return leaders[0] if len(leaders) == 1 and len(terms) == 1 and None not in terms else None


def post(nodes, path, body):
    for node in nodes:
        status, _ = node.request(path, body)
        if status == 201:
            return node
        if status == 409:
            # A rejected committed precondition can leave the object absent.
            # Confirm an existing matching object before treating a retry as done.
            status, actual = node.request(f"{path}/{body['metadata']['name']}")
            if (status == 200 and actual.get("kind") == body.get("kind")
                    and actual.get("metadata", {}).get("name") == body["metadata"]["name"]
                    and actual.get("data") == body.get("data")):
                return node
            continue
        if status not in (307, 503):
            raise ValueError(f"{node.name} unexpected write status {status}")
    return None


def configmap(name, value):
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
            "data": {"value": value}}


def value_on_all(nodes, name, value):
    for node in nodes:
        status, body = node.request(f"/api/v1/namespaces/ha-native/configmaps/{name}")
        if status != 200 or body.get("data", {}).get("value") != value:
            return False
    return True


def matching_configmaps(nodes, path, expected=None):
    """Require identical names, UIDs and contents, including across cold recovery."""
    inventories = []
    for node in nodes:
        status, body = node.request(path)
        if status != 200:
            return None
        rows = sorted(((item["metadata"]["name"], item["metadata"]["uid"], item.get("data", {}))
                       for item in body["items"]), key=lambda row: row[0])
        if not rows or any(not uid for _, uid, _ in rows):
            return None
        inventories.append(rows)
    reference = inventories[0] if expected is None else expected
    return reference if all(rows == reference for rows in inventories) else None


def compaction_churn(nodes, result, rounds):
    """Exercise the real authenticated API, with one voter offline past checkpoints."""
    path = "/api/v1/namespaces/ha-native/configmaps"
    baseline = inspect(nodes)
    leader = wait_for(lambda: post(nodes, path, configmap("compaction-sentinel", "preserved")))
    leader = wait_for(lambda: current_leader(nodes))
    delayed = next(node for node in nodes if node is not leader)
    assert delayed.stop(kill=True) == -signal.SIGKILL
    offline = inspect([delayed])[0]
    result["compactionOfflineState"] = offline
    active = [node for node in nodes if node is not delayed]
    result["compactionDelayedVoter"] = delayed.name
    result["compactionBeforeDisconnect"] = baseline
    result["compactionCompletedRounds"] = 0
    with (nodes[0].root.parent / "compaction-progress.jsonl").open("w") as progress:
        for index in range(rounds):
            name = f"compaction-{index:05d}"
            value = "x" * 65536
            item = f"{path}/{name}"

            def created():
                for node in active:
                    status, _ = node.request(path, configmap(name, value))
                    if status in (307, 503):
                        continue
                    assert status in (201, 409), (name, status)
                    status, body = node.request(item)
                    if status in (404, 503, 307):
                        continue  # retry the create, not an indefinitely missing read
                    assert status == 200, (name, status)
                    assert body.get("data", {}).get("value") == value, f"Unexpected contents: {name}"
                    uid = body.get("metadata", {}).get("uid")
                    assert uid, f"Missing UID: {name}"
                    return node, uid
                return None

            actor, uid = wait_for(created)
            attempted = set()

            def deleted():
                for node in [actor, *[n for n in active if n is not actor]]:
                    status, body = node.request(item)
                    if status == 404:
                        if node.name in attempted:
                            return True
                        continue  # an unconfirmed follower may still lack the create
                    if status in (307, 503):
                        continue
                    assert status == 200, (name, status)
                    assert body.get("metadata", {}).get("uid") == uid, f"Object identity changed: {name}"
                    assert body.get("data", {}).get("value") == value, f"Object contents changed: {name}"
                    attempted.add(node.name)
                    status, _ = node.request(item, {"apiVersion": "v1", "kind": "DeleteOptions",
                                                   "preconditions": {"uid": uid}}, method="DELETE")
                    assert status in (200, 202, 307, 404, 409, 503), (name, status)
                    if status != 307:
                        status, body = node.request(item)
                        if status == 404:
                            return True
                return False

            wait_for(deleted)
            result["compactionCompletedRounds"] = index + 1
            if index % 32 == 0 or index + 1 == rounds:
                sample = {"completedRounds": index + 1,
                          "walBytes": {node.name: node.wal.stat().st_size for node in active}}
                result["compactionLastSample"] = sample
                progress.write(json.dumps(sample) + "\n")
                progress.flush()
    offline_commit = offline["commit"]
    def advanced():
        states = inspect(active)
        return states if all(state["snapshotIndex"] > offline_commit for state in states) else None
    result["compactionWhileDisconnected"] = wait_for(advanced, timeout=240)
    delayed.start()
    wait_for(delayed.ready, timeout=240)
    wait_for(lambda: value_on_all(nodes, "compaction-sentinel", "preserved"), timeout=240)
    assert wait_for(lambda: post(nodes, path, configmap("compaction-after-catchup", "preserved")))
    wait_for(lambda: value_on_all(nodes, "compaction-after-catchup", "preserved"))
    result["compactionAfterCatchup"] = inspect(nodes)
    result["compactionMetrics"] = {
        node.name: {name: value for name, value in node.metrics().items()
                    if name.startswith(("gr8s_raft_", "gr8s_compaction_"))} for node in nodes}
    assert all(result["compactionMetrics"][node.name]["gr8s_compaction_completed_total"] >= 1 for node in active)
    assert all(values["gr8s_compaction_error"] == 0 for values in result["compactionMetrics"].values())
    fingerprints = []
    for node in nodes:
        status, body = node.request(path)
        assert status == 200
        rows = sorted((item["metadata"]["name"], item["metadata"]["uid"], item.get("data", {}))
                      for item in body["items"])
        assert not any(name.startswith("compaction-") and name not in
                       ("compaction-sentinel", "compaction-after-catchup") for name, _, _ in rows), "Leaked churn object"
        fingerprints.append(rows)
        assert node.wal.stat().st_size <= 32 * 1024 * 1024, "WAL exceeded checkpoint acceptance bound"
    assert all(rows == fingerprints[0] for rows in fingerprints), "ConfigMaps diverged after catch-up"
    result.update(compactionAcceptance=True, compactionPayloadBytes=rounds * 65536,
                  compactionUsesNaturalHistoryClock=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=REPO / "build/gr8s")
    parser.add_argument("--heap-mib", type=int, default=384)
    parser.add_argument("--compaction", action="store_true", help="Enable production checkpoints and disconnected-voter churn")
    parser.add_argument("--default-compaction", action="store_true",
                        help="Run checkpoint churn without passing an enable flag to serve")
    parser.add_argument("--compaction-rounds", type=int, default=2048)
    parser.add_argument("--smoke", action="store_true", help="Allow 128-round partial compaction integration evidence")
    parser.add_argument("--witness", action="store_true", help="Also validate witness catch-up, restart and quorum participation")
    args = parser.parse_args()
    if args.default_compaction:
        args.compaction = True
    if args.compaction and (args.compaction_rounds < 128 or (args.compaction_rounds < 2048 and not args.smoke)):
        parser.error("compaction requires 2048 rounds, or --smoke with at least 128")
    binary = args.binary.resolve()
    base = Path(tempfile.mkdtemp(prefix="gr8s-ha-production-"))
    nodes = [Node(binary, base, f"cp{i}", args.heap_mib, compaction=args.compaction,
                  default_compaction=args.default_compaction) for i in range(1, 4)]
    witness = Witness(binary, base, "w1", args.heap_mib) if args.witness else None
    cleanup_nodes = [*nodes, witness] if witness else nodes
    result = {"passed": False, "productionServe": True, "nativeBinary": True,
              "mutualTlsRaft": True, "agentsDisabled": True, "vmAcceptance": False,
              "conformanceAcceptance": False, "witnessAcceptance": args.witness,
              "heapLimitMiB": args.heap_mib,
              "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "evidence": str(base),
              "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "defaultCompactionRequested": args.default_compaction,
              "compactionEnableFlagPassed": args.compaction and not args.default_compaction,
              "compactionRequested": args.compaction, "compactionAcceptance": False,
              "fullCompactionWorkloadRequested": args.compaction and not args.smoke,
              "fullCompactionAcceptance": False,
              "compactionRounds": args.compaction_rounds if args.compaction else 0}
    print(f"Evidence: {base}", flush=True)
    try:
        nodes[0].start()
        wait_for(nodes[0].ready)
        assert post([nodes[0]], "/api/v1/namespaces",
                    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ha-native"}})
        for node in nodes[1:]:
            token = subprocess.run([str(binary), "join-token", "--role", "control-plane",
                                    "--node-name", node.name, "--state-directory", str(nodes[0].root)],
                                   cwd=REPO, check=True, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=30)
            node.start(nodes[0].raft, json.loads(token.stdout))
            wait_for(node.ready)
        result["initialMembership"] = wait_for(lambda: voters_ready(nodes))
        path = "/api/v1/namespaces/ha-native/configmaps"
        leader = wait_for(lambda: post(nodes, path, configmap("before-loss", "A")))
        wait_for(lambda: value_on_all(nodes, "before-loss", "A"))
        identities = {n.name: n.identities() for n in nodes}
        assert all(identities.values())
        if args.compaction:
            compaction_churn(nodes, result, args.compaction_rounds)
            leader = wait_for(lambda: post(nodes, path, configmap("after-compaction", "D")))
            wait_for(lambda: value_on_all(nodes, "after-compaction", "D"))
        leader = wait_for(lambda: current_leader(nodes))
        result["metricsBeforeLeaderLoss"] = {node.name: {key: value for key, value in node.metrics().items()
                                                       if key in ("gr8s_raft_term", "gr8s_raft_is_leader")}
                                              for node in nodes}
        result["killedLeader"] = leader.name
        assert leader.stop(kill=True) == -signal.SIGKILL
        survivors = [n for n in nodes if n is not leader]
        replacement = wait_for(lambda: post(survivors, path, configmap("after-loss", "B")))
        result["replacementLeader"] = replacement.name
        wait_for(lambda: value_on_all(survivors, "before-loss", "A"))
        wait_for(lambda: value_on_all(survivors, "after-loss", "B"))
        leader.start()  # existing credentials, no token and an unusable join seed
        wait_for(leader.ready)
        wait_for(lambda: value_on_all(nodes, "after-loss", "B"))
        result["membershipAfterRejoin"] = wait_for(lambda: voters_ready(nodes))
        result["configMapsBeforeFullRestart"] = wait_for(lambda: matching_configmaps(nodes, path))
        result["firstShutdown"] = {n.name: n.stop() for n in nodes}
        assert all(code == 0 for code in result["firstShutdown"].values())
        # Start only the founder first. Its Raft listener must stay available,
        # while its application cannot serve without the saved voting quorum.
        nodes[0].start()
        def raft_listening():
            nodes[0].live()
            with socket.create_connection(("127.0.0.1", nodes[0].raft), timeout=1):
                return True
        wait_for(raft_listening)
        result["founderAloneMembership"] = inspect([nodes[0]])[0]
        assert len(result["founderAloneMembership"]["members"]) == 3
        try:
            ready_alone = nodes[0].ready()
        except OSError:
            ready_alone = False
        assert not ready_alone
        result["founderAloneApplicationBlocked"] = True
        for node in nodes[1:]:
            node.start()  # proves startup is independent of enrollment seed/token
        for node in nodes:
            wait_for(node.ready)
        result["membershipAfterFullRestart"] = wait_for(lambda: voters_ready(nodes))
        wait_for(lambda: value_on_all(nodes, "before-loss", "A"))
        wait_for(lambda: value_on_all(nodes, "after-loss", "B"))
        result["configMapsAfterFullRestart"] = wait_for(
            lambda: matching_configmaps(nodes, path, result["configMapsBeforeFullRestart"]))
        final_leader = wait_for(lambda: post(nodes, path, configmap("after-restart", "C")))
        result["leaderAfterFullRestart"] = final_leader.name
        wait_for(lambda: value_on_all(nodes, "after-restart", "C"))
        if args.compaction:
            wait_for(lambda: value_on_all(nodes, "compaction-sentinel", "preserved"))
            wait_for(lambda: value_on_all(nodes, "compaction-after-catchup", "preserved"))
        if witness:
            token = subprocess.run([str(binary), "join-token", "--role", "witness",
                                    "--node-name", witness.name, "--state-directory", str(final_leader.root)],
                                   cwd=REPO, check=True, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=30)
            witness.start(final_leader.raft, json.loads(token.stdout))
            result["membershipWithWitness"] = wait_for(lambda: membership_with_witness(nodes, witness))
            assert not (witness.root / "raft/pki/cluster-ca.key").exists()
            assert not (witness.root / "pki/pki/cluster-ca.crt").exists()
            witness_identity = witness.identities()
            assert witness_identity
            assert witness.stop(kill=True) == -signal.SIGKILL
            assert wait_for(lambda: post(nodes, path, configmap("while-witness-down", "D")))
            witness.start(final_leader.raft)  # existing witness credentials, no new token
            result["membershipAfterWitnessRestart"] = wait_for(lambda: membership_with_witness(nodes, witness))
            assert all(witness.identities().get(p) == h for p, h in witness_identity.items())
            result["witnessIdentitiesPreserved"] = witness_identity
            # Four voting members require three acknowledgements. With one voter
            # down, a successful write requires the witness and both survivors.
            assert final_leader.stop(kill=True) == -signal.SIGKILL
            survivors = [n for n in nodes if n is not final_leader]
            new_leader = wait_for(lambda: post(survivors, path, configmap("witness-quorum", "E")))
            wait_for(lambda: value_on_all(survivors, "witness-quorum", "E"))
            result["leaderWithWitnessQuorum"] = new_leader.name
            final_leader.start()
            wait_for(final_leader.ready)
            wait_for(lambda: value_on_all(nodes, "witness-quorum", "E"))
            result["finalWitnessMembership"] = wait_for(lambda: membership_with_witness(nodes, witness))
            result["witnessShutdown"] = witness.stop()
            assert result["witnessShutdown"] == 0
        for node in nodes:
            current = node.identities()
            assert all(current.get(path) == digest for path, digest in identities[node.name].items())
        result["identitiesPreserved"] = identities
        result["finalShutdown"] = {n.name: n.stop() for n in nodes}
        assert all(code == 0 for code in result["finalShutdown"].values())
        result["fullCompactionAcceptance"] = bool(args.compaction and not args.smoke and result["compactionAcceptance"])
        result["passed"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
        result["traceback"] = traceback.format_exc()
    finally:
        for node in cleanup_nodes:
            try:
                node.stop()
            except Exception as error:
                result.setdefault("cleanupErrors", []).append(str(error))
                if node.process and node.process.poll() is None:
                    node.process.kill()
                    node.process.wait(timeout=10)
                result["passed"] = False
        (base / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
