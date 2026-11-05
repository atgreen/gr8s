#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Verify Pod attach, log streaming and PID namespaces through kubectl and real containers.

Requires root in a disposable Linux guest, a native gr8s executable, kubectl and
access to the busybox image. Unit tests cannot show what a client sees, so this
attaches to running processes, follows and rereads logs across a restart, reads
/proc and cgroups from inside each container, and watches what owner deletion and
init failure do to real objects and sidecars. Unknown arguments are ignored so
gr8s-upstream can queue this script for a VM like any other runner.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"
LONG = "sleep 3600"


def pod(name, *containers, **spec):
    """Return a Pod manifest with a short grace period."""
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "default"},
            "spec": {"terminationGracePeriodSeconds": 1, "containers": list(containers), **spec}}


def container(name, script, **fields):
    """Return a container running SCRIPT under sh."""
    return {"name": name, "image": IMAGE, "command": ["sh", "-c", script], **fields}


class Cluster:
    """Own one disposable native gr8s process and its state directory."""

    def __init__(self, binary, parent, port, node_port):
        self.binary, self.port, self.node_port = binary, port, node_port
        self.root = Path(tempfile.mkdtemp(prefix="gr8s-streams.", dir=parent))
        self.kubeconfig = self.root / "kubeconfig"
        self.process = None

    def start(self):
        log = open(self.root / "gr8s.log", "ab")
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--runtime", "containerd",
             "--state-directory", str(self.root / "state"), "--port", str(self.port),
             "--node-port", str(self.node_port), "--containerd-log-root", str(self.root / "pods"),
             "--kubeconfig", str(self.kubeconfig)], stdout=log, stderr=subprocess.STDOUT)
        wait_for("node registration", 180, lambda: self.kubectl("get", "nodes", "-o", "name", check=False))

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=180)

    def command(self, *arguments):
        return ["kubectl", "--kubeconfig", str(self.kubeconfig), *arguments]

    def run(self, *arguments, stdin=None, timeout=300):
        return subprocess.run(self.command(*arguments), input=stdin, capture_output=True, text=True,
                              check=False, timeout=timeout)

    def kubectl(self, *arguments, stdin=None, check=True):
        result = self.run(*arguments, stdin=stdin)
        if result.returncode != 0:
            if check:
                raise RuntimeError(f"kubectl {arguments}: {result.stderr}")
            return ""
        return result.stdout

    def apply(self, manifest):
        self.kubectl("apply", "-f", "-", stdin=json.dumps(manifest))

    def ready(self, name, seconds=600):
        wait_for(f"{name} running", seconds, lambda: self.kubectl(
            "get", "pod", name, "-o", "jsonpath={.status.phase}", check=False) == "Running")


def wait_for(description, seconds, predicate):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {description}")


def attach_scenarios(cluster, check):
    """Attach to processes that already run, with and without stdin and a terminal."""
    cluster.apply(pod("attach-stdin", container("main", "echo begin; cat; echo stdin-closed; " + LONG,
                                                stdin=True, stdinOnce=True)))
    cluster.ready("attach-stdin")
    wait_for("attach-stdin output", 60, lambda: "begin" in cluster.kubectl("logs", "attach-stdin", check=False))
    # The client stays attached to the process's output after its stdin has ended.
    process = subprocess.Popen(cluster.command("attach", "attach-stdin", "-c", "main", "-i"), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    process.stdin.write("through-attach\n")
    process.stdin.close()
    try:
        wait_for("stdin to reach the process and end", 60,
                 lambda: "stdin-closed" in cluster.kubectl("logs", "attach-stdin", check=False))
        echoed = process.stdout.readline()
    finally:
        process.terminate()
        process.wait(timeout=60)
    logs = cluster.kubectl("logs", "attach-stdin")
    check("attachDeliversStdinToTheRunningProcess", "through-attach" in logs and "stdin-closed" in logs,
          {"logs": logs, "echoed": echoed})

    cluster.apply(pod("attach-out", container("main", "i=0; while true; do echo tick-$i; i=$((i+1)); sleep 1; done")))
    cluster.ready("attach-out")
    process = subprocess.Popen(cluster.command("attach", "attach-out", "-c", "main"),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        lines = [process.stdout.readline() for _ in range(3)]
    finally:
        process.terminate()
        process.wait(timeout=60)
    check("attachStreamsOutputWithoutStdin", all(line.startswith("tick-") for line in lines), lines)

    cluster.apply(pod("attach-tty", container("main", "read line; echo got=$line; tty; " + LONG,
                                              stdin=True, tty=True)))
    cluster.ready("attach-tty")
    time.sleep(2)
    script = shutil.which("script")
    if script:
        command = " ".join(cluster.command("attach", "attach-tty", "-c", "main", "-it"))
        driver = subprocess.Popen(["script", "-qfc", command, "/dev/null"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(5)
        driver.stdin.write("typed\n")
        driver.stdin.flush()
        wait_for("attach-tty echo", 60, lambda: "got=typed" in cluster.kubectl("logs", "attach-tty", check=False))
        driver.terminate()
        driver.wait(timeout=30)
    logs = cluster.kubectl("logs", "attach-tty")
    check("attachReachesATerminalContainer", (not script) or ("got=typed" in logs and "/dev/pts" in logs), logs)

    result = cluster.run("run", "run-attach", f"--image={IMAGE}", "--restart=OnFailure", "--pod-running-timeout=10m",
                         "--attach=true", "--stdin", "--", "sh", "-c", "echo -n read: && cat && echo 'stdin closed'",
                         stdin="value\nabcd1234", timeout=900)
    logs = cluster.kubectl("logs", "run-attach")
    check("kubectlRunAttachesWithStdin",
          result.returncode == 0 and "abcd1234" in result.stdout and "stdin closed" in result.stdout
          and "read:value" in logs, {"out": result.stdout, "logs": logs, "code": result.returncode})

    cluster.apply(pod("exec-code", container("main", LONG)))
    cluster.ready("exec-code")
    good = cluster.run("exec", "-i", "exec-code", "--", "sh", "-c", "cat; exit 0", stdin="in\n", timeout=60)
    bad = cluster.run("exec", "-i", "exec-code", "--", "sh", "-c", "cat; exit 7", stdin="in\n", timeout=60)
    check("interactiveExecReportsExitCodes", good.returncode == 0 and good.stdout == "in\n" and bad.returncode == 7,
          {"good": [good.returncode, good.stdout, good.stderr], "bad": [bad.returncode, bad.stderr]})

    missing = cluster.run("attach", "attach-out", "-c", "nope", timeout=60)
    check("attachRefusesUnknownContainer", missing.returncode != 0, missing.stderr)


def log_scenarios(cluster, check):
    """Follow a live log, and read the previous attempt's log after a real restart."""
    cluster.apply(pod("logs-follow", container("main", "echo first; sleep 25; echo second; sleep 8; echo third; " + LONG)))
    cluster.ready("logs-follow")
    process = subprocess.Popen(cluster.command("logs", "-f", "logs-follow"), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    started = time.monotonic()
    received = []
    try:
        for _ in range(3):
            line = process.stdout.readline()
            received.append((line.strip(), round(time.monotonic() - started, 1)))
        alive = process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=60)
    check("logsFollowStreamsLinesAsTheyAreWritten",
          [line for line, _ in received] == ["first", "second", "third"] and alive
          and received[2][1] - received[0][1] > 5, received)

    cluster.apply(pod("logs-end", container("main", "echo one; sleep 15; echo two"), restartPolicy="Never"))
    wait_for("logs-end started", 600, lambda: "one" in cluster.kubectl("logs", "logs-end", check=False))
    ended = cluster.run("logs", "-f", "logs-end", timeout=120)
    check("logsFollowEndsWhenTheContainerExits", ended.returncode == 0 and ended.stdout == "one\ntwo\n",
          {"out": ended.stdout, "err": ended.stderr})

    cluster.apply(pod("logs-prev", container("main", "echo attempt-$(cat /scratch/n 2>/dev/null || echo 0); "
                                             "echo 1 > /scratch/n; [ -f /scratch/m ] && " + LONG + "; "
                                             "touch /scratch/m; exit 3",
                                             volumeMounts=[{"name": "scratch", "mountPath": "/scratch"}]),
                      volumes=[{"name": "scratch", "emptyDir": {}}]))
    wait_for("logs-prev restart", 300, lambda: cluster.kubectl(
        "get", "pod", "logs-prev", "-o", "jsonpath={.status.containerStatuses[0].restartCount}", check=False) == "1")
    wait_for("logs-prev current", 120, lambda: "attempt-1" in cluster.kubectl("logs", "logs-prev", check=False))
    previous = cluster.run("logs", "logs-prev", "--previous")
    current = cluster.run("logs", "logs-prev")
    check("logsPreviousReturnsThePriorAttempt",
          previous.stdout == "attempt-0\n" and current.stdout == "attempt-1\n",
          {"previous": previous.stdout, "current": current.stdout, "err": previous.stderr})
    none = cluster.run("logs", "logs-follow", "--previous")
    check("logsPreviousRefusesWithoutARestart", none.returncode != 0 and "previous terminated" in none.stderr,
          {"out": none.stdout, "err": none.stderr})


def pid_scenarios(cluster, check):
    """Read each container's process table from inside it."""
    probe = "echo pid1=$(cat /proc/1/cmdline | tr '\\0' ' '); " + LONG
    cluster.apply(pod("pid-private", container("first", probe), container("second", "exec sleep 3600")))
    cluster.ready("pid-private")
    first = wait_for("first log", 60, lambda: cluster.kubectl("logs", "pid-private", "-c", "first", check=False))
    check("processIsPid1InAPrivateNamespace", "pid1=sh" in first and "echo pid1" in first, first)
    second_seen = cluster.run("exec", "pid-private", "-c", "first", "--", "sh", "-c", "cat /proc/*/cmdline | tr '\\0' ' '")
    check("containersDoNotSeeEachOther", "sleep 3600" in second_seen.stdout and "exec sleep" not in second_seen.stdout
          and second_seen.stdout.count("sleep 3600") <= 2, second_seen.stdout)
    own = cluster.run("exec", "pid-private", "-c", "second", "--", "cat", "/proc/1/cmdline")
    check("execSeesTheContainerProcessAsPid1", own.stdout.replace("\0", " ").startswith("sleep 3600"), own.stdout)

    cluster.apply(pod("pid-shared", container("first", "exec sleep 3601"), container("second", "exec sleep 3602"),
                      shareProcessNamespace=True))
    cluster.ready("pid-shared")
    def shared():
        result = cluster.run("exec", "pid-shared", "-c", "first", "--", "sh", "-c", "cat /proc/*/cmdline | tr '\\0' ' '")
        return result.stdout if "3601" in result.stdout and "3602" in result.stdout else ""
    seen = wait_for("processes visible across containers", 60, shared)
    init = cluster.run("exec", "pid-shared", "-c", "first", "--", "cat", "/proc/1/cmdline")
    check("shareProcessNamespaceSharesProcesses", "3601" in seen and "3602" in seen and "pause" in init.stdout,
          {"seen": seen, "pid1": init.stdout})

    refused = cluster.run("apply", "-f", "-", stdin=json.dumps(pod(
        "pid-invalid", container("first", LONG), shareProcessNamespace=True, hostPID=True)))
    check("shareProcessNamespaceRefusedWithHostPid", refused.returncode != 0, refused.stderr)

    cluster.apply(pod("pid-term", container("main", "trap 'echo got-term; exit 0' TERM; echo ready; "
                                            "while true; do sleep 1; done"), terminationGracePeriodSeconds=30))
    cluster.ready("pid-term")
    wait_for("trap ready", 60, lambda: "ready" in cluster.kubectl("logs", "pid-term", check=False))
    started = time.monotonic()
    cluster.kubectl("delete", "pod", "pid-term", "--wait=true")
    check("pid1WithATrapStopsOnSigterm", time.monotonic() - started < 25, round(time.monotonic() - started, 1))

    cluster.apply(pod("pid-debug", container("main", "exec sleep 3603")))
    cluster.ready("pid-debug")
    cluster.kubectl("patch", "pod", "pid-debug", "--subresource=ephemeralcontainers", "--type=strategic", "-p", json.dumps(
        {"spec": {"ephemeralContainers": [{"name": "dbg", "image": IMAGE, "targetContainerName": "main",
                                           "command": ["sh", "-c", "cat /proc/1/cmdline | tr '\\0' ' '; echo; " + LONG]}]}}))
    log = wait_for("ephemeral log", 180, lambda: cluster.kubectl("logs", "pid-debug", "-c", "dbg", check=False))
    check("ephemeralTargetJoinsTheTargetNamespace", "sleep 3603" in log, log)


def owner_scenarios(cluster, check):
    """Delete owners through kubectl and watch what the collector does to their dependents."""
    def uid_of(kind, name):
        return cluster.kubectl("get", kind, name, "-o", "jsonpath={.metadata.uid}")

    def owned(name, *owners):
        return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "default", "ownerReferences": [
            {"apiVersion": "v1", "kind": "ConfigMap", "name": owner, "uid": uid_of("configmap", owner),
             "blockOwnerDeletion": True} for owner in owners]}}

    def references(kind, name):
        text = cluster.kubectl("get", kind, name, "-o", "jsonpath={.metadata.ownerReferences[*].name}", check=False)
        return text.split()

    for name in ("owner-a", "owner-b", "fore", "orphan-owner"):
        cluster.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": "default"}})
    cluster.apply(owned("shared", "owner-a", "owner-b"))
    cluster.kubectl("delete", "configmap", "owner-a")
    wait_for("the dangling reference to go", 120, lambda: references("configmap", "shared") == ["owner-b"])
    check("collectorDropsADanglingOwnerWhileAnotherIsLive", references("configmap", "shared") == ["owner-b"],
          references("configmap", "shared"))
    cluster.kubectl("delete", "configmap", "owner-b")
    wait_for("the last owner's dependent to go", 120,
             lambda: not cluster.kubectl("get", "configmap", "shared", "--ignore-not-found", "-o", "name"))
    check("collectorStillRemovesAnOwnerlessDependent", True, "gone")

    # A Pod held by a finalizer keeps the foreground owner waiting for as long as the test likes.
    held = pod("held", container("main", LONG))
    held["metadata"]["ownerReferences"] = owned("unused", "fore")["metadata"]["ownerReferences"]
    held["metadata"]["finalizers"] = ["example.com/hold"]
    cluster.apply(held)
    cluster.ready("held")
    cluster.kubectl("delete", "configmap", "fore", "--cascade=foreground", "--wait=false")
    def fore_held():
        text = cluster.kubectl("get", "configmap", "fore", "-o", "json", check=False)
        return json.loads(text) if text else None
    held_owner = wait_for("the foreground owner to show deletion", 60, fore_held)
    check("foregroundOwnerShowsItsDeletion", held_owner["metadata"].get("deletionTimestamp")
          and "foregroundDeletion" in held_owner["metadata"].get("finalizers", []), held_owner["metadata"])
    labelled = cluster.run("label", "configmap", "fore", "touched=yes")
    check("heldOwnerCanStillBeWritten", labelled.returncode == 0, labelled.stderr)
    cluster.kubectl("patch", "pod", "held", "--type=merge", "-p", '{"metadata":{"finalizers":[]}}')
    wait_for("the foreground owner to go", 120,
             lambda: not cluster.kubectl("get", "configmap", "fore", "--ignore-not-found", "-o", "name"))
    check("foregroundOwnerGoesOnceItsDependentHas", True, "gone")

    cluster.apply(owned("kept", "orphan-owner"))
    cluster.kubectl("delete", "configmap", "orphan-owner", "--cascade=orphan")
    wait_for("the orphaned dependent to be released", 120, lambda: references("configmap", "kept") == [])
    wait_for("the orphaning owner to go", 120,
             lambda: not cluster.kubectl("get", "configmap", "orphan-owner", "--ignore-not-found", "-o", "name"))
    check("orphanDeletionKeepsTheDependent", cluster.kubectl("get", "configmap", "kept", "-o", "name") != "", "kept")

    # A Pod in the foreground stops straight away and waits for its dependent.
    cluster.apply(pod("fg-owner", container("main", "trap 'exit 0' TERM; while true; do sleep 1; done")))
    cluster.ready("fg-owner")
    dependent = pod("fg-child", container("main", LONG))
    dependent["metadata"]["ownerReferences"] = [{"apiVersion": "v1", "kind": "Pod", "name": "fg-owner",
                                                 "uid": uid_of("pod", "fg-owner"), "blockOwnerDeletion": True}]
    dependent["metadata"]["finalizers"] = ["example.com/hold"]
    cluster.apply(dependent)
    cluster.ready("fg-child")
    cluster.kubectl("delete", "pod", "fg-owner", "--cascade=foreground", "--wait=false")
    def fg_stopped():
        text = cluster.kubectl("get", "pod", "fg-owner", "-o", "json", check=False)
        if not text:
            return None
        document = json.loads(text)
        states = [status["state"] for status in document["status"].get("containerStatuses", [])]
        return document if document["metadata"].get("deletionTimestamp") and all("terminated" in state for state in states) else None
    owner_view = wait_for("the held Pod's containers to stop", 120, fg_stopped)
    check("foregroundPodShowsDeletionAndStopsWhileHeld",
          "foregroundDeletion" in owner_view["metadata"].get("finalizers", []), owner_view["metadata"])
    child = cluster.kubectl("get", "pod", "fg-child", "-o", "jsonpath={.metadata.deletionTimestamp}")
    check("foregroundPodDependentIsDeleted", child != "", child)
    cluster.kubectl("patch", "pod", "fg-child", "--type=merge", "-p", '{"metadata":{"finalizers":[]}}')
    wait_for("the foreground Pod to go", 120,
             lambda: not cluster.kubectl("get", "pod", "fg-owner", "--ignore-not-found", "-o", "name"))
    check("foregroundPodGoesOnceItsDependentHas", True, "gone")


def sidecar_scenarios(cluster, check):
    """Fail an ordinary init container with a sidecar running, in a Pod that never restarts."""
    sidecar = container("sidecar", LONG, restartPolicy="Always")
    cluster.apply(pod("sc-fail", container("main", "true"), restartPolicy="Never",
                      initContainers=[sidecar, container("setup", "sleep 2; exit 7")]))
    def stopped():
        text = cluster.kubectl("get", "pod", "sc-fail", "-o", "json", check=False)
        if not text:
            return None
        document = json.loads(text)
        states = {s["name"]: s["state"] for s in document["status"].get("initContainerStatuses", [])}
        return document if ("terminated" in states.get("sidecar", {})
                            and states["setup"].get("terminated", {}).get("exitCode") == 7) else None
    view = wait_for("the sidecar to stop after init failed", 300, stopped)
    check("sidecarStopsWhenInitFailsANeverPod", view["status"]["phase"] == "Failed", view["status"]["phase"])
    time.sleep(5)
    view = json.loads(cluster.kubectl("get", "pod", "sc-fail", "-o", "json"))
    states = {s["name"]: s["state"] for s in view["status"]["initContainerStatuses"]}
    check("sidecarIsNotRestartedAfterwards", "terminated" in states["sidecar"] and view["status"]["phase"] == "Failed", states)


def resize_scenarios(cluster, check):
    """Resize a running container past what the node has, then within it."""
    allocatable = json.loads(cluster.kubectl("get", "nodes", "-o", "json"))["items"][0]["status"]["allocatable"]
    cpu = allocatable["cpu"]
    resources = {"requests": {"cpu": "100m"}, "limits": {"cpu": "200m"}}
    cluster.apply(pod("rz", container("main", LONG, resources=resources)))
    cluster.ready("rz")
    def resize(request, limit):
        return cluster.run("patch", "pod", "rz", "--subresource=resize", "--type=strategic", "-p", json.dumps(
            {"spec": {"containers": [{"name": "main", "resources": {"requests": {"cpu": request}, "limits": {"cpu": limit}}}]}}))
    def pending():
        conditions = json.loads(cluster.kubectl("get", "pod", "rz", "-o", "json"))["status"].get("conditions", [])
        return next((c for c in conditions if c["type"] == "PodResizePending"), None)
    too_big = f"{int(float(cpu.rstrip('m')) / (1000 if cpu.endswith('m') else 1)) * 4 + 4}"
    result = resize(too_big, too_big)
    check("resizeBeyondTheNodeIsRefused", result.returncode != 0 and "enough allocatable" in result.stderr, result.stderr)
    actual = cluster.kubectl("get", "pod", "rz", "-o", "jsonpath={.status.containerStatuses[0].resources.requests.cpu}")
    check("refusedResizeLeavesTheContainerAlone", actual == "100m", actual)
    resize("150m", "300m")
    wait_for("the fitting resize to apply", 180, lambda: not pending() and cluster.kubectl(
        "get", "pod", "rz", "-o", "jsonpath={.status.containerStatuses[0].resources.requests.cpu}") == "150m")
    weight = cluster.run("exec", "rz", "--", "cat", "/sys/fs/cgroup/cpu.max")
    check("fittingResizeReachesTheCgroup", weight.stdout.startswith("30000 "), weight.stdout)


def affinity_scenarios(cluster, check):
    """Place real Pods by what already runs on the node, with the one node this cluster has."""
    def labelled(name, app, **spec):
        manifest = pod(name, container("main", LONG), **spec)
        manifest["metadata"]["labels"] = {"app": app}
        return manifest

    def term(app, **fields):
        return {"topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": {"app": app}}, **fields}

    def phase(name):
        return cluster.kubectl("get", "pod", name, "-o", "jsonpath={.status.phase}", check=False)

    def unschedulable(name):
        return json.loads(cluster.kubectl("get", "pod", name, "-o", "json"))["status"]["conditions"][0].get("message", "")

    cluster.apply(labelled("aff-db", "db"))
    cluster.ready("aff-db")
    cluster.apply(labelled("aff-near", "web", affinity={"podAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [term("db")]}}))
    cluster.ready("aff-near", 300)
    check("podAffinityPlacesBesideItsTarget", phase("aff-near") == "Running", phase("aff-near"))

    cluster.apply(labelled("aff-none", "web", affinity={"podAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [term("absent")]}}))
    message = wait_for("the Pod with no target to be judged", 60, lambda: unschedulable("aff-none"))
    check("podAffinityWithoutATargetWaits", phase("aff-none") == "Pending" and "pod affinity" in message, message)

    cluster.apply(labelled("aff-self", "group", affinity={"podAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [term("group")]}}))
    cluster.ready("aff-self", 300)
    check("podAffinityLetsAGroupStartItself", phase("aff-self") == "Running", phase("aff-self"))

    cluster.apply(labelled("aff-away", "web", affinity={"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [term("db")]}}))
    message = wait_for("the anti-affine Pod to be judged", 60, lambda: unschedulable("aff-away"))
    check("podAntiAffinityKeepsAPodOffTheNode", phase("aff-away") == "Pending" and "anti-affinity" in message, message)
    cluster.kubectl("delete", "pod", "aff-db")
    cluster.ready("aff-away", 300)
    check("podAntiAffinityReleasesWhenItsTargetGoes", phase("aff-away") == "Running", phase("aff-away"))

    # Now aff-away refuses db Pods, so a newcomer labelled db is held by the existing Pod's rule.
    cluster.apply(labelled("aff-newcomer", "db"))
    message = wait_for("the existing rule to hold the newcomer", 60, lambda: unschedulable("aff-newcomer"))
    check("existingAntiAffinityKeepsANewcomerOff", phase("aff-newcomer") == "Pending" and "anti-affinity" in message, message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gr8s", required=True, type=Path)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--api-port", type=int, default=18194)
    parser.add_argument("--node-port", type=int, default=17451)
    parser.add_argument("--only", default="attach,logs,pid,owners,sidecars,resize,affinity")
    arguments, _ = parser.parse_known_args()
    if os.geteuid() != 0:
        sys.exit("this test runs containers; use a disposable guest as root")
    cluster = Cluster(arguments.gr8s, arguments.state_parent, arguments.api_port, arguments.node_port)
    report = {"root": str(cluster.root)}
    failures = []

    def check(name, passed, observed):
        report[name] = {"passed": bool(passed), "observed": observed}
        print(f"{'PASS' if passed else 'FAIL'} {name}: {str(observed)[:600]}", flush=True)
        if not passed:
            failures.append(name)

    scenarios = {"attach": attach_scenarios, "logs": log_scenarios, "pid": pid_scenarios,
                 "owners": owner_scenarios, "sidecars": sidecar_scenarios, "resize": resize_scenarios,
                 "affinity": affinity_scenarios}
    try:
        cluster.start()
        for name in arguments.only.split(","):
            try:
                scenarios[name](cluster, check)
            except Exception as error:  # Later scenarios still teach us something.
                check(f"{name}Scenario", False, repr(error))
    finally:
        cluster.stop()
        print(open(cluster.root / "gr8s.log", errors="replace").read()[-3000:] if failures else "", flush=True)
        shutil.rmtree(cluster.root, ignore_errors=True)
    print(json.dumps({"passed": not failures, "failures": failures}))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
