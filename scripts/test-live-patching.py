#!/usr/bin/env python3
"""Exercise signed patch planning, live ASDF reload, leadership handoff and restart.
Uses three independent SBCL control planes with the fake runtime; needs no root.
All state and logs are retained on failure and removed on success by default.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(function, timeout=90):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        try:
            value = function()
            if value:
                return value
        except (OSError, ValueError, urllib.error.URLError) as exc:
            error = exc
        time.sleep(0.2)
    raise RuntimeError(f"timed out: {error}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--witness", action="store_true", help="Use two control planes and a witness")
    parser.add_argument("--gr8s", type=Path, help="Run a native binary instead of SBCL server processes")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="gr8s-live-patch-"))
    processes = []
    files = []
    passed = False
    common = ["sbcl", "--noinform", "--non-interactive", "--eval", "(require :asdf)",
              "--eval", '(asdf:load-asd (truename "gr8s.asd"))',
              "--eval", "(asdf:load-system :gr8s)"]
    try:
        # The fixture publisher uses the same loaded release/build ID as the servers.
        source = work / "source"
        source.mkdir()
        name = "gr8s-patch-live-test-0001"
        (source / f"{name}.asd").write_text(
            f'(asdf:defsystem "{name}" :depends-on ("gr8s") :components ((:file "code")))\n')
        (source / "code.lisp").write_text('''(in-package #:gr8s.server)
(defun run-controller-pass (worker)
  (when (reconciliation-worker-before-reconcile worker)
    (funcall (reconciliation-worker-before-reconcile worker)))
  (reconcile-all (reconciliation-worker-reconciler worker)
                 :observer (reconciliation-worker-observer worker)))
(gr8s.patch:register-patch
 :migrate (lambda (manager)
   (gr8s.patch:checkpoint "marker" (lambda ()
      (gr8s.patch::durable-bytes (gr8s.patch::path manager "marker") #(111 107)))))
 :verify (lambda (manager) (probe-file (gr8s.patch::path manager "marker"))))
''')
        recipe = {"publisher": "fixture", "levels": [{"summary": "Live controller fixture", "mode": "reload",
                  "roles": ["control-plane"], "system": name,
                  "systemFile": f"{name}.asd", "sourceDirectory": str(source) + "/",
                  "files": [f"{name}.asd", "code.lisp"]}]}
        recipe_file = work / "recipe.json"
        recipe_file.write_text(json.dumps(recipe))
        publisher = work / "publish.lisp"
        publisher.write_text(f'''(let* ((key (ironclad:make-private-key :ed25519 :x (ironclad:random-data 32)))
 (public (getf (ironclad:destructure-private-key key) :y)))
 (gr8s.patch::durable-json #P{json.dumps(str(work / 'trusted.json'))}
   (gr8s.patch::object "fixture" (ironclad:byte-array-to-hex-string public)))
 (gr8s.patch::build-artifact (gr8s.patch::read-json #P{json.dumps(str(recipe_file))}) key
                            #P{json.dumps(str(work / 'image') + '/')}))\n''')
        with (work / "publisher.log").open("w") as output:
            subprocess.run(common + ["--load", str(publisher)], cwd=ROOT, stdout=output,
                           stderr=subprocess.STDOUT, check=True, timeout=120)

        nodes = [{"id": f"cp{i}", "http": port(), "raft": port(), "node": port(),
                  "state": work / f"cp{i}"} for i in range(1, 4)]
        if args.witness:
            nodes[-1]["witness"] = True
        for node in nodes:
            patch_dir = node["state"] / "patches"
            patch_dir.mkdir(parents=True)
            shutil.copyfile(work / "trusted.json", patch_dir / "trusted-keys.json")

        def launch(node, joining=None):
            arguments = ["serve", "--runtime", "fake", "--disable-agent", "--state-directory", str(node["state"]),
                         "--port", str(node["http"]), "--node-port", str(node["node"]),
                         "--node-name", node["id"], "--raft-id", node["id"], "--raft-port", str(node["raft"])]
            if joining:
                arguments += ["--raft-join", f"127.0.0.1:{nodes[0]['raft']}", "--raft-node-name", node["id"],
                              "--raft-token", joining["token"], "--raft-ca-pin", joining["caPin"]]
            else:
                arguments += ["--raft-init"]
            if node.get("witness"):
                arguments = ["witness", "--join", f"127.0.0.1:{nodes[0]['raft']}",
                             "--member-id", node["id"], "--node-name", node["id"],
                             "--port", str(node["raft"]), "--state-directory", str(node["state"]),
                             "--token", joining["token"], "--ca-pin", joining["caPin"]]
            output = (work / f"{node['id']}.log").open("a")
            files.append(output)
            command = ([str(args.gr8s.resolve())] if args.gr8s else
                       common + ["--eval", "(uiop:quit (gr8s:main (uiop:command-line-arguments)))",
                                 "--end-toplevel-options"])
            child = subprocess.Popen(command + arguments, cwd=work if args.gr8s else ROOT,
                                     stdout=output, stderr=subprocess.STDOUT)
            processes.append(child)
            node["process"] = child
            return child

        def version(node):
            with urllib.request.urlopen(f"http://127.0.0.1:{node['http']}/version", timeout=3) as reply:
                return json.load(reply)

        def request(node, action, **fields):
            token = (node["state"] / "patches" / "admin.token").read_text()
            data = json.dumps(dict(action=action, **fields)).encode()
            req = urllib.request.Request(f"http://127.0.0.1:{node['http']}/apis/gr8s.io/v1/patchrollouts",
                                         data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
            # POSTs to followers redirect to the leader; that leader has a different local token.
            # Probe members independently and use the current leader's own token.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *unused):
                    return None
            try:
                with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as reply:
                    return json.load(reply)
            except urllib.error.HTTPError as exc:
                raise RuntimeError(f"HTTP {exc.code}: {exc.read().decode()}") from exc

        launch(nodes[0])
        wait_for(lambda: version(nodes[0]))
        for node in nodes[1:]:
            expression = f'''(with-open-file (output #P{json.dumps(str(work / 'join.json'))}
              :direction :output :if-exists :supersede :if-does-not-exist :create)
              (gr8s.server::print-node-join-token
                (list :state-directory {json.dumps(str(nodes[0]['state']))} :role {json.dumps("witness" if node.get("witness") else "control-plane")}
                      :node-name {json.dumps(node['id'])}) output))'''
            with (work / "join.log").open("a") as output:
                subprocess.run(common + ["--eval", expression], cwd=ROOT, stdout=output,
                               stderr=subprocess.STDOUT, check=True, timeout=90)
            launch(node, json.loads((work / "join.json").read_text()))
            if node.get("witness"):
                wait_for(lambda: "holding quorum" in (work / f"{node['id']}.log").read_text())
            else:
                wait_for(lambda: version(node))
        time.sleep(2)
        pids = [node["process"].pid for node in nodes]
        plan = request(nodes[0], "plan", image=str(work / "image"), level=1, soakSeconds=0)
        rollout = plan["id"]
        watcher = None
        if args.gr8s:
            output = (work / "cli-watch.log").open("w")
            files.append(output)
            watcher = subprocess.Popen([str(args.gr8s.resolve()), "patch", "apply", rollout, "--watch", "--json",
                                        "--server", f"http://127.0.0.1:{nodes[0]['http']}", "--token-file",
                                        str(nodes[0]["state"] / "patches" / "admin.token")],
                                       cwd=work, stdout=output, stderr=subprocess.STDOUT)
            processes.append(watcher)
        else:
            request(nodes[0], "apply", id=rollout)
        final = None
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            for node in nodes:
                try:
                    final = request(node, "status", id=rollout)
                    break
                except (RuntimeError, OSError):
                    continue
            if final and final["state"] == "paused":
                raise RuntimeError(f"rollout paused: {final.get('error')}")
            if final and final["state"] == "complete":
                break
            time.sleep(0.2)
        assert final and final["state"] == "complete", final
        if watcher:
            assert watcher.wait(timeout=35) == 0, (work / "cli-watch.log").read_text()
            watched = [json.loads(line) for line in (work / "cli-watch.log").read_text().splitlines() if line.startswith("{")]
            assert watched[-1]["state"] == "complete", watched
        for node, pid in zip(nodes, pids):
            assert node["process"].poll() is None
            assert node["process"].pid == pid
            if node.get("witness"):
                assert json.loads((node["state"] / "patches" / "journal.json").read_text())["level"] == 1
            else:
                assert version(node)["gr8sPatch"]["loadedLevel"] == 1
                assert (node["state"] / "patches" / "marker").read_bytes() == b"ok"
        # Restart a follower using the same base binary and durable patch history.
        follower = nodes[0]
        follower["process"].send_signal(signal.SIGTERM)
        follower["process"].wait(timeout=30)
        launch(follower)
        wait_for(lambda: version(follower)["gr8sPatch"]["loadedLevel"] == 1)
        result = {"passed": True, "processes": 3, "preservedPIDs": pids,
                  "rollout": rollout, "restartRecovered": True, "witness": args.witness,
                  "native": bool(args.gr8s), "cliWatchCompleted": bool(watcher), "runtime": "fake", "evidence": str(work)}
        (work / "report.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        passed = True
    finally:
        for child in reversed(processes):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for output in files:
            output.close()
        if passed and not args.keep:
            shutil.rmtree(work)
        else:
            print(f"Evidence retained: {work}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
