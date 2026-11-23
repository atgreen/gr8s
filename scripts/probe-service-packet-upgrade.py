#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise native retained TCX migration in a disposable root VM, without containers.

Copy this file, its .lisp companion and gr8s-debug.py together. Uses an owned
veth/network namespace, real pinned maps and links, and a private debug server.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("upgrade_debug", Path(__file__).with_name("gr8s-debug.py"))
debug = importlib.util.module_from_spec(spec)
spec.loader.exec_module(debug)


def run(*args, check=True):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=30, check=check)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--legacy-fixture", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root in a disposable VM")
    args.report_directory.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="gr8s-upgrade.", dir="/var/tmp"))
    prefix = f"g8u{os.getpid():x}"
    namespace, host, peer = prefix + "n", prefix + "h", prefix + "p"
    pins = Path("/sys/fs/bpf") / prefix
    binary = args.gr8s.resolve(strict=True)
    report = {"root": str(root), "nativeSHA256": hashlib.sha256(binary.read_bytes()).hexdigest(), "checks": []}
    process, connection = None, None
    log = (args.report_directory / "native.log").open("w")
    request = 0

    def evaluate(name, form):
        nonlocal request
        request += 1
        status, output = debug.evaluate(connection, form, request)
        passed = status == "ok" and bool(re.search(r":PASSED\s+T", output))
        report["checks"].append({"name": name, "passed": passed, "output": output})
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        if not passed:
            raise AssertionError(f"{name}: {status}: {output}")
        return output

    def allowed():
        output = evaluate("counter", "(list :passed t :allowed (gr8s.network::upgrade-probe-allowed))")
        return int(re.search(r":ALLOWED\s+(\d+)", output)[1])

    def send():
        run("ip", "netns", "exec", namespace, "python3", "-c",
            "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'upgrade',('10.99.0.1',19092))")
        time.sleep(.2)

    try:
        run("mountpoint", "-q", "/sys/fs/bpf")
        run("ip", "netns", "add", namespace)
        run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
        run("ip", "link", "set", peer, "netns", namespace)
        run("ip", "link", "set", host, "up")
        run("ip", "addr", "add", "10.99.0.1/24", "dev", host)
        run("ip", "-n", namespace, "link", "set", peer, "name", "eth0")
        run("ip", "-n", namespace, "link", "set", "eth0", "up")
        run("ip", "-n", namespace, "addr", "add", "10.99.0.2/24", "dev", "eth0")
        mac = json.loads(run("ip", "-j", "link", "show", host).stdout)[0]["address"]
        run("ip", "-n", namespace, "neigh", "replace", "10.99.0.1", "lladdr", mac,
            "nud", "permanent", "dev", "eth0")
        process = subprocess.Popen([str(binary), "serve", "--disable-agent", "--runtime", "fake",
                    "--state-directory", str(root / "state"), "--port", "18197", "--node-port", "17457",
                    "--kubeconfig", str(root / "kubeconfig"), "--debug-slynk-port", "4017"],
                    stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 120
        secret = root / "state/debug/slynk.secret"
        while not secret.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("native debug server did not start")
            time.sleep(.1)
        connection = socket.create_connection(("127.0.0.1", 4017), timeout=180)
        debug.send(connection, secret.read_text().strip())
        source = debug.lisp_string(str(Path(__file__).with_suffix(".lisp").resolve()))
        evaluate("load-probe", f"(progn (load {source}) (list :passed t))")
        evaluate("setup", f"(gr8s.network::upgrade-probe-setup {debug.lisp_string(str(pins) + '/')} "
                          f"{debug.lisp_string('/run/netns/' + namespace)} {debug.lisp_string(host)})")
        evaluate("current-generation", "(gr8s.network::upgrade-probe-current)")
        if args.legacy_fixture:
            validation = run("python3", Path(__file__).with_name("test-service-program-upgrade.py"),
                "--validate-fixture", args.legacy_fixture.resolve(), "--endpoint-directory", pins / "endpoint",
                "--service-root", pins / "service-lb", check=False)
            (args.report_directory / "legacy-validate.stdout").write_text(validation.stdout)
            (args.report_directory / "legacy-validate.stderr").write_text(validation.stderr)
            if validation.returncode:
                raise RuntimeError(f"legacy validation failed: {validation.stderr[-4000:]}")
            report["checks"].append({"name": "legacy-kernel-acceptance", "passed": True,
                                     "observed": json.loads(validation.stdout)})
        before = allowed()
        send()
        assert allowed() > before, "valid packet did not traverse the endpoint guard"
        evaluate("partial-upgrade", "(gr8s.network::upgrade-probe-partial)")
        before = allowed()
        send()
        assert allowed() == before, "pinned blockers did not fail closed"
        evaluate("verifier-failure", "(gr8s.network::upgrade-probe-verifier-failure)")
        evaluate("recovery", "(gr8s.network::upgrade-probe-recover)")
        before = allowed()
        send()
        assert allowed() > before, "recovered endpoint did not pass traffic"
        evaluate("cached-generation", "(gr8s.network::upgrade-probe-current 1)")
        evaluate("shared-flow-ring", "(gr8s.network::upgrade-probe-shared-ring)")
        before = allowed()
        send()
        assert allowed() > before, "endpoint on the shared flow ring did not pass traffic"
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}")
    finally:
        if connection:
            try:
                evaluate("cleanup", "(gr8s.network::upgrade-probe-cleanup)")
            except Exception as error:
                report.update(passed=False, cleanupError=str(error))
            connection.close()
        if process:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                report.update(passed=False, shutdownTimeout=True)
        log.close()
        run("ip", "link", "del", host, check=False)
        run("ip", "netns", "del", namespace, check=False)
        if pins.exists():
            shutil.rmtree(pins)
        shutil.rmtree(root)
        report["cleanupCompleted"] = not pins.exists() and not root.exists()
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report.get("passed") and report.get("cleanupCompleted") else 1)


if __name__ == "__main__":
    main()
