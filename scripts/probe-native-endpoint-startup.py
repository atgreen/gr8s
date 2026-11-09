#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Measure endpoint bytecode preparation and kernel loading in a disposable root VM.

Starts an owned debug-enabled native server, records first/cached lookup times,
and loads unattached private pipelines, reusing opened shared maps when needed. Requires
kubectl and gr8s-debug.py alongside this script. --require-prepared verifies
that the native image already contains both endpoint compilation caches.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location("debug", Path(__file__).with_name("gr8s-debug.py"))
debug = importlib.util.module_from_spec(spec)
spec.loader.exec_module(debug)


def measurements(root):
    """Return forms that separate compilation, cache lookup and kernel loading."""
    forms = [("cache", """(list :plain-cold (null gr8s.network::*egress-guard-specs*)
                            :service-cold (null gr8s.network::*service-egress-guard-specs*))""")]
    for variant in ("service", "plain", "service", "plain"):
        service = "t" if variant == "service" else "nil"
        forms.append((variant, f"""
          (let ((start (get-internal-real-time)) (cpu (get-internal-run-time)))
            (let ((specs (gr8s.network::egress-guard-specs :service-packets {service})))
              (list :wall-seconds (/ (- (get-internal-real-time) start) (float internal-time-units-per-second))
                    :cpu-seconds (/ (- (get-internal-run-time) cpu) (float internal-time-units-per-second))
                    :maps (length (car specs)) :programs (length (cdr specs)))))"""))
    path = debug.lisp_string(str(root / "state/agent/containerd/bpf/service-lb") + "/")
    load = f"""
      (let ((gr8s.network::*cni-service-packets* t) (object nil))
        (unwind-protect
          (let ((start (get-internal-real-time)) (cpu (get-internal-run-time)))
            (setf object (gr8s.network::compile-egress-policy-object))
            (let ((before (loop for spec in (gr8s.network::egress-policy-object-program-specs object)
                                collect (copy-seq (getf spec :insns))))
                  (fds (when gr8s.network::*cni-service-packets*
                         (loop for spec in (gr8s.network::service-packet-map-specs)
                             collect (cons (first spec) (whistler/loader:open-pinned-object
                                       (concatenate 'string {path} (first spec))))))))
              (gr8s.network::load-egress-policy-object object fds)
              (list :wall-seconds (/ (- (get-internal-real-time) start) (float internal-time-units-per-second))
                    :cpu-seconds (/ (- (get-internal-run-time) cpu) (float internal-time-units-per-second))
                    :maps (length (gr8s.network::egress-policy-object-maps object))
                    :programs (length (gr8s.network::egress-policy-object-programs object))
                    :templates-unchanged
                    (equalp before (loop for spec in (gr8s.network::egress-policy-object-program-specs object)
                                         collect (getf spec :insns))))))
          (when object (gr8s.network::close-egress-policy-object object))))"""
    plain = load.replace("(gr8s.network::*cni-service-packets* t)",
                         "(gr8s.network::*cni-service-packets* nil)")
    return forms + [("kernel-load", load), ("kernel-load", load), ("kernel-load-plain", plain)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gr8s", type=Path, required=True)
    parser.add_argument("--report-directory", type=Path, required=True)
    parser.add_argument("--state-parent", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--require-prepared", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root in a disposable VM")
    binary = args.gr8s.resolve(strict=True)
    native_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="gr8s-cni-profile.", dir=args.state_parent))
    args.report_directory.mkdir(parents=True, exist_ok=True)
    report = {"root": str(root), "nativeSHA256": native_sha256,
              "measurements": [], "passed": False}
    process = None
    log = (args.report_directory / "native.log").open("w")
    try:
        process = subprocess.Popen(
            [str(binary), "serve", "--runtime", "containerd", "--state-directory", str(root / "state"),
             "--port", "18191", "--node-port", "17448", "--containerd-log-root", str(root / "pods"),
             "--kubeconfig", str(root / "kubeconfig"), "--debug-slynk-port", "4017"],
            env=dict(os.environ, GR8S_ENABLE_PACKET_SERVICES="1"), stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 180
        while True:
            if process.poll() is not None:
                raise RuntimeError("native process exited during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("native setup timeout")
            # Map creation follows Service program compilation. Also require node registration.
            if (root / "state/agent/containerd/bpf/service-lb/gr8s_pkt_tcp").exists():
                ready = subprocess.run(["kubectl", "--kubeconfig", str(root / "kubeconfig"),
                                        "--request-timeout=5s", "get", "nodes", "-o", "json"],
                                       capture_output=True, text=True)
                if ready.returncode == 0 and json.loads(ready.stdout).get("items"):
                    break
            time.sleep(.2)
        with socket.create_connection(("127.0.0.1", 4017), timeout=180) as connection:
            debug.send(connection, (root / "state/debug/slynk.secret").read_text().strip())
            for index, (name, form) in enumerate(measurements(root), 1):
                status, output = debug.evaluate(connection, form, index)
                item = {"name": name, "status": status, "output": output}
                for key in ("wall-seconds", "cpu-seconds", "maps", "programs"):
                    match = re.search(":" + key.upper() + r"\s+([0-9.eE+-]+)", output)
                    if match:
                        item[key] = float(match[1]) if key.endswith("seconds") else int(match[1])
                report["measurements"].append(item)
                print(name, status, output, flush=True)
                if status != "ok" or output.startswith("ERROR:"):
                    raise RuntimeError("debug evaluation failed")
                if name == "cache" and args.require_prepared:
                    assert re.search(r":PLAIN-COLD\s+NIL", output) and re.search(r":SERVICE-COLD\s+NIL", output), \
                        "native endpoint caches were not prepared"
                if name != "cache":
                    assert (item["maps"], item["programs"]) == ((16, 2) if name in ("plain", "kernel-load-plain") else (27, 5))
                if name.startswith("kernel-load"):
                    assert re.search(r":TEMPLATES-UNCHANGED\s+T", output), "loader mutated compiled templates"
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        if process:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                report["shutdownTimeout"] = True
            report["exitCode"] = process.returncode
            if process.returncode != 0 or report.get("shutdownTimeout"):
                report["passed"] = False
        log.close()
        # Remove only this owned process's mounts and state.
        mounts = [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()
                  if line.split()[4].startswith(str(root) + "/")]
        for mount in sorted(mounts, reverse=True):
            subprocess.run(["umount", "-l", mount], check=False)
        removed = subprocess.run(["rm", "-rf", "--one-file-system", str(root)], check=False)
        report["cleanupCompleted"] = removed.returncode == 0 and not root.exists()
        if not report["cleanupCompleted"]:
            report["passed"] = False
        (args.report_directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
