#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""How many browser nodes one server takes (podster-vyec).

Opens tabs on a join page in waves, in one headless Chromium, and every few seconds
samples the server over ssh (the gr8s process's resident memory, MemAvailable, CPU time
with niced time apart) and the cluster (browser nodes Ready, DaemonSet Pods Running).
Writes samples.csv and pods.csv into OUT and prints a summary.

  python3 scale-run.py --url http://10.77.77.20:8099/ --ssh 10.77.77.20 \\
      --kubeconfig ~/.kube/gr8s-laptop.yaml --waves 6 --per-wave 10 --out build/scale

The server must let this many tabs in from one address (--browser-max-per-client).
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PROBE = """apiVersion: apps/v1
kind: DaemonSet
metadata: {name: scale-probe, namespace: default}
spec:
  selector: {matchLabels: {app: scale-probe}}
  template:
    metadata: {labels: {app: scale-probe}}
    spec:
      nodeSelector: {gr8s.io/browser: "true"}
      tolerations: [{key: gr8s.io/browser, operator: Exists}]
      containers:
        - name: probe
          image: docker.io/library/busybox:1.37
          command: [sh, -c, "echo up; sleep 86400"]
"""


def sh(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, **kwargs).stdout


def kubectl(args, kubeconfig, **kwargs):
    return sh(["kubectl", "--kubeconfig", kubeconfig, *args], **kwargs)


def server_sample(host):
    """(rss_mib, available_mib, busy_ticks, total_ticks) of the gr8s server on HOST."""
    out = sh(["ssh", host,
              "pid=$(systemctl show -p MainPID --value gr8s-server); "
              "awk '/^VmRSS/{print $2}' /proc/$pid/status; "
              "awk '/^MemAvailable/{print $2}' /proc/meminfo; head -1 /proc/stat"]).split("\n")
    user, nice, system, idle, iowait, irq, softirq, steal = map(int, out[2].split()[1:9])
    busy = user + system + irq + softirq + steal
    return int(out[0]) / 1024, int(out[1]) / 1024, busy, busy + nice + idle + iowait


def nodes_ready(kubeconfig):
    items = json.loads(kubectl(["get", "nodes", "-l", "gr8s.io/browser=true", "-o", "json"], kubeconfig))["items"]
    return sum(1 for node in items
               if any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"].get("conditions", [])))


def probe_pods(kubeconfig):
    return json.loads(kubectl(["get", "pods", "-l", "app=scale-probe", "-o", "json"], kubeconfig))["items"]


def stamp(text):
    return time.mktime(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ssh", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--waves", type=int, default=6)
    parser.add_argument("--per-wave", type=int, default=10)
    parser.add_argument("--interval", type=float, default=30)
    parser.add_argument("--settle", type=float, default=60, help="seconds to keep sampling after the last wave")
    parser.add_argument("--no-pods", action="store_true", help="nodes only: no DaemonSet Pod on each")
    parser.add_argument("--chrome", default=os.path.expanduser(
        "~/.cache/ms-playwright/chromium_headless_shell-1228/chrome-headless-shell-linux64/chrome-headless-shell"))
    parser.add_argument("--port", type=int, default=9333)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    if not args.no_pods:
        kubectl(["apply", "-f", "-"], args.kubeconfig, input=PROBE)
    chrome = subprocess.Popen(
        [args.chrome, f"--remote-debugging-port={args.port}", f"--user-data-dir={os.path.join(args.out, 'profile')}",
         # A join page served over plain HTTP, as in a lab, still needs crypto.subtle.
         f"--unsafely-treat-insecure-origin-as-secure={urllib.parse.urlsplit(args.url)._replace(path='', query='', fragment='').geturl()}",
         "--no-first-run", "--disable-background-timer-throttling", "--disable-renderer-backgrounding",
         "--disable-backgrounding-occluded-windows", "--js-flags=--max-old-space-size=512", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=open(os.path.join(args.out, "chrome.log"), "w"))
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{args.port}/json/version", timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        start = time.time()
        opened = 0
        rows = []
        last = server_sample(args.ssh)
        next_wave = start
        end = start + (args.waves - 1) * args.interval + args.settle
        while time.time() < end:
            if opened < args.waves * args.per_wave and time.time() >= next_wave:
                for _ in range(args.per_wave):
                    request = urllib.request.Request(f"http://127.0.0.1:{args.port}/json/new?{args.url}", method="PUT")
                    urllib.request.urlopen(request, timeout=10).read()
                    opened += 1
                next_wave += args.interval
            time.sleep(5)
            sample = server_sample(args.ssh)
            busy = (sample[2] - last[2]) / max(1, sample[3] - last[3])
            last = sample
            row = {"t": round(time.time() - start), "tabs": opened, "nodes": nodes_ready(args.kubeconfig),
                   "running": 0 if args.no_pods else sum(1 for p in probe_pods(args.kubeconfig)
                                                         if p["status"].get("phase") == "Running"),
                   "rss_mib": round(sample[0]), "available_mib": round(sample[1]), "busy": round(busy, 3)}
            rows.append(row)
            print(json.dumps(row), flush=True)
        with open(os.path.join(args.out, "samples.csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        starts = []
        if not args.no_pods:
            for pod in probe_pods(args.kubeconfig):
                conditions = {c["type"]: c for c in pod["status"].get("conditions", [])}
                ready = conditions.get("Ready", {})
                if ready.get("status") == "True":
                    created = stamp(pod["metadata"]["creationTimestamp"])
                    starts.append({"pod": pod["metadata"]["name"], "created": round(created - start),
                                   "seconds": stamp(ready["lastTransitionTime"]) - created})
            with open(os.path.join(args.out, "pods.csv"), "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["pod", "created", "seconds"])
                writer.writeheader()
                writer.writerows(starts)
        base = rows[0]
        peak = max(rows, key=lambda r: r["nodes"])
        summary = {"tabs": opened, "peak_nodes": peak["nodes"],
                   "rss_mib_at_peak": peak["rss_mib"], "rss_mib_at_start": base["rss_mib"],
                   "mib_per_node": round((peak["rss_mib"] - base["rss_mib"]) / max(1, peak["nodes"] - base["nodes"]), 1),
                   "available_mib_min": min(r["available_mib"] for r in rows),
                   "busy_max": max(r["busy"] for r in rows)}
        if starts:
            seconds = sorted(s["seconds"] for s in starts)
            summary.update(pod_start_median=seconds[len(seconds) // 2],
                           pod_start_p95=seconds[min(len(seconds) - 1, int(len(seconds) * 0.95))],
                           pods_ready=len(seconds))
        print(json.dumps(summary, indent=2))
        with open(os.path.join(args.out, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
    finally:
        chrome.terminate()
        chrome.wait(timeout=30)
        if not args.no_pods:
            kubectl(["delete", "daemonset", "scale-probe", "--ignore-not-found"], args.kubeconfig)


if __name__ == "__main__":
    sys.exit(main())
