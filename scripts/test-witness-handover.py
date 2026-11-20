#!/usr/bin/env python3
"""Leader failure with two `gr8s serve` voters and a miniwit witness (podster-f15,
podster-00c), as real processes with agents disabled and a fake runtime.

Under write load the leader is frozen (SIGSTOP) for FREEZE seconds, ROUNDS times.
Reports the freezes in which the other voter took over, checks that no
acknowledged write is missing afterwards, and counts the entries in the
witness's log that hold a write's content in the clear.

Run it in a private network namespace so that the pod pool cannot collide with
the host's routes:

  (cd miniwit && go build -o /tmp/miniwit ./cmd/miniwit)
  unshare -Urn sh -c 'ip link set lo up; \
    python3 scripts/test-witness-handover.py build/gr8s /tmp/miniwit /tmp/handover'

Before the fix (1.37.2-g44eb5e6): the other voter took over in 1 of 6 freezes and
1865 of 1878 witness log entries were readable. After: 6 of 6, and none.

  test-witness-handover.py GR8S MINIWIT BASE [ROUNDS] [FREEZE]"""
import json, os, shutil, signal, subprocess, sys, time, pathlib, threading
binary, miniwit, base = (pathlib.Path(a).resolve() for a in sys.argv[1:4])
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 5
freeze = int(sys.argv[5]) if len(sys.argv) > 5 else 15
shutil.rmtree(base, ignore_errors=True); base.mkdir(parents=True, mode=0o700)
PORTS = {"a": (16443, 17443, 17000), "b": (26443, 27443, 27000)}
WPORT = 37000
procs = {}
def root(n): return base / n
def log(n): return base / f"{n}.log"
def start(n, mode, enrollment=None):
    api, grpc, raft = PORTS[n]
    root(n).mkdir(mode=0o700, exist_ok=True)
    args = [str(binary), "serve", "--disable-agent", "--runtime", "fake", "--state-directory", str(root(n)),
            "--listen", "127.0.0.1", "--port", str(api), "--node-listen", "127.0.0.1", "--node-port", str(grpc),
            "--node-name", n, "--raft-id", n, "--raft-listen", "127.0.0.1", "--raft-port", str(raft)] + mode
    if enrollment: args += ["--token", enrollment["token"], "--ca-pin", enrollment["caPin"]]
    procs[n] = subprocess.Popen(args, stdout=log(n).open("ab"), stderr=subprocess.STDOUT)
def run(*args, **kw): return subprocess.run([str(a) for a in args], capture_output=True, text=True, **kw)
def kubeconfig(n):
    f = base / f"{n}.kubeconfig"
    r = run(binary, "kubeconfig", "--state-directory", root(n), "--server", f"https://127.0.0.1:{PORTS[n][0]}", "--output", f)
    if r.returncode: raise RuntimeError(r.stderr[-400:])
def kubectl(n, *args, stdin=None, timeout="8s"):
    try:
        return subprocess.run(["kubectl", "--kubeconfig", str(base / f"{n}.kubeconfig"), f"--request-timeout={timeout}", *args],
                              capture_output=True, text=True, input=stdin, timeout=20)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timed out")
def wait_for(what, check, timeout=120, every=0.5, quiet=False):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = check()
            if v:
                if not quiet: print(f"  {what}: yes after {time.time()-t0:.0f}s", flush=True)
                return v
        except Exception: pass
        time.sleep(every)
    if not quiet: print(f"  {what}: NOT after {timeout}s", flush=True)
    return None
def metric(n, name):
    r = kubectl(n, "get", "--raw", "/metrics", timeout="3s")
    for line in r.stdout.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"): return float(line.split()[-1])
def leader():
    for n in ("a", "b"):
        if metric(n, "gr8s_raft_is_leader") == 1: return n
def members(n):
    return run(binary, "member", "list", "--kubeconfig", base / f"{n}.kubeconfig").stdout
def token(role, name):
    r = run(binary, "join-token", "--role", role, "--node-name", name, "--state-directory", root("a"))
    if r.returncode: raise RuntimeError(r.stderr[-400:])
    return json.loads(r.stdout)
acked, failed, lock, stop_writes = [], [0], threading.Lock(), [False]
counter = [0]
def writer(n):
    while not stop_writes[0]:
        with lock: counter[0] += 1; seq = counter[0]
        body = json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"w-{seq}", "namespace": "default"},
                           "data": {"secret": f"PLAINTEXT-MARKER-{seq}"}})
        r = kubectl(n, "create", "--validate=false", "-f", "-", stdin=body)
        with lock:
            if r.returncode == 0: acked.append(seq)
            else: failed[0] += 1
try:
    print(f"binary: {run(binary, '--version').stdout.strip()}; miniwit: {miniwit.name}", flush=True)
    start("a", ["--raft-init"]); wait_for("a has state", lambda: (root("a") / "pki").exists(), 60)
    time.sleep(2); kubeconfig("a"); wait_for("a ready", lambda: kubectl("a", "get", "--raw", "/readyz").returncode == 0)
    start("b", ["--join", f"127.0.0.1:{PORTS['a'][2]}"], token("control-plane", "b"))
    wait_for("b is a voter", lambda: any(l.split()[:2] == ["b", "voter"] for l in members("a").splitlines()), 180)
    kubeconfig("b")
    t = token("witness", "w")
    procs["w"] = subprocess.Popen([str(miniwit), "-join-address", f"127.0.0.1:{PORTS['a'][2]}", "-join-token", t["token"],
                                   "-ca-pin", t["caPin"], "-member-id", "w", "-node-name", "w",
                                   "-listen", f"127.0.0.1:{WPORT}", "-advertise", f"127.0.0.1:{WPORT}", "-data-dir", str(root("w"))],
                                  stdout=log("w").open("ab"), stderr=subprocess.STDOUT)
    wait_for("w is a witness", lambda: any(l.split()[:2] == ["w", "witness"] for l in members("a").splitlines()), 60)
    print("  " + members("a").strip().replace("\n", "\n  "), flush=True)
    for n in ("a", "b"):
        for _ in range(3): threading.Thread(target=writer, args=(n,), daemon=True).start()
    time.sleep(6)
    took_over = 0; lost_total = 0; verdict = 1
    for i in range(1, rounds + 1):
        old = wait_for("a leader", leader, 60, quiet=True)
        if not old: print(f"round {i}: no leader to freeze"); continue
        other = "b" if old == "a" else "a"
        before = len(acked)
        procs[old].send_signal(signal.SIGSTOP); t0 = time.time()
        new = wait_for("", lambda: metric(other, "gr8s_raft_is_leader") == 1, freeze, every=0.3, quiet=True)
        took = time.time() - t0
        time.sleep(max(0, freeze - took))
        during = len(acked) - before
        procs[old].send_signal(signal.SIGCONT)
        if new: took_over += 1
        print(f"round {i}: froze leader {old} for {freeze}s: " +
              (f"{other} took over after {took:.1f}s" if new else f"NO new leader; {other} stayed a follower") +
              f"; writes acknowledged during the freeze: {during}", flush=True)
        time.sleep(8)
    stop_writes[0] = True; time.sleep(10)
    print(f"freezes in which the other voter took over: {took_over} of {rounds}", flush=True)
    for n in ("a", "b"):
        have = None
        for _ in range(10):
            r = kubectl(n, "get", "configmaps", "-n", "default", "-o", "json", timeout="30s")
            if r.returncode == 0:
                have = {int(x["metadata"]["name"][2:]) for x in json.loads(r.stdout)["items"] if x["metadata"]["name"].startswith("w-")}; break
            time.sleep(3)
        if have is None: print(f"  {n}: could not list"); lost_total += 1; continue
        lost = sorted(set(acked) - have)
        print(f"  {n}: {len(set(acked) & have)} of {len(acked)} acknowledged writes present; LOST {len(lost)} {lost[:5] if lost else ''}", flush=True)
        lost_total += len(lost)
    wlog = (root("w") / "raft" / "log.jsonl").read_text(errors="replace")
    lines = wlog.splitlines()
    print(f"witness log: {len(lines)} entries, {sum('PLAINTEXT-MARKER' in l for l in lines)} contain a write's content in the clear, "
          f"{sum(':SEALED' in l for l in lines)} sealed", flush=True)
    wl = log("w").read_text(errors="replace")
    print(f"witness: stood in {wl.count('standing in for')} times, elected {wl.count('elected for term')}, handed over {wl.count('handed over to')}, gave up {wl.count('gave up leading')}", flush=True)
    readable = sum('PLAINTEXT-MARKER' in l for l in lines)
    for n in ("a", "b"):
        text = log(n).read_text(errors="replace")
        print(f"  {n} log: {text.count('sealed for witnesses under key')} seal-key line(s), {text.count('unsealed') + text.count('does not verify')} seal refusals", flush=True)
    verdict = 0 if (took_over == rounds and lost_total == 0 and readable == 0) else 1
    print("PASS" if verdict == 0 else "FAIL", flush=True)
finally:
    for n, p in list(procs.items()):
        try: p.send_signal(signal.SIGCONT)
        except Exception: pass
        p.send_signal(signal.SIGTERM)
    for p in procs.values():
        try: p.wait(40)
        except subprocess.TimeoutExpired: p.kill()
sys.exit(verdict)
