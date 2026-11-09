# Building, running & testing

A quick single-node start is in the [README](../README.md#getting-started); this
document covers the full picture — requirements, multi-node clusters, the native
payload, the test matrix, and debugging a live process.

## Requirements

- Linux and SBCL for building
- ASDF dependencies from `gr8s.asd` (this checkout includes an OCICL lockfile and
  dependency tree)
- `kubectl` for client-side smoke testing
- root privileges and working cgroup delegation for running real Pods
- Linux 6.6 or newer with TCX eBPF support and BPF/network-administration
  privileges for the Whistler CNI stage
- Python 3, `ip`, `nsenter`, `nft`, and a non-loopback upstream resolver for the
  privileged two-node smoke

## Build & run the self-contained server

Build the static runtime payload and dump it into the SBCL executable:

```sh
make native
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

Without `--kubeconfig`, `serve` writes an owner-only `kubeconfig` in the state
directory and prints its path. `gr8s kubeconfig [--server URL]` prints a
kubeconfig to standard output, or writes it with `--output FILE`. No system
containerd or host glibc is used by the embedded payload; root is still required
for mounts, namespaces, cgroups, and the overlay snapshotter.

Then, from another terminal:

```sh
kubectl --kubeconfig /tmp/gr8s.kubeconfig apply -f pod.yaml
kubectl --kubeconfig /tmp/gr8s.kubeconfig get pods
kubectl --kubeconfig /tmp/gr8s.kubeconfig describe pod POD_NAME
kubectl --kubeconfig /tmp/gr8s.kubeconfig delete pod POD_NAME
```

### Entry paths

- `gr8s serve` runs the HTTP control plane and a loopback gRPC node endpoint, and
  optionally joins a Raft cluster with `--raft-init`/`--raft-join` (see
  [high availability](high-availability.md)). It starts a local agent named
  `gr8s-local` by default; `--disable-agent` runs a control-plane-only process.
- `gr8s agent` enrolls with a one-time token, persists its node key and
  certificate, and maintains the revisioned desired-state session.
- `gr8s witness` runs a headless Raft voting member (a quorum tie-breaker).
- `gr8s version` prints the version; a CNI invocation is selected automatically
  when `CNI_COMMAND` is present.

The node endpoint defaults to loopback port 7443. Set `--node-listen` and
`--node-port` for a node-facing address; the Kubernetes HTTP API stays on
loopback. Agents advertise the source IPv4 address of their control connection for
VXLAN, or use an explicit `--node-address` on multi-interface hosts.

## A second node

Start `serve` bound to the control node's reachable IPv4 address:

```sh
sudo build/gr8s serve --state-directory /var/lib/gr8s-control \
  --node-listen 192.0.2.10 --node-address 192.0.2.10
```

Create the worker's join token from another terminal on the control node:

```sh
sudo build/gr8s join-token --state-directory /var/lib/gr8s-control \
  --node-name worker-b
```

`join-token` uses the existing cluster CA and prints JSON with a one-time,
node-bound `token` and its `caPin`. On the second node, use those values:

```sh
sudo build/gr8s agent --server 192.0.2.10:7443 --node-name worker-b \
  --state-directory /var/lib/gr8s-worker-b --node-address 192.0.2.11 \
  --token TOKEN --ca-pin CA_PIN
```

The two nodes need underlay connectivity for the node endpoint and VXLAN UDP port
4789. Each agent receives its own Pod CIDR and the peer route set; no bridge or
host-local CNI configuration is required. Enrollment verifies the server
certificate against `--ca-pin` before sending the token, generates the private key
on the node, and stores `node.key`, `node.crt`, `ca.crt`, the assigned Pod CIDR,
and the last-applied revision below the agent state directory.

See [runtime.md](runtime.md) for **preloaded (airgap) images** and **external
containerd** mode.

## The native executable

SBCL dumps the loaded system and all runtime artifacts into a native image,
avoiding an ASDF load and external runtime installation on startup. `make native`
dumps straight into `build/gr8s` (no launcher script):

```sh
make native
build/gr8s --help
build/gr8s runtime-assets
```

Useful targets:

```text
make containerd-bundle   build and verify containerd, runc, and CNI payloads
make test                unit and HTTP tests
make test-containerd     include live CRI/containerd integration tests
make test-whistler-cni   build the eBPF object and test the Common Lisp CNI path
make check               shell syntax checks plus tests
make smoke               build normally, then sudo the embedded-containerd smoke
make run                 start the current server
make kubeconfig          write a loopback kubeconfig
make native              build the dumped SBCL executable
make clean               remove build outputs
```

## Test matrix

Ordinary Common Lisp and HTTP suite:

```sh
make test
make check
```

**Routed-veth backend** (no sudo on hosts allowing unprivileged user/network
namespaces) — creates two isolated Pod namespaces and verifies host-to-Pod and
routed Pod-to-Pod connectivity, repeated setup/deletion, and namespace restoration
on a worker thread:

```sh
make test-routed-network
```

**Native VXLAN** between two isolated node namespaces, each with its own Pod
namespace and CIDR:

```sh
make test-vxlan-network
```

**Agent CNI integration** — the real Unix-socket client, durable IPAM restoration
across an agent restart, and Pod DNS over UDP and TCP (BPF policy ops are
substituted, since unprivileged user namespaces can't load those programs):

```sh
make test-agent-network
```

**Live node topology** — real gRPC agent sessions in separate node network
namespaces: source-address discovery, snapshot publication, bidirectional VXLAN,
tunnel restoration before reconnect, a peer underlay change, and route withdrawal:

```sh
make test-node-topology
```

**Self-contained native smoke** — build the payload unprivileged, then `sudo` only
to start the local agent's managed containerd and exercise a real Pod. Checks DNS,
logs, exec success/failure, source-spoof rejection, exported policy counters, and
namespace/pin/shim cleanup:

```sh
make smoke
```

**Two-node smoke** — a control plane and two containerd agents with persistent,
separate mount/network namespaces; routed underlay veths carry VXLAN without a
bridge. Verifies Pod connectivity, DNS, logs, exec, tunnel dependency/repair,
traffic while one agent is stopped, certificate-based restart, unchanged Pod
identities/IPs, fresh telemetry, live CNI CHECK, and cleanup:

```sh
make smoke-two-node
```

Set `GR8S_SMOKE_KEEP_WORKDIR=1` to keep harness logs;
`GR8S_TWO_NODE_FAIL_AFTER_CREATE=1` exercises failure cleanup after both Pods reach
Running.

**Service map restart recovery** — in a disposable root VM, copy
`scripts/test-service-restart.py`, `scripts/test-service-traffic.py` and
`scripts/smoke-two-node.py` together with the native binary. The regression stops
one agent while retaining its Pods, deletes a Service while it is offline, seeds
orphan entries in all six Service control maps, and checks map identity,
withdrawal, Pod identity and Service traffic after restart. This uses native
containers; it does not establish guest connection-state survival.

```sh
python3 test-service-restart.py --gr8s ./gr8s --report-directory ./restart-evidence
```

Optional `--ctr /path/to/ctr` preloads the test image through the managed
containerd socket when testing independently of the image mirror.

**Direct containerd checks** (opt-in; require a prepared CRI socket with a working
CRI plugin, snapshotter, OCI runtime, pause image, and CNI configuration):

```sh
make test-containerd
```

## Conformance harness

Run the upstream PodTemplate lifecycle and chunking cases, or the entire certified
selection, in a disposable privileged Linux guest:

```sh
python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s --sonobuoy /path/to/sonobuoy

python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s --sonobuoy /path/to/sonobuoy \
  --certified-conformance --timeout 21600
```

The runner preserves the official Sonobuoy archive, native and worker logs, and
individual executed specs in its printed report directory. A passing result
requires every selected spec to execute and pass; running it does not establish
certification. `--image-archives DIRECTORY` stages preloaded images so specs don't
wait on cold pulls. See [CONFORMANCE.md](CONFORMANCE.md) for the current posture
and run records.

## Debugging a running cluster

`gr8s serve --debug-slynk-port PORT` starts an opt-in
[Slynk](https://github.com/joaotavora/sly) server for inspecting a live process.
It is off by default and is for disposable environments only: **it allows
arbitrary code execution as the gr8s user, normally root.** It binds to
`127.0.0.1` and requires a secret, newly generated at each start in
`<state>/debug/slynk.secret` (because `hostNetwork` Pods share loopback); a
connecting Emacs Sly client needs a matching `~/.sly-secret`.

Forms can also be evaluated from a shell, in the `gr8s` package:

```sh
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-threads)'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-backtraces "reconciler")'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-pod "default" "web")'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-journal 20)'
```

`*debug-store*` and `*debug-reconciler*` hold the live objects. The conformance
runner accepts `--debug-slynk-port PORT` and `--hold-on-failure SECONDS` to keep a
failed cluster running for inspection; both are refused with
`--certified-conformance`, because a process changed this way is not conformance
evidence.
