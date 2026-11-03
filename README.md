# gr8s

gr8s is a small Kubernetes-compatible Pod control plane written in Common
Lisp. One dumped native image provides the control-plane, node-agent, and CNI
roles. It serves the Kubernetes HTTP API on loopback and uses the same basic
runtime boundary as k3s: containerd reached through the Kubernetes CRI, rather
than shelling out to Podman. Workload execution is currently verified on the
local node through the same private gRPC control channel used by standalone
agents. The control plane schedules Pods and publishes desired state; the agent
owns the node runtime and reports observed status.

The runtime client is Common Lisp too. gr8s uses ag-gRPC over a Unix-domain
socket and generated bindings for the pinned Kubernetes CRI v1 schema. The
native build embeds pinned, statically linked containerd 2.4.2,
`containerd-shim-runc-v2`, runc 1.5.2, and CNI `bridge`, `host-local`, and
`loopback` plugins 1.9.1. It also embeds a TC/eBPF classifier compiled from Lisp
by Whistler 1.15.0. The dumped gr8s image implements the CNI protocol as a thin Unix-socket client.
The agent owns IPAM, native rtnetlink setup, and the Whistler loader.
At startup the local gr8s agent
mounts a private `tmpfs`, materializes the payload there, starts its own
containerd, and unmounts the payload after containerd stops. It also mounts a
private BPF filesystem under the selected state directory for the lifetime of
the managed runtime:

```text
kubectl -> gr8s HTTP API -> scheduler -> desired-state snapshot
                                           |
                                           v
                              gRPC NodeService.Connect
                                           |
                                           v
                    gr8s agent -> reconciler -> CRI v1 -> containerd
                                                            |
                                                            +-> runc
                                                            +-> gr8s CNI client
                                                                      |
                                                               agent Unix socket
                                                                      |
                                                        IPAM -> routed veths
                                                                      |
                                                               Whistler TC/eBPF
```

Verified CRI operations include runtime version discovery, image pull, Pod
sandbox creation, container creation and start, status/exit-code observation,
CRI log output, and clean container/sandbox removal. The node agent uses this
managed containerd adapter by default. The existing Podman adapter remains only
as a legacy compatibility implementation.

## Kubernetes surface

The current API supports Pods in the `default` namespace:

- `kubectl apply`, `get`, `describe`, and `delete`
- images, commands, arguments, environment variables, and container ports
- durable desired state and optimistic resource-version checks
- periodic, idempotent reconciliation with transient-failure retry

The log and exec API routes exist, but their correlated agent-operation proxy
is still being completed after the runtime ownership split. Services,
Deployments, volumes, production multi-node workload execution, and Kubernetes
API authentication/TLS are outside the verified boundary. The API server
refuses non-loopback listener addresses.

## Runtime architecture

The executable has three entry paths:

- `gr8s serve` runs the HTTP control plane and a loopback gRPC node endpoint;
- `gr8s agent` enrolls with a one-time token, persists its node key and
  certificate, and maintains the revisioned desired-state session;
- a CNI invocation is selected automatically when `CNI_COMMAND` is present.

`serve` starts a local agent named `gr8s-local` by default. That agent crosses
the same ag-gRPC boundary as a separately launched agent; `--disable-agent`
runs a control-plane-only process and does not create a managed node runtime.
The node endpoint defaults to loopback port 7443. Set `--node-listen` and
`--node-port` for a node-facing address; the Kubernetes HTTP API stays on
loopback. Agents advertise the source IPv4 address of their control connection
for VXLAN, or use an explicit `--node-address` on multi-interface hosts. The
local node name can be changed with `--node-name`.

Enrollment generates the private key on the node, verifies the returned cluster
CA against `--ca-pin`, and stores `node.key`, `node.crt`, `ca.crt`, and the
last-applied revision below the agent state directory. Revisioned sessions carry
node hello, heartbeat, complete desired-state snapshots, observed Pod status,
and durable revision acknowledgements. The agent persists assigned Pods,
reconciles them through its node runtime, adopts matching runtime objects after
a restart, and treats omission from an authoritative snapshot as deletion.

gr8s does not reimplement an OCI runtime. Its embedded containerd owns images,
sandboxes, containers, and the OCI runtime lifecycle. gr8s owns desired state,
while each agent calls containerd's `runtime.v1.RuntimeService` and
`ImageService` directly over its private Unix socket. containerd root, state,
temporary files, CRI socket, runc state, shim sockets, and logs are configured
as agent-owned paths.

The checked-in [`proto/cri-v1.proto`](proto/cri-v1.proto) is the full CRI v1
schema pinned from Kubernetes `cri-api` v0.36.0. Its generated Common Lisp
bindings live in `src/cri-v1-generated.lisp`.

Managed Pods receive directly routed veth pairs and `/32` addresses from
persistent agent IPAM. The control plane assigns each node a distinct Pod CIDR
within `10.88.0.0/16` and includes the network configuration in desired-state
snapshots. The agent persists that assignment and restores IPAM before restarting
reconciliation. Containerd invokes only the `gr8s` CNI plugin, which sends typed
requests to the agent's private Unix socket. CNI ADD retains its durable lease
through partial failures; DEL releases it only after removing policy and links.

Each Pod uses `169.254.1.1` as its link-local gateway and DNS server. The agent
serves DNS there and writes the standard `default.svc.cluster.local`,
`svc.cluster.local`, and `cluster.local` searches into the Pod resolver. It
answers `kubernetes.default.svc.cluster.local` authoritatively and forwards names
outside `cluster.local` to the host's IPv4 resolvers, over UDP or TCP.

The Whistler classifier attaches to Pod egress through the agent. It uses an
agent-initialized map to check the exact IPAM IPv4 address and interface MAC,
validates ARP sender identity, and drops malformed or unsupported frames. It
counts accepted/dropped packets and bytes, rejected spoofs, malformed packets,
and unsupported protocols. Identity initialization precedes TCX attachment;
replacement links are attached and pinned before atomically replacing the old
pin. Existing counter maps survive repeated CNI ADD calls.

Each endpoint has `rejected_spoofs`, `endpoint_identity`, and `traffic_stats`
maps alongside its `tcx-egress` link under
`AGENT_STATE_DIR/containerd/bpf/CONTAINER_ID/`. CHECK validates kernel map schemas,
identity, and the TCX interface/direction; DEL removes staged links and all maps
even after the Pod namespace disappears. Tests exercise the actual compiled
bytecode on packet fixtures. Privileged kernel verification and telemetry
publication remain in progress.

The native VXLAN backend uses static router neighbors and forwarding database
entries, preserving Pod source addresses across nodes. Isolated two-node kernel
tests cover bidirectional connectivity, the 1450-byte inner MTU, repeated setup,
and peer route removal. Node underlay addresses are durable control-plane
records. Address changes and withdrawals publish new peer snapshots. Agents
journal pending topology changes before touching the kernel and retain the last
applied topology until reconciliation succeeds, so a restart can remove stale
entries from a partial update. A changed local underlay replaces the owned
tunnel while retaining Pod endpoints and allocations.

## Requirements

- Linux and SBCL for building
- ASDF dependencies from `gr8s.asd`; this checkout includes an OCICL lockfile
  and dependency tree
- `kubectl` for client-side smoke testing
- root privileges and working cgroup delegation for running real Pods
- Linux 6.6 or newer with TCX eBPF support and BPF/network-administration
  privileges for the Whistler CNI stage
- Podman only for the optional legacy-adapter integration test

## Build and run the self-contained server

Build the static Go runtime payload and dump it into the SBCL executable:

```sh
make native
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

No Podman, system containerd, or host glibc is used by the embedded runtime
payload. Root is still required for the Linux facilities used by containers:
mounts, namespaces, cgroups, and the overlay snapshotter.

To accept agents from another machine, select the control node's reachable
IPv4 address (replace the documentation addresses below with your node IPs):

```sh
sudo build/gr8s serve --state-directory /var/lib/gr8s-control \
  --node-listen 192.0.2.10 --node-address 192.0.2.10
```

With `serve` running, create the second node's join token from another terminal
on the control node:

```sh
sudo build/gr8s join-token --state-directory /var/lib/gr8s-control \
  --node-name worker-b
```

`join-token` uses the existing cluster CA and prints JSON containing a one-time,
node-bound `token` and its `caPin`. On the second node, use those values with
the same dumped executable:

```sh
sudo build/gr8s agent --server 192.0.2.10:7443 --node-name worker-b \
  --state-directory /var/lib/gr8s-worker-b --node-address 192.0.2.11 \
  --token TOKEN --ca-pin CA_PIN
```

The two nodes need underlay connectivity for the node endpoint and VXLAN UDP
port 4789. Each agent receives its own Pod CIDR and the peer route set; no
bridge or host-local CNI configuration is required.

For development against an already-running containerd, opt into external mode:

```sh
scripts/gr8s serve \
  --containerd-mode external \
  --containerd-socket /run/containerd/containerd.sock
```

Then, from another terminal:

```sh
kubectl --kubeconfig /tmp/gr8s.kubeconfig apply -f pod.yaml
kubectl --kubeconfig /tmp/gr8s.kubeconfig get pods
kubectl --kubeconfig /tmp/gr8s.kubeconfig describe pod POD_NAME
kubectl --kubeconfig /tmp/gr8s.kubeconfig delete pod POD_NAME
```

`kubectl logs` and `kubectl exec` return to this example once their correlated
operation streams cross the node-agent gRPC boundary.

Runtime objects are labeled with gr8s ownership metadata so reconciliation and
deletion can avoid unrelated workloads.

The pinned containerd 2.4.2 daemon, shim, and baseline CNI plugins 1.9.1 are
built from Go source with cgo disabled; the pinned static runc release is
checksum-verified. The dumped Common Lisp image is exposed to containerd under
the `gr8s` CNI name, so there is no separate CNI helper binary.
Whistler compiles the egress guard directly from Common Lisp without LLVM or a
C toolchain. Every embedded executable ELF is checked for
dynamic interpreters and shared-library dependencies, and the classifier is
checked as an eBPF ELF object:

```sh
make containerd-bundle
```

## Test

Run the ordinary Common Lisp and HTTP suite:

```sh
make test
make check
```

The native routed-veth backend can also be exercised without sudo on hosts
that allow unprivileged user/network namespaces:

```sh
make test-routed-network
```

This creates two isolated Pod namespaces, verifies host-to-Pod and routed
Pod-to-Pod connectivity, checks repeated setup and deletion after namespace
removal, and tests namespace restoration on an agent worker thread. Link,
address, and route changes use Common Lisp rtnetlink calls.

To exercise native VXLAN between two isolated node namespaces, each with its own
Pod namespace and CIDR:

```sh
make test-vxlan-network
```

The agent CNI integration test also checks the real Unix-socket client, durable
IPAM restoration across an agent restart, and Pod DNS over UDP and TCP:

```sh
make test-agent-network
```

This substitutes only the BPF policy operations because unprivileged user
namespaces cannot load those programs. These kernel tests do not exercise
containerd or eBPF and do not replace the full smoke gates.

The live topology test adds real gRPC agent sessions in separate node network
namespaces. It checks source-address discovery, snapshot publication,
bidirectional VXLAN traffic, tunnel restoration before reconnect, a peer
underlay change, and route withdrawal:

```sh
make test-node-topology
```

Run the self-contained native smoke workflow. Invoke `make` as your normal
user; the target builds the embedded payload without privileges and uses
`sudo` only to start the local agent's managed containerd and exercise a real
Pod. During the agent-operation transition, this remains the gate that will
restore logs and exec coverage:

```sh
make smoke
```

The disposable legacy Podman test is opt-in:

```sh
make test-podman
```

The direct containerd checks are opt-in and require a prepared CRI socket:

```sh
make test-containerd
```

The lifecycle test pulls `docker.io/library/busybox:1.37.0` and creates real
runtime objects, then removes them in cleanup. Its containerd must have a
working CRI plugin, snapshotter, OCI runtime, pause image, and CNI configuration.

## Native executable

SBCL dumps the loaded system and all seven runtime artifacts into a native
image, avoiding an ASDF load and external runtime installation on startup.
`build/gr8s` forwards arguments to the dumped `build/gr8s.bin` payload:

```sh
make native
build/gr8s --help
build/gr8s runtime-assets
```

Useful targets include:

```text
make containerd-bundle build and verify containerd, runc, and CNI payloads
make test          unit and HTTP tests
make test-containerd include live CRI/containerd integration tests
make test-podman   include the legacy Podman integration test
make test-whistler-cni build the eBPF object and test the Common Lisp CNI path
make check         shell syntax checks plus tests
make smoke         build normally, then sudo the embedded-containerd smoke workflow
make run           start the current server
make kubeconfig    write a loopback kubeconfig
make native        build the dumped SBCL executable
make clean         remove build outputs
```

See [`docs/design.md`](docs/design.md) for the compatibility and architecture
boundary.
