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
by Whistler 1.15.0. The dumped gr8s image itself implements the chained CNI
protocol and calls Whistler's Common Lisp loader directly.
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
                                                            +-> CNI -> gr8s0
                                                                       |
                                                                       +-> Whistler TC/eBPF
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
The node endpoint defaults to loopback port 7443 and can be changed with
`--node-port`; the local node name can be changed with `--node-name`.

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

Managed Pods receive network namespaces, veth pairs, and addresses from the
embedded CNI bridge and host-local plugins. The default network is `gr8s0` on
`10.88.0.0/16`; host-local keeps its allocation data under the selected gr8s
state directory. gr8s serves DNS on the bridge gateway at `10.88.0.1:53` and
writes the standard `default.svc.cluster.local`, `svc.cluster.local`, and
`cluster.local` searches into each Pod's resolver configuration. It answers
`kubernetes.default.svc.cluster.local` authoritatively and forwards names
outside `cluster.local` to the IPv4 resolvers in the host's `/etc/resolv.conf`,
over UDP or TCP.

Whistler is layered on top: a chained gr8s CNI
plugin attaches a Whistler-generated TC/eBPF program after the baseline CNI
plugin has created the link. The current 27-instruction egress guard rejects
IPv4 packets whose source is outside `10.88.0.0/16`, preventing a Pod from
spoofing an address outside the managed network, and counts rejections in an
eBPF map. The Common Lisp CNI path attaches it with a persistent TCX link and
pins both objects. The map lives at
`STATE_DIR/containerd/bpf/CONTAINER_ID/rejected_spoofs`, reuses it across
idempotent CNI ADD calls, and the link lives beside it as `tcx-egress`. CHECK
verifies both pins and the target interface; DEL removes both even if the Pod
network namespace has already disappeared. The private bpffs
is unmounted only after containerd stops. Whistler is not asked to replace CNI
link and IPAM setup.

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
