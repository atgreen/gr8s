# gr8s

**A self-contained Kubernetes implementation in Common Lisp, with an eBPF dataplane.**

gr8s puts a Kubernetes API server, controllers, scheduler, node agent,
container runtime, networking, and datastore in one native executable. It uses
`kubectl` and standard Kubernetes manifests. You can run it on one node or
across a cluster.

The control plane and node agent are written from scratch in Common Lisp. The
binary embeds containerd and runc, compiles its own eBPF networking programs,
and includes a Raft datastore for high availability.

> **Project status:** gr8s is experimental and has **not passed Kubernetes
> conformance**. It is intended for exploration, development, and testing.
> Evaluate its compatibility and operational behavior before production use.
> See the [API coverage](docs/kubernetes-surface.md),
> [known gaps](docs/k3s-gap-inventory.md), and
> [conformance results](docs/CONFORMANCE.md) for the current scope and evidence.

## Why gr8s?

- The same executable can run a complete single-node cluster, a control plane,
  or a worker agent. It includes its container runtime and CNI integration. It
  also supports preloaded images for airgapped nodes.
- The Kubernetes API provides workload controllers, scheduling, RBAC, Services,
  persistent storage, and custom resources. The
  [compatibility reference](docs/kubernetes-surface.md) lists the supported
  behavior and limitations.
- The kernel handles Service load balancing, NetworkPolicy, same-node
  forwarding, and Pod anti-spoofing. The agent uses Whistler to compile eBPF
  directly from Lisp, without clang or LLVM.
- Raft replicates control-plane state without an external database. Certificates
  authenticate node enrollment and internal communication.
- An adaptive WireGuard overlay selects paths between nodes. Authenticated
  BitTorrent v2 peers share verified image blobs. This avoids repeated registry
  downloads during multi-node rollouts.
- The API, controllers, agent, networking compiler, and datastore use Common
  Lisp. An optional Slynk endpoint lets you inspect a live development system.

Run `gr8s skill` for built-in operator and AI agent guidance, including first-response
checks, live Slynk inspection, and selector-scoped kernel tracing. It works offline
and can be saved with `gr8s skill > gr8s-guide.md`.

## Getting started

Build gr8s on Linux with **SBCL** and the project's ASDF dependencies. To run a
cluster, you need **Linux 6.6+ with TCX eBPF support**, **root privileges**, and
working cgroups. Install **`kubectl`** to use the Kubernetes API. See the
[build requirements](docs/building-and-testing.md#requirements) and
[runtime payload details](docs/runtime.md#the-self-contained-payload) for the
full setup. Start with a disposable Linux VM.

From the repository root:

```sh
make native

# Start a single-node cluster; leave this running.
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

In another terminal, create a Pod and wait until it is ready. The server creates
an owner-only kubeconfig, so these commands use `sudo` to read it. The node needs
registry access to download the image.

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig run web \
  --image=docker.io/library/nginx:1.27 --restart=Never
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig wait \
  --for=condition=Ready pod/web --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig get pods -o wide
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig logs web

# Remove the example workload when finished.
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig delete pod web
```

Stop the server with Ctrl-C. The state directory keeps the cluster state for the
next start.

See [Building, running & testing](docs/building-and-testing.md) to add
[worker nodes](docs/building-and-testing.md#a-second-node), use external
containerd, or run tests. The runtime guide explains how to
[preload images](docs/runtime.md#preloaded-images-airgap).

To manage a persistent server or agent with systemd, see
[Installing and operating gr8s with systemd](docs/installing.md).
It covers verified upgrades, rollback, scoped cleanup, and uninstall.

## Kubernetes capabilities

The implemented API surface includes:

| Area | Capabilities |
|---|---|
| Workloads | Pods, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, ReplicationControllers, rolling updates, owner-reference garbage collection |
| Scheduling | Resource requests and limits, node affinity and anti-affinity, taints and tolerations, priority and preemption, host ports, ephemeral-storage eviction |
| Configuration and identity | ConfigMaps, Secrets, ServiceAccounts, bound tokens, RBAC, certificate issuance, admission webhooks, CEL admission policies |
| Networking | ClusterIP, NodePort and LoadBalancer Services, EndpointSlices, NetworkPolicy, Gateway API, cluster DNS |
| Storage | PersistentVolumes and Claims, StorageClasses, local-path provisioning, NFS, CSI drivers |
| Observability | Metrics endpoints, [Lisp heap/GC and watch retention](docs/control-plane-metrics.md), cAdvisor and API server/scheduler series, resource metrics for `kubectl top` |
| Extensibility | Schema-backed custom resources, defaulting, pruning, validation, finalizers |

Support varies by feature. This overview does not imply complete upstream
semantics. See the [Kubernetes API surface](docs/kubernetes-surface.md) for
supported operations, validation evidence, and limitations.

## How it fits together

```text
kubectl -> Kubernetes API -> controllers and scheduler -> desired state
                                                        |
                                                  node protocol
                                                        |
                                                     agent
                                                   /       \
                                         CRI / containerd   networking
                                                |           /       \
                                               runc    routed veths   eBPF
```

`gr8s serve` runs the control plane and a local agent. Worker nodes run
`gr8s agent` and connect through an authenticated gRPC protocol. The control
plane schedules work and publishes the desired state. Agents reconcile
containers and networking, then report their status. By default, each agent
manages its own containerd instance.

For a replicated control plane, Raft supports three voting members or two
members and a witness. A quorum can continue after a leader fails. A single-node
cluster needs no Raft configuration. See
[High availability](docs/high-availability.md) for membership and durability
guarantees. See [Design](docs/design.md) for component boundaries.

## Networking and security

Whistler is the embedded Lisp-to-eBPF compiler. The agent uses it to compile and
load networking programs at runtime. A socket load balancer directs Pod
connections to ready Service backends. Programs at Pod veths enforce
NetworkPolicy and anti-spoofing. A same-node fast path sends traffic directly to
local Pods. The agent also implements Gateway API routing.

For cross-node traffic, the WireGuard overlay uses authenticated endpoint
advertisements, active path trials, and eBPF telemetry. It supports NAT
traversal, encrypted relaying, packet-size discovery, and topology-aware sparse
routing. `gr8s network explain NODE PEER` shows why it selected a path. Path
health and locality also affect Service backend selection and image-peer
ordering.

Internal TLS uses a pure-Lisp TLS 1.3 implementation. It prefers the hybrid
X25519MLKEM768 key exchange, which combines classical and post-quantum
cryptography. Classical X25519/P-256 is available as a fallback. Image
distribution uses node certificates and mutual TLS to authenticate its private
peer swarm. Each node can seed the verified blobs that it receives.

See [Networking & the eBPF dataplane](docs/networking.md) for configuration,
protocol details, and operational behavior.

## Container runtimes

The embedded containerd uses runc by default. `RuntimeClass` resolves Pod
overhead, scheduling constraints, and the CRI runtime handler. Pods use it to
select a configured handler on the node.

The optional gVisor and Kata Containers runtimes support sandboxed and microVM
workloads. gr8s can install and validate them automatically. Use
`gr8s runtime install gvisor` or `gr8s runtime install kata` to install them,
then select the runtime with `RuntimeClass`. See
[Runtime & the container stack](docs/runtime.md) for configuration.

## Development and documentation

Run the unit and HTTP tests with `make test`. Tests that load eBPF programs or
run real containers need a privileged environment. Use a disposable VM and
follow the [testing guide](docs/building-and-testing.md#test-matrix).

- [Building, running & testing](docs/building-and-testing.md)
- [Kubernetes API surface](docs/kubernetes-surface.md)
- [Networking & the eBPF dataplane](docs/networking.md)
- [Runtime & the container stack](docs/runtime.md)
- [High availability](docs/high-availability.md)
- [In-process patching](docs/live-patching.md)
- [Design & compatibility boundary](docs/design.md)
- [Multi-node design](docs/multi-node-design.md)
- [Known compatibility gaps](docs/k3s-gap-inventory.md)
- [Conformance results](docs/CONFORMANCE.md)

## Versioning

A gr8s version combines the Kubernetes API version with a gr8s release suffix.
For example: `v1.37.2-gr8s.0`. The API version identifies the compatibility
target. It does not show Kubernetes conformance. `gr8s version` and the
Kubernetes `/version` endpoint report the running build's version.

## License

[Apache License 2.0](LICENSE).
