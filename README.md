# gr8s

**A self-contained, eBPF-native Kubernetes implementation in Common Lisp.**

gr8s brings a Kubernetes API server, controllers, scheduler, node agent,
container runtime, networking, and datastore together in one native executable.
Use `kubectl` and Kubernetes manifests to run workloads on a single node or
across a cluster.

The control plane and node agent are written from scratch in Common Lisp.
The binary embeds containerd and runc to run containers, compiles its own eBPF
programs for networking, and includes a Raft datastore for high availability.

> **Project status:** gr8s is experimental and has **not passed Kubernetes
> conformance**. It is intended for exploration, development, and testing;
> compatibility and operational behavior need evaluation before production use.
> See the [API coverage](docs/kubernetes-surface.md),
> [known gaps](docs/k3s-gap-inventory.md), and
> [conformance results](docs/CONFORMANCE.md) for the current scope and evidence.

## Why gr8s?

- **One executable to deploy.** The same binary runs a complete single-node
  cluster, a control plane, or a worker agent. It carries its container runtime
  and CNI integration, and supports preloaded images for airgapped nodes.
- **Familiar Kubernetes workflows.** Workload controllers, scheduling, RBAC,
  Services, persistent storage, and custom resources are available through the
  Kubernetes API. The [compatibility reference](docs/kubernetes-surface.md)
  documents supported behavior and limitations.
- **An integrated eBPF dataplane.** Service load balancing, NetworkPolicy,
  same-node forwarding, and Pod anti-spoofing run in the kernel. The agent
  compiles eBPF directly from Lisp using Whistler, without clang or LLVM.
- **Built-in cluster coordination.** Raft replicates control-plane state without
  an external database. Node enrollment and internal communication use
  certificate-based authentication.
- **Cluster-aware networking and image delivery.** An adaptive WireGuard overlay
  selects paths between nodes. Authenticated BitTorrent v2 peers share verified
  image blobs, reducing repeated registry downloads during multi-node rollouts.
- **A Common Lisp system you can inspect.** The API, controllers, agent,
  networking compiler, and datastore share one language. An optional Slynk
  endpoint supports live inspection in development environments.

## Getting started

Build on Linux with **SBCL** and the project's ASDF dependencies. Running the
cluster requires **Linux 6.6+ with TCX eBPF support**, **root privileges**, and
working cgroups. Install **`kubectl`** to use the Kubernetes API. See
[build requirements](docs/building-and-testing.md#requirements) and
[runtime payload details](docs/runtime.md#the-self-contained-payload) for setup.
Use a disposable Linux VM for an initial trial.

From the repository root:

```sh
make native

# Start a single-node cluster; leave this running.
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

In another terminal, create a Pod and wait for it to become ready. The kubeconfig
is owner-only, so these commands use `sudo` to read the file created by the server.
The node needs registry access to download the image.

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

Stop the server with Ctrl-C. The state directory holds cluster state for reuse
on the next start.

For [adding worker nodes](docs/building-and-testing.md#a-second-node),
[preloading images](docs/runtime.md#preloaded-images-airgap), external containerd,
and testing, see [Building, running & testing](docs/building-and-testing.md).

## Kubernetes capabilities

The implemented API surface includes:

| Area | Capabilities |
|---|---|
| Workloads | Pods, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, ReplicationControllers, rolling updates, owner-reference garbage collection |
| Scheduling | Resource requests and limits, node affinity and anti-affinity, taints and tolerations, priority and preemption, host ports, ephemeral-storage eviction |
| Configuration and identity | ConfigMaps, Secrets, ServiceAccounts, bound tokens, RBAC, certificate issuance, admission webhooks, CEL admission policies |
| Networking | ClusterIP, NodePort and LoadBalancer Services, EndpointSlices, NetworkPolicy, Gateway API, cluster DNS |
| Storage | PersistentVolumes and Claims, StorageClasses, local-path provisioning, NFS, CSI drivers |
| Observability | Metrics endpoints, cAdvisor and API server/scheduler series, resource metrics for `kubectl top` |
| Extensibility | Schema-backed custom resources, defaulting, pruning, validation, finalizers |

Support varies by feature; this overview does not imply complete upstream
semantics. The [Kubernetes API surface](docs/kubernetes-surface.md) is the detailed
reference for supported operations, validation evidence, and limitations.

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

`gr8s serve` runs the control plane and a local agent. Workers run `gr8s agent`
and connect over an authenticated gRPC node protocol. The control plane schedules
work and publishes desired state; agents reconcile containers and networking and
report status. The agent manages its own containerd instance by default.

For a replicated control plane, Raft supports three voting members or two
members plus a witness. A quorum can continue after a leader failure;
single-node operation requires no Raft configuration. See
[High availability](docs/high-availability.md) for membership and durability
guarantees, and [Design](docs/design.md) for component boundaries.

## Networking and security

Whistler, the embedded Lisp-to-eBPF compiler, lets the agent compile and load
networking programs at runtime. A socket load balancer directs Pod connections
to ready Service backends. Programs at Pod veths enforce NetworkPolicy and
anti-spoofing, while a same-node fast path redirects traffic to local Pods.
The agent also implements Gateway API routing.

For cross-node traffic, the WireGuard overlay combines authenticated endpoint
advertisements, active path trials, and eBPF telemetry. It supports NAT traversal,
encrypted relaying, packet-size discovery, and topology-aware sparse routing.
`gr8s network explain NODE PEER` exposes path-selection decisions. Path health
and locality also inform Service backend selection and image-peer ordering.

Internal TLS uses a pure-Lisp TLS 1.3 implementation and prefers hybrid
X25519MLKEM768 key exchange, combining classical and post-quantum cryptography.
Classical X25519/P-256 remains available as a fallback. Image distribution uses
node certificates and mutual TLS to authenticate its private peer swarm;
verified blobs can be seeded by each node that receives them.

See [Networking & the eBPF dataplane](docs/networking.md) for configuration,
protocol details, and operational behavior.

## Container runtimes

The embedded containerd uses runc by default. `RuntimeClass` resolves Pod
overhead, scheduling constraints, and the CRI runtime handler, allowing Pods
to select configured handlers on a node.

Optional gVisor and Kata Containers runtimes support sandboxed and microVM
workloads, with automatic installation and end-to-end validation. Use
`gr8s runtime install gvisor` or `gr8s runtime install kata` to install them,
then select the runtime through `RuntimeClass`. See
[Runtime & the container stack](docs/runtime.md) for configuration.

## Development and documentation

Run the unit and HTTP tests with `make test`. Tests that load eBPF programs or
run real containers require a privileged environment; use a disposable VM and
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

gr8s versions combine the Kubernetes API version with a gr8s release suffix,
for example `v1.37.2-gr8s.0`. The API version identifies the compatibility target;
it does not indicate Kubernetes conformance. `gr8s version` and the Kubernetes
`/version` endpoint report the version of the running build.

## License

[Apache License 2.0](LICENSE).
