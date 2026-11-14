# gr8s

**Kubernetes, built from scratch in Common Lisp, with an eBPF dataplane.**

gr8s puts a Kubernetes API server, controllers, scheduler, node agent,
container runtime, networking, and datastore in one native executable. Use
`kubectl` and standard Kubernetes manifests on one node or across a cluster.

**gr8s passed 100% of the upstream Kubernetes v1.37 `certified-conformance`
tests: 462/462, zero failures**, in the recorded two-node Sonobuoy run on
2026-11-11. See the [results and evidence](docs/CONFORMANCE.md).

Run containers with embedded containerd/runc, choose
[Kata Containers or gVisor](docs/runtime.md#runtimeclass--pluggable-runtimes)
through `RuntimeClass`, or run virtual machines with [KubeVirt](docs/kubevirt.md).
Explore the cluster through its integrated [Headlamp dashboard](#dashboard),
trace selected Pods with [bpftrace programs](docs/design-gr8s-trace.md), and
inspect running control-plane and agent processes through
[Slynk](docs/building-and-testing.md#debugging-a-running-cluster).

> **Project status:** gr8s is experimental software for exploration, development,
> and testing. It is not yet a CNCF-submitted _Certified Kubernetes_ distribution.
> See the [API coverage](docs/kubernetes-surface.md) and
> [known gaps](docs/k3s-gap-inventory.md) for the current scope.

The name **gr8s** is a portmanteau of *Green* — its author's surname — and
*k8s*, the usual contraction of *Kubernetes*: in short, "Green Kubernetes."

Start with the [documentation guide](docs/index.md). If you already know Kubernetes,
the [component map](docs/kubernetes-users.md) explains where familiar components live.

## Why gr8s?

- **Explore the cluster in a browser.** The integrated Headlamp dashboard
  provides a Kubernetes web UI with live resource updates. Source builds need
  the [dashboard assets step](docs/building-and-testing.md#optional-dashboard-assets).
- **Trace workloads in the kernel.** `gr8s trace` runs ephemeral bpftrace programs
  on nodes hosting Pods selected through the Kubernetes API. The agent uses
  [Whistler](https://github.com/atgreen/Whistler) to compile and attach them
  in-process, without a separate bpftrace binary or tracing DaemonSet.
- **Inspect the running implementation.** The API, controllers, agent,
  networking compiler, and datastore use Common Lisp. An authenticated Slynk
  tunnel lets you inspect live control-plane and agent processes.
- **Program the dataplane directly from Lisp.** The kernel handles Service load
  balancing, NetworkPolicy, same-node forwarding, and Pod anti-spoofing.
  [Whistler](https://github.com/atgreen/Whistler) compiles eBPF directly from Lisp,
  without clang or LLVM.
- The same executable can run a complete single-node cluster, a control plane,
  or a worker agent. It embeds containerd and runc, includes CNI integration,
  and supports preloaded images for airgapped nodes.
- The Kubernetes API provides workload controllers, scheduling, RBAC, Services,
  persistent storage, and custom resources. The
  [compatibility reference](docs/kubernetes-surface.md) lists supported behavior
  and limitations.
- Raft replicates control-plane state without an external database. Certificates
  authenticate node enrollment and internal communication.
- Cross-node traffic uses VXLAN by default. An optional adaptive WireGuard
  overlay selects paths between nodes. Authenticated BitTorrent v2 peers share
  verified image blobs, avoiding repeated registry downloads during multi-node
  rollouts.

Run `gr8s skill` for built-in operator and AI agent guidance, including first-response
checks, live Slynk inspection, and selector-scoped kernel tracing. It works offline
and can be saved with `gr8s skill > gr8s-guide.md`.

## How is gr8s different from k3s?

k3s is the closest comparison to gr8s. Both provide a Kubernetes-compatible
cluster that you can operate with `kubectl`. k3s is a packaged Kubernetes
distribution built from upstream components and familiar ecosystem add-ons.
gr8s is an independent implementation: one native Common Lisp executable runs
the API, controllers, scheduler, node agent, and embedded runtime. It uses its own Raft datastore and
an eBPF dataplane rather than assembling the usual separate control-plane and
networking components.

That architecture gives gr8s an integrated system to explore and develop,
with features such as live Lisp inspection and a directly compiled eBPF
dataplane. It also means its compatibility and operational behavior differ from
k3s. gr8s passes the upstream Kubernetes v1.37 `certified-conformance` suite,
but is experimental and does not yet provide every k3s add-on or operational
workflow. Check the
[compatibility gaps](docs/k3s-gap-inventory.md), [API coverage](docs/kubernetes-surface.md),
and [conformance results](docs/CONFORMANCE.md) for supported behavior and limitations.

## Getting started

Build gr8s on Linux with **SBCL** and the project's ASDF dependencies. To run a
cluster, you need **Linux 6.6+ with TCX eBPF support**, **root privileges**, and
working cgroups. Install **`kubectl`** to use the Kubernetes API. See the
[build requirements](docs/building-and-testing.md#requirements) and
[runtime payload details](docs/runtime.md#the-self-contained-payload) for the
full setup. Start with a disposable Linux VM.

Like k3s and k0s, `gr8s serve` exposes one authenticated HTTPS Kubernetes API.
It listens on `0.0.0.0:6443` by default; there is no separate unauthenticated
localhost HTTP API. The generated owner-only kubeconfig embeds the cluster CA
and an administrative client certificate.

From the repository root:

```sh
make native

# Start a single-node cluster; leave this running.
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

In another terminal, deploy the [example](examples/getting-started.yaml). The
server creates an owner-only kubeconfig, so these commands use `sudo` to read it.
The node needs registry access for the nginx and BusyBox images.

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig wait \
  --for=condition=Ready node/gr8s-local --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig apply -f examples/getting-started.yaml
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo rollout status \
  deployment/web --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo wait \
  --for=condition=Ready pod/client --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo exec client -- \
  wget -qO- http://web.gr8s-demo.svc.cluster.local
```

Expect two ready web replicas and an HTML response containing `Welcome to nginx!`.
The [full walkthrough](docs/getting-started.md) checks DNS, performs a rolling
restart, shows expected results, and explains common failures. Remove the example
with `sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig delete namespace gr8s-demo`.
Stop the server with Ctrl-C; the state directory preserves cluster state for the
next start, although the host may clear `/tmp`.

See [Building, running & testing](docs/building-and-testing.md) to add
[worker nodes](docs/building-and-testing.md#a-second-node), use external
containerd, or run tests. The runtime guide explains how to
[preload images](docs/runtime.md#preloaded-images-airgap).

For expiry inventory, leaf replacement, staged cluster-CA rotation, and
ServiceAccount signer rotation, see [Certificate management](docs/certificate-management.md).
Secrets encryption and key rotation are described in the
[ConfigMap and Secret API guide](docs/configmap-secret-api.md).

To manage a persistent server or agent with systemd, see
[Installing and operating gr8s with systemd](docs/installing.md).
It covers verified upgrades, rollback, scoped cleanup, and uninstall.

For multi-member operation, recovery, automatic checkpoints and heap sizing, see
[High availability](docs/high-availability.md).

## Dashboard

`gr8s dashboard` opens a Kubernetes web UI in your browser. It serves the
[Headlamp](https://headlamp.dev) frontend — embedded in the binary, with no
separate install — and reverse-proxies the API over mutual TLS to the running
cluster, with live resource updates.

```sh
# With a cluster running, from another terminal:
sudo build/gr8s dashboard --kubeconfig /tmp/gr8s.kubeconfig
```

It serves on loopback `http://127.0.0.1:8080` by default (change with `--port`)
and launches your browser; `--no-launch` prints the URL instead. The process
runs in the foreground until Ctrl-C. Source builds need the optional
[dashboard assets step](docs/building-and-testing.md#optional-dashboard-assets)
before dumping the native executable.

## Kubernetes capabilities

The implemented API surface includes:

| Area | Capabilities |
|---|---|
| Workloads | Pods, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, ReplicationControllers, rolling updates, owner-reference garbage collection |
| Scheduling | Resource requests and limits, node affinity and anti-affinity, taints and tolerations, priority and preemption, host ports, ephemeral-storage eviction |
| Configuration and identity | ConfigMaps, Secrets, ServiceAccounts, bound tokens, RBAC, certificate issuance, admission webhooks, CEL admission policies |
| Networking | ClusterIP, NodePort and LoadBalancer Services, EndpointSlices, NetworkPolicy, Gateway API, cluster DNS |
| Storage | PersistentVolumes and Claims, StorageClasses, local-path provisioning, NFS, CSI drivers |
| Observability | Metrics endpoints, [Lisp heap/GC, Raft and filesystem metrics](docs/control-plane-metrics.md), cAdvisor and API server/scheduler series, resource metrics for `kubectl top` |
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

[Whistler](https://github.com/atgreen/Whistler) is the embedded Lisp-to-eBPF
compiler. The agent uses it to compile and load networking programs at runtime.
A socket load balancer directs Pod connections to ready Service backends.
Programs at Pod veths enforce NetworkPolicy and anti-spoofing. A same-node fast
path sends traffic directly to local Pods. The agent also implements Gateway
API routing.

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

- [Documentation paths](docs/index.md)
- [First workload: Deployment, Service, DNS, and rollout](docs/getting-started.md)
- [Kubernetes component map](docs/kubernetes-users.md)
- [Building, running & testing](docs/building-and-testing.md)
- [Kubernetes API surface](docs/kubernetes-surface.md)
- [Networking & the eBPF dataplane](docs/networking.md)
- [Runtime & the container stack](docs/runtime.md)
- [High availability](docs/high-availability.md)
- [Source map and developer walkthrough](docs/development.md)
- [Design & compatibility boundary](docs/design.md)
- [Multi-node design](docs/multi-node-design.md)
- [Known compatibility gaps](docs/k3s-gap-inventory.md)
- [Conformance results](docs/CONFORMANCE.md)
- [v1.37 certified-conformance evidence (462/462)](docs/evidence/conformance-full-v1.37-2026-11-11.json)

## Versioning

A gr8s version combines the Kubernetes API version with a gr8s release suffix.
For example: `v1.37.2-gr8s.0`. The API version identifies the compatibility
target. It does not show Kubernetes conformance. `gr8s version` and the
Kubernetes `/version` endpoint report the running build's version.

## License

[Apache License 2.0](LICENSE).
