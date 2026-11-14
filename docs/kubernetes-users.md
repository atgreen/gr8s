# gr8s for Kubernetes users

gr8s is an independent implementation of Kubernetes APIs and cluster behavior in
Common Lisp. You use `kubectl`, manifests, RBAC, Services, and workload controllers.
The control plane and node agent run inside the same executable; upstream
Kubernetes component binaries are not embedded in it. Container execution uses
embedded containerd and runc.

## Where familiar components went

| Familiar responsibility | gr8s implementation | Where to read |
|---|---|---|
| kube-apiserver | In-process authenticated HTTPS API, discovery, admission, RBAC, and watches | [API surface](kubernetes-surface.md), `src/apiserver/`, `src/security/` |
| kube-controller-manager | In-process workload, storage, Service, EndpointSlice, and lifecycle controllers | `src/controllers/`, `src/resources/` |
| kube-scheduler | In-process scheduling, resource accounting, placement, and preemption | `src/controllers/scheduler.lisp` |
| kubelet | Node agent, Pod reconciliation, probes, volumes, CRI, and status reporting | `src/agent/`, `src/kubelet/` |
| etcd | gr8s durable store; optional replicated control plane using Raft | [HA](high-availability.md), `src/store/`, `src/ha/`, `src/raft/` |
| container runtime | Embedded containerd, shim, and runc; optional external CRI socket and runtime handlers | [Runtime](runtime.md) |
| CNI | The gr8s executable forwards CNI calls to its agent, which owns native IPAM, links, routes, and eBPF | [Networking](networking.md) |
| kube-proxy | Agent-managed eBPF Service forwarding and node relays | [Services](networking.md#services--load-balancing) |
| CoreDNS | Agent's embedded cluster DNS implementation | [DNS](networking.md#dns) |
| Ingress / Gateway controller | In-process controllers and agent proxies; no Traefik installation required | [Networking](networking.md) |
| local-path provisioner | In-process provisioner; CSI drivers and sidecars can be installed separately | [Storage](persistent-storage.md) |
| metrics-server | Native `metrics.k8s.io` API backed by node observations | [Metrics](kubernetes-surface.md#metrics--autoscaling) |

These are responsibility mappings. They do not promise every upstream flag,
extension, or operational behavior. See the [compatibility gaps](k3s-gap-inventory.md)
and [conformance evidence](CONFORMANCE.md).

The optional `gr8s dashboard` command serves an embedded Headlamp web UI and
proxies the cluster API. See [dashboard setup](building-and-testing.md#optional-dashboard-assets).

## Processes and defaults

- `gr8s serve` runs a control plane and local agent. `--disable-agent` selects a
  control plane without local workloads.
- `gr8s agent` joins another machine using a one-time node-bound token and CA pin.
  It persists a private key and certificate for reconnects.
- `gr8s witness` is an optional Raft quorum participant without an API or workloads.

The Kubernetes API defaults to authenticated HTTPS on `0.0.0.0:6443`. The private
node endpoint defaults to `127.0.0.1:7443`; expose it on a reachable address to
join workers. It is a gr8s protocol, not a kubelet replacement endpoint for arbitrary
upstream clients. The local agent also exposes selected kubelet-compatible APIs.

**VXLAN is the default cross-node overlay.** WireGuard is selected explicitly with
`serve --overlay-backend wireguard`. Native networking and embedded containerd are
the default; external CNI and CRI integration are explicit options.
See [ports and prerequisites](building-and-testing.md#network-access).

A fresh cluster does not need separate etcd, kube-proxy, CoreDNS, or metrics-server
Pods. Their absence in `kube-system` is expected. Start with the
[first workload](getting-started.md); use [the source walkthrough](development.md)
when you want to understand how its objects become containers.
