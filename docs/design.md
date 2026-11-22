# Architecture and compatibility boundary

gr8s implements a Kubernetes control plane and node agent in Common Lisp. One
native executable supplies a combined server/node, a worker agent, a control-plane-only
server, or a Raft witness. It embeds containerd/runc for container execution and
[Whistler](https://github.com/atgreen/Whistler) for compiling and loading its eBPF dataplane.

The user-facing contract is the Kubernetes API: authenticated HTTPS, standard
manifests, discovery, workload controllers, scheduling, RBAC, storage, and custom
resources. The [API reference](kubernetes-surface.md) and
[gap inventory](k3s-gap-inventory.md) describe its scope. The
[conformance ledger](CONFORMANCE.md) records measured compatibility. gr8s remains
experimental; a conformance result does not establish operational maturity.

## Ownership boundaries

```text
kubectl / Kubernetes clients
             |
       HTTPS API + admission + RBAC
             |
       durable desired state <---- optional Raft replication
             |
       controllers + scheduler
             |
       revisioned node protocol: one gRPC stream per node,
       opened by the agent, over mutual TLS
             |
       agent + Pod reconciler
          /              \
   CRI / containerd       native networking / DNS / Services
          |                       |
         runc                 kernel links + eBPF
```

The agent opens the node protocol's connection, and the control plane never
opens one to a node. Desired state, status, logs, exec, attach, port-forward,
metrics, tracing, debugging, and the API server's own connections into Pods and
nodes (webhooks, aggregated APIs and the proxy subresources) all travel over
that one stream. Nodes need no inbound port and no route from the control
plane; see [a control plane in another network](building-and-testing.md#a-control-plane-in-another-network).

The control plane owns API identities, desired state, placement, enrollment,
Pod CIDR assignment, and the desired snapshot sent to each node. Controllers
create and update ordinary API objects. They run only on the leader in HA mode.

Each agent owns its private containerd instance by default, its assigned Pods,
local IPAM, mounts, interfaces, routing, probes, and runtime observations. The
agent's CNI Unix socket is private; the same executable invoked as CNI forwards
ADD/CHECK/DEL to that agent. The local agent uses the same ownership and protocol
boundary as a remote worker. See [multi-node design](multi-node-design.md).

containerd supplies CRI and container lifecycle; runc supplies OCI execution.
gr8s supervises and materializes its embedded runtime payload, while keeping
mutable runtime data below the configured state directory. External CRI and CNI
modes are documented in [runtime](runtime.md) and [networking](networking.md).

## State and convergence

API writes persist desired state; accepting an object does not mean a container
has started. Controllers and scheduling produce assignments. Agents reconcile
those assignments with runtime state and report observations, from which the API
publishes Pod conditions and status. Retries are idempotent and identities use UIDs,
so a replacement object does not inherit an old object's runtime state by name.

Standalone operation uses the local durable store. HA adds a Raft log and application
checkpoints, replicates desired state and selected observations, and gates controller
work on leadership. Some telemetry remains local; Events replicate, and leave every
member in the same write, so that all members count revisions alike. A read that names no
resourceVersion is confirmed with the leader before any member answers it; a read at
resourceVersion=0 is served from the member's own state and may be old.
See [HA consistency and recovery](high-availability.md) for the exact guarantees.

## Networking and identity

Native agents create routed Pod interfaces and program Service forwarding,
NetworkPolicy, and anti-spoofing through eBPF. Cross-node networking defaults to
VXLAN; the adaptive WireGuard overlay is opt-in. Cluster DNS, Service publication,
and Gateway/Ingress reconciliation are integrated. See [networking](networking.md).

The public API defaults to HTTPS on `0.0.0.0:6443`. Nodes enroll through a separate
endpoint using a one-time token and pinned CA, then reconnect with node certificates
and mutual TLS. Raft membership has a separate enrollment authority. See
[certificate management](certificate-management.md) and
[security deviations](security-deviations.md).

## Reading the implementation

Start with the [Kubernetes component map](kubernetes-users.md), then follow the
[source map and apply-to-container walkthrough](development.md). Tests use fake
runtimes for fast checks and disposable privileged VMs for real container and eBPF
behavior; see [building and testing](building-and-testing.md).

The [original single-node Pod-only design](history/initial-design.md) is historical.
Its unauthenticated loopback API and narrow resource scope do not describe the
current implementation.
