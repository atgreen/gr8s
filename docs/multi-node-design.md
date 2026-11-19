# gr8s multi-node design

> **Status:** this is the original multi-node design, kept for the
> responsibility split and protocol rationale, which still hold. The items it
> defers or excludes — WireGuard, ClusterIP Services, NetworkPolicy, Pod
> affinity, taint-based eviction, HA, IPv6, NodePort/LoadBalancer, the socket
> load balancer, the kubelet API — have since shipped; the passages below mark
> each where it appears. [networking.md](networking.md) describes the current
> dataplane.

## Goal

gr8s runs a multi-node Kubernetes-compatible control plane and node agents from
one native executable. Its server and worker entry points also supply the native
CNI integration:

- `gr8s serve` runs the Kubernetes API and cluster control plane.
- `gr8s agent` runs the node-local runtime and networking control loop.
- CNI environment variables dispatch that same image into its thin CNI entry
  point.

`gr8s serve` starts a local agent by default. `--disable-agent` makes it a
control-plane-only process, and `gr8s agent --server ...` joins another node.
The local agent uses the same protocol and ownership boundary as a remote one.

## Responsibility split

The control plane owns Kubernetes API objects, durable desired state, node
records, scheduling assignments, the cluster CA and enrollment tokens, Node
PodCIDR allocation, cluster network topology, and the desired-state revision
sent to each node. It does not call CRI, enter Pod network namespaces, or
modify node routes.

Each agent owns its node identity, managed containerd lifecycle, reconciliation
of Pods assigned to that node, image and sandbox operations, observed Pod
status, logs and exec, node heartbeats, local IPAM, veths, host routes, VXLAN
peer state, embedded DNS, and [Whistler](https://github.com/atgreen/Whistler) programs and maps. The agent continues
reconciling its last acknowledged desired snapshot while temporarily
disconnected.

The CNI entry point is deliberately thin. It forwards CNI ADD, CHECK, and DEL
requests over a mode-0600 Unix socket to the local agent and returns the
agent's CNI result. The agent performs allocation, namespace and link changes,
route installation, and [Whistler](https://github.com/atgreen/Whistler) attachment. If the agent is unavailable, the
CNI operation fails rather than making an unrecorded network change.

## Agent protocol

The node initiates every management connection. Nodes expose no management
listener on the cluster network. A private, versioned ag-gRPC bidirectional
stream over TLS carries:

- node registration and capabilities;
- heartbeat and readiness;
- complete, revisioned desired-Pod snapshots and acknowledgements;
- observed sandbox/container state and Pod status;
- revisioned node, PodCIDR, VTEP, Pod-IP, and identity topology;
- correlated log and exec requests, output, input, resize, exit, and cancel
  messages.

The protocol sends revisioned snapshots and negotiates desired-state deltas for
agents advertising that capability. Agents reconstruct and apply desired state
idempotently, acknowledging the highest fully applied revision. After reconnect,
the agent registers its last acknowledged revisions and the server sends current
state as needed. See [`node-session.lisp`](../src/apiserver/node-session.lisp)
for capability negotiation and snapshot/delta construction.

The authenticated Kubernetes HTTPS API remains the user-facing compatibility surface. The
private agent protocol is not presented as a Kubernetes kubelet API.

## Enrollment and identity

The server creates a cluster CA and bootstrap token. A joining agent is given
the server address, CA fingerprint, token, and requested node name. It verifies
the server certificate, generates its node key locally, and exchanges the
one-time bootstrap credential for a node-bound client certificate. Persistent
gRPC connections then use mutual TLS; the token is not a reconnect credential.

The server rejects duplicate live node identities and records certificate
serials so a node can be revoked. Node private keys never leave their node.
Leaf certificates renew automatically before expiry while retaining their keys;
an explicit `gr8s certificate rotate --service NAME` replaces both certificate
and key. Cluster CA and ServiceAccount signing-key changes use prepare, promote,
and finalize
stages. In HA clusters, run those stages online with `--kubeconfig`: the leader
stores an authenticated encrypted authority record in Raft, every voter extracts
the same active/prepared/retiring material before serving, and follower requests
are routed to the leader. After CA promotion, restart control-plane members one
at a time, then let agents reconnect and renew before finalizing the retiring CA.
External CA integration remains deferred.

The complete command sequence, safety gates, offline/HA distinction, and restart
order are in [Certificate management](certificate-management.md).

The CNI Unix socket uses filesystem permissions and Linux peer credentials,
not cluster certificates.

## Scheduling

An explicit `spec.nodeName` is respected when the named node exists. Otherwise
the initial scheduler chooses a Ready node with the fewest assigned
non-terminal Pods. The assignment is persisted with the Pod and is not changed
merely because another node becomes less loaded.

If no node is Ready, the Pod remains Pending. Loss of a node marks its Pods
Unknown. The deferrals this design listed here have since shipped: inter-Pod
affinity and anti-affinity are implemented and scored in placement
([`pod-affinity.lisp`](../src/resources/pod-affinity.lisp), used by the
scheduler's node-preference scoring), and NoExecute taints evict Pods with
toleration timers ([`node-taints.lisp`](../src/resources/node-taints.lisp)).

## Node networking

IPv4 IPAM starts with a configurable cluster Pod CIDR split into one persistent
fixed-size CIDR per node. The initial default shape is a `/12` cluster pool
with a `/20` per node, supporting 256 nodes and roughly 4096 addresses per
node. Pools are checked for overlap with host routes before use.

The target local dataplane has no `gr8s0` bridge. Every Pod receives a directly
routed veth endpoint and an individual address, normally configured as `/32`.
The agent creates a host route for that address through the host-side veth. The
host owns `169.254.1.1/32` on a node-local interface. Inside each Pod the CNI
installs a link route to `169.254.1.1`, a permanent neighbor entry mapping that
address to the host veth MAC, and a default route through it. Embedded DNS also
listens on `169.254.1.1`. This supplies gateway and DNS reachability without
ARP proxying, a bridge, or one gateway address per Pod.

Cross-node traffic initially uses one ordinary Linux VXLAN device and one
cluster VNI. Agents reconcile remote Node PodCIDR routes, VTEP peers, and FDB
entries from revisioned control-plane topology. Linux performs encapsulation;
[Whistler](https://github.com/atgreen/Whistler) does not implement a custom tunnel. The predicted WireGuard
replacement shipped without changing local Pod attachment: `--overlay-backend
wireguard` selects the self-tuning encrypted overlay
([`wireguard.lisp`](../src/network/wireguard.lisp)); VXLAN remains the default.

[Whistler](https://github.com/atgreen/Whistler) enforces exact local Pod source ownership, and persistent maps
hold Pod identity, policy, counters, and flow telemetry. The remote-source
validation maps this paragraph originally planned — checking that a remote
source address belongs to the PodCIDR/VTEP advertised by the encapsulating
node — were never implemented; the shipped BPF map set has no such tables.
Security identity is still derived from control-plane state, not trusted from
VXLAN metadata.

IPv4 ClusterIP Services and standard NetworkPolicy, "the next dataplane layers"
when this was written, are implemented; see
[networking.md](networking.md).

## Recovery

Agent state is durable beneath its configured state directory. On restart it
observes gr8s-owned CRI objects, reloads CNI allocations and pinned BPF state,
reconciles node routes, and then reconnects with its last acknowledged
revisions. Unknown or unowned runtime objects are not adopted or deleted.

On control-plane restart, agents reconnect and receive authoritative snapshots.
On temporary network partition, existing Pods continue running and the agent
reconciles the last snapshot, but new assignments and remote topology changes
wait. CNI DEL remains locally available. Stale topology is removed only after
a newer authoritative revision, avoiding route loss during a transient
disconnect.

## First walking skeleton

The first implementation remains on one machine while crossing the real
boundary end to end:

1. Define and generate the private agent protocol.
2. Add node enrollment, mutual TLS, registration, heartbeat, and revisioned
   desired/status snapshots.
3. Move managed containerd and Pod reconciliation behind `gr8s agent`.
4. Have the default local agent connect through the same loopback gRPC endpoint
   as a remote agent; remove the control plane's direct runtime path.
5. Add persistent node assignment with the minimal scheduler.
6. Replace the chained bridge setup with the local agent Unix API and the
   directly routed gr8s CNI.
7. Preserve the current single-node smoke workflow, then add a two-node network
   namespace or VM smoke test for cross-node VXLAN Pod traffic.

Only after that skeleton passes do we add Service translation, NetworkPolicy,
automatic node-loss eviction, or more sophisticated scheduling.

## Explicit exclusions (historical)

The first version excluded control-plane HA, etcd compatibility, Kubernetes
kubelet and Node API compatibility, cloud-provider integration, dynamic
multi-block IPAM, IPv6, BGP, WireGuard, NodePort, LoadBalancer, ExternalIP,
socket-level load balancing, XDP acceleration, DSR, Maglev, L7 policy, and
automatic Pod rescheduling after node loss. Many of these have since shipped:
control-plane HA, the kubelet API, IPv6 Pod CIDRs, WireGuard, NodePort and
LoadBalancer Services, and the eBPF socket load balancer all exist now. The
list records the original scope cut, not the current feature set.
