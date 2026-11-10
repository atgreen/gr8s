# gr8s multi-node design

## Goal

gr8s becomes a small multi-node Kubernetes-compatible Pod control plane without
giving up its single-binary deployment. One dumped native image supplies three
roles:

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
peer state, embedded DNS, and Whistler programs and maps. The agent continues
reconciling its last acknowledged desired snapshot while temporarily
disconnected.

The CNI entry point is deliberately thin. It forwards CNI ADD, CHECK, and DEL
requests over a mode-0600 Unix socket to the local agent and returns the
agent's CNI result. The agent performs allocation, namespace and link changes,
route installation, and Whistler attachment. If the agent is unavailable, the
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

The initial protocol sends full snapshots rather than a subtle delta/watch
protocol. Every snapshot has a monotonically increasing revision. Agents apply
messages idempotently and acknowledge the highest fully persisted revision.
After reconnect, the agent registers its last acknowledged revisions and the
server resends current snapshots when necessary.

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
an explicit `gr8s certificate rotate` replaces both certificate and key. Cluster
CA and ServiceAccount signing-key changes use prepare, promote, and finalize
stages. In HA clusters, run those stages online with `--kubeconfig`: the leader
stores an authenticated encrypted authority record in Raft, every voter extracts
the same active/prepared/retiring material before serving, and follower requests
are routed to the leader. After CA promotion, restart control-plane members one
at a time, then let agents reconnect and renew before finalizing the retiring CA.
External CA integration remains deferred.

The CNI Unix socket uses filesystem permissions and Linux peer credentials,
not cluster certificates.

## Scheduling

An explicit `spec.nodeName` is respected when the named node exists. Otherwise
the initial scheduler chooses a Ready node with the fewest assigned
non-terminal Pods. The assignment is persisted with the Pod and is not changed
merely because another node becomes less loaded.

If no node is Ready, the Pod remains Pending. Loss of a node marks its Pods
Unknown. Automatic eviction on node loss, timeout-based replacement, Pod affinity
and anti-affinity, and resource scoring are deferred.

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
Whistler does not implement a custom tunnel. VXLAN can later be replaced by
native routing or WireGuard without changing local Pod attachment.

Whistler initially enforces exact local Pod source ownership and validates
that remote source addresses belong to the PodCIDR advertised by the
encapsulating node. Persistent maps hold Pod-IP identity, Node PodCIDR/VTEP,
policy, counters, and flow/drop telemetry. Security identity is derived from
control-plane state, not trusted from VXLAN metadata.

IPv4 ClusterIP Services and standard NetworkPolicy remain the next dataplane
layers. They are not prerequisites for splitting the agent and CNI ownership.

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

## Explicit exclusions

The first version excludes control-plane HA, etcd compatibility, Kubernetes
kubelet and Node API compatibility, cloud-provider integration, dynamic
multi-block IPAM, IPv6, BGP, WireGuard, NodePort, LoadBalancer, ExternalIP,
socket-level load balancing, XDP acceleration, DSR, Maglev, L7 policy, and
automatic Pod rescheduling after node loss.
