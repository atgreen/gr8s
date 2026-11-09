# Networking & the eBPF dataplane

gr8s has **no kube-proxy and no iptables**. Packet handling lives in the kernel,
programmed from Common Lisp through **Whistler**, which compiles s-expressions
directly to eBPF bytecode — no LLVM, no clang, no `.c`, no hand-written ELF. The
eBPF compiler and loader live *inside* the running agent, so dataplane programs
are compiled and loaded on the fly, and per-Pod state lives in BPF maps the agent
updates.

This document covers the whole dataplane: the egress guard, NetworkPolicy,
Services and load balancing, the Gateway API, CNI/IPAM, DNS, and the VXLAN and
self-tuning WireGuard cross-node overlays.

## The per-Pod egress guard

The Whistler classifier attaches to each Pod's host-veth ingress (its egress
path) as a persistent TCX link. It uses an agent-initialized map to check the
exact IPAM IPv4 address and interface MAC, validates ARP sender identity, and
drops malformed or unsupported frames. It counts accepted/dropped packets and
bytes, rejected spoofs, malformed packets, and unsupported protocols.

Identity initialization precedes TCX attachment; replacement links are attached
and pinned before atomically replacing the old pin. Existing counter maps survive
repeated CNI ADD calls. Each endpoint keeps `rejected_spoofs`,
`endpoint_identity`, and `traffic_stats` maps alongside its `tcx-ingress` link
under `AGENT_STATE_DIR/containerd/bpf/CONTAINER_ID/`. CNI CHECK validates kernel
map schemas, identity, and the TCX interface/direction; DEL removes staged links
and all maps even after the Pod namespace disappears.

Tests exercise the actual compiled bytecode on packet fixtures with both an
interpreter and the Linux BPF test-run facility. The privileged native smoke
injects a spoofed source into a live Pod namespace and requires the rejection
counter to appear through agent telemetry.

## NetworkPolicy — a compiled eBPF firewall

`networking.k8s.io/v1` NetworkPolicy is enforced as a compiled eBPF firewall on
real Pods. Rather than recompiling a program per policy change, gr8s folds
enforcement into the per-Pod egress classifier at the host veth and drives it
from BPF maps: the resolved policy — allowed destination CIDRs in an LPM trie and
permitted `(group, protocol, port)` tuples in a hash — is written as *data* into
pinned maps, so a policy change is a map update, not a recompile or a re-attach.

Egress to a destination no rule permits is dropped (default-deny), and the drops
are counted and exported through the same endpoint telemetry as the anti-spoof
guard.

The smoke test applies a default-deny-egress policy to a running Pod and requires
its previously reachable gateway to become unreachable, proving enforcement on a
live Pod; detach-on-removal is covered by unit tests.

**Tracked for completeness:** ingress-direction enforcement, connection tracking
for reply traffic, namespace selectors, and `ipBlock.except`.

## Services & load balancing

Managed native clusters allocate durable IPv4 ClusterIP Services from
`10.96.0.0/16`, over TCP, UDP, or SCTP. Services accept JSON and typed Kubernetes
protobuf requests, including numeric and named target ports.

A **cgroup eBPF socket load balancer** rewrites a native client's `connect(2)` to
a ready backend, resolving numeric or named target ports against selected Pods or
manually managed slices. There is no DNAT and no conntrack: the socket connects
directly to the real backend, so the return path needs no reverse translation.
IPv4 and IPv6 `connect` hooks steer connected sockets, `sendmsg` hooks steer
unconnected UDP `sendto(2)`, and `recvmsg` hooks restore the Service source address
on UDP replies. `sessionAffinity: ClientIP`
holds each client's network namespace on one backend until the timeout passes or
the Service's backend set changes. The reserved `default/kubernetes` Service
describes the HTTPS API at `10.96.0.1:443`, with matching Endpoints and an
EndpointSlice.

Before rewriting a socket, the program validates that the selected backend belongs
to the requested Service. This prevents shared backend-slot repacking from sending
a connection to another Service during a reconcile or interrupted update. A failed
membership check refuses the attempt; later attempts recover after convergence.
`make test-service-lb-program` exercises the compiled bytecode across these update
boundaries. The same fixture can be tested with actual attached socket hooks using
`scripts/test-service-lb-program.py FIXTURE --kernel` inside a disposable root VM.
Host socket hooks do not intercept connections initiated inside a guest kernel.
The experimental IPv4 TCP/UDP TC Service pipeline can be enabled with
`GR8S_ENABLE_PACKET_SERVICES=1` on the node agent. The generated CNI configuration
then binds each endpoint guard to the node's shared pinned Service maps.
Source validation runs before destination translation; egress policy and local
delivery see the backend address. Client ingress policy sees the backend before
reverse translation restores the Service source address. Missing continuation
programs drop traffic and fail CNI CHECK. The continuation table is pinned with
the endpoint, and Service map pins survive clean agent shutdown.

This remains disabled by default. A real Kata guest has reached a same-node
native backend through IPv4 TCP and UDP ClusterIP translation, with TC request
and reply counters and guest source-IP preservation verified. See
[the guest validation evidence](service-guest-validation-2026-11-09.json).
The two-node guest regression also verifies TCP/UDP traffic over VXLAN to a
backend on another node, source-IP preservation, native socket acceleration,
guest egress policy on backend addresses/ports, reply handling under default-deny
guest ingress, and remote backend ingress denial/recovery. It uses two agents in
separate mount/network namespaces within one disposable VM; physical-host and NIC
offload behavior remains unverified. See
[the cross-node validation evidence](service-guest-two-node-validation-2026-11-09.json).
On reopening pinned maps, the controller inventories all six IPv4/IPv6 Service
control maps before reconciliation. It removes retained entries for Services
deleted while the agent was offline, including sparse orphan backend slots.
A native two-node restart regression verifies withdrawal, retained map IDs,
unchanged Pod identities and recovered Service traffic. See
[the restart validation evidence](service-map-restart-validation-2026-11-09.json).
Guest connection-state survival across agent restart remains unverified.
Packet flows currently expire after 180 seconds of UDP inactivity or two hours
of TCP inactivity, counting requests and replies. The next packet removes an
expired forward entry before selecting from the current Service plan. Forward
and reverse tuple reservations serialize state changes; contention drops the
packet without waiting, and all reservations are released before the policy
continuation. Replaced-backend replies fail the forward/reverse ownership check.
This is lazy expiry: background cleanup of idle/orphan entries and TCP
SYN/FIN/RST state handling remain unfinished. See
[the expiry and guest regression evidence](service-packet-expiry-validation-2026-11-09.json).
Kernel packet tests additionally cover program lifetime. Flow garbage collection,
source NAT/hairpin,
return-tuple collision resolution, IPv6 packet translation and external Service
replacement remain in development. Hairpin and conflicting return tuples
currently drop safely. See [the engine validation scope](service-packet-engine-validation-2026-11-09.json)
and [the guard integration evidence](service-packet-guard-validation-2026-11-09.json).

To repeat the guest test in a disposable root VM with nested KVM, copy
`scripts/test-service-guest.py` and `scripts/test-service-traffic.py` together,
then run:

```sh
python3 test-service-guest.py --gr8s /root/gr8s \
  --kata-bundle /root/kata-static-4.3.1-amd64.tar.zst \
  --kata-sha256 VERIFIED_BUNDLE_SHA256 --report-directory /var/tmp/guest-evidence
```

The runner installs the checksum-pinned addon, enables experimental TC Services,
and requires a distinct guest kernel, an owned QEMU process, and translation
counters in both directions. Its test-only Kata configuration allows 120 seconds
for agent connection on slow nested machines and enables diagnostics. `--ctr`
can select an existing containerd `ctr` binary to preload the test image directly
when testing independently of the image mirror.

`scripts/test-service-guest-two-node.py` accepts the same binary, bundle, checksum,
and report arguments for the cross-node checks. Copy it with the two guest-test
helpers and `scripts/smoke-two-node.py`. The fixture isolates each node's standard
kubelet sockets/checkpoints and preserves that directory across agent restarts.

`NodePort` and `LoadBalancer` Services allocate node ports from 30000–32767. The
agent relays each in userspace, for TCP and UDP, with client-address affinity, so
a Pod sees the node as the source; a port with no ready backends has no listener.
No cloud controller assigns a LoadBalancer an address, and only `Cluster` traffic
policies are accepted.

The API server proxies `services/[scheme:]name[:port]/proxy` to a ready backend,
as it does for Pods, and keeps a proxied HTML page's rooted links inside the
proxy.

### Endpoints & EndpointSlices

Core Endpoints follow selector Services, and manual Endpoints behind a
selectorless Service are mirrored into EndpointSlices. EndpointSlices expose the
stable `discovery.k8s.io/v1` JSON/protobuf API with selector lists, durable
watches, strategic patches, and collection deletion. The Service controller
publishes actual Pod IPs, readiness and terminating conditions, resolves named
target ports, and partitions generated slices at 100 endpoints. Exact Service UID
ownership and durable slice identities survive restart. Manual slices remain
independently writable and provide real forwarding backends for selectorless
Services. TCP headless Services and `publishNotReadyAddresses` are supported;
generated Service addresses remain single-stack IPv4. Manual slices also admit
IPv6 and deprecated FQDN address types.

`networking.k8s.io/v1` also serves IPAddress as stored objects that allocation
does not create, and ServiceCIDR, where only the default `kubernetes` range is
`Ready`.

## Ingress

The same in-agent proxy reconciles ordinary `networking.k8s.io/v1` Ingress
resources owned by the `gr8s.io/ingress-controller` IngressClass. It supports
exact and prefix paths, default backends, named or numeric Service ports, and TLS
termination from `kubernetes.io/tls` Secrets. Each ready node serves ports 80 and
443 and is published in `status.loadBalancer.ingress`; foreign IngressClasses
remain untouched.

Listeners bind only to agent loopback. A per-agent `sk_lookup` program steers
node-address connections to those sockets, while the listener lifecycle admits
and withdraws its TCP ports in an active firewalld. Removing the last Ingress for
a port therefore removes the proxy listener, sockhash entry, and firewall rule.
`scripts/test-ingress-native.py` proves HTTP and HTTPS through every advertised
node in a three-node cluster and cleans up the fixture afterward.

## Gateway API — the agent is the gateway

gr8s implements the Kubernetes Gateway API as a capability of the in-image
agent — **no Envoy, no sidecars, no kube-proxy, no iptables**. `GatewayClass`,
`Gateway`, `HTTPRoute`, `TCPRoute`, `TLSRoute`, and `GRPCRoute` are served as
durable `gateway.networking.k8s.io/v1` objects and projected to the node that
runs them. Two things set it apart.

**The routing table is compiled, not interpreted.** When HTTPRoutes change, SBCL
JIT-compiles the match table into a native Lisp dispatch function — hostnames
(exact and `*.suffix`), path `Exact`/`PathPrefix`, method and exact-header
matches, and weighted backends — with the route constants inlined and
Gateway-API match precedence baked into the `cond` branch order. A route change
recompiles in microseconds; there is no per-request walk of a rules table.

**The agent is the gateway.** An eBPF `sk_lookup` program (compiled from Lisp,
keyed by destination port through a `SOCKHASH`) steers an inbound connection for a
gateway port straight onto the agent's own listening socket — a port the agent
never bound — with `bpf_sk_assign`, so there is no kube-proxy hop and no iptables.
The in-agent L7 proxy then terminates the request and dispatches through the
compiled router to a ready backend Pod endpoint.

Supported today:

- **HTTP routing** with full match precedence, weighted traffic splitting, and
  HTTP filters: request/response header modifiers, URL rewrite
  (`ReplaceFullPath`/`ReplacePrefixMatch`), and request redirect.
- **HTTPS termination** on a listener, using the cert/key from a referenced
  `kubernetes.io/tls` Secret through the in-image pure-tls stack.
- **L4 routing** for TCPRoute (TCP splice) and TLSRoute/GRPCRoute (SNI
  passthrough: the TLS ClientHello SNI is peeked without terminating and used to
  pick the backend).
- **Per-route observability and protection**:
  `gr8s_gateway_requests_total{gateway,route,code}` on `/metrics`, and a per-route
  token-bucket rate limiter (`gr8s.io/rate-limit-rps` → HTTP 429).

`make smoke` creates a Gateway, an HTTPRoute, and a backend Service + Pod, then
proves a host/path request routes end-to-end through the in-agent proxy to the
real Pod.

**Tracked follow-ups:** ACME auto-issuance, HTTP RequestMirror, backendRef-level
filters, and an eBPF rate-limit fast path.

## CNI, IPAM & the Pod gateway

Managed Pods receive directly routed veth pairs and `/32` addresses from
persistent agent IPAM. The control plane assigns each node a distinct Pod CIDR
within `10.80.0.0/12` and includes the network configuration in desired-state
snapshots. The agent persists that assignment and restores IPAM before restarting
reconciliation. containerd invokes only the `gr8s` CNI plugin, which sends typed
requests to the agent's private Unix socket. CNI ADD retains its durable lease
through partial failures; DEL releases it only after removing policy and links.

Use `--cni-mode external --cni-conf-dir /etc/cni/net.d` to give ownership of
Pod links, addresses, routes, IPAM, and cross-node transport to operator-supplied
CNI configuration. Repeat `--cni-bin-dir DIR` to add plugin search directories;
the bundled gr8s plugin directory remains available. In external mode gr8s
points its managed containerd at the supplied directory but neither creates nor
overwrites a conflist, and it does not apply the native Pod CIDR, VXLAN, routes,
or IPAM. This is the ownership boundary needed by primary plugins such as
Calico, Cilium, Canal, or a Multus-selected default network.

The gr8s policy plugin may optionally supplement an external primary plugin by
appearing after it in the same conflist. Its entry needs `type: "gr8s"`, the
agent socket at `<state>/containerd/run/gr8s-cni.sock`, and `mapPinRoot` at
`<state>/containerd/bpf`. ADD and CHECK require the primary plugin's
`prevResult`; gr8s extracts the assigned IPv4 address, attaches its policy guards
to `CNI_IFNAME` inside the Pod namespace, and returns the previous result
unchanged. Successful ADD/DEL operations update an atomic local endpoint
registry, which survives agent restart and drives subsequent gr8s NetworkPolicy
map convergence without assuming native IPAM or native veth names. Omitting the
gr8s entry leaves policy entirely with the external plugin. External mode still
creates only the owned `169.254.1.1/32` node-local
gateway while the embedded DNS listener is running, so the Pod resolver address
remains reachable without claiming the external plugin's dataplane.

External mode also supports multiple Pod interfaces through a CNI meta-plugin
such as Multus. Configure Multus as the alphabetically first/default network,
put its binary in an operator-owned directory supplied with `--cni-bin-dir`, and
install its `NetworkAttachmentDefinition` CRD. gr8s forwards the complete Pod
annotation string map through CRI, including
`k8s.v1.cni.cncf.io/networks`; Multus therefore performs secondary ADD/CHECK/DEL
and publishes `k8s.v1.cni.cncf.io/network-status` back onto the durable Pod.
Those annotations survive agent restart without recreating an unchanged
sandbox.

The primary delegate remains responsible for the Pod IP, default route and DNS
reachability. Secondary definitions should omit a default route unless the Pod's
JSON network-selection annotation explicitly chooses one. This keeps route
selection unambiguous while `/etc/resolv.conf` continues to use gr8s's
node-local DNS address. For example, a Pod may request a named secondary link
with:

```yaml
metadata:
  annotations:
    k8s.v1.cni.cncf.io/networks: secondary-net@net1
```

The resulting `network-status` identifies the primary interface with
`"default": true` and records each secondary interface, address and MAC.

Each node owns `169.254.1.1/32` on the `gr8s-gateway` dummy interface. Pod veths
have individual `/32` routes without duplicating that gateway address. Each Pod
has a permanent neighbor mapping the gateway to its host-veth MAC, plus a link
route and default route through it. CNI CHECK verifies these addresses, routes,
and neighbor state; repeated ADD repairs drift and removes legacy gateway
addresses from the endpoint veth. The agent keeps its gateway while durable leases
exist and removes it on shutdown after all leases are gone.

## DNS

The agent serves DNS at the node gateway and writes
`<pod-namespace>.svc.cluster.local`, `svc.cluster.local`, and `cluster.local`
searches into the Pod resolver. It answers Service A/AAAA address queries from
durable local discovery data and forwards names outside `cluster.local` to the
host's IPv4 resolvers, over UDP or TCP. Pod `dnsPolicy` selects actual cluster,
host, or explicitly configured resolver settings; `dnsConfig` merges validated
nameservers, search paths, and options, and `None` uses only the supplied
settings. DNS policy/configuration are immutable after Pod creation.

Native DNS publishes normal Service A/AAAA records from cluster IPs and headless
Service / explicit endpoint-hostname records from ready EndpointSlice addresses.
Public Service discovery data travels once per node in authenticated snapshots and
installs atomically with Pod references, separately from namespace-scoped Secret
delivery. It also serves named-port SRV, reverse PTR, DNS-schema TXT, generated
endpoint-hostname, ExternalName CNAME, and CoreDNS-compatible insecure
`IP.NAMESPACE.pod.cluster.local` records. Multi-address headless replies rotate
their first address between queries.

Forwarded positive answers remain cached for the lowest record TTL. NXDOMAIN and
NODATA answers with an authority record use its TTL for negative caching. Cache
hits preserve the caller's DNS transaction ID and report the remaining TTL. The
cache is bounded and shared by the UDP and TCP listeners. Repeat
`--dns-forward ZONE=IP[:PORT]` on `gr8s serve` or `gr8s agent` to configure stub
domains; the longest matching zone wins, and repeated zones provide multiple
upstreams. Other names continue to use the host's IPv4 resolvers.

The kubelet `/metrics` endpoint includes query and response counters, cache hits
and misses, upstream success and error counts, and forwarding duration. DNS is
embedded in every native agent rather than deployed as Pods, so its lifecycle and
availability follow the node agent.

`scripts/test-pod-dns-config.py` verifies actual resolver files and custom
UDP/TCP queries against a separate resolver in an owned guest.

## Self-tuning WireGuard overlay

Start the control plane with `--overlay-backend wireguard`; each agent keeps its
private key locally and advertises only its public key and authenticated endpoint
candidates. Repeat `--wireguard-endpoint NAME=IPV4:PORT` for LAN, public, or other
operator-known paths. The control plane rejects malformed, duplicate, and
identity-conflicting claims. A kernel-observed NAT endpoint is accepted only from
fresh authenticated WireGuard traffic, rate-limited, and owned by the server—not
by an arbitrary node report.

The agent continuously combines fresh WireGuard handshakes and returned bytes
with active probes and passive Whistler/eBPF measurements: RTT, retransmits,
congestion window, active flows, and throughput. A broken selected endpoint fails
over immediately. A healthy optimization needs repeated proof and a material cost
improvement. Endpoint changes are trialled without deleting the last-known-good
path, require returned authenticated bytes and a fresh handshake, and roll back on
failure. Selections, observations, MTU evidence, and bounded decision history are
persisted across restart. `gr8s network explain NODE DESTINATION` resolves a
sparse destination to its effective peer and prints both the topology decision
(`direct-peer` or `sparse-next-hop`) and ranked endpoint evidence.

NATed nodes first establish authenticated sessions with the rendezvous point;
the control plane exchanges the observed reflexive endpoints so both sides can
hole-punch. If direct traversal remains unavailable, an optional UDP relay keeps
the original WireGuard encryption end to end. Configure it with
`--wireguard-relay-address IPV4`; the relay has bounded channels, expiring
authorization, idle reaping, and per-node source-change limits. Relay ownership is
currently single-control-plane. The path tuner prefers any healthy direct path to
the relay.

The MTU tuner sends bounded DF probes through the selected encrypted path. A
packet-size black hole lowers the device MTU immediately; increases require three
successful proofs. Cached-network repair never raises a previously proven-safe
MTU.

### Sparse topology and gateways

Clusters of eight nodes or fewer use a direct full mesh. Above eight, the planner
uses the standard `topology.kubernetes.io/region` and
`topology.kubernetes.io/zone` labels (stable `unknown-*` domains when absent):

- nodes form deterministic rings inside a zone;
- two indexed zone gateways connect zones inside each region;
- two indexed regional gateways connect regions;
- weighted shortest paths prefer zone-local, then region-local, then cross-region
  edges, with normal planned degree bounded to six;
- domains with fewer than two gateway candidates are explicitly degraded.

Recovering leaves choose the currently lowest-degree eligible gateways, so spare
capacity is used evenly and the six-peer bound is retained whenever the remaining
stable topology has enough attachment capacity. Availability wins when that is
mathematically impossible (for example, many recovering leaves and only one stable
gateway): the plan reports `:peer-degree NODE COUNT` in its degraded-domain evidence
instead of silently claiming the normal bound. The intentional direct full mesh at
eight nodes or fewer is not a sparse-degree degradation.

Every destination remains an ordinary `NodeRoute`; an authenticated `nextHop`
only says which peer carries it. Agents group all destination CIDRs for that peer
into one WireGuard `AllowedIPs` set while retaining one kernel route per
destination. Before any destination CIDR migrates to a new peer, gr8s adds only
that gateway's reserved router `/32`, proves returned authenticated traffic, and
then commits the complete peer replacement. Failure restores the exact previous
configuration.

Lease expiry removes a failed gateway and republishes surviving routes on the
next monitor tick. A recovered node is reachable as a destination immediately but
cannot carry third-party traffic until 30 seconds of uninterrupted readiness.
That hysteresis makes failure fast and optimization slow; unchanged monitor ticks
do not create snapshot revisions. If no stable gateway exists during recovery,
temporary direct links preserve connectivity rather than appointing an unproven
transit node.

Useful kubelet metrics include:

- `gr8s_wireguard_path_selected`, `gr8s_wireguard_path_healthy`, and
  `gr8s_wireguard_path_score`;
- `gr8s_wireguard_path_consecutive_failures` and
  `gr8s_wireguard_peer_latest_handshake_seconds`;
- `gr8s_wireguard_path_passive_rtt_microseconds`,
  `gr8s_wireguard_path_passive_retransmits`,
  `gr8s_wireguard_path_passive_congestion_window`,
  `gr8s_wireguard_path_passive_active_flows`, and
  `gr8s_wireguard_path_passive_bytes_per_second`;
- `gr8s_wireguard_path_safe_mtu_bytes` and
  `gr8s_wireguard_telemetry_available`.

The overlay is IPv4-only today. Sparse mode's threshold and 30-second gateway
stability interval are conservative fixed defaults rather than public tuning
knobs. `scripts/test-wireguard-sparse-routing.sh` builds two independent gateways
in disposable namespaces, invokes the production next-hop trial, removes the
selected gateway, proves bidirectional recovery, checks peer bounds, and verifies
with an underlay packet capture that an application marker never appears in
plaintext.

### Network-aware consumers

Service and image distribution decisions share one deterministic, bounded score.
It combines same-node/zone/region locality, kernel-authenticated WireGuard path
health and cost, bounded active-flow load, advertised CPU capacity, and the
planner's link cost. Every numeric input is clamped at the trust boundary. An
unhealthy path loses immediately; optimization among healthy paths remains slow
and deterministic, and the second choice is promoted from another region/zone
failure domain when one exists.

The agent applies the score to ready Service endpoints before programming the
`cgroup/connect4` backend map. It programs at most four preferred endpoints per
port, reconverges when path observations change, keeps local endpoints cheapest,
and retains unhealthy candidates only as a last-resort availability fallback.
The control plane applies the same ordering to mTLS-authenticated BitTorrent
announcements using the requester's authenticated node status; tracker responses
contain at most eight peers. Missing path evidence is conservative neutral cost,
not a fabricated failure, so a new node can still bootstrap. Peer ordering is a
copy-only operation outside the tracker lock and cannot mutate swarm membership.

## Cross-node VXLAN

The native VXLAN backend uses static router neighbors and forwarding-database
entries, preserving Pod source addresses across nodes. Isolated two-node kernel
tests cover bidirectional connectivity, the 1450-byte inner MTU, repeated setup,
and peer-route removal.

Node underlay addresses are durable control-plane records. Address changes and
withdrawals publish new peer snapshots. Agents journal pending topology changes
before touching the kernel and retain the last applied topology until
reconciliation succeeds, so a restart can remove stale entries from a partial
update. A changed local underlay replaces the owned tunnel while retaining Pod
endpoints and allocations. Periodic local reconciliation repairs forwarding
entries lost to tunnel link events without requiring a newer control-plane
snapshot. Graceful agent restart retains pinned policy links/maps, Pod
assignments, and addresses.

Nodes need underlay connectivity for the node endpoint and VXLAN UDP port 4789.
Each agent receives its own Pod CIDR and the peer route set; no bridge or
host-local CNI configuration is required.

## Telemetry

Agents sample the pinned counters and publish endpoint telemetry through their
node sessions. The loopback control-plane `/metrics` endpoint exposes accepted and
dropped packets/bytes, spoof rejections, malformed/unsupported packets, sample
timestamps, and node readiness. An unreadable map sets
`gr8s_endpoint_telemetry_available` to zero and omits its counter series instead
of reporting false zero traffic.
