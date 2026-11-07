# Networking & the eBPF dataplane

gr8s has **no kube-proxy and no iptables**. Packet handling lives in the kernel,
programmed from Common Lisp through **Whistler**, which compiles s-expressions
directly to eBPF bytecode — no LLVM, no clang, no `.c`, no hand-written ELF. The
eBPF compiler and loader live *inside* the running agent, so dataplane programs
are compiled and loaded on the fly, and per-Pod state lives in BPF maps the agent
updates.

This document covers the whole dataplane: the egress guard, NetworkPolicy,
Services and load balancing, the Gateway API, CNI/IPAM, DNS, and cross-node VXLAN.

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

A **`cgroup/connect4` eBPF socket load balancer** rewrites a Pod's `connect(2)` to
a ready backend, resolving numeric or named target ports against selected Pods or
manually managed slices. There is no DNAT and no conntrack: the socket connects
directly to the real backend, so the return path needs no reverse translation.
Unconnected UDP `sendto(2)` does not pass through it. `sessionAffinity: ClientIP`
holds each client's network namespace on one backend until the timeout passes or
the Service's backend set changes. The reserved `default/kubernetes` Service
describes the HTTPS API at `10.96.0.1:443`, with matching Endpoints and an
EndpointSlice.

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
delivery. SRV, PTR, DNS-schema TXT, generated endpoint-hostname records, and
ExternalName are tracked separately.

`scripts/test-pod-dns-config.py` verifies actual resolver files and custom
UDP/TCP queries against a separate resolver in an owned guest.

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
