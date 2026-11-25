# Networking & the eBPF dataplane

gr8s has **no kube-proxy and no iptables**. Packet handling lives in the kernel,
programmed from Common Lisp through **[Whistler](https://github.com/atgreen/Whistler)**, which compiles s-expressions
directly to eBPF bytecode. It needs no LLVM, clang, `.c` file, or hand-written ELF. The
eBPF compiler and loader live *inside* the agent. Native builds prepare the
fixed endpoint bytecode templates before saving the executable; the agent loads
a relocated copy for each Pod. Other dataplane programs compile in the running
agent, and per-Pod state lives in BPF maps the agent updates.

This document covers the whole dataplane: the egress guard, NetworkPolicy,
Services and load balancing, the Gateway API, CNI/IPAM, DNS, and the VXLAN and
self-tuning WireGuard cross-node overlays. **VXLAN is the default**;
select WireGuard explicitly with `serve --overlay-backend wireguard`.
The [network access table](building-and-testing.md#network-access) lists the
baseline ports needed to join nodes.

## The per-Pod egress guard

The [Whistler](https://github.com/atgreen/Whistler) classifier attaches to each Pod's host-veth ingress (its egress
path) as a persistent TCX link. It uses an agent-initialized map to check the
exact IPAM IPv4 address and interface MAC, validates ARP sender identity, and
drops malformed or unsupported frames. It counts accepted/dropped packets and
bytes, rejected spoofs, malformed packets, and unsupported protocols. A
multicast the host itself sends out a Pod's veth -- an mDNS query from
avahi-daemon, say -- comes back to the host as a `PACKET_LOOPBACK` copy received
on that veth; the guard passes it unjudged and uncounted, since it isn't the
Pod's and never enters it, and only the host's own stack makes such a copy.

Identity initialization precedes TCX attachment; replacement links are attached
and pinned before atomically replacing the old pin. Existing counter maps survive
repeated CNI ADD calls. Each endpoint keeps `rejected_spoofs`,
`endpoint_identity`, and `traffic_stats` maps, the `netpol_*` NetworkPolicy
mode/CIDR/port/flow maps in IPv4 and IPv6 variants, and the `local_pod_v4` and
`host_redirect_v4` fast-path tables, alongside its `tcx-ingress` and
`tcx-egress` links
under `AGENT_STATE_DIR/containerd/bpf/CONTAINER_ID/`. CNI CHECK validates kernel
map schemas, identity, and the TCX interface/direction; DEL removes staged links
and all maps even after the Pod namespace disappears.

The guard also carries two host-firewall bypass fast paths. When a packet's
destination is another Pod on the same node, the guard redirects it straight to
that Pod's veth, driven by the `local_pod_v4` map (destination Pod IPv4 →
destination ifindex and MACs), skipping the kernel forward path and any host
firewall FORWARD reject
([`local-pod-delivery.lisp`](../src/network/local-pod-delivery.lisp)). When the
destination is host-local — the API server ClusterIP `10.96.0.1` or the node's
own address — the guard redirects the packet to the loopback ingress, which the
host firewall trusts, so Pod-to-host traffic never crosses the INPUT path
([`host-redirect.lisp`](../src/network/host-redirect.lisp)). The agent rebuilds
both tables in every Pod's pinned maps on each node reconcile.

The native image contains both ordinary and Service-enabled endpoint templates,
including their map descriptors and relocations. First CNI ADD uses the existing
five-second IPC deadline for kernel map creation, verification and attachment;
it reuses the prepared templates. Source-based runs compile them lazily once.
An isolated native VM measurement found 16.2 seconds of cold Service template
compilation versus 39 milliseconds for map creation and kernel program loading.
Native preparation moves that compilation into the build. The startup probe `scripts/probe-native-endpoint-startup.py`
measures both cache variants and loads unattached Service and ordinary pipelines,
checking that relocation preserves the templates. Run it in a disposable root VM
with `scripts/gr8s-debug.py` alongside it:

```sh
python3 scripts/probe-native-endpoint-startup.py --gr8s /root/gr8s \
  --require-prepared --report-directory /var/tmp/startup-evidence
```

Two fresh cross-node native/Kata runs pass all 28 checks with zero CNI ADD
timeouts on either node. See [the cold-start evidence](evidence/service-cni-startup-validation-2026-11-09.json).

Tests exercise the actual compiled bytecode on packet fixtures with both an
interpreter and the Linux BPF test-run facility. The privileged native smoke
injects a spoofed source into a live Pod namespace and requires the rejection
counter to appear through agent telemetry.

## NetworkPolicy: a compiled eBPF firewall

`networking.k8s.io/v1` NetworkPolicy controls ingress and egress on real native
Pods through eBPF guards at the Pod's host veth. The control plane resolves
Pod/Namespace selectors and named ports into peer addresses and port rules;
agents publish those rules into pinned maps. Policy changes update data rather
than requiring a new program for each policy.

Policy supports `podSelector`, `namespaceSelector`, combined selectors,
`ipBlock` with `except`, protocol/port ranges, and direction-specific default deny.
IPv6 neighbor discovery and MLD (ICMPv6, or MLD behind a hop-by-hop header) to or
from a link-scope peer -- `fe80::/10`, `ff02::/16` or the unspecified `::` -- are
not subject to NetworkPolicy: they keep the Pod's interface working, and Cilium
likewise always admits NDP. Other link-local traffic, such as mDNS, is.
Connection state permits reply traffic for allowed flows: for 5 days after a TCP
connection's last packet, as conntrack keeps an established connection (well past
the 2-hour `tcp_keepalive_time`, so an idle connection's keepalives get through),
and 3 minutes for other protocols. A refused packet is dropped
silently, with no reset or ICMP reply, so a client sees a timeout rather than an
error. Each Pod endpoint counts the packets policy refused, in both directions, as
`gr8s_endpoint_policy_drops_total`; they are also included in
`gr8s_endpoint_dropped_packets_total`. The counter says how many packets a Pod lost to
policy, not which policy refused them. See
[`network-policy.lisp`](../src/network/network-policy.lisp) and the enforcing guards in
[`egress-guard-program.lisp`](../src/network/egress-guard-program.lisp).

The original native smoke demonstrated egress default-deny on a live Pod.
Current source implements both directions and dual-family policy paths; the
[compatibility inventory](k3s-gap-inventory.md) distinguishes focused support from
the remaining combined IPv6/dual-stack acceptance work. An old egress-only smoke
result is not evidence for all newer policy behavior.

## Services & load balancing

Managed native clusters allocate durable IPv4 ClusterIP Services from
`10.96.0.0/16`, over TCP, UDP, or SCTP. Services accept JSON and typed Kubernetes
protobuf requests, including numeric and named target ports.

A **cgroup eBPF socket load balancer** rewrites a native client's `connect(2)` to
a ready backend, resolving numeric or named target ports against selected Pods or
manually managed slices. It covers TCP and UDP. In the socket LB there is no DNAT
and no conntrack: the socket connects
directly to the real backend, so the return path needs no reverse translation.
IPv4 and IPv6 `connect` hooks steer connected sockets, `sendmsg` hooks steer
unconnected UDP `sendto(2)`, and `recvmsg` hooks restore the Service source address
on UDP replies. `sessionAffinity: ClientIP`
holds each client's network namespace on one backend until the timeout passes or
the Service's backend set changes. The reserved `default/kubernetes` Service
describes the HTTPS API at `10.96.0.1:443`, with matching Endpoints and an
EndpointSlice.

SCTP ClusterIP traffic takes a separate path: the kernel never runs the
`connect4` hook for SCTP sockets, so two TC classifiers on the client Pod's veth
perform a DNAT-style rewrite of the IPv4 addresses, reusing the shared Service
and backend maps and a small `gr8s-sctp-ct` conntrack map to restore the VIP as
the reply source. Only addresses are rewritten, never ports — SCTP's CRC32c
covers the transport header but not the IP header — so a Service whose
`targetPort` differs from its `port` drops SCTP packets, as other eBPF
dataplanes also require. See
[`service-sctp-nat.lisp`](../src/network/service-sctp-nat.lisp).

Before rewriting a socket, the program validates that the selected backend belongs
to the requested Service. This prevents shared backend-slot repacking from sending
a connection to another Service during a reconcile or interrupted update. A failed
membership check refuses the attempt; later attempts recover after convergence.
`make test-service-lb-program` exercises the compiled bytecode across these update
boundaries. The same fixture can be tested with actual attached socket hooks using
`scripts/test-service-lb-program.py FIXTURE --kernel` inside a disposable root VM.
Host socket hooks do not intercept connections initiated inside a guest kernel.
The selected Service architecture follows the split common to eBPF dataplanes: keep socket
load balancing for native Pod connections and use the TC packet path for guest
interfaces and traffic that bypasses socket hooks. Ordinary Service traffic does
not require an additional identity envelope or Service-specific tunnel. This is
an implementation direction, not a claim that the packet path below is enabled
by default or that all kube-proxy Service modes are complete.

The packet path currently keys return translation on transport tuples. If the
same backend is exposed through multiple Service VIPs and independent flows
produce indistinguishable tuples, Service identity can be ambiguous: the
known multiple-VIP collision of tuple-keyed load balancers. The next packet-path
increment will adapt Calico's [collision-triggered source-port NAT][calico-nat]
where a reserved port and return route can be proved unique for the flow. Normal
flows should keep their source address and port. An unresolved collision must
drop instead of delivering to the wrong Service. This is planned behavior, not
a claim about the current opt-in packet pipeline. The
[experimental identity envelope](service-wire-protocol.md) is retained as
research and is not part of the default dataplane.

[calico-nat]: https://github.com/projectcalico/calico/blob/master/felix/design/bpf-services.md

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
[the guest validation evidence](evidence/service-guest-validation-2026-11-09.json).
The two-node guest regression also verifies TCP/UDP traffic over VXLAN to a
backend on another node, source-IP preservation, native socket acceleration,
guest egress policy on backend addresses/ports, reply handling under default-deny
guest ingress, and remote backend ingress denial/recovery. It uses two agents in
separate mount/network namespaces within one disposable VM; physical-host and NIC
offload behavior remains unverified. See
[the cross-node validation evidence](evidence/service-guest-two-node-validation-2026-11-09.json).
On reopening pinned maps, the controller inventories all six IPv4/IPv6 Service
control maps before reconciliation. It removes retained entries for Services
deleted while the agent was offline, including sparse orphan backend slots.
A native two-node restart regression verifies withdrawal, retained map IDs,
unchanged Pod identities and recovered Service traffic. See
[the restart validation evidence](evidence/service-map-restart-validation-2026-11-09.json).
An established guest TCP connection has also survived graceful restart of both
agents without reconnecting; see the restart evidence below.
Packet flows expire after 180 seconds of UDP inactivity, 120 seconds for pending
TCP handshakes, or two hours for established and legacy TCP flows, counting
requests and replies. A separate TCP metadata map records initial sequence
numbers and handshake progress without changing NAT value layouts. Same-sequence
SYN retransmissions retain their backend; a newer SYN beyond the observed stream
retires the old generation and selects a current eligible backend. Stale SYN and
SYN-ACK packets cannot overwrite that handshake metadata. The next packet removes an
expired forward entry before selecting from the current Service plan. Forward
and reverse tuple reservations serialize state changes; contention drops the
packet without waiting, and all reservations are released before the policy
continuation. Replaced-backend replies fail the forward/reverse ownership check.
The agent also visits at most 128 forward keys and 128 reverse keys per
reconciliation tick. An unattached BPF maintenance program rechecks lifetime and
paired ownership under those reservations, reclaiming expired pairs and abandoned
reverse entries. Userspace enumerates keys and invokes bounded kernel transactions;
it never holds a packet reservation across a userspace pause or agent exit.
Collection preserves fresh flows and does not refresh their timestamps. Affinity
state is separately bounded by its LRU map and validated on use.

Before collecting retained state, the agent verifies and refreshes pinned native
endpoint programs. It loads replacements against the existing maps before
publishing them, then prepends drop guards in both TCX directions. These guards
drain earlier packet executions before the agent changes the continuation table
and entry programs. The agent verifies the resulting kernel programs and map
references before removing the guards. Map and TCX link identities are preserved.
An interrupted refresh retains its guards for retry; CNI CHECK rejects that
endpoint until recovery. CNI changes serialize with refresh, and endpoint deletion
detaches retained guards as well as the ordinary links.

The agent prepares at most eight uncached endpoints per reconciliation tick.
Pending upgrades, incompatible map schemas, unsupported attachment modes and
failed kernel operations defer GC with diagnostics. Automatic refresh currently
supports native attachments. Retained TCP translations without observed handshake
metadata use the conservative legacy lifetime; refresh does not invent sequence
numbers or shorten their lifetime on FIN/RST. Newly observed connections use the
current TCP tracker. The agent reports verified retained pipelines and logs
enumeration/syscall failures; its dataplane tracks scanned, reclaimed, deferred
and failed transactions. See
[the expiry evidence](evidence/service-packet-expiry-validation-2026-11-09.json) and
[the background collection evidence](evidence/service-packet-gc-validation-2026-11-09.json).
BPF load diagnostics preserve the initial error, logging-retry errno and available
verifier output. A real restart captured initial EAGAIN followed by a full-buffer
ENOSPC; collection remained deferred until pipeline verification succeeded. See
[the loader diagnostic evidence](evidence/service-bpf-load-diagnostics-validation-2026-11-09.json).
The loader makes at most five syscall attempts per initial or logging phase,
retrying only transient EAGAIN. Other errors stop that phase immediately.
Failure diagnostics retain every attempt's errno; successful transient recovery
logs a compact message. See
[the bounded retry evidence](evidence/service-bpf-load-retry-validation-2026-11-09.json).
See [the program-upgrade evidence](evidence/service-packet-upgrade-validation-2026-11-09.json)
for kernel failure/recovery checks and actual guest connections across historical
and interrupted pipeline upgrades.
The generation and handshake stage is validated by an actual Kata guest reusing
its source port after backend replacement; see
[the TCP generation evidence](evidence/service-tcp-generation-validation-2026-11-09.json).
FIN sequence ends and their acknowledgments are tracked in both directions.
Half-closed connections retain the established lifetime so the peer can send its
final data. After both FINs are acknowledged, the retained entry expires after
120 seconds. A reset whose sequence matches both observed receiver ACK progress
and the sender stream end expires after 10 seconds; a SYN-SENT refusal must
acknowledge the current SYN.
Delayed packets still use the retained translation but do not refresh terminal
metadata or timestamps. Invalid resets reach the endpoint for challenge-ACK
handling without shortening the mapping's lifetime. See
[the TCP close evidence](evidence/service-tcp-close-validation-2026-11-09.json) for bytecode,
kernel GC and actual guest reset/graceful-close checks.
The tracker parses bounded TCP options, negotiates window scaling in both
directions, leaves SYN windows unscaled, and retains the largest advertised
window to allow retransmissions after window shrinkage. In-window FINs can
arrive before preceding data; closure still requires cumulative peer ACKs.
Stale or missing negotiated timestamps, out-of-window data, and ACKs beyond the
observed stream keep their translation without refreshing tracking state.
Timestamp floors advance only at the receiver ACK edge and age independently
after 24 days. RST handling does not require timestamps. Fresh timestamps can
distinguish new connections at a reused tuple, including the same initial
sequence after closure; SYN-ACK timestamp echoes protect the new handshake.
Retained entries from earlier agents keep compatibility tracking until a new
SYN records option negotiation. The pinned TCP value remains 64 bytes with
previously used field offsets preserved. See
[the TCP option evidence](evidence/service-tcp-options-validation-2026-11-09.json).
An actual guest regression keeps one TCP socket open across a selector change
and both agents' graceful restarts. Fresh sockets reach the replacement backend;
the established socket keeps its original backend, TCP initial sequences, map
IDs and workload identity, exchanges data while each agent is stopped, and
responds after fresh readiness returns. See
[the established-flow restart evidence](evidence/service-established-restart-validation-2026-11-09.json).
The fixture also verifies the same held-connection behavior with SIGKILL of each
agent, checking actual signal exit statuses and preserving the original TCP
generation through both restarts. Bytecode and kernel checks cover early data in
SYN/SYN-ACK packets, partial early-data acceptance, retransmission and closure.
A refusal may acknowledge the SYN without all its payload; only ACKs within the
observed SYN sequence range can shorten its lifetime. See
[the early-data and abrupt-restart evidence](evidence/service-tcp-early-data-validation-2026-11-09.json).
Kernel packet tests also cover program lifetime. Source NAT/hairpin,
return-tuple collision resolution, IPv6 packet translation and external Service
replacement remain in development. Hairpin and conflicting return tuples
currently drop safely. See [the engine validation scope](evidence/service-packet-engine-validation-2026-11-09.json)
and [the guard integration evidence](evidence/service-packet-guard-validation-2026-11-09.json).

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
For the additional TCP generation checks, build `make build/service-tcp-client`
with static libc development libraries available, copy the resulting test-only
binary to the VM, and pass `--tcp-client /root/service-tcp-client`. The runner
verifies its checksum after copying it into the guest, binds a fixed source port,
replaces the Service backend, then verifies both the new response and the pinned
TCP generation metadata. It also verifies reset and graceful-close metadata
using real guest connections, observes negotiated window/timestamp options,
and deletes/recreates a Service at the same VIP and client tuple.
`make test-service-tcp-state` exercises the interpreter;
add `--kernel` to the Python runner in a disposable root VM for kernel execution.
Pass `--tcp-restart` with `--tcp-client` to keep one guest socket open while
changing the Service selector and restarting each agent. Copy
`scripts/test-service-restart.py` alongside the other helpers for pinned map
inspection. This mode requires both stream directions to advance while the
agent is stopped, a further HTTP response after readiness returns, unchanged
TCP initial sequences and backend, retained map IDs, and unchanged Pod/container
identities. New connections must reach the updated backend while the held
connection keeps its original backend, then closes gracefully.
Add `--tcp-abrupt-restart` to send SIGKILL instead of SIGTERM to both agents;
the fixture requires each killed process to return the corresponding signal
status before checking offline traffic and restarting it.
For historical-program upgrade coverage, first build
`make build/gr8s-legacy-service-packet-guard-test.json`, copy that fixture and
`scripts/test-service-program-upgrade.py` into the VM, and add
`--tcp-upgrade /root/gr8s-legacy-service-packet-guard-test.json`. This installs the
pre-reservation NAT stages while the client agent is stopped and requires their
automatic refresh, retained map/link identities and activation of flow collection.
The held connection uses legacy tracking after refresh because its handshake
metadata was absent; a new connection must use the current tracker. Alternatively,
`--tcp-interrupted-upgrade` leaves two drop guards and a missing reverse stage
across restart. That mode requires blocked offline traffic, automatic recovery
and preservation of the held connection's original TCP metadata. Its test client
allows a longer receive deadline for the intentional interruption.

`NodePort` and `LoadBalancer` Services allocate node ports from 30000–32767. The
agent relays each in userspace, for TCP, UDP, and SCTP, with client-address
affinity; a port with no ready backends has no listener. `externalTrafficPolicy`
accepts `Cluster` and `Local`, `internalTrafficPolicy` accepts `Local`, and
`trafficDistribution` accepts `PreferClose`, `PreferSameZone`, and
`PreferSameNode`. Under `Cluster` policy a Pod sees the node as the source;
under `Local` the relay binds an `IP_TRANSPARENT` upstream socket to the
client's address so the Pod sees the original client (TCP and UDP; it falls
back to the node address without CAP_NET_ADMIN), and a Local LoadBalancer's
`healthCheckNodePort` answers whether this node has ready endpoints. No cloud
controller assigns a LoadBalancer an address.

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

## Gateway API: the agent is the gateway

gr8s implements the Kubernetes Gateway API as a capability of the in-image
agent — **no Envoy, no sidecars, no kube-proxy, no iptables**. `GatewayClass`,
`Gateway`, `HTTPRoute`, `TCPRoute`, `TLSRoute`, and `GRPCRoute` are served as
durable `gateway.networking.k8s.io/v1` objects and projected to the node that
runs them. Two things set it apart.

**Routing updates build immutable hostname indexes.** Matching code is compiled
once with gr8s. HTTPRoute changes build a replacement table of exact-host and
wildcard-suffix buckets containing precedence-ordered match records. Requests
check only the applicable host buckets, with path `Exact`/`PathPrefix`, method
and exact-header matching, filters, and weighted backend selection. The agent
hot-swaps the complete dispatcher; in-flight requests retain their old table.
Unchanged routing content reuses the existing dispatcher. Route updates do not
invoke the Lisp compiler.

Committed configuration changes wake the control-plane reconciliation worker.
A fixed 5 ms window coalesces pending changes, and writes arriving during a pass
request a follow-up pass. Status-only updates, resource-version bookkeeping,
Events, and Leases do not trigger these wakeups. The one-second periodic repair
pass remains, as does the HA leader gate. Pod and node state transitions retain
their periodic reconciliation path.

Changes confined to Gateway configuration publish keyed additions, replacements,
and deletions over the negotiated `gateway-config-delta-v1` node-session channel.
The publisher captures changed rows directly from committed state; it includes
newly referenced TLS Secrets with Gateway edits. Gateway status and attached-route
counts remain on the periodic full controller pass. Targeted publications do not
postpone that repair deadline, and a newly active leader runs a full pass first.
Older agents continue receiving full node snapshots.

Each batch names its full-node baseline and previous Gateway revision. Agents
reject stale, skipped, or malformed batches. A dependency revision fences changes
to Services, endpoints, policy, and other node configuration: those changes require
a full snapshot before later Gateway batches can activate. Gateway acknowledgments
do not satisfy node-snapshot acknowledgments or Service readiness grants.

The agent keeps a derived, immutable Gateway view in memory. HTTPRoute edits parse
only changed routes and replace affected hostname buckets; untouched candidate
vectors are shared with the previous table. Each published backend retains the
resolver for its view, so in-flight requests use a coherent endpoint version.
Listener and certificate changes use full listener planning. Service receiver,
risk, and selection checks remain prerequisites for applying a Gateway batch.

Gateway batches do not journal node desired state or run Pod/network reconciliation.
The control plane retains durable desired state. On disconnect the agent clears
its Gateway synchronization state; a new session must install a full baseline
before accepting batches or reporting synchronized Gateway observations. After a
process restart the agent rebuilds the derived view from full synchronization.
Full snapshots remain the initial-sync, reconnect, dependency-change, and periodic
repair path, and retain the existing node durability rules.

The [incremental Gateway evidence](evidence/gateway-incremental-validation-2026-11-15.json)
records the 3,000-route measurements and native recovery scope. A native agent
restored an unjournaled route after VM reboot through full synchronization, using
an external backend without Pod reservations. Restarting the complete benchmark
workload hit the existing resource-manager checkpoint rejection tracked as
`podster-z3h`, before Gateway synchronization could start.

Full discovery projection and attached-route counting read immutable captured
resource rows directly, avoiding redundant deep copies. Public resource reads
continue returning private copies. The evidence also separates the instrumented
2 GiB/4 GiB heap experiment from the uninstrumented route measurements: a larger
heap reduced GC time, while repeated full reconciliation still allocated substantial
temporary data. Heap sizing is unchanged by this implementation.

**The agent is the gateway.** An eBPF `sk_lookup` program (compiled from Lisp,
keyed by destination port through a `SOCKHASH`) steers an inbound connection for a
gateway port straight onto the agent's own listening socket — a port the agent
never bound — with `bpf_sk_assign`, so there is no kube-proxy hop and no iptables.
The in-agent L7 proxy then terminates the request and dispatches through the
indexed router to a ready backend Pod endpoint.

Supported today:

- **HTTP routing** with full match precedence, weighted traffic splitting, and
  HTTP filters: request/response header modifiers, URL rewrite
  (`ReplaceFullPath`/`ReplacePrefixMatch`), and request redirect.
- **HTTPS termination** on a listener, using the cert/key from a referenced
  `kubernetes.io/tls` Secret through the in-image pure-tls stack.
- **L4 routing** for TCPRoute (TCP splice) and TLSRoute/GRPCRoute (SNI
  passthrough: the TLS ClientHello SNI is peeked without terminating and used to
  pick the backend). The agent opens its own connection to the backend, so the
  backend sees the node as its peer. To learn the client, annotate the backend
  Service `gr8s.io/proxy-protocol: v2`: the agent then sends a PROXY protocol v2
  header with the client's address and port and the address it dialed, before
  any client byte (the replayed ClientHello included). The backend must expect
  the header, and should accept it only from the nodes' addresses.
- **Per-route observability and protection**:
  `gr8s_gateway_requests_total{gateway,route,code}` on `/metrics`, and a per-route
  token-bucket rate limiter (`gr8s.io/rate-limit-rps` → HTTP 429).
- **Tracing**, with OpenTelemetry: see below.

### Gateway tracing (OpenTelemetry)

An agent can trace the HTTP requests its Gateway listeners answer and send the
spans to an OpenTelemetry collector, or to anything that takes OTLP: Tempo,
Jaeger, Honeycomb, Grafana Cloud. Each request gets one SERVER span, named by
its method and route (`GET shop/web`), with OTel's HTTP attributes
(`http.request.method`, `url.path`, `http.route`, `http.response.status_code`,
`client.address`, `server.address`), the backend it reached
(`network.peer.address`, `k8s.namespace.name`) and the listener. A 5xx reply is
an error span. A request that arrives with a W3C `traceparent` joins that
trace; one without starts a trace. The backend is sent a `traceparent` naming
the Gateway's span as its parent, and the client's `tracestate`, so an
application instrumented with OpenTelemetry continues the trace: a trace shows
the browser's request, the Gateway's hop and the application's own work.

Tracing is off until an agent has somewhere to send spans. It reads OTel's
standard environment variables when it starts, so set them on the agent's
service and restart it, for example with `systemctl edit gr8s-server`:

```ini
[Service]
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://collector.lab:4318
Environment=OTEL_TRACES_SAMPLER=parentbased_traceidratio
Environment=OTEL_TRACES_SAMPLER_ARG=0.1
```

| Variable | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | The URL spans are posted to, as given |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Otherwise, a base URL; spans go to its `/v1/traces` |
| `OTEL_EXPORTER_OTLP_HEADERS`, `..._TRACES_HEADERS` | `name=value,...` headers sent with each export, such as an API key |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `parentbased_always_on` (the default), `parentbased_traceidratio` with a ratio, `always_on`, `always_off`, `traceidratio`, `parentbased_always_off` |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | The spans' resource; the service is `gr8s-gateway` unless set |
| `OTEL_SDK_DISABLED=true` | Off, whatever else is set |

gr8s sends OTLP over HTTP with JSON encoding, which every OTLP receiver accepts
on its HTTP port (4318 by convention), not gRPC (4317). A parent-based sampler
follows the caller's decision, so a trace is recorded whole or not at all; a
ratio sampler decides by the trace id, the same way on every node. Tracing
never slows a request: spans wait in a queue of 2,048 that one thread sends
every two seconds, or at 512, and a full queue or a failed export drops spans,
counted on `/metrics` as `gr8s_otel_spans_total{result}`. With tracing off, a
client's `traceparent` passes through to the backend unchanged. A traced
request's flow event carries its trace id (`l7.traceId`).

An agent can also send its [flow events](#flow-events) as OTLP **log
records**, to a logs backend such as Loki or anything behind an OpenTelemetry
Collector. Flow events far outnumber spans, so this is opt-in:
`OTEL_LOGS_EXPORTER=otlp`, with the logs going to
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`, or `OTEL_EXPORTER_OTLP_ENDPOINT`'s
`/v1/logs` (headers from `OTEL_EXPORTER_OTLP_LOGS_HEADERS` or the general
ones). Each event is one record of service `gr8s-flows`: a WARN for a drop,
INFO otherwise, with a one-line body (`DROPPED cave/cave-0 ->
secure.gravatar.com:443 TCP (policy)`) and OTel's attributes --
`source.address`/`.port` and `destination.address`/`.port` from the Pod's side,
`network.transport`, `k8s.namespace.name`, `k8s.pod.name`, `k8s.node.name` --
plus `gr8s.flow.verdict`, `.reason`, `.direction`, `.policies` and
`.peer.name`; a Gateway request adds its HTTP attributes and its trace id, so a
logs backend links the record to its trace. The records share the spans'
queueing and limits, counted as `gr8s_otel_log_records_total`.


GatewayClass and Gateway expose `/status` subresources. The control plane
publishes Gateway addresses only after a ready node reports that the current
Gateway UID and spec generation have running listeners. `Accepted` describes
configuration ownership and support; `Programmed` describes observed listener
readiness. Expired reports and replaced node connections cannot keep a Gateway
programmed. Each listener reports its supported route kinds, `attachedRoutes`,
and conditions; attachment counts follow parent references and `allowedRoutes`.
Status updates do not change the spec generation or the node configuration digest.

Wait for `Programmed=True` before sending traffic. HTTP listeners return 404
before the first matching route and remain available after the last route is
removed. `scripts/test-gateway-native.py --binary /path/to/gr8s` verifies this
lifecycle, controller-published addresses, attachment counts, and spec-generation
changes with real containers; run it as root in a disposable test VM.

`make smoke` creates a Gateway, an HTTPRoute, and a backend Service + Pod, then
proves a host/path request routes end-to-end through the in-agent proxy to the
real Pod.

**Tracked follow-ups:** ACME auto-issuance, HTTP RequestMirror, backendRef-level
filters, and an eBPF rate-limit fast path.

## CNI, IPAM & the Pod gateway

Managed Pods receive directly routed veth pairs and `/32` addresses from
persistent agent IPAM. The control plane assigns each node a distinct Pod CIDR
within `10.80.0.0/12` and includes the network configuration in desired-state
snapshots. The ranges are configurable: `--cluster-pod-cidr` takes one or more
comma-separated cluster pools (IPv6 CIDRs allowed), and `--node-pod-prefix` /
`--node-pod-prefix-ipv6` set the per-node CIDR size carved from them. The agent
persists that assignment and restores IPAM before restarting reconciliation. containerd invokes only the `gr8s` CNI plugin, which sends typed
requests to the agent's private Unix socket. CNI ADD retains its durable lease
through partial failures; DEL releases it only after removing policy and links.

### Traffic leaving the cluster

A Pod's address means nothing outside the cluster: a router upstream has no
route back to `10.80.x`, so a Pod's packet to the LAN or the internet would go
out and its reply never come. Each agent therefore masquerades traffic from its
node's Pod CIDRs to any address outside the cluster's Pod CIDRs as the node's
own address, as Flannel, Calico and Cilium do by default. The rule is an nftables
table of its own, `gr8s-egress`, which the agent replaces whenever the node's
network changes and removes when the node leaves. Pod-to-Pod traffic, on one
node or across the overlay, keeps its addresses, so NetworkPolicy and flow
events see the real peer; a Service's ClusterIP has already been translated to
a Pod's address by then. Masquerading applies when a connection starts, so the
replies of a connection made *to* a Pod, through a NodePort or the Gateway, are
not rewritten. An egress NetworkPolicy still sees the Pod's own address: the
guard runs at the Pod's veth, before the node translates anything.

On a network that routes the Pod CIDRs to the nodes itself (BGP, or static
routes on the router), start the agents with `--pod-masquerade off` and Pods
reach the outside with their own addresses; the agent then removes the table.


For packet-Service endpoints with IPv4, CNI ADD reserves a private IPv4 Service
translation address from the node's pool in addition to the ordinary Pod lease.
After policy installation succeeds, ADD installs a `/32` host return route and
a permanent neighbor to the owned peer MAC. It creates routes exclusively and
refuses to overwrite a conflicting route. The private address is not assigned in
the Pod, included in CNI result IPs, or permitted as an endpoint source address.
It consumes one additional IPv4 pool address per participating endpoint.
The agent reports it only for the Pod's current sandbox and observed IPv4 address.
The control plane binds the record to the assigned Pod and durable Node ID,
checks address ownership, and checkpoints it with the private observation.
Node-network snapshots carry these identities through readiness loss and agent
restarts. Public Pod status and watches exclude the private record, and client
status writes cannot set it. The route ownership journal recognizes validated
private leases under the endpoint's existing veth owner. See
[the identity validation evidence](evidence/service-translation-identity-validation-2026-11-09.json).
CHECK verifies retained return routes and neighbors. Repeating ADD can restore
missing state; partial ADD failures retain both leases, and DEL releases them
after removing the owned link and its routes/neighbors. Existing private leases
retain this handling if new allocation is disabled. Ordinary and IPv6-only
endpoints keep their previous allocation behavior; CHECK does not invent leases
for endpoints from older versions. See
[the return-path validation evidence](evidence/service-return-path-validation-2026-11-09.json).
Packet source NAT, versioned flow ownership, policy identity normalization and
receiving-node installation/readiness gating remain in progress.

A separate ABI-v2 packet component registers direct and Service tuples, reserves
return ownership, and uses private source addresses and ports for hairpin or
colliding connections. Its stages put translation around egress and ingress
policy boundaries. Source and backend incarnation checks prevent tuple reuse by
a replacement endpoint. Native routed CNI can attach the graph for an explicitly
opted-in v2 endpoint after the local risk inventory and exact owner pair are
published. The native build embeds the graph, and CNI validates shared map
schemas before attachment. After both TCX guards attach, CNI marks the exact
local owner pair receiver-ready; DEL disables that pair before removing links.
For disposable validation, managed native Pods can opt into the v2 CNI profile
with `GR8S_ENABLE_PACKET_SERVICES=1`,
`GR8S_PREPARE_PACKET_SERVICES_V2=1`, and
`GR8S_ENABLE_NATIVE_SERVICE_V2=1`. The last flag requires the first two; the
default managed profile remains v1 while live Service traffic is being tested.
The node's periodic status reports the complete set of locally ready owner
incarnations for its current risk revision. The server validates each report
against its authenticated node session and ACKed owner assignment, retaining
the report separately from short Pod status updates. The cluster grant is
withheld unless every trusted owner in the current projection appears in its
node's complete ready report; withdrawal revokes the grant on reconciliation.
The server distributes the validated receiver set in desired snapshots. Each
agent publishes remote receiver bits for those exact owner incarnations and
reads the map back before ACKing. The server requires ACKs of those snapshots
before minting the cluster grant. Retained-flow migration and live Service
traffic activation remain in progress.
`make test-service-nat` runs its synthetic packet interpreter tests. The same
fixture passed 42 packet cases and seven capacity/contention cases using real
BPF programs in a disposable VM; see
[the component validation evidence](evidence/service-nat-component-validation-2026-11-09.json).

The component also has a SYN generation preflight and incarnation-keyed TCP
metadata, with sequence/window checks, timestamps, handshake and closure
lifetimes. TCP observation runs in the policy-approved commit/restore stages.
The same check target exercises interleaved Service, direct and hairpin streams;
480 interpreter and 478 real-kernel TCP cases passed (two nonlinear-skb checks
are interpreter-only). After a return claim is removed, unmatched traffic to a
primary address passes unchanged without altering the new TCP state; unmatched
private-alias replies are dropped. This remains synthetic component evidence,
with no live workload or agent activation claim. See
[the TCP validation evidence](evidence/service-nat-tcp-validation-2026-11-09.json).

A separate maintenance program collects expired forward/return pairs and
incarnation-keyed TCP orphans under the same tuple reservations. It preserves
replacement and foreign owners; active TCP claims with missing or mismatched
metadata fail closed. The userspace v2 scanner is bounded to 128 keys per map
per tick by default (384 across three maps), with resumable cursors. Its profile
remains uncalled by the agent pending retained-writer and map validation. The
component passed 56 collection checks in both engines, capacity recovery using
actual one-entry kernel maps, and six concurrent calling threads. The latter
observed no natural contention; deterministic reservation cases test contention
separately. See
[the collector validation evidence](evidence/service-nat-gc-validation-2026-11-09.json).

Use `--cni-mode external --cni-conf-dir /etc/cni/net.d` to give ownership of
Pod links, addresses, routes, IPAM, and cross-node transport to operator-supplied
CNI configuration. Repeat `--cni-bin-dir DIR` to add plugin search directories;
the bundled gr8s plugin directory remains available. In external mode gr8s
points its managed containerd at the supplied directory but neither creates nor
overwrites a conflist, and it does not apply the native Pod CIDR, VXLAN, routes,
or IPAM. This is the ownership boundary needed by primary plugins such as
Calico, Canal, Flannel, or a Multus-selected default network.

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

`--dns-serve-zone ZONE` (repeatable) serves an external zone authoritatively
from each node's own address: an in-zone name matching a Gateway listener,
HTTPRoute, or Ingress hostname resolves to that node's gateway address, an
in-zone name that matches nothing is NXDOMAIN, and anything outside the zone is
REFUSED — the listener is never an open forwarder. Point a static forward or NS
delegation for the zone at the node addresses instead of running ExternalDNS.

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
with active probes and passive [Whistler](https://github.com/atgreen/Whistler)/eBPF measurements: RTT, retransmits,
congestion window, active flows, and throughput. A broken selected endpoint fails
over immediately. A healthy optimization needs repeated proof and a material cost
improvement. Endpoint changes are trialled without deleting the last-known-good
path, require returned authenticated bytes and a fresh handshake, and roll back on
failure. Selections, observations, MTU evidence, and bounded decision history are
persisted across restart. `gr8s network explain NODE PEER` takes two node names
(DNS labels, not addresses), resolves the sparse-topology destination to its
effective peer, and prints both the topology decision (`direct-peer` or
`sparse-next-hop`) and ranked endpoint evidence. It authenticates through the
kubeconfig like the other operator commands (`--kubeconfig PATH`, defaulting to
`$KUBECONFIG` or `~/.kube/config`); `--server URL` bypasses that with an
explicit endpoint.

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

WireGuard endpoint candidates (`--wireguard-endpoint NAME=IPV4:PORT` and
NAT-observed endpoints) are IPv4-only today; the VXLAN and WireGuard devices
themselves carry IPv6 Pod CIDRs and enable IPv6 forwarding for them. Sparse
mode's threshold and 30-second gateway
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

Registered VXLAN peers retain their direct Pod CIDR routes while an agent's
readiness lease expires. Existing Pods can keep exchanging traffic during an
agent restart; readiness still expires for scheduling and Service endpoint
selection. WireGuard gateway/transit readiness rules remain separate. The
[restart regression](evidence/service-established-restart-validation-2026-11-09.json)
reproduces the previous route withdrawal and verifies established guest traffic
through both agents' graceful restarts.

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

Cross-node traffic deliberately stays on the kernel's normal routing path, so an
active firewalld could drop it. The agent programs a narrow, overlay-scoped set
of ACCEPTs instead of trusting whole cluster CIDRs: the selected overlay device
joins an ACCEPT zone (admitting decapsulated or decrypted traffic), this node's
Pod CIDR becomes a zone source (admitting local Pod egress and forwarding in the
NEW direction; conntrack admits the replies as ESTABLISHED), and the overlay's
UDP port is admitted on the uplink. With no active firewalld nothing is
programmed; every step is idempotent and fail-soft. See
[`host-firewall.lisp`](../src/network/host-firewall.lisp).

## Telemetry

Agents sample the pinned counters and publish endpoint telemetry through their
node sessions. The loopback control-plane `/metrics` endpoint exposes accepted and
dropped packets/bytes, NetworkPolicy drops (`gr8s_endpoint_policy_drops_total`), spoof
rejections, malformed/unsupported packets, sample timestamps, and node readiness. An unreadable map sets
`gr8s_endpoint_telemetry_available` to zero and omits its counter series instead
of reporting false zero traffic.

### Flow events

The endpoint guards also report individual flows. Each node pins one ring
buffer, `flow_events`, in its private bpffs, and every endpoint's guards write
to it:

- **Drops**, with their reason: `policy`, `spoof`, `malformed` or
  `unsupported`. A policy drop carries the flow it refused, as seen from the
  Pod: the peer, both ports, the protocol and the direction.
- **New connections**, once each, in the direction they started: every Pod's
  by default, or with `--flow-events drops` (on `serve`, `agent` and
  `net-agent`) only those of Pods a NetworkPolicy isolates, the first time
  policy allows them. The guards keep each Pod's recent connections in its
  flow table, so a connection is reported once however many packets it has;
  a connection open before a policy isolates its Pod keeps passing until it
  goes quiet, as an established one. The setting is node-wide, in a
  `flow_config` map pinned beside the ring.
- **Gateway requests.** The agent's Gateway proxy reports each HTTP request it
  answers as an L7 flow from the client to the backend Pod: its method, host,
  path (never the query string), status, latency, route and listener port.
  `doctor observe` prints it as `HTTP GET host/path 200 12.0ms`; Hubble shows
  it as an `http-response` and applies `--http-method`, `--http-status` and
  `--http-path` to it.

A flow to an address outside the cluster carries `peerName`: the name a Pod
on that node asked the node's DNS server about to get the address, such as
`secure.gravatar.com` for `192.0.73.2`. The server notes the A and AAAA answers
it forwards upstream under the name asked for, not the end of a CNAME chain,
and an address keeps its latest name for six hours (4,096 addresses per node
at most). Two names that share an address, as on a CDN, show whichever was
asked last. An address no Pod looked up has no name, nor has one a Pod
resolved before the node's agent last started and hasn't looked up since.

A Pod's guards bind to the ring when the CNI installs them. After an upgrade
from a release without flow events, a Pod that was already running reports
none until it is recreated, unless its node runs the Service packet pipeline,
whose upgrade moves existing guards onto the ring. The same holds for any later
change to the guards: a running Pod keeps the guard it was created with. A
guard from before v1.37.2-gr8s.5, for instance, reports a Pod's replies to an
incoming connection as connections of their own; restart the Pod to replace it. An IPv4-only Pod has IPv6
turned off on its interface, so the kernel's IPv6 link-local chatter never
reaches its guard as spoofed traffic.

The agent reads the ring, names the local Pod each event belongs to, and keeps
the most recent 4,096. Nothing leaves the node until someone asks: the
control plane then opens a `FLOWS` operation on each node's existing session,
which sends events in batches of up to 64 KiB, at most ten a second while
following, merges the streams, and names the peer Pod and, for a policy drop, the
NetworkPolicies that isolate the Pod in that direction. A drop under
Kubernetes NetworkPolicy has no single deciding rule: the Pod is isolated by
every policy that selects it, and none of their rules allowed the traffic.

`GET /apis/gr8s.io/v1/flows` streams them as one JSON object per line, and
`?watch=true` keeps the stream open for new ones.
`/apis/gr8s.io/v1/namespaces/NAMESPACE/flows` returns the flows either side of
which is in NAMESPACE. RBAC authorizes these as `list` and `watch` of the
gr8s.io resource `flows`.

```sh
gr8s doctor observe                                # every node's recent flow events
gr8s doctor observe -n shop -f --verdict dropped   # follow one namespace's drops
gr8s doctor observe --pod cart --json              # one Pod's flows, as JSON lines
```

`gr8s doctor observe --serve` serves Hubble's Observer gRPC API on `127.0.0.1:4245` (`--listen` moves it), from
the same API and with the kubeconfig's credentials, so the stock `hubble` CLI
works against gr8s:

```sh
gr8s doctor observe --serve &
hubble observe --verdict DROPPED --namespace shop
```

It serves `GetFlows`, `GetNodes` and `ServerStatus`. It applies Hubble's flow
filters on the server, as Hubble does, and refuses one it can't apply
(Services) instead of widening it; one on DNS names matches nothing. Flows carry Pod labels as
`k8s:` labels and a numeric identity derived, as Cilium's are, from the Pod's
namespace and labels without the ones that tell replicas apart
(`pod-template-hash` and the like), so a workload's replicas share one.

`gr8s dashboard`'s Network tab draws the same flows as a service map, on a
loopback port under an unguessable path, read with the kubeconfig's
credentials. A node of the map is a workload -- a Pod resolved through its
owners to its Deployment, StatefulSet, DaemonSet or Job -- or a Service, a
Gateway, a cluster node, the LAN, or the world. A Gateway sits between the
clients it serves (the world for a public address, the LAN's clients for a
private one) and the workloads its routes send to. An edge counts a connection
once over the last 1, 5 and 15 minutes, with its drops, HTTP errors and median
latency, and keeps its latest flows; the map shows what flow events show, drops
and new connections, not each packet or byte. A card's icon is the app's own
favicon when it has a web UI, read through the Service proxy, else the
software its image shows it to be, else its kind. A peer outside the cluster
is drawn as its DNS name when its flows carry one (`peerName`, below), so each
site the cluster talks to is a node of its own; an address no Pod looked up is
the world, or the bare address for a private one.

Selecting an edge explains its connections under NetworkPolicy, as the
dataplane reads it: for each distinct source, destination, port and protocol,
whether a policy isolates the source leaving and the destination arriving, and
which rule of which policy allows the connection. For a denied connection, it
names the policies that isolate the end that refused it and suggests the
smallest rule to add to one of them: the peer selected by the labels that say
what it is (`app.kubernetes.io/name` and its companions, else `app`), never
the labels that tell replicas apart, in a `namespaceSelector` too when it is
in another namespace, or as a `/32` ipBlock when it isn't a Pod. The suggestion
is text to review; the dashboard changes nothing. A card with a shield is a
workload a policy isolates; its panel says which, each way. The view is in the
page's URL (`#ns=cave&edge=…`), so it can be linked. A policy's name, and a
selected workload's "Open in Headlamp", open that resource in the dashboard's
Headlamp tab, to read or edit it there. An edge the Gateway carries lists its
slowest recent requests under Traces, each with its status and latency; when a
dashboard tab shows traces (a `DashboardTab` with `spec.traces`, such as
Grafana with Tempo), each one opens its trace there -- the Gateway's span and,
for an instrumented backend, the backend's own beneath it.

The tab asks [`gr8s doctor`](doctor.md) about the whole cluster every minute
and draws its problems on the map: a card with a red edge is a workload a
problem is about, one with an amber edge is held up by a problem elsewhere,
and its panel shows each problem with its evidence, next step and what it holds
up. Health, in the header, lists them all, including those about resources
with no traffic on the map. NetworkPolicy drops are left to the edges. A drop the
dataplane made for another reason, such as its anti-spoofing check, is named
as such in an edge's Policy section rather than explained by policy.

On a foreign cluster, where gr8s-net provides the network and nothing serves
`/apis/gr8s.io/v1/flows`, each `gr8s net-agent` collects its node's flow
events the same way and serves them on `127.0.0.1:4246` (`--flow-port`). It
opens no port on the node: the agent Pod is on the host network, and a reader
reaches it through the cluster API's `pods/portforward`, which the kubelet
connects to loopback. `gr8s doctor observe` (with or without `--serve`) and
`gr8s dashboard`'s Network tab do this by themselves when the cluster doesn't serve the
gr8s.io API: they find the agent Pods by their `app.kubernetes.io/name=gr8s-net`
label, read every node's stream, and name peers and isolating policies from
the Pods and NetworkPolicies they list. The reader's credentials need `list`
of Pods and NetworkPolicies, and `create` of `pods/portforward` in the
gr8s-net namespace.
