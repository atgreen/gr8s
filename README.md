# gr8s

**A whole Kubernetes node — control plane, agent, CRI runtime, CNI, and a
Lisp-compiled eBPF dataplane — in one self-contained native image.**

gr8s is a small, Kubernetes-compatible Pod control plane written in Common Lisp.
A single SBCL-dumped executable plays every role: it serves the Kubernetes HTTP
API, schedules Pods, acts as the node agent, speaks CRI to an embedded
containerd, implements the CNI plugin, and compiles its own eBPF dataplane — with
no Envoy, no kube-proxy, no iptables, and no C toolchain anywhere in the build.
It uses the same runtime boundary as k3s (containerd through the Kubernetes CRI,
rather than shelling out to a container CLI), but almost everything above and
around that boundary is Lisp. The control plane schedules Pods and publishes
desired state; the agent owns the node runtime and reports observed status.

## What's special about gr8s

gr8s is a clean-slate, modern implementation of Kubernetes. Kubernetes grew up
before eBPF, and the ecosystem spent a decade bolting modern primitives onto it:
eBPF dataplanes replacing kube-proxy/iptables, consensus behind a separate etcd,
gateways behind proxy sidecars. gr8s starts from where the ecosystem landed and
makes those primitives **foundational** rather than retrofitted — the dataplane
*is* eBPF, the datastore *is* a built-in Raft, the gateway *is* the node agent —
and it does it in one language and one static binary, with no kube-proxy, no
iptables, no Envoy, no etcd, and no C toolchain anywhere in the build.

- **eBPF is the dataplane, not an add-on.** Whistler compiles eBPF *directly from
  Lisp* — no LLVM, no clang, no `.c`, no hand-written ELF. The CNI anti-spoof
  egress guard, the NetworkPolicy firewall, the ClusterIP service load balancer,
  and the Gateway's inbound `sk_lookup` steering are all Lisp→eBPF, loaded through
  a Lisp BPF loader and a Lisp rtnetlink stack. There is no kube-proxy and no
  iptables; packet handling lives in the kernel, programmed from Lisp.
- **One static image, every role.** `gr8s serve` is the control plane *and* a
  node; the same binary is the standalone agent and the CNI plugin. It embeds
  statically linked containerd 2.4.2, `containerd-shim-runc-v2`, runc 1.5.2, and
  the `bridge`/`host-local`/`loopback` CNI plugins 1.9.1 — no system containerd,
  no host glibc, no separate CNI helper binary. At startup it mounts a private
  `tmpfs` and BPF filesystem, materializes the payload, and runs its own
  containerd.
- **Gateway API with no proxy sidecar.** HTTPRoutes are *JIT-compiled*: SBCL
  turns the routing table into a native dispatch function with route constants
  inlined and Gateway-API precedence baked into the branch order, recompiled on
  change in microseconds. The agent itself terminates HTTP/HTTPS and L4, and an
  eBPF `sk_lookup` program steers the gateway port straight to the agent's
  socket. The agent *is* the gateway. See [Gateway API](#gateway-api-no-envoy).
- **NetworkPolicy as a compiled firewall.** Policies become data in per-Pod eBPF
  maps enforced at the Pod's host veth — default-deny egress proven on a real Pod
  in the smoke test, with no per-change recompile. See
  [NetworkPolicy](#networkpolicy-compiled-ebpf-firewall).
- **Multi-master HA on a Raft written from scratch in Lisp.** No etcd, no
  external database: the control plane replicates its desired state over a
  pure-Common-Lisp Raft that speaks ag-gRPC. A three-member (or two-member +
  witness) cluster survives the loss of its leader with no loss of committed
  state — proven end to end over HTTP in a smoke test that kills the leader. See
  [High availability](#high-availability-pure-lisp-raft).
- **Lisp all the way down.** API server (Hunchentoot), JSON (jzon), CRI client
  (ag-gRPC over a Unix socket), TLS + ACME (pure-tls), the scheduler, the
  controllers, IPAM, rtnetlink, DNS, and the eBPF compiler — one language, one
  image, no external runtime to install.
- **Honest about scope.** Capabilities below are backed by committed evidence
  records, and conformance numbers are reported as-is. gr8s has not passed
  Kubernetes conformance, and it says so plainly.

## Contents

- [How it fits together](#how-it-fits-together)
- [Kubernetes surface](#kubernetes-surface)
- [Gateway API (no Envoy)](#gateway-api-no-envoy)
- [NetworkPolicy (compiled eBPF firewall)](#networkpolicy-compiled-ebpf-firewall)
- [High availability (pure-Lisp Raft)](#high-availability-pure-lisp-raft)
- [Runtime architecture](#runtime-architecture)
- [Requirements](#requirements)
- [Build and run](#build-and-run-the-self-contained-server)
- [Test](#test)
- [Native executable](#native-executable)
- [Versioning](#versioning)

## How it fits together

The runtime client is Common Lisp too. gr8s uses ag-gRPC over a Unix-domain
socket and generated bindings for the pinned Kubernetes CRI v1 schema. The
native build embeds pinned, statically linked containerd 2.4.2,
`containerd-shim-runc-v2`, runc 1.5.2, and CNI `bridge`, `host-local`, and
`loopback` plugins 1.9.1. It also embeds a TC/eBPF classifier compiled from Lisp
by Whistler 1.15.0. The dumped gr8s image implements the CNI protocol as a thin Unix-socket client.
The agent owns IPAM, native rtnetlink setup, and the Whistler loader.
At startup the local gr8s agent
mounts a private `tmpfs`, materializes the payload there, starts its own
containerd, and unmounts the payload after containerd stops. It also mounts a
private BPF filesystem under the selected state directory for the lifetime of
the managed runtime:

```text
kubectl -> gr8s HTTP API -> scheduler -> desired-state snapshot
                                           |
                                           v
                              gRPC NodeService.Connect
                                           |
                                           v
                    gr8s agent -> reconciler -> CRI v1 -> containerd
                                                            |
                                                            +-> runc
                                                            +-> gr8s CNI client
                                                                      |
                                                               agent Unix socket
                                                                      |
                                                        IPAM -> routed veths
                                                                      |
                                                               Whistler TC/eBPF
```

Verified CRI operations include runtime version discovery, image pull, Pod
sandbox creation, container creation and start, status/exit-code observation,
CRI log output, and clean container/sandbox removal. The node agent uses this
managed containerd adapter by default.

## Kubernetes surface

The current API supports Pods in the `default` namespace:

- `kubectl apply`, `get`, `describe`, and `delete`
- images, commands, arguments, environment variables, and container ports
- durable desired state and optimistic resource-version checks
- periodic, idempotent reconciliation with transient-failure retry

Pods support finalizers that retain API objects after actual runtime cleanup,
including zero-grace deletion. Native validation covers real exit codes 0 and
137, restart recovery, UID reuse, unrelated execution during finalizer retention,
and cancellation of a blocked Exec probe. See the
[finalizer evidence](docs/pod-finalizers-native-2026-11-04.json).

Namespaced ConfigMap and Secret APIs support durable CRUD, list/selectors,
pagination, patch, optimistic concurrency, and dry-run through current kubectl
clients. See [ConfigMap and Secret APIs](docs/configmap-secret-api.md) for the
supported surface. Pods can consume referenced environment keys and mounted
files. A deleted Namespace turns Terminating and refuses new content while its
Pods drain first, then its other objects, until its finalizers are released.

Lease, flow control, dynamic resource allocation and admission policy objects are
served with protobuf requests, selectors, watches, status subresources and
finalizers. Only the API exists for most of them: no flow control limits requests
and no allocator serves ResourceClaims. Admission policies are enforced:
ValidatingAdmissionPolicy and MutatingAdmissionPolicy evaluate CEL on the admission
path, though `status.typeChecking`, audit annotations and the `authorizer` variable
are not implemented.

Pods mount signed ES256 ServiceAccount tokens bound to the Pod and its node, renewed
by the control plane after 80% of their lifetime. TokenRequest, TokenReview, the
SubjectAccessReview family, authorized impersonation and OIDC discovery are served.

ResourceQuota, LimitRange, RuntimeClass and PriorityClass are served with real
effects. Quota usage is computed from the live objects and checked under the store
lock at admission, so a write that would exceed a hard limit gets a 403; the
`Terminating`, `NotTerminating`, `BestEffort`, `NotBestEffort` and `PriorityClass`
scopes apply. LimitRange defaults and bounds new Pods and bounds new claims.
RuntimeClass admission resolves overhead and scheduling constraints, and the handler
reaches CRI `RunPodSandbox`, so an unconfigured handler leaves the Pod pending with
the runtime's error. PriorityClass resolves `spec.priority`.

The scheduler charges Pod requests and overhead against the CPU, memory, storage
and Pod count agents report, and against extended resources advertised through
Node status. It evaluates node selectors and node affinity, and when nothing fits
it preempts lower-priority Pods, marking them with a `DisruptionTarget` condition.
Pod affinity and anti-affinity filter and order nodes as upstream's plugin does, in
both directions, and quota has a `CrossNamespacePodAffinity` scope. Containers get
private PID namespaces unless `shareProcessNamespace` sets one for the Pod.
`spec.activeDeadlineSeconds` is counted
from Pod creation rather than from the first node's acceptance. A declared
`ephemeral-storage` limit counts for quota, LimitRange and scheduling, and the node
evicts a Pod whose writable layers and disk-backed emptyDirs exceed it, checking
every ten seconds. Container logs are not included in that measurement.

Pod logs and exec run through correlated agent operations, including interactive
streams and nonzero exit status. Complete agent-crash recovery
remain outside the verified boundary. The administrative HTTP API refuses
non-loopback listener addresses; native Pods use the authenticated HTTPS API
described below.

`admissionregistration.k8s.io/v1` webhook configurations call their backends
with AdmissionReview on API writes and Pod connections, over TLS verified against
the `caBundle` and within `timeoutSeconds`, with rules, selectors, `failurePolicy`,
ordered JSON patches and `reinvocationPolicy` applied as upstream does. A Service
backend is reached directly at a ready endpoint. `matchConditions` run a bounded
CEL subset (`src/admission-cel.lisp`): `authorizer`, `matches`, uint, bytes and
other unsupported CEL fail at registration instead of being misjudged. Objects
written by in-process controllers do not pass through webhooks yet.

## Gateway API (no Envoy)

gr8s implements the Kubernetes Gateway API as a capability of the in-image
agent — no Envoy, no sidecars, no kube-proxy, no iptables. `GatewayClass`,
`Gateway`, `HTTPRoute`, `TCPRoute`, `TLSRoute` and `GRPCRoute` are served as
durable, discoverable `gateway.networking.k8s.io/v1` objects and projected to
the node that runs them. Two unfair advantages set it apart.

**The routing table is compiled, not interpreted.** When HTTPRoutes change, SBCL
JIT-compiles the match table into a native Lisp dispatch function — hostnames
(exact and `*.suffix`), path `Exact`/`PathPrefix`, method and exact-header
matches, and weighted backends — with the route constants inlined and
Gateway-API match precedence baked into the `cond` branch order. A route change
recompiles in microseconds; there is no per-request walk of a rules table.

**The agent is the gateway.** An eBPF `sk_lookup` program (compiled from Lisp,
keyed by destination port through a `SOCKHASH`) steers an inbound connection for
a gateway port straight onto the agent's own listening socket — a port the agent
never bound — with `bpf_sk_assign`, so there is no kube-proxy hop and no
iptables. The in-agent L7 proxy then terminates the request and dispatches
through the compiled router to a ready backend Pod endpoint.

Supported today:

- **HTTP routing** with full match precedence, weighted traffic splitting, and
  HTTP filters: request/response header modifiers, URL rewrite
  (`ReplaceFullPath`/`ReplacePrefixMatch`) and request redirect.
- **HTTPS termination** on a listener, using the cert/key from a referenced
  `kubernetes.io/tls` Secret through the in-image pure-tls stack.
- **L4 routing** for TCPRoute (TCP splice) and TLSRoute/GRPCRoute (SNI
  passthrough: the TLS ClientHello SNI is peeked without terminating and used to
  pick the backend).
- **Per-route observability and protection**:
  `gr8s_gateway_requests_total{gateway,route,code}` on `/metrics`, and a
  per-route token-bucket rate limiter (`gr8s.io/rate-limit-rps` → HTTP 429).

`make smoke` creates a Gateway, an HTTPRoute, and a backend Service + Pod, then
proves a host/path request routes end-to-end through the in-agent proxy to the
real Pod. ACME auto-issuance, HTTP RequestMirror, backendRef-level filters, and
an eBPF rate-limit fast path are tracked follow-ups.

## NetworkPolicy (compiled eBPF firewall)

`networking.k8s.io/v1` NetworkPolicy is enforced as a compiled eBPF firewall on
real Pods. Rather than recompiling a program per policy change, gr8s folds
enforcement into the per-Pod egress classifier at the host veth and drives it
from BPF maps: the resolved policy — allowed destination CIDRs in an LPM trie and
permitted `(group, protocol, port)` tuples in a hash — is written as *data* into
pinned maps, so a policy change is a map update, not a recompile or a re-attach.
Egress to a destination no rule permits is dropped (default-deny), and the drops
are counted and exported through the same endpoint telemetry as the anti-spoof
guard.

The smoke test applies a default-deny-egress policy to a running Pod and
requires its previously reachable gateway to become unreachable, proving
enforcement on a live Pod; detach-on-removal is covered by unit tests.
Ingress-direction enforcement, connection tracking for reply traffic, namespace
selectors and `ipBlock.except` are tracked for completeness.

## High availability (pure-Lisp Raft)

The control plane can run multi-master on a Raft consensus layer written from
scratch in Common Lisp — no etcd, no external database. Members talk over the
same ag-gRPC transport as everything else. The Raft core (leader election, log
replication, the §5.4.2 commit rule, apply-once-in-order) runs under a
deterministic in-process simulator for failover/partition tests *and* under real
gRPC, from one implementation. The log is a durable write-ahead log with
snapshot/compaction and crash recovery.

gr8s splits state along a **consistency plane**: durable desired state (the
stored API resources) is proposed through Raft so every member converges, while
observed status, endpoint telemetry, node heartbeats/leases, and self-expiring
Events stay off the log — each member keeps its own and agents re-report after a
failover. What is replicated, and verified to survive a leader kill with its
identity intact: core API resources (including controller-written status, Job
accounting, EndpointSlices, CSR/certificate issuance state), **Pods**, and a
Node's assigned PodCIDR. Events are deliberately local.

Around the datastore:

- **Controllers are leader-gated** — reconciliation runs only on the leader; a
  follower idles until promoted.
- **Leader-aware HTTP** — a follower answers a mutating API request with a 307 to
  the current leader (preserving path and query), or 503 when no leader is known;
  reads are served locally.
- **Agents reconnect across failover** — given more than one control-plane
  endpoint, a node agent rotates through them on reconnect and resumes against
  the new leader.
- **Membership is dynamic** — single-member, effective-on-commit changes grow or
  shrink the cluster; a **witness** votes for quorum but never leads, so a
  two-node + witness topology survives one node loss. New members enroll with a
  one-time token, then join with the certificate they receive (a follower
  redirects to the leader).
- **Members use mutual TLS** — replication carries every Secret, so each member
  needs a certificate from the cluster's own Raft CA, and a message must come from
  the member it names. Worker certificates and tokens aren't accepted, because
  they come from a separate CA and token store. A joiner checks the CA against its
  pin before sending anything. Voters hold the CA key so they can admit replacements
  after a failover; witnesses don't, but their log does hold replicated state, which
  is why it's created with mode `0600`. Member certificates last a year and renew
  themselves in their last 30 days: a voter signs its own, and a witness asks a
  voter, so a witness that stays offline past expiry has to enroll again.
- **Voters share the node CA** — a joining control plane receives the cluster's
  node CA when it enrolls, so agents and API clients keep working after a failover.
  Join with a new state directory, because one that already has a different CA is
  refused rather than orphaning the certificates it issued.

Three commands and a flag surface it:

```sh
# Found a cluster.
gr8s serve --raft-init --raft-id cp1 --raft-port 7000 ...
# On cp1, create a token for each new member. This prints its token and caPin.
gr8s join-token --role control-plane --node-name cp2
# Join through the member that created the token.
gr8s serve --raft-join 10.0.0.1:7000 --raft-id cp2 --raft-port 7000 \
  --raft-node-name cp2 --raft-token "$TOKEN" --raft-ca-pin "$CA_PIN" ...
# A headless quorum tie-breaker (no API, no workloads).
gr8s witness --join 10.0.0.1:7000 --node-name arb --token "$TOKEN" --ca-pin "$CA_PIN"
```

This is opt-in: with no `--raft-*` flag, `gr8s serve` runs exactly as the
single-node path always has — no Raft member starts. An HA acceptance smoke test
stands up a three-member cluster over HTTP, creates a resource through the
leader, kills the leader, and requires the survivors to keep serving the
committed data and accept new writes.

Honest about scope: gr8s has not passed Kubernetes conformance, and HA does not
change that. Pod desired state uses a leader-applies-then-replicate model (so a
multi-step controller transaction sees its own writes), which leaves a narrow
window on a leader crash mid-commit; and replication currently ships the whole
resource index per write rather than per-key deltas. Both are tracked as
refinements, not correctness gaps — no *committed* desired state is lost on
failover.

## Runtime architecture

The executable has these entry paths:

- `gr8s serve` runs the HTTP control plane and a loopback gRPC node endpoint, and
  optionally joins a Raft cluster with `--raft-init`/`--raft-join` (see
  [High availability](#high-availability-pure-lisp-raft));
- `gr8s agent` enrolls with a one-time token, persists its node key and
  certificate, and maintains the revisioned desired-state session;
- `gr8s witness` runs a headless Raft voting member (a quorum tie-breaker);
- `gr8s version` prints the version; a CNI invocation is selected automatically
  when `CNI_COMMAND` is present.

`serve` starts a local agent named `gr8s-local` by default. That agent crosses
the same ag-gRPC boundary as a separately launched agent; `--disable-agent`
runs a control-plane-only process and does not create a managed node runtime.
The node endpoint defaults to loopback port 7443. Set `--node-listen` and
`--node-port` for a node-facing address; the Kubernetes HTTP API stays on
loopback. Agents advertise the source IPv4 address of their control connection
for VXLAN, or use an explicit `--node-address` on multi-interface hosts. The
local node name can be changed with `--node-name`.

`--containerd-no-sync` is off by default and is for disposable test machines only.
It makes the managed containerd skip fsync on its metadata database (bbolt
`no_sync`), which shortens Pod startup on virtual disks where a flush takes
hundreds of milliseconds. The snapshotter and runc still sync. After a host crash or power loss, containerd's metadata can be lost
or corrupted, and containerd may then not start until its state is removed. A gr8s
process crash is unaffected, and the flag changes nothing about how gr8s itself
persists state. `scripts/test-podtemplates-sonobuoy.py` passes it only when asked,
and records the setting as `containerdNoSync` in `report.json`, so compare runs only
when it matches.

Enrollment verifies the server certificate against `--ca-pin` before sending the
one-time join token. It generates the private key on the node and stores
`node.key`, `node.crt`, `ca.crt`, the assigned Pod CIDR, and the last-applied
revision below the agent state directory. Persistent sessions require a client
certificate signed by the cluster CA and bound to the node name. Revisioned sessions carry
node hello, heartbeat, complete desired-state snapshots, observed Pod status,
and durable revision acknowledgements. The agent persists assigned Pods,
reconciles them through its node runtime, adopts matching runtime objects after
a restart, and treats omission from an authoritative snapshot as deletion.
Persistent agents apply snapshots in order on a session-owned worker, allowing
the receive loop to serve log and exec requests while another Pod's runtime
operation is still converging. Acknowledgements follow durable application;
disconnect cancels and joins snapshot work before the session is replaced.
The [node log validation record](docs/node-log-delivery-validation-2026-11-04.json)
preserves the starvation reproducer, cancellation checks and the passing
upstream Secret-volume mappings case.

gr8s does not reimplement an OCI runtime. Its embedded containerd owns images,
sandboxes, containers, and the OCI runtime lifecycle. gr8s owns desired state,
while each agent calls containerd's `runtime.v1.RuntimeService` and
`ImageService` directly over its private Unix socket. containerd root, state,
temporary files, CRI socket, runc state, shim sockets, and logs are configured
as agent-owned paths.

The checked-in [`proto/cri-v1.proto`](proto/cri-v1.proto) is the full CRI v1
schema pinned from Kubernetes `cri-api` v0.36.0. Its generated Common Lisp
bindings live in `src/cri-v1-generated.lisp`.

Managed Pods receive directly routed veth pairs and `/32` addresses from
persistent agent IPAM. The control plane assigns each node a distinct Pod CIDR
within `10.80.0.0/12` and includes the network configuration in desired-state
snapshots. The agent persists that assignment and restores IPAM before restarting
reconciliation. Containerd invokes only the `gr8s` CNI plugin, which sends typed
requests to the agent's private Unix socket. CNI ADD retains its durable lease
through partial failures; DEL releases it only after removing policy and links.

Each node owns `169.254.1.1/32` on the `gr8s-gateway` dummy interface. Pod
veths have individual `/32` routes without duplicating that gateway address.
Each Pod has a permanent neighbor mapping the gateway to its host veth MAC,
plus a link route and default route through it. CNI CHECK verifies these
addresses, routes, and neighbor state; repeated ADD repairs drift and removes
legacy gateway addresses from the endpoint veth. The agent keeps its gateway
while durable leases exist and removes it on shutdown after all leases are gone.
The agent serves DNS there and writes `<pod-namespace>.svc.cluster.local`,
`svc.cluster.local`, and `cluster.local` searches into the Pod resolver. It
answers Service A/AAAA address queries from durable local discovery data and
forwards names outside `cluster.local` to the host's IPv4 resolvers, over UDP or TCP.
Pod `dnsPolicy` selects actual cluster, host or explicitly configured resolver
settings. `dnsConfig` merges validated nameservers, search paths and options;
`None` uses only the supplied settings. DNS policy/configuration are immutable
after Pod creation, and equivalent default metadata round trips preserve the
runtime fingerprint. `scripts/test-pod-dns-config.py` verifies actual resolver
files and custom UDP/TCP queries against a separate resolver in an owned guest.

The Whistler classifier attaches to the host veth ingress for Pod egress. It uses an
agent-initialized map to check the exact IPAM IPv4 address and interface MAC,
validates ARP sender identity, and drops malformed or unsupported frames. It
counts accepted/dropped packets and bytes, rejected spoofs, malformed packets,
and unsupported protocols. Identity initialization precedes TCX attachment;
replacement links are attached and pinned before atomically replacing the old
pin. Existing counter maps survive repeated CNI ADD calls.

Each endpoint has `rejected_spoofs`, `endpoint_identity`, and `traffic_stats`
maps alongside its `tcx-ingress` link under
`AGENT_STATE_DIR/containerd/bpf/CONTAINER_ID/`. CHECK validates kernel map schemas,
identity, and the TCX interface/direction; DEL removes staged links and all maps
even after the Pod namespace disappears. Tests exercise the actual compiled
bytecode on packet fixtures with both an interpreter and Linux BPF test-run.
The privileged native smoke injects a spoofed source into a live Pod namespace
and requires the rejection counter to appear through agent telemetry.

Agents sample the pinned counters and publish endpoint telemetry through their
node sessions. The loopback control-plane `/metrics` endpoint exposes accepted
and dropped packets/bytes, spoof rejections, malformed/unsupported packets,
sample timestamps, and node readiness. An unreadable map sets
`gr8s_endpoint_telemetry_available` to zero and omits its counter series instead
of reporting false zero traffic. Pod phase and IP are also refreshed from the
agent's reconciliation observations without requiring a new desired snapshot.

The native VXLAN backend uses static router neighbors and forwarding database
entries, preserving Pod source addresses across nodes. Isolated two-node kernel
tests cover bidirectional connectivity, the 1450-byte inner MTU, repeated setup,
and peer route removal. Node underlay addresses are durable control-plane
records. Address changes and withdrawals publish new peer snapshots. Agents
journal pending topology changes before touching the kernel and retain the last
applied topology until reconciliation succeeds, so a restart can remove stale
entries from a partial update. A changed local underlay replaces the owned
tunnel while retaining Pod endpoints and allocations. Periodic local
reconciliation repairs forwarding entries lost to tunnel link events without
requiring a newer control-plane snapshot. Graceful agent restart retains pinned
policy links/maps, Pod assignments and addresses; withdrawn assignments persist
deletion intent under the reconciliation lock so a background retry cannot
recreate a deleted Pod.

## Requirements

- Linux and SBCL for building
- ASDF dependencies from `gr8s.asd`; this checkout includes an OCICL lockfile
  and dependency tree
- `kubectl` for client-side smoke testing
- root privileges and working cgroup delegation for running real Pods
- Linux 6.6 or newer with TCX eBPF support and BPF/network-administration
  privileges for the Whistler CNI stage
- Python 3, `ip`, `nsenter`, `nft`, and a non-loopback upstream resolver for
  the privileged two-node smoke

## Build and run the self-contained server

Build the static Go runtime payload and dump it into the SBCL executable:

```sh
make native
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

Without `--kubeconfig`, `serve` writes an owner-only `kubeconfig` file in the
state directory and prints its path. `gr8s kubeconfig [--server URL]` prints a
kubeconfig to standard output, or writes it with `--output FILE`.

No system containerd or host glibc is used by the embedded runtime
payload. Root is still required for the Linux facilities used by containers:
mounts, namespaces, cgroups, and the overlay snapshotter.

To accept agents from another machine, select the control node's reachable
IPv4 address (replace the documentation addresses below with your node IPs):

```sh
sudo build/gr8s serve --state-directory /var/lib/gr8s-control \
  --node-listen 192.0.2.10 --node-address 192.0.2.10
```

With `serve` running, create the second node's join token from another terminal
on the control node:

```sh
sudo build/gr8s join-token --state-directory /var/lib/gr8s-control \
  --node-name worker-b
```

`join-token` uses the existing cluster CA and prints JSON containing a one-time,
node-bound `token` and its `caPin`. On the second node, use those values with
the same dumped executable:

```sh
sudo build/gr8s agent --server 192.0.2.10:7443 --node-name worker-b \
  --state-directory /var/lib/gr8s-worker-b --node-address 192.0.2.11 \
  --token TOKEN --ca-pin CA_PIN
```

The two nodes need underlay connectivity for the node endpoint and VXLAN UDP
port 4789. Each agent receives its own Pod CIDR and the peer route set; no
bridge or host-local CNI configuration is required.

For development against an already-running containerd, opt into external mode:

```sh
scripts/gr8s serve \
  --containerd-mode external \
  --containerd-socket /run/containerd/containerd.sock
```

Then, from another terminal:

```sh
kubectl --kubeconfig /tmp/gr8s.kubeconfig apply -f pod.yaml
kubectl --kubeconfig /tmp/gr8s.kubeconfig get pods
kubectl --kubeconfig /tmp/gr8s.kubeconfig describe pod POD_NAME
kubectl --kubeconfig /tmp/gr8s.kubeconfig delete pod POD_NAME
```

`kubectl logs` and `kubectl exec` return to this example once their correlated
operation streams cross the node-agent gRPC boundary.

Runtime objects are labeled with gr8s ownership metadata so reconciliation and
deletion can avoid unrelated workloads.

The pinned containerd 2.4.2 daemon, shim, and baseline CNI plugins 1.9.1 are
built from Go source with cgo disabled; the pinned static runc release is
checksum-verified. The dumped Common Lisp image is exposed to containerd under
the `gr8s` CNI name, so there is no separate CNI helper binary.
Whistler compiles the egress guard directly from Common Lisp without LLVM or a
C toolchain. Every embedded executable ELF is checked for
dynamic interpreters and shared-library dependencies, and the classifier is
checked as an eBPF ELF object:

```sh
make containerd-bundle
```

## Test

Run the ordinary Common Lisp and HTTP suite:

```sh
make test
make check
```

The native routed-veth backend can also be exercised without sudo on hosts
that allow unprivileged user/network namespaces:

```sh
make test-routed-network
```

This creates two isolated Pod namespaces, verifies host-to-Pod and routed
Pod-to-Pod connectivity, checks repeated setup and deletion after namespace
removal, and tests namespace restoration on an agent worker thread. Link,
address, and route changes use Common Lisp rtnetlink calls.

To exercise native VXLAN between two isolated node namespaces, each with its own
Pod namespace and CIDR:

```sh
make test-vxlan-network
```

The agent CNI integration test also checks the real Unix-socket client, durable
IPAM restoration across an agent restart, and Pod DNS over UDP and TCP:

```sh
make test-agent-network
```

This substitutes only the BPF policy operations because unprivileged user
namespaces cannot load those programs. These kernel tests do not exercise
containerd or eBPF and do not replace the full smoke gates.

The live topology test adds real gRPC agent sessions in separate node network
namespaces. It checks source-address discovery, snapshot publication,
bidirectional VXLAN traffic, tunnel restoration before reconnect, a peer
underlay change, and route withdrawal:

```sh
make test-node-topology
```

Run the self-contained native smoke workflow. Invoke `make` as your normal
user; the target builds the embedded payload without privileges and uses
`sudo` only to start the local agent's managed containerd and exercise a real
Pod. The smoke checks DNS, logs, exec success and failure, source-spoof rejection,
exported policy counters, and Pod namespace/pin/shim cleanup:

```sh
make smoke
```

The native two-node smoke launches a control plane and two containerd agents
with persistent, separate mount/network namespaces. Routed underlay veths carry
VXLAN traffic without a bridge. It verifies real Pod connectivity, DNS, logs,
exec, tunnel dependency and repair, traffic while one agent is stopped,
certificate-based restart, unchanged Pod identities/IPs, fresh telemetry, live
CNI CHECK, and cleanup. Temporary NAT serves only external image/DNS downloads
from the test underlay.

```sh
make smoke-two-node
```

Set `GR8S_SMOKE_KEEP_WORKDIR=1` when invoking the Python harness directly to keep
its logs. `GR8S_TWO_NODE_FAIL_AFTER_CREATE=1` exercises failure cleanup after
both Pods reach Running. Remote VTEP source validation, abrupt agent/crash
recovery, and the remaining Pod-pool configuration requirements are still tracked
work.

The direct containerd checks are opt-in and require a prepared CRI socket:

```sh
make test-containerd
```

The lifecycle test pulls `docker.io/library/busybox:1.37.0` and creates real
runtime objects, then removes them in cleanup. Its containerd must have a
working CRI plugin, snapshotter, OCI runtime, pause image, and CNI configuration.

## Native executable

SBCL dumps the loaded system and all seven runtime artifacts into a native
image, avoiding an ASDF load and external runtime installation on startup.
`build/gr8s` forwards arguments to the dumped `build/gr8s.bin` payload:

```sh
make native
build/gr8s --help
build/gr8s runtime-assets
```

Useful targets include:

```text
make containerd-bundle build and verify containerd, runc, and CNI payloads
make test          unit and HTTP tests
make test-containerd include live CRI/containerd integration tests
make test-whistler-cni build the eBPF object and test the Common Lisp CNI path
make check         shell syntax checks plus tests
make smoke         build normally, then sudo the embedded-containerd smoke workflow
make run           start the current server
make kubeconfig    write a loopback kubeconfig
make native        build the dumped SBCL executable
make clean         remove build outputs
```

See [`docs/design.md`](docs/design.md) for the compatibility and architecture
boundary.

The Kubernetes API compatibility target is **1.36** (`/version` reports
`v1.36.0-gr8s.0`). This selects the upstream client and conformance test version;
it is not a claim that gr8s passes Kubernetes conformance. The gr8s project release
version is maintained separately in `gr8s.asd`.

The [fourth complete native conformance run](docs/conformance-full-fourth-2026-11-04.json)
ran all **446** selected v1.36 conformance specs: **64 passed, 382 failed**.
Compared with the [third run](docs/conformance-full-third-2026-11-04.json),
16 previously failing cases passed and none regressed. The official JUnit archive,
complete case inventory and artifact hashes were verified. The native process
exited cleanly, but the original cleanup report records two leftover test-owned
shims. A [separate recovery](docs/conformance-fourth-cleanup-2026-11-04.json)
completed their cleanup and all pending Pod deletions with a clean exit, preserving
the original report. This binary includes graceful
deletion, readiness/reconnect and generated Pod-name fixes, but predates newer
storage/workload APIs, per-container restarts and connection cleanup fixes.
gr8s has not passed Kubernetes conformance. The earlier
[bootstrap record](docs/conformance-bootstrap-2026-11-03.json) remains available.

Bootstrap APIs also store Namespaces, ServiceAccounts, Roles, RoleBindings,
ClusterRoles and ClusterRoleBindings with durable metadata and optimistic
updates. All these durable resources accept JSON and typed Kubernetes protobuf
requests with API group/version validation. They also support resumable JSON
watches and
revision-consistent paginated lists. Pod and Node watches remain pending.
The Nodes API reports registered agents and their live readiness.
The local administrative HTTP API remains loopback-only. Managed native clusters
also expose a separate HTTPS API at `10.96.0.1:443`, authenticated with issued
ServiceAccount tokens and authorized against live RoleBindings and
ClusterRoleBindings.

Events share durable identities and revisions between core `v1` and
`events.k8s.io/v1`. Both versions support JSON/protobuf CRUD, patches, field and
label selectors, collection deletion, consistent pagination and resumable
watches. Timestamps preserve microseconds, and submitted Events expire one hour
after their last write, producing real deletion events. Native runtime event
emission remains pending.

Pods accept JSON and typed Kubernetes protobuf requests. The decoder uses pinned
Kubernetes wire definitions and Go JSON omission rules, preserving explicit
pointer values and empty command arguments. Pod creation supports
`metadata.generateName` with bounded generated names and collision retries;
an explicit `metadata.name` takes precedence. Pod names accept DNS subdomains up
to 253 characters, while runtime hostnames are limited to 63 characters.
The [native name validation record](docs/generated-pod-names-validation-2026-11-04.json)
captures real container hostname/name output, restart identities and cleanup.
Runtime admission still validates
the supported Pod feature set and rejects unsupported fields with HTTP 422.

Pods report PodScheduled, Initialized, ContainersReady and Ready conditions.
Readiness requires actual running, ready observations for every declared
application container. Terminal Pods report false readiness, and unavailable node/runtime
observations report unknown readiness. Condition transition history and actual
observed revisions persist separately across restarts. Valid node readiness
leases survive a control-plane restart, and reconnecting agents receive snapshot
revisions beyond their saved acknowledgements. Startup, readiness and liveness
probes execute real exec, HTTP(S), TCP and standard gRPC Health checks. Startup
success gates readiness/liveness; consecutive thresholds control readiness and
exact-container restart, preserving healthy siblings. Probe-specific termination
grace and actual failure Events survive node process restarts. Ordinary init
containers execute in declaration order; applications wait for real zero exits.
Failed initialization obeys the Pod restart policy, and native restart retains
actual attempts and retry history. Restartable init sidecars start before later
containers, restart whatever the Pod's policy, and stop last in reverse order.
postStart and preStop hooks run against the exact attempt, and termination messages
come from a per-attempt file with optional log fallback. A container whose
configuration cannot be generated reports `CreateContainerConfigError` while its
siblings run; image pulls run in the background and failures report `ErrImagePull`.
Private registries work through the `imagePullSecrets` of a Pod or its ServiceAccount,
matched as the kubelet matches them apart from `[...]` patterns in host names. There's
no node-wide credential file or credential provider plugin. An image already on a node
isn't checked against a Pod's credentials, so any Pod there can use it with
`IfNotPresent`; upstream's kubelet has checked this by default since v1.35.
`kubectl port-forward` works over its WebSocket tunnel and over plain SPDY, for Pods on
any node. containerd reaches the port inside the Pod's network namespace, so a server
listening only on the Pod's localhost works. Each forwarded connection is one operation
on the node's session, with a 1 MiB window each way, so a slow client or Pod pauses its
own connection instead of filling memory. It can still hold up the other connections
of the same `kubectl`, as upstream's can. As with `exec` and `attach`, it takes the
`create` verb on the subresource, even through a WebSocket's GET.
Ephemeral containers are added through `pods/ephemeralcontainers`, and `pods/resize`
changes CPU and memory in place, or restarts that container under a RestartContainer
policy. Readiness gates and a Pod's own `resources` remain unsupported.

External API servers can be registered with an `APIService`. gr8s publishes the
`extension-apiserver-authentication` ConfigMap they read from `kube-system`, with a separate
front-proxy CA, checks each one's discovery document to set its `Available` condition, lists its
group in discovery and proxies its requests over TLS with the caller's identity in `X-Remote-*`
headers. OpenAPI documents aren't merged, so `kubectl explain` doesn't cover aggregated types.

All ten unchanged upstream probe conformance cases pass in the
[focused result](docs/container-probes-upstream-2026-11-04.json). The
[native validation record](docs/container-probes-native-2026-11-04.json)
records seven real scenarios, including physical cleanup of a blocked exec probe.
These focused results do not establish full Kubernetes certification.

Pod HTTP proxy requests use the assigned Pod's actual observed address and
first declared port (or an explicit numeric port). Ordinary GET, POST, PUT,
PATCH, DELETE, HEAD and OPTIONS requests forward real bodies, status codes and
application headers, with separate `pods/proxy` authorization. Same-server
absolute redirects remain within the proxy URL. Connection upgrades and HTML
link rewriting remain tracked gaps; upgrades return HTTP 501. The
[proxy validation record](docs/pod-http-proxy-validation-2026-11-04.json)
includes actual workload forwarding and preserved test failures.

The [readiness validation record](docs/pod-readiness-validation-2026-11-03.json)
captures seven passing native scenarios and the official graceful-generation
case changing from failure to success, including verified archives and cleanup.

PodTemplates support namespaced CRUD and cluster-wide lists, JSON and Kubernetes
protobuf requests, selectors, dry-run, optimistic updates, strategic merge and
JSON patches, delete-collection, and JSON watch streams. Templates use the pinned
Kubernetes 1.36 structural schemas and retain nested PodSpec fields independently
of the agent's execution subset; storing a template does not start any Pods.
Server-side apply and finalizer processing remain unsupported.
Templates have a 2 MiB serialized storage limit so admitted objects can be read
back by the durable JSON loader.

`apps/v1` StatefulSets have `status` and `scale` subresources and a controller with
stable ordinal names and hostnames, `OrderedReady` and `Parallel` Pod management,
`spec.ordinals`, rolling updates in reverse ordinal order bounded by a partition,
`OnDelete`, and ControllerRevision history, so a template returning to an earlier
form rolls back to that revision. Each `volumeClaimTemplates` entry becomes a real
PersistentVolumeClaim per ordinal that binds through the storage controller, using
the default `local-path` class unless a template names another.
`persistentVolumeClaimRetentionPolicy` is honored in both
directions. A rolling update's `maxUnavailable` above 1 is refused.

`policy/v1` PodDisruptionBudgets have a `status` subresource and a disruption
controller that computes status from observed Pod readiness with upstream's
arithmetic. A selected Pod with a controller of unknown scale fails safe to no
disruptions. The Pod `eviction` subresource spends a budget atomically and answers
429 with the `DisruptionBudget` cause when nothing remains, honors
`unhealthyPodEvictionPolicy`, and marks the Pod with a `DisruptionTarget` condition.

The scheduler keeps TCP host ports, as well as declared requests, within what a node
has, leaving a Pod that does not fit Pending with the reason in its `PodScheduled`
condition. A Pod that named its own node bypasses the scheduler, so it fails with
`OutOfcpu`, `OutOfmemory`, `OutOfpods` or `NodePorts` as a kubelet would fail it. The agent makes a `hostPort` real with a userspace TCP
or UDP relay, so a Pod sees the node, not the original client, as the source;
SCTP host ports are scheduled but not relayed.

Deployments and ReplicaSets expose `apps/v1` JSON/protobuf CRUD, selectors,
resumable watches, revision-consistent lists, strategic patches and separate
`scale` and `status` subresources. ReplicaSet controllers create and scale real
Pods, adopt matching orphans, release selector mismatches and preserve exact
controller UIDs. Deployment controllers perform bounded rolling updates or
recreate updates, retain revision history, honor pause and minimum readiness
durations, and derive availability from actual Pod conditions. Controller state
survives restart through the durable API objects and owner references.
Templates retain the broad Kubernetes Pod schema; execution still uses the
supported Pod subset. Rejected Pod admission produces a ReplicaFailure condition
rather than reporting successful replicas. Background deletion cascades through
the existing owner collector. Foreground and orphan workload deletion checkpoint
their intent: foreground waits for owned children, while orphaning releases
controller references before removing the parent. Custom finalizers on workloads
remain unsupported.

ReplicationControllers expose the same controller, `scale` and `status` through
`core/v1`, with a mutable map selector and, as upstream, orphaning as the default
deletion policy. DaemonSets run one Pod on every node their template selects,
following node labels written through the Node API, and record `apps/v1`
ControllerRevisions whose data is the JSON a typed client marshals for the
template. RollingUpdate replaces Pods within `maxUnavailable`, or with `maxSurge`
starts each replacement before removing what it replaces. OnDelete leaves running
Pods alone.
A Node's labels, annotations, taints and `spec.unschedulable` can be written: the
scheduler enforces taints and cordoning, and a control-plane pass evicts Pods that
do not tolerate a NoExecute taint. A Node created through the API has no agent, so
it can never run a Pod and keeps whatever status was written; an agent's own Node
cannot be deleted through the API.

PersistentVolume, PersistentVolumeClaim and StorageClass APIs now support durable
CRUD, typed protobuf, status subresources and resumable JSON watches. A default
`local-path` class and a `gr8s.io/nfs` provisioner create volumes on demand with no
helper Pod, static NFS, `local` and `hostPath` volumes mount into native Pods, and
CSI drivers can be installed with their usual sidecars. The dynamic, NFS and CSI
paths have unit tests but haven't yet run against real NFS mounts or real drivers.
See [persistent storage](docs/persistent-storage.md) for supported behavior,
protection, reclamation and remaining extensions.

CRDs in `apiextensions.k8s.io/v1` now establish real schema-backed custom APIs.
Custom resources support durable JSON CRUD/status/watch, per-version discovery
and OpenAPI, recursive defaults/pruning, strict field validation and finalizer
cleanup. Definition UIDs isolate watches and historical lists across recreation.
See [custom resources](docs/custom-resources.md) for the supported schema subset,
validation evidence and remaining extensions.

Stored-resource list continuations are signed and bound to their resource type,
namespace and selectors. A shared durable change journal preserves a consistent
resourceVersion across
mutations and restarts, with five-minute retention and a 4,096-change bound on
disk. Compacted or expired continuations return HTTP 410 with a replacement token for
resuming at the last key in a newer view. Restart the list without a token when a
consistent full snapshot is required. Watch supports revision resumption,
selector transitions, timeouts, bookmarks and initial events. A running server
resumes a watch from up to ten minutes back, with 16,384 stored-resource, 16,384 Pod
and 4,096 Node changes as the most it holds. A watch from further back than that is
established and then ended by an ERROR event carrying a 410 Expired Status, which
clients answer by relisting. Upgrades preserve
legacy PodTemplate history and continuations; requests for older history of
newly tracked resource types return HTTP 410. The expanded journal uses storage
format 2, which older executables reject; downgrading requires restoring a
pre-upgrade state backup.

Run `sh scripts/test-podtemplate-api.sh` for real kubectl apply, ordering and
restart checks against a native API with its fake workload runtime. Run the five
upstream PodTemplate lifecycle and API chunking cases in a disposable privileged
Linux guest with:

```sh
python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s.bin --sonobuoy /path/to/sonobuoy
```

Run the entire upstream certified selection with the same disposable harness:

```sh
python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s.bin --sonobuoy /path/to/sonobuoy \
  --certified-conformance --timeout 21600
```

The runner preserves the official Sonobuoy archive, native and worker logs, and
individual executed specs in its printed report directory. A timeout preserves
partial worker logs. A passing result requires every selected spec to execute
and pass; running this command alone does not establish certification.

### Debugging a running cluster

`gr8s serve --debug-slynk-port PORT` starts an opt-in [Slynk](https://github.com/joaotavora/sly)
server for inspecting a live process. It is off by default and is for disposable
environments only: **it allows arbitrary code execution as the gr8s user, normally
root.** It binds to `127.0.0.1` and requires a secret, newly generated at each start
in `<state>/debug/slynk.secret`, because `hostNetwork` Pods share loopback. The
secret is the bare first protocol message, and a connecting Emacs Sly client needs a
matching `~/.sly-secret`.

Forms can also be evaluated from a shell, in the `gr8s` package:

```sh
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-threads)'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-backtraces "reconciler")'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-pod "default" "web")'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-journal 20)'
```

`*debug-store*` and `*debug-reconciler*` hold the live objects. For a focused
diagnostic run, the conformance runner accepts `--debug-slynk-port PORT` and
`--hold-on-failure SECONDS`, which keeps a failed cluster running until the time
passes or `<run>/release` exists. Both are refused with `--certified-conformance`,
because a process changed this way is not conformance evidence.

For the four supplemental upstream Event API cases, use
`--focus '\[sig-instrumentation\].*Events.*\[Conformance\]' --expected-specs 4`.
Custom focus/count arguments are rejected with `--certified-conformance`, which
always runs the full upstream selection.

This focused validation
includes the normal five-minute continuation expiry; it is separate from a full
certified-conformance run. Regenerate the pinned schemas with
`python3 scripts/generate-podtemplate-schema.py`; input checksums are verified.
The [native validation record](docs/podtemplate-conformance-2026-11-03.json)
captures all five upstream cases passing, plus local API and persistence checks.

Services accept JSON and typed Kubernetes protobuf requests, including numeric
and named target ports. Managed native clusters allocate durable IPv4 ClusterIP
Services from `10.96.0.0/16`, over TCP, UDP or SCTP. A cgroup `connect4` eBPF
program rewrites a Pod's connect(2) to a ready backend, resolving numeric or named
target ports against selected Pods or manually managed slices; unconnected UDP
`sendto(2)` does not pass through it. `sessionAffinity: ClientIP` holds each
client's network namespace on one backend until the timeout passes or the
Service's backend set changes. The reserved `default/kubernetes` Service describes
the HTTPS API at `10.96.0.1:443`, with matching Endpoints and an EndpointSlice.

`NodePort` and `LoadBalancer` Services allocate node ports from 30000-32767. The
agent relays each in userspace, for TCP and UDP, with client-address affinity, so a
Pod sees the node as the source; a port with no ready backends has no listener.
No cloud controller assigns a LoadBalancer an address, and only `Cluster` traffic
policies are accepted.

The API server proxies `services/[scheme:]name[:port]/proxy` to a ready backend,
as it does for Pods, and keeps a proxied HTML page's rooted links inside the proxy.
`nodes/name/proxy` answers the kubelet reads `/pods` and `/healthz` from the store,
since no kubelet HTTP server exists to forward to.

Core Endpoints follow selector Services, and manual Endpoints behind a selectorless
Service are mirrored into EndpointSlices. The `networking.k8s.io/v1` API serves
Ingress and IngressClass with no controller behind them, IPAddress as stored
objects that allocation does not create, and ServiceCIDR, where only the default
`kubernetes` range is `Ready` because nothing allocates from another.

EndpointSlices expose the stable `discovery.k8s.io/v1` JSON/protobuf API with
selector lists, durable watches, strategic patches and collection deletion. The
Service controller publishes actual Pod IPs, readiness and terminating conditions,
resolves named target ports and partitions generated slices at 100 endpoints.
Exact Service UID ownership and durable slice identities survive restart. Manual
slices remain independently writable and provide real forwarding backends for
selectorless Services. TCP headless Services and `publishNotReadyAddresses` are
supported; generated Service addresses remain single-stack IPv4. Manual slices
also admit IPv6 and deprecated FQDN address types.

Run `scripts/test-endpointslices.py` in an isolated privileged guest for actual
selector/manual HTTP forwarding, readiness withdrawal, container identity recovery
and terminating-endpoint checks. Add `--verify-dns` to check actual UDP/TCP
Service answers, headless Pod addresses, empty-headless NXDOMAIN, DNS recovery
after restart and terminating address withdrawal.

Native DNS publishes normal Service A/AAAA records from cluster IPs and headless
Service/explicit endpoint-hostname records from ready EndpointSlice addresses.
Public Service discovery data travels once per node in authenticated snapshots
and installs atomically with Pod references, separately from namespace-scoped
Secret delivery. Unchanged discovery does not advance node revisions or rewrite
the agent journal. SRV, PTR, DNS schema TXT, generated endpoint hostname records
and ExternalName are tracked separately in `podster-uqb.21.1`.

Pods can mount referenced ConfigMaps, Secrets and disk-backed emptyDir volumes.
The control plane sends only referenced objects to the assigned node over mTLS;
the agent projects files into private host directories and maps numeric user,
group and fsGroup settings to containerd. Downward environment fields include
Pod identity, node name and Pod IP, plus namespace-local Secret and ConfigMap key
references. Pod metadata revisions preserve running containers; canonical spec
fingerprints in sandbox labels identify the actual workload across agent restarts.
Native container retries follow Always, OnFailure and Never independently,
preserving the sandbox and healthy sibling containers. Attempt history, actual
last termination state and exponential retry deadlines persist across server
restarts, with separate logs for each attempt. Missing CRI history and failed
sandboxes recover from retained observations; mutable image/spec updates still
replace the sandbox. The [native restart validation record](docs/container-restarts-validation-2026-11-04.json)
captures four real policy scenarios and durable backoff across a server restart.
Projected data is applied during Pod setup;
live refresh is not yet implemented. Managed native startup projects namespace-bound
ServiceAccount token/CA files automatically unless the Pod or account opts out.
Deleting and recreating an account or its credential Secret revokes the old token.

Owner references are preserved on Pods and stored resources. The control plane
collects dependents after all known owners disappear, comparing UIDs so a newly
created object cannot inherit an old object's dependents by name. Foreground
deletion of a workload or Pod waits for `blockOwnerDeletion` dependents and only
detaches a dependent that another owner still holds. A Pod held this way shows a
`deletionTimestamp` and a `foregroundDeletion` finalizer: its containers stop at
once and only the object waits. Foreground and orphan deletion hold other kinds
too, custom resources included, and a dangling reference is removed once another
owner keeps the dependent alive.

Controllers create and delete through the admission webhooks, outside the store
lock, as their upstream service accounts. A refused Pod shows on its owner as a
ReplicaFailure, and a refused deletion is retried. EndpointSlices, bootstrap objects
and status writes do not yet pass through webhooks.

A node reports each container's CPU and memory from CRI statistics, from which a
HorizontalPodAutoscaler controller scales Deployments, ReplicaSets, ReplicationControllers
and StatefulSets on Resource and ContainerResource metrics, with upstream's tolerance,
stabilization and rate policies. There is no metrics API or custom metrics source, so
other metric types report a failed `ScalingActive` condition.

## Versioning

gr8s versions itself as the **Kubernetes API version it implements plus a gr8s
release suffix**, following the k3s/k0s convention (k3s's `v1.31.4+k3s1`). The
ASDF `:version` in `gr8s.asd` is the Kubernetes API version (`1.36.0`) and the
single source of truth for the `/version` endpoint's `major`/`minor`, a Node's
`kubeletVersion`, and the startup banner. The release suffix lives in a git tag
(`v1.36.0-gr8s.0`), surfaced through the `version-string` library as
`+gr8s-version+` and reported by `gr8s version`:

- a tagged release prints the tag verbatim (`v1.36.0-gr8s.0`, `+dirty` if the
  tree has uncommitted changes);
- an untagged build prints the base version with the commit (`v1.36.0-g1a2b3c4`);
- the native binary bakes the string in at build time.

Cutting a release is therefore just a tag — `git tag v1.36.0-gr8s.1` — and the
binary, `/version`, `kubeletVersion`, and banner all report it with no code
change.
