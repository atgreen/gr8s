# gr8s

gr8s is a small Kubernetes-compatible Pod control plane written in Common
Lisp. One dumped native image provides the control-plane, node-agent, and CNI
roles. It serves the Kubernetes HTTP API on loopback and uses the same basic
runtime boundary as k3s: containerd reached through the Kubernetes CRI, rather
than shelling out to a container CLI. Workload execution is currently verified on the
local node through the same private gRPC control channel used by standalone
agents. The control plane schedules Pods and publishes desired state; the agent
owns the node runtime and reports observed status.

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
files. Watch, server-side apply, and full Namespace lifecycle are not yet implemented.

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
Pod affinity and anti-affinity are refused. `spec.activeDeadlineSeconds` is counted
from Pod creation rather than from the first node's acceptance. A declared
`ephemeral-storage` limit counts for quota, LimitRange and scheduling, but the node
does not yet evict a Pod that exceeds it.

Pod logs and exec run through correlated agent operations, including interactive
streams and nonzero exit status. Complete agent-crash recovery
remain outside the verified boundary. The administrative HTTP API refuses
non-loopback listener addresses; native Pods use the authenticated HTTPS API
described below.

## Runtime architecture

The executable has three entry paths:

- `gr8s serve` runs the HTTP control plane and a loopback gRPC node endpoint;
- `gr8s agent` enrolls with a one-time token, persists its node key and
  certificate, and maintains the revisioned desired-state session;
- a CNI invocation is selected automatically when `CNI_COMMAND` is present.

`serve` starts a local agent named `gr8s-local` by default. That agent crosses
the same ag-gRPC boundary as a separately launched agent; `--disable-agent`
runs a control-plane-only process and does not create a managed node runtime.
The node endpoint defaults to loopback port 7443. Set `--node-listen` and
`--node-port` for a node-facing address; the Kubernetes HTTP API stays on
loopback. Agents advertise the source IPv4 address of their control connection
for VXLAN, or use an explicit `--node-address` on multi-interface hosts. The
local node name can be changed with `--node-name`.

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
actual attempts and retry history. Restartable init sidecars and readiness gates
remain unsupported.

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
controller references before removing the parent. Custom finalizers remain
unsupported.

PersistentVolume, PersistentVolumeClaim and StorageClass APIs now support durable
CRUD, typed protobuf, status subresources and resumable JSON watches. Static
filesystem hostPath/local volumes bind to matching claims and mount real backing
storage into native Pods. See [persistent storage](docs/persistent-storage.md)
for supported behavior, protection, Retain reclamation and remaining extensions.

CRDs in `apiextensions.k8s.io/v1` now establish real schema-backed custom APIs.
Custom resources support durable JSON CRUD/status/watch, per-version discovery
and OpenAPI, recursive defaults/pruning, strict field validation and finalizer
cleanup. Definition UIDs isolate watches and historical lists across recreation.
See [custom resources](docs/custom-resources.md) for the supported schema subset,
validation evidence and remaining extensions.

Stored-resource list continuations are signed and bound to their resource type,
namespace and selectors. A shared durable change journal preserves a consistent
resourceVersion across
mutations and restarts, with five-minute retention and a 4,096-change bound.
Compacted or expired continuations return HTTP 410 with a replacement token for
resuming at the last key in a newer view. Restart the list without a token when a
consistent full snapshot is required. Watch supports revision resumption,
selector transitions, timeouts, bookmarks and initial events. Upgrades preserve
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
and named target ports. Managed native clusters allocate durable IPv4 TCP
ClusterIP Services from
`10.96.0.0/16`. Native listeners forward connections to ready Service backends, resolving numeric
or named target ports against selected Pods or manually managed slices. The
reserved `default/kubernetes` Service describes the HTTPS API at `10.96.0.1:443`.
This initial implementation supports single-stack TCP without session affinity;
UDP, NodePort, LoadBalancer and legacy Endpoints resources remain unsupported.
TCP forwarding currently replaces the original client source address.

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

Supported nonblocking owner references are preserved on Pods and stored resources.
The control plane collects dependents after all known owners disappear, comparing
UIDs so a newly created object cannot inherit an old object's dependents by name.
Outside Deployment and ReplicaSet deletion, blocking foreground deletion and
finalizer controllers remain unsupported.
