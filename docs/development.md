# Reading and changing gr8s

Read the [architecture](design.md) for ownership boundaries and the
[Kubernetes component map](kubernetes-users.md) for familiar names. This guide
connects those boundaries to the source tree.

## Source map

| Path | Responsibility |
|---|---|
| [`src/server/`](../src/server/) | CLI parsing, startup, process/state ownership, and shutdown; begin with `main.lisp` |
| [`src/apiserver/`](../src/apiserver/) | HTTP routing, API serialization, admission, watches, aggregation, and node sessions |
| [`src/security/`](../src/security/) | Authentication, authorization, certificates, and encryption |
| [`src/resources/`](../src/resources/) | Resource validation and operations, schemas, storage, and API object lifecycle |
| [`src/model/`](../src/model/) | Domain objects shared across boundaries |
| [`src/store/`](../src/store/) | Durable state, revisions, journals, transactions, and publication |
| [`src/controllers/`](../src/controllers/) | Workload and infrastructure controllers, scheduler, Services, Gateway/Ingress |
| [`src/agent/`](../src/agent/) | Node sessions, assigned workload runtime, remote operations, tracing |
| [`src/kubelet/`](../src/kubelet/) | Pod convergence, probes, volumes, node resources, and runtime observations |
| [`src/runtime/`](../src/runtime/) | Runtime protocol, embedded artifacts, and containerd CRI adapter |
| [`src/network/`](../src/network/) | Native CNI/IPAM, routes, overlays, Service forwarding, and eBPF policies |
| [`src/ha/`](../src/ha/), [`src/raft/`](../src/raft/) | Application replication and Raft transport/integration |
| [`src/protocol/`](../src/protocol/), [`src/generated/`](../src/generated/) | Transport helpers and generated protocol bindings |
| [`src/image-distribution/`](../src/image-distribution/) | Authenticated peer image-content distribution |
| [`tests/`](../tests/), [`scripts/`](../scripts/) | Unit/HTTP checks, build tools, and privileged acceptance runners |

[`gr8s.asd`](../gr8s.asd) defines the load order and package dependencies. Generated
bindings and structural schemas have different version pins from the public API
target; check their provenance before changing a wire format. The
[documentation style guide](documentation-style.md) covers source comments and docstrings.

## From apply to a running container

Follow the Deployment from the [first workload](getting-started.md). These are
asynchronous boundaries, not one synchronous call stack:

1. **Receive and admit the API object.** `kubectl apply` sends requests to the
   HTTPS API. Start in [`apiserver/in-cluster-api.lisp`](../src/apiserver/in-cluster-api.lisp),
   [`apiserver/http.lisp`](../src/apiserver/http.lisp),
   [`apiserver/workload-http.lisp`](../src/apiserver/workload-http.lisp), and
   [`apiserver/admission-http.lisp`](../src/apiserver/admission-http.lisp).
   Authentication/RBAC, field validation, and admission precede the accepted write.
2. **Persist desired state.** Workload operations in
   [`resources/workload-resources.lisp`](../src/resources/workload-resources.lisp)
   update durable API state. [`store/persistence.lisp`](../src/store/persistence.lisp)
   and [`store/journal.lisp`](../src/store/journal.lisp) manage persistence and
   revisions; [`ha/plane.lisp`](../src/ha/plane.lisp) adds replicated application
   operations in HA mode. The write response does not wait for nginx to become Ready.
3. **Create the owned objects.**
   [`controllers/workload-controller.lisp`](../src/controllers/workload-controller.lisp)
   reconciles Deployment → ReplicaSet → Pods, preserving selectors and owner UIDs.
   Controller-created Pods pass through the controller admission path in
   `admission-http.lisp`.
4. **Choose a node.** [`controllers/scheduler.lisp`](../src/controllers/scheduler.lisp)
   evaluates placement and resource fit. Node assignment becomes desired state.
   A Pod explicitly naming a node takes a different admission/fit path.
5. **Deliver the assignment.**
   [`apiserver/node-session.lisp`](../src/apiserver/node-session.lisp) publishes
   revisioned desired state over the authenticated node protocol.
   [`agent/session.lisp`](../src/agent/session.lisp) receives snapshots or negotiated
   deltas; [`agent/runtime.lisp`](../src/agent/runtime.lisp) applies assigned state
   and reports observations. The local agent crosses this boundary too.
6. **Converge containers and networking.**
   [`kubelet/reconciler.lisp`](../src/kubelet/reconciler.lisp) drives Pod lifecycle.
   [`runtime/containerd/cri.lisp`](../src/runtime/containerd/cri.lisp) issues CRI
   calls. containerd invokes the gr8s CNI entry point; [`network/cni.lisp`](../src/network/cni.lisp)
   and the agent establish interfaces, IPAM, routes, and BPF attachments.
7. **Publish observed readiness.** Container status and probes feed
   [`kubelet/pod-conditions.lisp`](../src/kubelet/pod-conditions.lisp).
   Node reports update the control-plane view; the
   [Pod watch](../src/apiserver/pod-watch.lisp) lets clients observe changes.
   Service/EndpointSlice controllers select ready backends and the agent updates
   DNS and Service forwarding. `rollout status` then observes controller status
   derived from the resulting Pods.

When debugging, find the boundary that stopped progressing: accepted object,
owned Pods, node assignment, delivered revision, runtime sandbox, readiness, or
Service endpoints. This is more useful than assuming an accepted API write proves
successful execution.

## Make and verify a change

Follow [host setup](building-and-testing.md#requirements), then `make test` for
unit and HTTP checks. Use the [test matrix](building-and-testing.md#test-matrix)
to select additional coverage for the boundary you changed. Tests that substitute
BPF operations or use fake runtimes do not prove real kernel/container behavior.
Run those acceptance scripts in disposable root VMs as described in
[`AGENTS.md`](../AGENTS.md).

For inspection of a live development process, use the
[authenticated Slynk tunnel](building-and-testing.md#debugging-a-running-cluster).
File discovered work in beads as described in `AGENTS.md`. For compatibility
claims, distinguish source support, focused tests, native acceptance, and the
specific build recorded in [conformance evidence](CONFORMANCE.md).

## Live-patching boundary

Managed signed live-patching is unavailable in this checkout. Use the documented
[binary upgrade workflow](installing.md#upgrade-and-recovery). Slynk inspection
and evaluation are development tools, not a managed patch lifecycle.
