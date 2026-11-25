# Kubernetes API surface

This guide lists what gr8s implements today and its known gaps. Each area links
to a committed validation record where one exists.
Networking (Services, Gateway API, NetworkPolicy, DNS) lives in
[networking.md](networking.md); the container runtime lives in
[runtime.md](runtime.md); high availability lives in
[high-availability.md](high-availability.md).

> The recorded two-node run passed all **462 upstream Kubernetes v1.37
> `certified-conformance` cases** on 2026-11-11. gr8s has not been submitted for
> CNCF certification. See [the result and its scope](CONFORMANCE.md).

This reference was reconciled with the source on 2026-11-14. A feature described
as implemented is not necessarily covered by native acceptance; dated evidence
links retain the scope of their original run. For reader paths and component
names, start with the [documentation guide](index.md) and
[Kubernetes component map](kubernetes-users.md).

## Pods & lifecycle

Pods accept JSON and typed Kubernetes protobuf requests. The decoder uses pinned
Kubernetes wire definitions and Go JSON omission rules, preserving explicit
pointer values and empty command arguments. `kubectl apply`, `get`, `describe`,
and `delete` work, with durable desired state and optimistic resource-version
checks, plus periodic, idempotent reconciliation with transient-failure retry.

Pod creation supports `metadata.generateName` with bounded generated names and
collision retries. An explicit `metadata.name` takes precedence. Pod names accept
DNS subdomains up to 253 characters, while runtime hostnames are limited to 63.
Runtime admission validates the supported Pod feature set and rejects unsupported
fields with HTTP 422. See the
[generated-name record](evidence/generated-pod-names-validation-2026-11-04.json).

Pods support finalizers that retain API objects after actual runtime cleanup,
including zero-grace deletion. Native validation covers real exit codes 0 and 137,
restart recovery, UID reuse, unrelated execution during finalizer retention, and
cancellation of a blocked Exec probe. See the
[finalizer evidence](evidence/pod-finalizers-native-2026-11-04.json).

**Conditions & probes.** Pods report PodScheduled, Initialized, ContainersReady,
and Ready conditions. Readiness requires actual running, ready observations for
every declared application container. Terminal Pods report false readiness, and
unavailable node/runtime observations report unknown readiness. Startup, readiness,
and liveness probes execute real exec, HTTP(S), TCP, and standard gRPC Health
checks. Startup success gates readiness and liveness. Consecutive thresholds control
readiness and exact-container restart, preserving healthy siblings. See the
[readiness record](evidence/pod-readiness-validation-2026-11-03.json) and the upstream and
native [probe records](evidence/container-probes-upstream-2026-11-04.json).

**Init, sidecars & hooks.** Ordinary init containers execute in declaration order.
restartable init sidecars start before later containers, restart per the Pod's
policy, and stop last in reverse order. postStart and preStop hooks run against the
exact attempt; termination messages come from a per-attempt file with optional log
fallback.

**Restarts.** Native container retries follow Always, OnFailure, and Never
independently, preserving the sandbox and healthy siblings. Attempt history, last
termination state, and exponential retry deadlines persist across server restarts,
with separate logs per attempt. See the
[restart record](evidence/container-restarts-validation-2026-11-04.json).

**Ephemeral & resize.** Ephemeral containers are added through
`pods/ephemeralcontainers`; `pods/resize` changes CPU and memory in place, or
restarts the container under a RestartContainer policy. Readiness gates hold
Ready false until the named custom conditions are true. Pod-level `spec.resources`
supports CPU, memory, and hugepage requests/limits, with validation, scheduling,
quota, and runtime resource accounting. See
[`pod-level-resources.lisp`](../src/resources/pod-level-resources.lisp).

**Logs, exec & proxy.** Pod logs and exec run through correlated agent operations,
including interactive streams and nonzero exit status. `kubectl port-forward`
works over its WebSocket tunnel and over plain SPDY, for Pods on any node, with a
1 MiB window each way. Pod HTTP proxy forwards real bodies, status codes, and
headers with separate `pods/proxy` authorization, and relays connection upgrades
as bidirectional streams, without following backend redirects. See the
[proxy record](evidence/pod-http-proxy-validation-2026-11-04.json).

## Config, identity & secrets

Namespaced ConfigMap and Secret APIs support durable CRUD, list/selectors,
pagination, patch, optimistic concurrency, and dry-run through current kubectl
clients — see [ConfigMap and Secret APIs](configmap-secret-api.md). Pods can mount
referenced ConfigMaps, Secrets, and disk-backed emptyDir volumes; the control
plane sends only referenced objects to the assigned node over mTLS, and the agent
projects files into private host directories, mapping numeric user, group, and
fsGroup settings to containerd. Downward environment fields include Pod identity,
node name, and Pod IP. Projected ConfigMap, Secret, and token files are refreshed
during reconciliation. Refresh errors are logged and retried; updates are not a
transaction over all files in a projection. Existing `subPath` bind mounts do not
follow replacement files. See
[`pod-volume-projection.lisp`](../src/kubelet/pod-volume-projection.lisp).

Pods mount signed ES256 ServiceAccount tokens bound to the Pod and its node,
renewed by the control plane after 80% of their lifetime. TokenRequest,
TokenReview, the SubjectAccessReview family, authorized impersonation, and OIDC
discovery are served. Deleting and recreating an account or its credential Secret
revokes the old token.

Private registries work through the `imagePullSecrets` of a Pod or its
ServiceAccount, matched as the kubelet matches them apart from `[...]` host
patterns. `gr8s serve` and `gr8s agent` also accept a Docker `config.json` via
`--registry-credentials-file`; Pod credentials are tried before these node-wide
credentials. Every registry's TLS certificate is verified against the system
roots. A registry with a private CA is trusted cluster-wide by a
ClusterTrustBundle annotated `gr8s.io/registries: "HOST[:PORT], ..."`: every
node verifies exactly those registries against its `spec.trustBundle`, from
the next node snapshot, and keeps the last trust it received across restarts.
The annotation is validated on write, and only it crosses to nodes. Per node,
`--registry-ca HOST=FILE` (repeatable) does the same, and a bare
`--registry-ca HOST` trusts the cluster CA, for a registry serving a
cert-manager certificate from the cluster's `ca` issuer. A host named by both
trusts the union. Kubelet v1 executable credential-provider plugins are configured
with `--image-credential-provider-config` and
`--image-credential-provider-bin-dir`. Matching, arguments and environment,
response cache scopes and durations, validation, and fallback ordering follow
the kubelet protocol. A provider's `tokenAttributes` are validated and honored:
the control plane mints an audience-specific token bound to the exact Pod after
authenticating its node, and returns only the requested ServiceAccount annotations.
`requireServiceAccount`, `ServiceAccount` and `Token` cache identities follow the
kubelet semantics; the cluster signing key never leaves the control plane.

## RBAC, CSRs & certificates

Bootstrap APIs store Namespaces, ServiceAccounts, Roles, RoleBindings,
ClusterRoles, and ClusterRoleBindings with durable metadata and optimistic
updates. The Kubernetes API defaults to authenticated HTTPS on `0.0.0.0:6443`,
using client certificates or bearer tokens and live RBAC bindings. Managed clusters
publish the in-cluster `kubernetes` Service at `10.96.0.1:443`. Its backing listener
can share the public API listener; there is no separate unauthenticated
administrative API. The generated owner-only kubeconfig embeds the cluster CA
and an administrative client certificate.

CSR and certificate issuance are served and replicated; see the
[client-certificate docs](api-client-certificates.md) and the
[CSR docs](certificate-signing-requests.md).

## Admission

Pod Security Admission evaluates Pod creates and updates using the
`pod-security.kubernetes.io/{enforce,audit,warn}` namespace labels. It implements
the privileged, baseline, and restricted profiles at the selected Kubernetes
minor version, validates policy labels on Namespace writes, emits Warning
headers, and supports namespace, username, and RuntimeClass exemptions. These
checks run alongside the existing typed `SecurityContext` validation rather
than replacing it.

`admissionregistration.k8s.io/v1` webhook configurations call their backends with
AdmissionReview on API writes and Pod connections, over TLS verified against the
`caBundle` and within `timeoutSeconds`, with rules, selectors, `failurePolicy`,
ordered JSON patches, and `reinvocationPolicy` applied as upstream does. A Service
backend is reached directly at a ready endpoint. `matchConditions` use the
`cl-cel` expression implementation, including authorization checks against RBAC.

ValidatingAdmissionPolicy and MutatingAdmissionPolicy evaluate CEL on the
admission path. Policy support includes variables, parameter selection, audit
annotations, the `authorizer` environment, and reported `status.typeChecking`.
See [`admission-policies.lisp`](../src/apiserver/admission-policies.lisp).
Controller-created Pods use the admission path too. Internal writes have explicit
entry points in [`admission-http.lisp`](../src/apiserver/admission-http.lisp);
do not assume every internal mutation is equivalent to an external API request.

## Scheduling & resource governance

The scheduler charges Pod requests and overhead against the CPU, memory, storage,
and Pod count agents report, and against extended resources advertised through
Node status. It evaluates node selectors and node affinity, and when nothing fits
it preempts lower-priority Pods, marking them with a `DisruptionTarget` condition.
Pod affinity and anti-affinity filter and order nodes in both directions, and
quota has a `CrossNamespacePodAffinity` scope. The scheduler keeps TCP host ports
within what a node has; a Pod that named its own node bypasses the scheduler and
fails with `OutOfcpu`/`OutOfmemory`/`OutOfpods`/`NodePorts` as a kubelet would.

Containers get private PID namespaces unless `shareProcessNamespace` sets one for
the Pod. `spec.activeDeadlineSeconds` counts from Pod creation. A declared
`ephemeral-storage` limit counts for quota, LimitRange, and scheduling, and the
node evicts a Pod whose writable layers and disk-backed emptyDirs exceed it,
checking every ten seconds (container logs excluded).

ResourceQuota, LimitRange, RuntimeClass, and PriorityClass are served with real
effects. Quota usage is computed from live objects and checked under the store
lock at admission, so a write that would exceed a hard limit gets a 403; the
`Terminating`, `NotTerminating`, `BestEffort`, `NotBestEffort`, and `PriorityClass`
scopes apply. LimitRange defaults and bounds new Pods and claims. PriorityClass
resolves `spec.priority`.

The agent makes a `hostPort` real with a userspace TCP or UDP relay, so a Pod sees
the node as the source; SCTP host ports are scheduled but not relayed.

## Workload controllers

- **Deployments & ReplicaSets** — `apps/v1` JSON/protobuf CRUD, selectors,
  resumable watches, revision-consistent lists, strategic patches, and separate
  `scale`/`status` subresources. ReplicaSet controllers create and scale real
  Pods, adopt orphans, release selector mismatches, and preserve controller UIDs.
  Deployment controllers do bounded rolling or recreate updates, retain revision
  history, honor pause and minimum-readiness durations, and derive availability
  from actual Pod conditions.
- **ReplicationControllers** — the same controller, `scale`, and `status` through
  `core/v1`, with a mutable map selector and orphaning as the default deletion
  policy.
- **StatefulSets** — `status`/`scale` subresources and a controller with stable
  ordinal names and hostnames, `OrderedReady` and `Parallel` management,
  `spec.ordinals`, reverse-ordinal rolling updates bounded by a partition,
  `OnDelete`, and ControllerRevision history. Each `volumeClaimTemplates` entry
  becomes a real PVC per ordinal; `persistentVolumeClaimRetentionPolicy` is honored
  both directions. `maxUnavailable` accepts counts and percentages from 1 to 100%
  and bounds the rolling update; 0 and percentages above 100% are refused.
- **DaemonSets** — one Pod on every node their template selects, following node
  labels, recording `apps/v1` ControllerRevisions. RollingUpdate respects
  `maxUnavailable`/`maxSurge`; OnDelete leaves running Pods alone.
- **Jobs & CronJobs** — controllers create and account for Job Pods, retry or
  complete work according to the Job policy, and create scheduled Jobs from
  CronJobs. See [`job-controller.lisp`](../src/controllers/job-controller.lisp)
  and [`cronjob-controller.lisp`](../src/controllers/cronjob-controller.lisp).
- **PodDisruptionBudgets** — `policy/v1` with a `status` subresource and a
  controller using upstream's arithmetic. The Pod `eviction` subresource spends a
  budget atomically, answers 429 with the `DisruptionBudget` cause, honors
  `unhealthyPodEvictionPolicy`, and marks the Pod with `DisruptionTarget`.

Controller state survives restart through durable API objects and owner
references. See the [workload record](evidence/workload-validation-2026-11-04.json).
Custom finalizers retain deleting workload objects until a client removes them;
foreground/orphan deletion also coordinates owner/dependent cleanup. See
[`workload-deletion.lisp`](../src/controllers/workload-deletion.lisp).

**Garbage collection.** Owner references are preserved on Pods and stored
resources; the control plane collects dependents after all known owners disappear,
comparing UIDs so a new object cannot inherit an old one's dependents by name.
Foreground deletion waits for `blockOwnerDeletion` dependents; orphan deletion
releases controller references before removing the parent.

**PodTemplates** support namespaced CRUD and cluster-wide lists, JSON/protobuf,
selectors, dry-run, optimistic updates, strategic/JSON patches, delete-collection,
and JSON watch streams, using pinned 1.36 structural schemas, with a 2 MiB storage
limit.

## Nodes

A Node's labels, annotations, taints, and `spec.unschedulable` can be written: the
scheduler enforces taints and cordoning, and a control-plane pass evicts Pods that
do not tolerate a NoExecute taint. A Node created through the API has no agent, so
it never runs a Pod; an agent's own Node cannot be deleted through the API. The
Nodes API reports registered agents and their live readiness.

## Storage

PersistentVolume, PersistentVolumeClaim, and StorageClass APIs support durable
CRUD, typed protobuf, status subresources, and resumable JSON watches. A default
`local-path` class and a `gr8s.io/nfs` provisioner create volumes on demand with
no helper Pod; static NFS, `local`, and `hostPath` volumes mount into native Pods;
and CSI drivers can be installed with their usual sidecars. The dynamic, NFS, and
CSI paths have unit tests but haven't yet run against real NFS mounts or real
drivers. See [persistent storage](persistent-storage.md).

## Custom resources (CRDs)

CRDs in `apiextensions.k8s.io/v1` establish real schema-backed custom APIs. Custom
resources support durable JSON CRUD/status/watch, per-version discovery and
OpenAPI, recursive defaults/pruning, strict field validation, and finalizer
cleanup. Definition UIDs isolate watches and historical lists across recreation.
See [custom resources](custom-resources.md).

## API aggregation

External API servers register with an `APIService`. gr8s publishes the
`extension-apiserver-authentication` ConfigMap in `kube-system` with a separate
front-proxy CA, checks each one's discovery document to set its `Available`
condition, lists its group in discovery, and proxies its requests over TLS with the
caller's identity in `X-Remote-*` headers. Available servers' OpenAPI v2 is
merged into `/openapi/v2` and their v3 group documents are proxied, so
`kubectl explain` covers aggregated types.

## Events

Events share durable identities and revisions between core `v1` and
`events.k8s.io/v1`. Both support JSON/protobuf CRUD, patches, field/label
selectors, collection deletion, consistent pagination, and resumable watches.
Timestamps preserve microseconds; submitted Events expire one hour after their last
write, producing real deletion events. Nodes report probe and container lifecycle
occurrences, which become Events after the server validates Pod UID, assignment,
and desired revision. Replayed cumulative counts do not duplicate occurrences;
see [`node-runtime-events.lisp`](../src/resources/node-runtime-events.lisp).

A container that can't start says why in its waiting state and an Event, worded as
a kubelet words them:

| Cause | Waiting reason and message | Event |
|---|---|---|
| A volume that can't be set up, such as a missing ConfigMap or Secret | `ContainerCreating`, `MountVolume.SetUp failed for volume "cfg" : configmap "x" not found` | Warning `FailedMount` |
| A failed image pull | `ErrImagePull`, the registry's error | Warning `Failed`, `Failed to pull image "x": ...` |
| The same image still failing, before the next pull | `ImagePullBackOff`, `Back-off pulling image "x": ...` | Normal `BackOff` |
| A missing image under pull policy `Never` | `ErrImageNeverPull` | Warning `ErrImageNeverPull` |
| The runtime refusing to create the container | `CreateContainerError`, the runtime's error | Warning `Failed`, `Error: ...` |
| A missing environment source, or an invalid subPath | `CreateContainerConfigError` | Warning `Failed`, `Error: ...` |
| Repeated crashes | `CrashLoopBackOff`, `back-off 40s restarting failed container=...` | Warning `BackOff` |

An evicted Pod also gets a Warning `Evicted` Event with the eviction message. A
failure that lasts many reconciliation passes is one Event, not one per pass.
Unlike a kubelet, gr8s records no `Pulling` or `Pulled` Events, and a container
whose StartContainer call fails is still reported on the Pod as `RuntimeError`.

## Namespaces, quotas & lifecycle

A deleted Namespace turns Terminating and refuses new content while its Pods drain
first, then its other objects, until its finalizers are released. Lease, flow
control, dynamic resource allocation, and admission policy objects have typed APIs.
API Priority and Fairness classifies requests by FlowSchema and applies per-priority
seat limits with bounded waiting/refusal; see
[`flowcontrol.lisp`](../src/apiserver/flowcontrol.lisp).
Dynamic Resource Allocation includes ResourceClaim allocation and scheduling,
node plugin registration, durable prepare/unprepare, and CDI device injection;
see the [resource management guide](resource-management.md) and
[`dra-node.lisp`](../src/kubelet/dra-node.lisp). API availability alone should not
be read as support for every optional upstream feature.

## API machinery — watches, lists & pagination

Stored-resource list continuations are signed and bound to their resource type,
namespace, and selectors. A shared durable change journal preserves a consistent
`resourceVersion` across mutations and restarts, with five-minute retention and a
4,096-change on-disk bound. Compacted or expired continuations return HTTP 410 with
a replacement token. Watch supports revision resumption, selector transitions,
timeouts, bookmarks, and initial events; a running server resumes a watch from up
to ten minutes back (16,384 stored-resource, 16,384 Pod, and 4,096 Node changes
held at most), ending older watches with a 410 Expired for clients to relist. The
expanded journal uses storage format 2, which older executables reject; downgrading
requires restoring a pre-upgrade state backup. Pod and Node list/watch paths are
implemented alongside stored-resource watches; see
[`pod-watch.lisp`](../src/apiserver/pod-watch.lisp) and
[`node-watch.lisp`](../src/apiserver/node-watch.lisp).

## Metrics & autoscaling

The local agent serves the kubelet's endpoints on port 10250 (`serve
--kubelet-port`, 0 to disable) only when the node runs managed containerd; under
any other runtime the kubelet port is forced to 0. A worker joined with `gr8s
agent` serves them too: over its node identity it asks the control plane for its
kubelet's serving and client certificates, as kubelet TLS bootstrap would, and
asks again on a start within 90 days of their expiry. Their keys never leave the node, and the
control plane names the certificates itself (`system:node:NAME` for the node's
name, its address and loopback). That kubelet has the API server of the member it
joined through review its callers. The endpoints are
`/metrics/resource`, `/metrics/cadvisor`,
`/stats/summary`, `/metrics`, and `/healthz`, measured from CRI container
statistics and the cgroup v2 files of each container, sandbox, and the root.
`/metrics/cadvisor` carries cAdvisor's `container_*`/`machine_*` series,
including OOM kills (`container_oom_events_total`) and, on kernels with PSI,
CPU, memory and I/O pressure stalls (`container_pressure_*_waiting_seconds_total`
and `container_pressure_*_stalled_seconds_total`). CFS throttling series appear
only for containers with a CPU limit;
`/metrics` carries the kubelet's own CRI-operation, Pod-start/sync-latency, and
`process_*` series; `/metrics/probes` carries `prober_probe_*`.

The API server's `/metrics` carries upstream's `apiserver_request_total`,
`apiserver_request_duration_seconds`, `apiserver_longrunning_requests`,
`apiserver_current_inflight_requests`, and `process_*`, plus the scheduler's
`scheduler_schedule_attempts_total`, `scheduler_scheduling_*_duration_seconds`,
and `scheduler_pending_pods`, since the scheduler runs in the control plane. These
are served over TLS with a cluster-CA certificate; callers authenticate with a
client certificate or a bearer token (TokenReview) and are authorized by
SubjectAccessReview on `nodes/metrics`/`nodes/stats`/`nodes/healthz`/`nodes/proxy`.
The control plane also serves `metrics.k8s.io/v1beta1` directly from the node
summaries. It implements discovery plus list/get for NodeMetrics and PodMetrics,
including label and field selectors and ordinary Kubernetes RBAC. This powers
`kubectl top` and the CPU/MEM columns of k9s and Headlamp without a metrics-server
Pod, Service, or APIService. A standalone `gr8s agent` doesn't serve the kubelet
endpoints yet.

Additional authenticated `/metrics` families cover Lisp heap/GC, Raft/checkpoint
health, datastore and filesystem capacity, and reconciliation convergence. See
[control-plane metrics](control-plane-metrics.md) for labels and sampling limits.

A HorizontalPodAutoscaler controller scales Deployments, ReplicaSets,
ReplicationControllers, StatefulSets, and custom resources whose served version
declares the scale subresource, on Resource and ContainerResource metrics,
with upstream's tolerance, stabilization, and rate policies. Each node reports
CPU/memory from CRI statistics; the control plane uses that shared snapshot for
the native resource-metrics API and derives the cumulative rates used by HPA.
There is no custom or external metrics source, so other metric types report a
failed `ScalingActive` condition.
