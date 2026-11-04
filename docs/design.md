# gr8s v1 design

## Goal

gr8s is a single-machine, Kubernetes-compatible Pod control plane written in
Common Lisp. It lets a local user manage Pods with ordinary `kubectl` commands
while an embedded containerd performs container execution.

The supported workflow is `kubectl apply`, `get`, `delete`, `describe`, and
`logs` for Pods in the `default` namespace. Pod specs cover images, commands,
arguments, environment variables, and container ports.

## Boundaries

gr8s v1 runs on SBCL and Linux. Its unauthenticated HTTP API binds only to
`127.0.0.1`. It does not implement Deployments, Services, volumes, multi-node
scheduling, admission control, RBAC, or TLS.

Kubernetes compatibility is behavioral and intentionally limited to the API
surface required by the supported workflow. Unsupported resources and fields
return Kubernetes-shaped status errors rather than being silently accepted.

## Architecture

`gr8s-api` serves Kubernetes discovery and core v1 Pod endpoints. It maps HTTP
requests to domain operations and emits Kubernetes-shaped JSON objects, lists,
and status errors.

`gr8s-store` persists desired Pod objects and their metadata as atomic JSON
files. The store owns resource versions and generated UIDs, and exposes no
containerd concepts.

`gr8s-reconciler` compares stored desired state with observed runtime state. It
creates, replaces, or removes runtime Pods and projects current container state
into the API response.

`gr8s-runtime` is a protocol for observing and changing runtime Pods. The
production adapter calls Kubernetes CRI v1 over a private Unix socket using
ag-gRPC. A deterministic fake implementation supports unit and API tests.

The native image contains containerd, its runc-v2 shim, runc, the bridge,
host-local, and loopback CNI plugins, and a Whistler-generated eBPF object. The
chained CNI executable name is a symlink to the dumped gr8s image rather than a
separate program. Managed mode materializes these artifacts on a
private tmpfs, configures all mutable containerd and IPAM data under the gr8s
state directory, supervises the daemon, and removes the tmpfs after shutdown.
A private bpffs mounted at `containerd/bpf` keeps policy maps observable for
exactly the managed-runtime lifetime. External mode can instead connect to an
operator-provided CRI socket.

## Networking boundary

Containerd invokes the embedded bridge and host-local plugins through CNI. The
baseline network creates `gr8s0`, connects Pod network namespaces with veth
pairs, and allocates addresses from `10.88.0.0/16`. Containerd supplies its
internal loopback setup; the loopback binary remains in the complete embedded
CNI toolset.

Whistler supplies the policy layer. It compiles Lisp to eBPF, but it does not
create network namespaces, links, or IP allocations. The same dumped gr8s
image recognizes the `gr8s` CNI environment, invokes
its Common Lisp CNI implementation, and loads the generated sched-cls program
through Whistler's loader after the bridge stage has established the Pod
interface. It attaches the program as a persistent TCX link. The
current egress guard permits ARP and non-IPv4 traffic and rejects IPv4 source
addresses outside `10.88.0.0/16`. Its `rejected_spoofs` array is pinned beneath
the Pod sandbox container ID. Repeated ADD reuses the pinned map so its count
survives link replacement; CHECK requires both the pinned link and map; DEL
removes both, including late DEL calls with no remaining network namespace.

## Persistence and convergence

The API writes desired state before asking the runtime to converge. Each Pod is
stored under its UID and indexed by namespace/name. File replacement uses a
temporary sibling followed by an atomic rename. A restart reloads desired state
and resumes reconciliation.

Reconciliation is idempotent. Runtime object labels establish ownership; gr8s
does not mutate or delete unrelated containerd objects. Deletion removes the
runtime sandbox before removing the persisted final record. Runtime failures
appear in Pod status and are retried.

## Compatibility contract

The API implements Kubernetes discovery endpoints plus create, list, read,
replace/patch, delete, status projection, and container logs for core v1 Pods.
Namespaced routes accept only `default` in v1. JSON merge patch and the apply
patch media type cover requests produced by the supported `kubectl` workflow;
gr8s does not claim general server-side-apply semantics.

The executable includes readiness and liveness endpoints. Tests exercise HTTP
behavior against the fake runtime, persistence across store restarts,
reconciliation idempotence, CRI request construction, embedded-runtime
lifecycle, static payload validation, and an opt-in root-required end-to-end
smoke path.
