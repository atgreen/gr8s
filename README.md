# gr8s

**A clean-slate, eBPF-native Kubernetes — control plane, node agent, container
runtime, networking, and datastore — in one self-contained binary.**

gr8s is a small, Kubernetes-compatible cluster that ships as a *single* native
executable. The same binary serves the Kubernetes API, schedules Pods, runs the
node, speaks CRI to an embedded containerd, implements the CNI plugin, and
**compiles its own eBPF dataplane** — with no kube-proxy, no iptables, no Envoy,
no etcd, and no C toolchain anywhere in the build.

It is not a fork or a repackaging of upstream Kubernetes. Almost everything
above the container runtime is written from scratch in Common Lisp. The result
is a cluster you can read, reason about, and run from one file.

**Post-quantum secure by default.** gr8s carries its own pure-Lisp TLS 1.3 stack
— no OpenSSL, no C — and every internal channel (the Kubernetes API, the node
agent protocol, and Raft) prefers **post-quantum hybrid key exchange
(X25519MLKEM768, FIPS 203 ML-KEM-768)** on every handshake. Because gr8s owns
both ends of its own mutually-authenticated TLS, that traffic actually lands on
the hybrid — so cluster communications resist "harvest-now, decrypt-later"
attacks out of the box, with classical X25519/P-256 as automatic fallback.

> **Status:** gr8s is young and ambitious. It implements a large and growing
> slice of the Kubernetes API, but it has **not** passed Kubernetes conformance,
> and we say so plainly ([details](docs/CONFORMANCE.md)). It is a great place to
> explore a modern, eBPF-first design — not yet a drop-in replacement for a
> production k3s cluster. The concrete missing and partial capabilities are
> maintained in the [Kubernetes and k3s gap inventory](docs/k3s-gap-inventory.md).

---

## Why gr8s?

If you like k3s — one small binary, embedded containerd, airgap-friendly, no
heavyweight dependencies — gr8s will feel familiar. The difference is *what's
inside*. k3s packages the standard upstream Kubernetes components (kube-apiserver,
kubelet, kube-proxy) with iptables + flannel for networking and etcd/SQLite for
storage. gr8s rebuilds those pieces around primitives the ecosystem spent a
decade bolting *onto* Kubernetes — and makes them foundational instead:

| | **k3s** | **gr8s** |
|---|---|---|
| Implementation | Upstream Kubernetes, bundled | Clean-slate, in Common Lisp |
| Service load balancing | kube-proxy + iptables | **eBPF socket LB** (no kube-proxy, no iptables) |
| Pod networking / CNI | flannel | **Lisp-compiled eBPF** + native rtnetlink |
| NetworkPolicy | depends on CNI | **eBPF firewall at the Pod veth** |
| Ingress / Gateway | Traefik | **The agent is the gateway** (JIT-compiled routes, `sk_lookup`) |
| Datastore | SQLite / embedded etcd | **Built-in Raft**, written from scratch |
| Build toolchain | Go | Lisp — **no C toolchain, no LLVM** |
| Container runtime | containerd via CRI | containerd via CRI *(same boundary)* |

The through-line: **eBPF *is* the dataplane, Raft *is* the datastore, and the
agent *is* the gateway** — one language, one static image.

---

## eBPF-centric networking

gr8s has no kube-proxy and no iptables. Packet handling lives in the kernel,
programmed from Lisp through **Whistler**, a compiler that turns s-expressions
straight into eBPF bytecode — no LLVM, no clang, no `.c`, no hand-written ELF.
Four small programs do the work:

- **Service load balancing** — a `cgroup/connect4` **socket load balancer**
  rewrites a Pod's `connect(2)` directly to a ready backend. No DNAT, no
  conntrack, no kube-proxy hop. ClientIP session affinity is supported.
- **Same-node fast path** — Pod-to-Pod traffic to a destination on the same node
  is redirected straight to the target veth, bypassing the kernel forward path.
- **NetworkPolicy as a compiled firewall** — policies become data in per-Pod eBPF
  maps enforced at the Pod's host veth; a policy change is a *map update*, not a
  recompile.
- **Anti-spoof egress guard** — every Pod's egress is checked against its exact
  IPAM address and MAC in-kernel, with per-endpoint counters.

Because the eBPF compiler lives *inside* the running agent, these programs are
compiled and loaded on the fly — and the whole design opens the door to tracing,
flow visibility, and load-aware balancing as first-class, low-overhead features.

→ **[Networking & the eBPF dataplane](docs/networking.md)** — services, Gateway
API, NetworkPolicy, the egress guard, DNS, and cross-node VXLAN in depth.

---

## Sandboxed & microVM runtimes

gr8s treats the OCI runtime as a swappable layer. `RuntimeClass` is supported,
and the runtime-handler configuration is **data-driven**, so stronger-isolation
runtimes register as handlers and a Pod opts into one by its `runtimeClassName` —
default `runc` for one workload, a sandbox or a microVM for the next, on the same
node.

Two isolation classes are the target:

- **Sandboxed runtimes** — **gVisor (`runsc`)**, a userspace kernel that
  intercepts syscalls, is the first optional runtime being wired in.
- **microVM runtimes** — hardware-virtualized isolation in the
  **Kata Containers / Firecracker** style, where each Pod gets its own lightweight
  VM and kernel. This is the "virt-ready" direction the handler layer is built for.

The configuration seam has landed (a Pod can already be pointed at an
alternate runtime handler); automatic fetch-verify-install of a runtime and a Pod
booting under it end-to-end are in progress (tracked under `podster-mgw`).

→ **[Runtime & the container stack](docs/runtime.md)** — the embedded containerd
payload, CRI boundary, RuntimeClass, and the pluggable sandbox/microVM design.

---

## Getting started

You need **Linux 6.6+** (with TCX eBPF support), **SBCL**, **`kubectl`**, and
**root** (for container namespaces, cgroups, mounts, and loading eBPF).

```sh
# Build the single self-contained binary.
make native

# Run a one-node cluster (control plane + node in one process).
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig

# From another terminal, talk to it with kubectl as usual.
kubectl --kubeconfig /tmp/gr8s.kubeconfig apply -f pod.yaml
kubectl --kubeconfig /tmp/gr8s.kubeconfig get pods
kubectl --kubeconfig /tmp/gr8s.kubeconfig describe pod POD_NAME
```

That's a working cluster from one binary — no system containerd, no host glibc,
no separate CNI helper. To add a second node, preload images for airgap nodes,
run against an external containerd, or run the full test suite, see
**[Building, running & testing](docs/building-and-testing.md)**.

---

## Architecture at a glance

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

The control plane schedules Pods and publishes desired state; the agent owns the
node runtime and reports observed status. Both live in the same binary and cross
the same ag-gRPC boundary, so `gr8s serve` is a complete cluster and a separately
launched `gr8s agent` is just another node.

→ **[Design & compatibility boundary](docs/design.md)** ·
**[Kubernetes API surface](docs/kubernetes-surface.md)** (what works today, in detail).

---

## High availability

The control plane can run multi-master on a **Raft consensus layer written from
scratch in Common Lisp** — no etcd, no external database. A three-member cluster
(or two members plus a headless *witness*) survives the loss of its leader with
no loss of committed state, proven end-to-end in a smoke test that kills the
leader. HA is opt-in: with no `--raft-*` flag, `gr8s serve` runs exactly as the
single-node path always has.

→ **[High availability](docs/high-availability.md)** — the Raft design,
membership, mTLS between members, and the failover guarantees.

---

## What works today

gr8s implements a broad and growing slice of Kubernetes, including:

- **Workloads** — Pods, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs,
  ReplicationControllers, with real controllers, rolling updates, and owner-ref
  garbage collection.
- **Scheduling** — requests/limits, node (anti-)affinity, taints/tolerations,
  priority & preemption, `hostPort`, ephemeral-storage eviction.
- **Config & identity** — ConfigMaps, Secrets, ServiceAccounts, bound ES256
  tokens, full RBAC, CSR/certificate issuance, admission webhooks, and CEL
  admission policies.
- **Networking** — Services (ClusterIP/NodePort/LoadBalancer), EndpointSlices,
  NetworkPolicy, the Gateway API, and cluster DNS.
- **Storage** — PersistentVolumes/Claims, StorageClasses, a default `local-path`
  provisioner, NFS, and CSI driver support.
- **Observability** — kubelet metrics endpoints, cAdvisor and apiserver/scheduler
  series on `/metrics`, and a native resource-metrics API for `kubectl top`.
- **CRDs** — schema-backed custom resources with defaulting, pruning, validation,
  and finalizers.

→ **[Full Kubernetes API surface](docs/kubernetes-surface.md)** for the detailed,
evidence-backed list and the known gaps.

---

## Honest about scope

Every capability above is backed by committed evidence records in
[`docs/`](docs/), and conformance numbers are reported as-is. **gr8s has not
passed Kubernetes conformance.** What it offers today is a remarkably compact,
readable, eBPF-native implementation of a large part of Kubernetes — and a clean
foundation for the ideas a retrofitted stack makes hard. See
[`docs/CONFORMANCE.md`](docs/CONFORMANCE.md) for the current conformance posture.

---

## Documentation

- [Networking & the eBPF dataplane](docs/networking.md)
- [Runtime & the container stack](docs/runtime.md)
- [High availability (pure-Lisp Raft)](docs/high-availability.md)
- [Kubernetes API surface](docs/kubernetes-surface.md)
- [Building, running & testing](docs/building-and-testing.md)
- [Design & compatibility boundary](docs/design.md)
- [Multi-node design](docs/multi-node-design.md)
- [Conformance posture](docs/CONFORMANCE.md)

## Versioning

gr8s versions itself as the **Kubernetes API version it implements plus a gr8s
release suffix**, following the k3s convention (k3s's `v1.31.4+k3s1`). The ASDF
`:version` in `gr8s.asd` is the Kubernetes API version (`1.37.2`) and the single
source of truth for `/version`, a Node's `kubeletVersion`, and the startup
banner. The release suffix lives in a git tag (`v1.37.2-gr8s.0`). Cutting a
release is just a tag; the binary, `/version`, `kubeletVersion`, and banner all
report it with no code change.
