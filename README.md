# gr8s

[![CI](https://github.com/atgreen/gr8s/actions/workflows/test.yml/badge.svg)](https://github.com/atgreen/gr8s/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Kubernetes-compatible clusters, built from scratch in Common Lisp — with an eBPF dataplane you can run on its own.**

**One executable is a complete Kubernetes-compatible cluster.** gr8s puts a
Kubernetes-compatible API server, controllers, scheduler, node agent,
container runtime, networking, DNS, ingress, storage, metrics, a dashboard,
and the datastore into a single native binary. Copy it to a Linux machine, run `gr8s serve`, and use `kubectl` and
standard Kubernetes manifests. The same file scales out: run it as
`gr8s agent` to add worker nodes, or as `gr8s serve --join` to add
control-plane members for a [highly available](docs/high-availability.md),
Raft-replicated control plane.

> [!WARNING]
> **This is an experiment.** gr8s is for people interested in exploring and
> developing a new Kubernetes-compatible implementation. It does not promise compatibility,
> stability, or operational reliability. It may fail or behave incorrectly.
>
> The project also explores building a Kubernetes-compatible implementation through
> human-guided AI development. It may never meet its goals. See
> [Creation and development](#creation-and-development).

**gr8s passed 100% of the upstream Kubernetes v1.37 conformance tests:
462/462, zero failures**, in the recorded two-node Sonobuoy run on 2026-11-11.
See the [results and evidence](docs/CONFORMANCE.md), and the
[API coverage](docs/kubernetes-surface.md) and
[known gaps](docs/k3s-gap-inventory.md) for the current scope.

Start with the [documentation guide](docs/index.md). If you already know Kubernetes,
the [component map](docs/kubernetes-users.md) explains where familiar components live.

## One binary, nothing else to install

A gr8s cluster has nothing else to install, version, or keep in step. The
release binary carries its own statically linked container runtime and CNI
plugins, so it needs no system containerd, runc, CNI plugin binaries,
`iptables`, or add-on manifests. On the host it needs only a recent kernel,
glibc 2.39 or later, and libzstd. Every node runs the same file, so there is no
version skew between components.

| You would normally deploy | In gr8s |
|---|---|
| kube-apiserver, kube-controller-manager, kube-scheduler | Built in |
| etcd | Built-in durable datastore, replicated with Raft for high availability; `gr8s backup` / `gr8s restore`. Two-node HA takes [miniwit](#miniwit--a-tiny-third-raft-vote), a tiny Go arbiter you can deploy anywhere, even on a home router |
| kubelet, containerd, runc, CNI plugins | Built in; containerd, runc, and CNI plugins are embedded and started on demand |
| CNI, kube-proxy, NetworkPolicy controller | Built-in eBPF dataplane, with VXLAN or WireGuard between nodes |
| CoreDNS | Built-in node-local cluster DNS |
| Ingress controller, Gateway API implementation, LoadBalancer provider | Built in |
| local-path provisioner, NFS volumes | Built in; CSI drivers still work |
| metrics-server, cAdvisor | Built in; `kubectl top` and Prometheus scrapes work |
| Kubernetes dashboard | Built-in Headlamp UI: `gr8s dashboard` |
| Certificate management | Automatic leaf renewal, staged CA rotation, one-time join tokens |
| bpftrace, debug tooling | `gr8s debug trace` and a live Lisp REPL into any node |
| Registry mirror, peer-to-peer image distribution (Dragonfly, Kraken, Spegel) | Built-in BitTorrent v2: nodes share image layers with each other instead of each pulling from the registry |

The same file takes every role:

```sh
gr8s serve              # control plane plus a local node: a complete cluster
gr8s serve --join       # another control-plane member, for high availability
gr8s agent              # a worker node joining that cluster
gr8s net-agent          # just the eBPF dataplane, on a Kubernetes cluster you already run
```

For two-node high availability, the tie-breaking third vote is
[miniwit](#miniwit--a-tiny-third-raft-vote), a tiny Go program you can deploy
almost anywhere: a small VM, a Raspberry Pi, or even a home router.

Upgrading is replacing one file. The [systemd installer](docs/installing.md)
verifies the new binary, restarts the service, and rolls back automatically if
it does not become ready. Containers run with embedded containerd and runc;
[Kata Containers or gVisor](docs/runtime.md#runtimeclass--pluggable-runtimes)
are one command away (`gr8s runtime install gvisor` or `gr8s runtime install kata`),
and virtual machines run with [KubeVirt](docs/kubevirt.md).

## Getting started

To run a cluster, you need **Linux 6.6+ with TCX eBPF support**, **root
privileges**, and working cgroups. Install **`kubectl`** to use the Kubernetes
API. Start with a disposable Linux VM.

**1. Install** the binary from the
[latest release](https://github.com/atgreen/gr8s/releases) (`amd64` or `arm64`):

```sh
VERSION=v1.37.2-gr8s.2 ARCH=amd64
curl -fLO https://github.com/atgreen/gr8s/releases/download/$VERSION/gr8s-linux-$ARCH
curl -fLO https://github.com/atgreen/gr8s/releases/download/$VERSION/gr8s-linux-$ARCH.sha256
sha256sum -c gr8s-linux-$ARCH.sha256
sudo install -m 0755 gr8s-linux-$ARCH /usr/local/bin/gr8s
```

**2. Start a cluster** and leave it running:

```sh
sudo gr8s serve
```

**3. Use it.** In another terminal, save a kubeconfig and deploy the
[example](examples/getting-started.yaml). The node needs registry access for
the nginx and BusyBox images.

```sh
(umask 077; sudo gr8s kubeconfig > ~/gr8s.kubeconfig)
export KUBECONFIG=~/gr8s.kubeconfig

kubectl wait --for=condition=Ready node/gr8s-local --timeout=180s
kubectl apply -f https://raw.githubusercontent.com/atgreen/gr8s/main/examples/getting-started.yaml
kubectl -n gr8s-demo rollout status deployment/web --timeout=180s
kubectl -n gr8s-demo wait --for=condition=Ready pod/client --timeout=180s
kubectl -n gr8s-demo exec client -- wget -qO- http://web.gr8s-demo.svc.cluster.local
```

Expect an HTML response containing `Welcome to nginx!`. The
[full walkthrough](docs/getting-started.md) checks DNS, performs a rolling
restart, and explains common failures. Remove the example with
`kubectl delete namespace gr8s-demo`. Stop the server with Ctrl-C; cluster
state persists in root's `~/.local/state/gr8s` for the next start
(`--state-directory` picks another place).

`gr8s serve` exposes one authenticated HTTPS Kubernetes API on `0.0.0.0:6443`;
there is no unauthenticated localhost API. The kubeconfig embeds the cluster CA
and an administrative client certificate, so keep it private.

To build the binary yourself instead, install **SBCL** and **ocicl**, plus Go
for the runtime payload and podman or docker and cpio for the embedded
dashboard, and run `make native`; see the
[build requirements](docs/building-and-testing.md#requirements). Every `gr8s`
command works the same with `build/gr8s`.

See [Building, running & testing](docs/building-and-testing.md) to add
[worker nodes](docs/building-and-testing.md#a-second-node), use external
containerd, or run tests. The runtime guide explains how to
[preload images](docs/runtime.md#preloaded-images-airgap).

For expiry inventory, leaf replacement, staged cluster-CA rotation, and
ServiceAccount signer rotation, see [Certificate management](docs/certificate-management.md).
Secrets encryption and key rotation are described in the
[ConfigMap and Secret API guide](docs/configmap-secret-api.md).

To manage a persistent server or agent with systemd, see
[Installing and operating gr8s with systemd](docs/installing.md).
It covers verified upgrades, rollback, scoped cleanup, and uninstall.

For multi-member operation, recovery, automatic checkpoints and heap sizing, see
[High availability](docs/high-availability.md).

## Why gr8s?

- **Nothing to assemble.** One file is the whole cluster, on every node, at one
  version. Upgrading replaces that file, and the installer rolls back if the new
  one does not become ready.
- **Small clusters and slow links.** Two control-plane nodes and a witness give
  high availability. The witness, [miniwit](#miniwit--a-tiny-third-raft-vote),
  is small enough to put on whatever always-on box you have — the author's runs
  on a FreeBSD pfSense router. Nodes fetch image layers from each other over BitTorrent v2,
  so a rollout to many nodes normally costs the registry one download of each
  layer, and [preloaded images](docs/runtime.md#preloaded-images-airgap) cover
  airgapped nodes.
- **A dataplane you can adopt piece by piece.** The eBPF networking stack also
  runs on [a cluster you already have](#use-the-gr8s-dataplane-with-your-own-kubernetes),
  as a full CNI or just as a Gateway or kube-proxy replacement.
- **Debugging built into the cluster.** [`gr8s doctor`](#doctor) links causes to
  symptoms. `gr8s debug trace` sends programs written in a
  [bpftrace-compatible language](docs/design-gr8s-trace.md) to the nodes that
  host selected Pods and attaches them in the agent process, with no bpftrace
  binary or tracing DaemonSet. An authenticated
  [Slynk](https://github.com/joaotavora/sly) tunnel opens a live REPL into any
  control-plane or agent process; see
  [debugging a running cluster](docs/building-and-testing.md#debugging-a-running-cluster).
  `gr8s skill` prints built-in operator and AI agent guidance that works offline.
- **An independent implementation to study.** The control plane and node agent
  are written from scratch rather than packaged from upstream Kubernetes. gr8s
  is an experiment in large systems programming in Common Lisp:
  concurrency, networking, storage, compilers, and distributed systems in one
  project. See [For Common Lisp developers](#for-common-lisp-developers).

## How is gr8s different from k3s?

k3s is the closest comparison to gr8s. Both provide a Kubernetes-compatible
cluster that you can operate with `kubectl`. k3s is a packaged Kubernetes
distribution built from upstream components and familiar ecosystem add-ons.
gr8s is an independent implementation: one native Common Lisp executable runs
the API, controllers, scheduler, node agent, and embedded runtime. It uses its
own datastore, with Raft replication, and an eBPF dataplane rather than
assembling the usual separate control-plane and networking components.

That architecture gives gr8s an integrated system to explore and develop,
with features such as live Lisp inspection and a directly compiled eBPF
dataplane. It also means its compatibility and operational behavior differ from
k3s. gr8s passes the upstream Kubernetes v1.37 conformance tests, but is
experimental and does not yet provide every k3s add-on or operational
workflow. Check the
[compatibility gaps](docs/k3s-gap-inventory.md), [API coverage](docs/kubernetes-surface.md),
and [conformance results](docs/CONFORMANCE.md) for supported behavior and limitations.

## Use the gr8s dataplane with your own Kubernetes

The gr8s eBPF dataplane also installs as a standalone DaemonSet on a cluster you
already run — no gr8s control plane required. On a k3s cluster with
`kube-proxy`, flannel, and the built-in NetworkPolicy controller disabled, gr8s
provides a complete eBPF networking stack:

- **Pod networking and IPAM** over a VXLAN fabric (cross-node Pod-to-Pod), or an
  **encrypted WireGuard fabric** (`overlay.backend=wireguard`) that transparently
  encrypts Pod-to-Pod traffic while leaving node and API traffic in the clear.
- **Services** — a kube-proxy replacement in the Whistler eBPF socket and packet
  load balancer.
- **NetworkPolicy** enforced in eBPF, for TCP, UDP, and SCTP.
- **Gateway API** — HTTPRoute routing, status, and LoadBalancer Services — and
  `networking.k8s.io/v1` **Ingress** (IngressClass `gr8s.io/ingress-controller`)
  served by the same proxy.
  [ListenerSets](docs/design-listenersets.md) let teams attach HTTP/HTTPS listeners
  to a shared Gateway, including separate TLS certificates on the same port.
- **hostPort** (in-kernel DNAT at the socket hook) and cluster **DNS** reachability.

Each piece is an independently selectable feature of the `gr8s net-agent`
DaemonSet: run the full stack, or turn the CNI feature off and add just the
Gateway or the kube-proxy replacement on top of the CNI you already run — they
only need Pod IPs reachable from the host network, which most CNIs provide.

Everything is JIT-compiled from a Lisp eBPF DSL by
[Whistler](https://github.com/atgreen/Whistler), so the only host requirement is
a recent kernel — there is no bundled `iptables` or `nft` binary to match. Run as
the CNI on a two-node k3s cluster, the dataplane passes the upstream Kubernetes
conformance tests for NetworkPolicy (TCP, UDP and SCTP), Gateway API (core
HTTPRoute), and the sig-network suite covering Services (ClusterIP and NodePort),
hostPort, DNS and EndpointSlices.

Install it with the Helm chart (point `apiServer.host` at an API server
address nodes reach over the host network):

```sh
helm install gr8s-net deploy/chart/gr8s-net -n kube-system \
  --set apiServer.host=CONTROL_PLANE_IP
```

See [deploy/](deploy/) for the chart and conformance harness, and the
[foreign-cluster networking design](docs/design-foreign-cluster-networking.md)
for how it works.

## Dashboard

`gr8s dashboard` opens a Kubernetes web UI in your browser. It serves the
[Headlamp](https://headlamp.dev) frontend — embedded in the binary, with no
separate install — and reverse-proxies the API over mutual TLS to the running
cluster, with live resource updates.

```sh
gr8s dashboard    # uses $KUBECONFIG, or ~/.kube/config
```

It serves on loopback `http://127.0.0.1:8080` by default (change with `--port`)
and launches your browser; `--no-launch` prints the URL instead. `make native`
embeds the assets automatically; see
[dashboard assets](docs/building-and-testing.md#dashboard-assets).

## Doctor

`gr8s doctor diagnose` reads a cluster and says what is wrong and why. It
links the resources it reads — a workload to the Pods it owns, a Service to
the Pods it selects, a Pod to its Node, Secrets, ConfigMaps and claims — so
the report names causes instead of listing every symptom. A missing Secret
is one problem, with the Pods and workloads it holds up listed beneath it.

```sh
gr8s doctor diagnose                               # the whole cluster
gr8s doctor diagnose -n production                 # one namespace
gr8s doctor diagnose deployment/web -n production  # one resource and what it depends on
gr8s doctor impact node/worker-1                   # what stops if this goes away
```

Problems are listed in the order to fix them. Each one shows the evidence
behind it — conditions, recent Events, the last lines a crashed container
wrote — and a suggested next step. `diagnose` only reads, and a cause is the
deepest finding the doctor could see, not proof of a root cause.

`gr8s doctor impact KIND/NAME` follows the same links the other way, before
you drain a node or delete a Secret. `gr8s doctor host` checks the kernel,
cgroups, firewall and state directory of a machine before it runs a node.
See [Doctor](docs/doctor.md) for output formats, exit codes, rules, coverage
and limits.

## Kubernetes capabilities

The implemented API surface includes:

| Area | Capabilities |
|---|---|
| Workloads | Pods, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs, ReplicationControllers, rolling updates, owner-reference garbage collection |
| Scheduling | Resource requests and limits, node affinity and anti-affinity, taints and tolerations, priority and preemption, host ports, ephemeral-storage eviction |
| Configuration and identity | ConfigMaps, Secrets, ServiceAccounts, bound tokens, RBAC, certificate issuance, admission webhooks, CEL admission policies |
| Networking | ClusterIP, NodePort and LoadBalancer Services, EndpointSlices, NetworkPolicy, Gateway API, cluster DNS |
| Storage | PersistentVolumes and Claims, StorageClasses, local-path provisioning, NFS, CSI drivers |
| Observability | Metrics endpoints, [Lisp heap/GC, Raft and filesystem metrics](docs/control-plane-metrics.md), cAdvisor and API server/scheduler series, resource metrics for `kubectl top` |
| Extensibility | Schema-backed custom resources, defaulting, pruning, validation, finalizers |

Support varies by feature. This overview does not imply complete upstream
semantics. See the [Kubernetes API surface](docs/kubernetes-surface.md) for
supported operations, validation evidence, and limitations.

## How it fits together

```text
kubectl -> Kubernetes API -> controllers and scheduler -> desired state
                                                        |
                                                  node protocol
                                                        |
                                                     agent
                                                   /       \
                                         CRI / containerd   networking
                                                |           /       \
                                               runc    routed veths   eBPF
```

`gr8s serve` runs the control plane and a local agent. Worker nodes run
`gr8s agent` and connect through an authenticated gRPC protocol. The control
plane schedules work and publishes the desired state. Agents reconcile
containers and networking, then report their status. By default, each agent
manages its own containerd instance.

For a replicated control plane, Raft supports three voting members or two
members and a witness. A quorum can continue after a leader fails. A single-node
cluster needs no Raft configuration. See
[High availability](docs/high-availability.md) for membership and durability
guarantees. See [Design](docs/design.md) for component boundaries.

## miniwit — a tiny third Raft vote

[`miniwit`](miniwit/) is a tiny Go program with minimal memory, CPU, and
storage needs. You run two full gr8s master nodes plus miniwit as the third
Raft-cluster participant: it provides the deciding vote for leader election and
split-brain scenarios without running the control-plane dataplane. It never
campaigns, so it cannot become leader — it only grants votes, acknowledges
AppendEntries, and tracks the Raft log boundary for quorum.

miniwit is a self-contained Go module (its own `go.mod`, independent of the
Lisp build) that speaks gr8s's `RaftTransport` gRPC/mTLS protocol — enroll,
join, follow. It is pure Go, so it cross-compiles to a single static binary
for any platform Go targets: Linux, the BSDs, macOS, Windows, on amd64, arm64
and more. That gives you a wide choice of where to put the third vote: a
small cloud VM, a Raspberry Pi, or even a home router (the author runs it on
a FreeBSD pfSense router). See
[`miniwit/README.md`](miniwit/README.md) for the protocol, flags, and build and
enroll/join instructions.

## Networking and security

[Whistler](https://github.com/atgreen/Whistler) is the embedded Lisp-to-eBPF
compiler. The agent uses it to compile and load networking programs at runtime,
without clang or LLVM. A socket load balancer directs Pod connections to ready
Service backends. Programs at Pod veths enforce NetworkPolicy and anti-spoofing.
A same-node fast path sends traffic directly to local Pods. The agent also
implements Gateway API routing.

For cross-node traffic, VXLAN is the default. The optional WireGuard overlay
uses authenticated endpoint advertisements, active path trials, and eBPF
telemetry. It supports NAT traversal, encrypted relaying, packet-size discovery,
and topology-aware sparse routing. `gr8s network explain NODE PEER` shows why it
selected a path. Path health and locality also affect Service backend selection
and image-peer ordering.

Internal TLS uses a pure-Lisp TLS 1.3 implementation. It prefers the hybrid
[X25519MLKEM768](https://atgreen.github.io/repl-yell/posts/post-quantum-tls-primer/)
key exchange, which combines classical and post-quantum cryptography. Classical
X25519/P-256 is available as a fallback.

Container images travel between nodes over BitTorrent v2. The control plane
runs a private tracker with one swarm per image layer. A layer the cluster
does not have yet is fetched from the registry by one node, and the others
download its pieces from every node that already holds them. Peers
authenticate each other with cluster certificates over mutual TLS, and each
piece is checked against the layer's digest.

See [Networking & the eBPF dataplane](docs/networking.md) for configuration,
protocol details, and operational behavior.

## Container runtimes

The embedded containerd uses runc by default. `RuntimeClass` resolves Pod
overhead, scheduling constraints, and the CRI runtime handler. Pods use it to
select a configured handler on the node.

The optional gVisor and Kata Containers runtimes support sandboxed and microVM
workloads. gr8s can install and validate them automatically. Use
`gr8s runtime install gvisor` or `gr8s runtime install kata` to install them,
then select the runtime with `RuntimeClass`. See
[Runtime & the container stack](docs/runtime.md) for configuration.

## For Common Lisp developers

gr8s is a large, working Common Lisp system — roughly 100,000 lines of
handwritten Lisp under [src/](src/), plus generated protocol bindings, spanning
an API server, controllers, a scheduler, a node agent, a durable store with Raft
replication, an eBPF compiler, and a TLS stack — built to be explored from a
REPL while it runs.

- **REPL into a live cluster.** `gr8s debug icl NODE` opens an
  authenticated, RBAC-gated Slynk tunnel to the node's running image and
  launches [ICL](https://atgreen.github.io/icl)'s browser IDE against it in
  one step (`--no-launch` prints the `icl -b --connect` line instead). ICL
  brings syntax highlighting, completion, a TUI object inspector, package
  and class browsers, flame-graph profiling, and notebooks. Built-in
  helpers in the `GR8S` package — `(debug-threads)`, `(debug-backtraces)`,
  `(debug-pod "default" "web")`, `(debug-journal 20)` — inspect the node's
  local context.
- **If you'd rather attach with Emacs or Lem**, run `gr8s debug slynk
  --node NODE --kubeconfig KUBECONFIG --local-port 4005` and point
  [Sly](https://github.com/joaotavora/sly) (or Lem's Lisp mode) at the
  printed loopback port; the tunnel stays open while the command runs.
- **Fix and continue.** Conditions, restarts, and the interactive debugger let
  you inspect a failure in context, correct a definition, and resume through an
  available restart. With suitable debugging settings, SBCL can
  [restart a stack frame using the redefined function](https://www.sbcl.org/manual/).
  SBCL [saves the loaded Lisp environment as an executable](https://www.sbcl.org/manual/#Saving-a-Core-Image),
  which is how gr8s packages its native binary.
- **eBPF written in Lisp.** [Whistler](https://github.com/atgreen/Whistler)
  compiles the entire dataplane — Service load balancing, NetworkPolicy,
  tracing probes — from a Lisp DSL to eBPF at runtime, with no clang or LLVM.
- **A Lisp network stack, no OpenSSL.** Internal TLS 1.3 is
  [pure Lisp](#networking-and-security), and the repository
  [shims `cl+ssl`](cl+ssl.asd) so even vendored HTTP clients link the
  pure-Lisp TLS instead of OpenSSL.
- **A stable language on a rich ecosystem.** Common Lisp is defined by
  [ANSI INCITS 226-1994](https://www.lispworks.com/documentation/common-lisp.html),
  so compiler and library upgrades are separate from changes to the language.
  gr8s [builds on existing libraries](gr8s.asd) for HTTP, gRPC, cryptography,
  parsing, and concurrency, and SBCL compiles it all to native code.
- **Pinned, reproducible dependencies.** [ocicl](https://github.com/ocicl/ocicl)
  restores the dependency tree from a lockfile ([ocicl.csv](ocicl.csv)).
  The full-server source launcher and Makefile core-system Lisp commands use
  [a controlled bootstrap](scripts/bootstrap.lisp) to select the locked paths
  without inheriting host ASDF registries or Lisp startup files. The local
  `cl+ssl` shim takes precedence; missing pins require `ocicl install` rather
  than silently falling back to a host library.
- **Where to start reading.** The
  [source map and developer walkthrough](docs/development.md) tours the code;
  the [documentation style guide](docs/documentation-style.md) explains how
  the source is annotated and why.

## Development and documentation

Run the unit and HTTP tests with `make test`. Tests that load eBPF programs or
run real containers need a privileged environment. Use a disposable VM and
follow the [testing guide](docs/building-and-testing.md#test-matrix).

- [Documentation paths](docs/index.md)
- [First workload: Deployment, Service, DNS, and rollout](docs/getting-started.md)
- [Kubernetes component map](docs/kubernetes-users.md)
- [Building, running & testing](docs/building-and-testing.md)
- [Kubernetes API surface](docs/kubernetes-surface.md)
- [Networking & the eBPF dataplane](docs/networking.md)
- [Runtime & the container stack](docs/runtime.md)
- [High availability](docs/high-availability.md)
- [Doctor: diagnose, impact, and host checks](docs/doctor.md)
- [Source map and developer walkthrough](docs/development.md)
- [Design & compatibility boundary](docs/design.md)
- [Multi-node design](docs/multi-node-design.md)
- [Known compatibility gaps](docs/k3s-gap-inventory.md)
- [Conformance results](docs/CONFORMANCE.md)
- [v1.37 conformance evidence (462/462)](docs/evidence/conformance-full-v1.37-2026-11-11.json)

## Versioning

A gr8s version combines the Kubernetes API version with a gr8s release suffix.
For example: `v1.37.2-gr8s.1`. The API version names the compatibility target;
conformance is recorded separately in [Conformance results](docs/CONFORMANCE.md).
`gr8s version` and the Kubernetes `/version` endpoint report the running build's
version.

## Creation and development

Anthony Green is the creator of gr8s. He guides its architecture and development;
AI assistants generate code, tests, and documentation under his direction.
Automated tests help find defects, but do not establish correctness or security.

The name **gr8s** is a portmanteau of *Green* — its creator's surname — and
*k8s*, the usual contraction of *Kubernetes*: in short, "Green Kubernetes."

## Contributing

Bug reports, questions, and pull requests are welcome through
[GitHub Issues](https://github.com/atgreen/gr8s/issues). The
[source map and developer walkthrough](docs/development.md) explains how the
code is organized; [Building, running & testing](docs/building-and-testing.md)
covers the toolchain and `make test`. Run eBPF and container tests only in a
disposable VM. Report suspected vulnerabilities privately per
[SECURITY.md](SECURITY.md); releases are summarized in
[CHANGELOG.md](CHANGELOG.md).

## License

[Apache License 2.0](LICENSE).
