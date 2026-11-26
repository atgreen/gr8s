<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Browser nodes

> **Status:** proposed (podster-57fv, 2026-11-26). Nothing here is built yet.

## Goal

Visiting a page of a gr8s cluster, and agreeing to contribute, makes the browser a
worker node:

```console
$ kubectl get nodes -o wide
NAME           STATUS   AGE   OS-IMAGE
server-01      Ready    12d   Fedora Linux
browser-a81f   Ready    12m   unkernel
browser-b92e   Ready    8m    unkernel
```

No installation, no root, no VPN, no container runtime and no inbound firewall rule
on the contributing machine. Browser nodes and native nodes are in one cluster, and
the scheduler decides what goes where.

**Use them for:** try-it pages, demos, teaching, and batch work that tolerates
losing a node, such as Jobs. **Don't use them for** anything confidential, or
anything that needs a guaranteed share of a machine.

## How it works

The browser runs only containers. Everything a node does on the Kubernetes side
runs in the gr8s server: registration, leases, Pod sync, status, probes, and
volumes. The Pod network runs there too.

```
 gr8s server (native)                                   browser tab
 ┌──────────────────────────────────────────┐            ┌───────────────────────────────┐
 │ API server, scheduler, controllers       │            │ join page (JavaScript)        │
 │                                          │            │   ├ session: runtime calls,    │
 │ browser node "browser-a81f"              │            │   │ logs, exec, packets        │
 │   node-runtime object, lease, Pod sync ──┼─ one wss:// ┼─▶ └ per Pod: a Web Worker      │
 │   runtime = browser-runtime (session)    │ connection │       running unkernel         │
 │                                          │            │       (Linux as wasm, arm64)   │
 │ gateway: per browser Pod, a netns with   │            │       └ the Pod's containers   │
 │   the Pod's IP and a tunnel device ──────┼─ packets ──┼─▶  guest NIC (kwnet)           │
 └──────────────────────────────────────────┘            └───────────────────────────────┘
```

### The node is an object in the server

gr8s's agent drives containers through a CLOS runtime protocol: the `runtime-*`
generic functions in `src/runtime/` and `src/kubelet/`. Both the containerd runtime
and a `fake` runtime implement them, and tests already run several node objects in
one process. A browser node is a node-runtime object in the server whose runtime is
a `browser-runtime`. Each method sends a request over the browser's session and
waits for the reply. The browser implements a small protocol: create a Pod sandbox,
create, start, stop and remove containers, report status, stream logs, and run exec
and attach. It implements none of Kubernetes.

So there is no second agent. Pod sync, probes, restart policy, status, volumes and
events are the code native nodes already run, and the browser can't see or bypass
them.

The scheduler, leases, cordon and drain, DaemonSets, affinity, topology spread and
Jobs all work unchanged. A closed tab is a node whose lease expires.

### Registration

1. The join page checks what the browser can do: WebAssembly with JSPI, worker
   threads, memory.
2. The visitor chooses how much CPU and memory to give, and agrees to it.
3. The page creates a non-extractable WebCrypto key pair, kept in IndexedDB, and
   opens `wss://SERVER/join`. The server sends a challenge, and the page signs it.
4. The server creates the Node and its node-runtime object. The Node gets:
   - the labels `kubernetes.io/arch: arm64` (the guest's architecture, not the
     host CPU's), `kubernetes.io/os: linux`, `gr8s.io/runtime: unkernel`, and
     `gr8s.io/browser: "true"`;
   - the taint `gr8s.io/browser=true:NoSchedule`;
   - the visitor's numbers as its capacity.
5. The node goes Ready once the browser reports its runtime started.

The key identifies the browser across reloads: a reload of the same browser
profile is the same node, and a new profile is a new node.

### Fencing

Every session gets an epoch, and every runtime call carries it. When a browser
reconnects, the server gives it a new epoch and tells it which Pods it still holds.
The browser kills any others before it reports Ready. A browser whose node was
declared lost, and whose Pods were rescheduled, therefore never resumes them.
Session messages with an old epoch are ignored.

### Pods run in unkernel

[unkernel](https://github.com/pithings/unkernel) is Linux 7.3 built as one wasm
module. Only user programs are emulated (aarch64), so it boots in under a second.
Each Pod gets its own unkernel instance in a Web Worker, which isolates Pods from
each other and lets the browser spread them across cores. A small init in the
guest takes the runtime calls, runs the containers with crun, and passes logs and
exec through. unkernel already has namespaces, cgroup2 with the pids controller,
overlayfs, seccomp, TUN, veth and AF_VSOCK to the page.

Pods need aarch64 images, or multi-arch ones. The `arm64` label makes the scheduler
pick nodes accordingly, and multi-arch images resolve to their arm64 variant.

### Images

Registries mostly don't let a browser fetch from them (no CORS), and unpacking
layers in the guest would be slow. So the server pulls the image, flattens its
layers into a read-only erofs image (the format unkernel uses for its distro
roots), caches it, and serves it over the session or as a URL the page fetches by
range. The guest mounts it under an overlay with a writable upper layer.

### Networking: packets, not sockets

A browser can open only outbound TCP and WebSocket connections. That limits the
browser's own sockets, not what travels inside a WebSocket. So each browser Pod is
given a network namespace on a gateway host, a native gr8s node, normally the
server. That namespace holds the Pod's IP and a tunnel device, whose packets the
session carries to the guest's network card. Inside the guest, the Pod sees an
ordinary interface with its cluster IP.

What that buys:

- The Pod is a full member of the cluster network: it accepts inbound
  connections, uses UDP and DNS, and reaches Services.
- Everything that happens to a native Pod's packets happens on the gateway host:
  NetworkPolicy, Service translation, the egress proxy and its credential
  injection, and flow events. So the dashboard shows browser Pods like any other.
- The browser never learns the cluster's addressing, and needs no relay server for
  the Pod's traffic.

Each browser node gets a Pod CIDR, routed to its gateway host the way any node's
CIDR is routed to its host.

### Trust and admission

The person at the browser can read and change everything that runs there: memory,
files and network traffic. Browser nodes are therefore untrusted by construction:

- The taint keeps Pods off them unless a Pod tolerates it.
- An admission rule applies to Pods bound to a browser node. It refuses Pods that
  mount Secrets, ServiceAccount tokens (automount is off there), host paths or
  privileged settings.
- Credentials such Pods need go through the egress proxy's stand-ins
  ([agent egress](design-agent-egress.md)), so the real values stay on the gateway
  host.
- The node's own session credential can only act as that node's runtime. The
  server never sends it anything that isn't for that node's Pods.

### Resources

A browser node's capacity is what the visitor offered, not something the server
can measure or enforce. A browser can't hold a Pod to a CPU or memory limit the way
cgroups do. unkernel's cgroup2 has only the pids controller, and the tab can be
throttled when hidden. Capacity is used for scheduling and shown as advisory.
Several tabs on one machine share its CPU and fail together. The page reports a
per-profile host ID, and nodes from one host share a
`topology.kubernetes.io/zone` value, so topology spread treats them as one failure
domain.

## Milestones

1. **A virtual node in the server.** `serve` creates a node-runtime object backed by
   the `fake` runtime. It registers, goes Ready, takes Pods and reports them
   Running. No browser yet. This proves the server-side node.
2. **The browser runtime.** The session protocol and `browser-runtime`, plus a
   minimal page running unkernel: one busybox Pod, its logs, and exec. No network
   yet.
3. **The packet tunnel.** A gateway network namespace per browser Pod, with a
   tunnel device over the session into the guest's network card. Services and
   NetworkPolicy work for browser Pods.
4. **Images.** Pull, flatten to erofs, cache, and serve to the browser.
5. **Joining and trust.** The `/join` page, consent, the browser key and challenge,
   fencing, the taint, the admission rule, and advisory capacity.

## Open questions

- Several containers in one Pod in one unkernel instance: crun in the guest should
  handle it, but nobody has tested it.
- The page-to-guest control channel: AF_VSOCK to the page (unkernel's `kwvsock`) is
  the likely transport for runtime calls, and `kwnet` for packets. Their throughput
  over a session isn't measured.
- Browser memory: how many unkernel instances fit in one tab, and how they behave
  when the tab is in the background.
- Which gateway hosts a browser node's Pods: the server, or the native node with the
  most room. Starting with the server is simplest.

## Earlier directions

The browser spike (podster-182x) first ran the whole gr8s agent inside a tab, on an
emulated x86_64 PC (qemu-wasm). It worked: the node went Ready. But the agent's own
costs dominated: 13 s to start the binary, a 22 s first TLS handshake before
pre-warming, more than 300 MB of heap, and minutes to Ready. Running the node's
Kubernetes half in the server removes every one of those costs from the tab. The
spike's fixes for slow hosts (pre-warming, and the deadline bugs podster-ewxh,
podster-135e and podster-i8my) still help native nodes.
