# Runtime & the container stack

gr8s does not reimplement an OCI runtime. It embeds containerd and speaks to it
over CRI — the same runtime boundary k3s uses — while owning everything above
that boundary itself.

## The self-contained payload

The native build embeds pinned, statically linked **containerd 2.4.2**,
`containerd-shim-runc-v2`, **runc 1.5.2**, and the `bridge`, `host-local`, and
`loopback` CNI plugins 1.9.1 — no system containerd, no host glibc, no separate
CNI helper binary.

At startup the local gr8s agent mounts a private `tmpfs`, materializes the
payload there, starts its own containerd, and unmounts the payload after
containerd stops. It also mounts a private BPF filesystem under the selected state
directory for the lifetime of the managed runtime.

The pinned containerd daemon, shim, and baseline CNI plugins are built from Go
source with cgo disabled; the pinned static runc release is checksum-verified.
Every embedded executable ELF is checked for dynamic interpreters and
shared-library dependencies, and the Whistler classifier is checked as an eBPF ELF
object. Build and verify the payload with:

```sh
make containerd-bundle
```

## The CRI boundary

The runtime client is Common Lisp too: gr8s uses ag-gRPC over a Unix-domain
socket and generated bindings for the pinned Kubernetes CRI v1 schema. The
checked-in [`proto/cri-v1.proto`](../proto/cri-v1.proto) is the full CRI v1 schema
pinned from Kubernetes `cri-api` v0.36.0; its generated Common Lisp bindings live
in `src/cri-v1-generated.lisp`.

gr8s owns desired state, while each agent calls containerd's
`runtime.v1.RuntimeService` and `ImageService` directly over its private Unix
socket. containerd root, state, temporary files, CRI socket, runc state, shim
sockets, and logs are all configured as agent-owned paths. Verified CRI operations
include runtime version discovery, image pull, Pod sandbox creation, container
creation and start, status/exit-code observation, CRI log output, and clean
container/sandbox removal.

The dumped gr8s image is exposed to containerd under the `gr8s` CNI name, so a CNI
invocation is selected automatically when `CNI_COMMAND` is present — there is no
separate CNI helper binary.

For development against an already-running containerd, opt into external mode:

```sh
scripts/gr8s serve \
  --containerd-mode external \
  --containerd-socket /run/containerd/containerd.sock
```

## RuntimeClass & pluggable runtimes

`RuntimeClass` admission resolves overhead and scheduling constraints, and the
handler reaches CRI `RunPodSandbox`, so an unconfigured handler leaves the Pod
pending with the runtime's error. The runtime-handler configuration is
**data-driven** (`extra-runtime-handlers`), so stronger-isolation runtimes
register as handlers and a Pod opts into one with its `runtimeClassName` — default
`runc` for one workload, a sandbox or microVM for the next, on the same node.

Two isolation classes are the target (tracked under `podster-mgw`):

### Sandboxed runtimes — gVisor

**gVisor (`runsc`)** is a userspace application kernel that intercepts a
container's syscalls instead of passing them straight to the host kernel, shrinking
the host attack surface without a full VM. It is the first optional runtime being
wired in.

### microVM runtimes — Kata / Firecracker

The handler layer is built to be **virt-ready**: hardware-virtualized isolation in
the **Kata Containers / Firecracker** style, where each Pod runs in its own
lightweight virtual machine with its own guest kernel. This gives VM-grade
isolation while keeping container ergonomics, and is the direction the pluggable
layer is designed for beyond gVisor.

### Status

The configuration seam has landed (PR #125) — a Pod can already be pointed at an
alternate runtime handler. Still in progress: a `gr8s`-driven runtime install that
fetches, checksum-verifies, and registers a runtime (`podster-rpc`), and proving a
Pod boots end-to-end under gVisor (`podster-nhf`) and, beyond that, under a
microVM runtime.

## Preloaded images (airgap)

An agent with its own managed containerd imports every `*.tar` image archive in
its `images/` state directory at startup, before any Pod can start — as k3s does
with its airgap images. For `serve`'s local agent that directory is
`<state>/agent/images/`; for `gr8s agent` it is `<state>/images/`. Archives may be
OCI image layouts or `docker save` output; they go into containerd's `k8s.io`
namespace under the names they carry, so a Pod that asks for one by that name
doesn't pull it (with the default `IfNotPresent` policy for tagged images). Use
this for nodes without registry access or to skip slow pulls:

```sh
sudo mkdir -p /var/lib/gr8s-worker-b/images
skopeo copy docker://docker.io/library/nginx:1.27 \
  oci-archive:nginx.tar:docker.io/library/nginx:1.27
sudo mv nginx.tar /var/lib/gr8s-worker-b/images/
```

Keep the full reference after the archive path: a bare tag would be stored as
`import-gr8s:TAG`. `scripts/save-image-archives.sh DIRECTORY` saves the images the
upstream conformance selection uses. Archives are imported again on every start;
an import saves the network but not the disk work, since containerd still writes,
flushes, and unpacks every layer.

## A note on durability

`--containerd-no-sync` is off by default and is for disposable test machines only.
It makes the managed containerd skip fsync on its metadata database (bbolt
`no_sync`), shortening Pod startup on virtual disks where a flush takes hundreds of
milliseconds. The snapshotter and runc still sync. After a host crash or power
loss, containerd's metadata can be lost or corrupted; a gr8s process crash is
unaffected, and the flag changes nothing about how gr8s itself persists state.
