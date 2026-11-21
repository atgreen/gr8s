# Runtime & the container stack

gr8s does not reimplement an OCI runtime. It embeds containerd and communicates
through CRI, the same runtime boundary that k3s uses. gr8s owns everything above
that boundary.

## The self-contained payload

The native build embeds pinned, statically linked **containerd 2.4.2**,
`containerd-shim-runc-v2`, **runc 1.5.2**, and the `bridge`, `host-local`,
`loopback`, and `firewall` CNI plugins 1.9.1. It needs no system containerd, host glibc, or
separate CNI helper binary.

At startup the local gr8s agent mounts a private `tmpfs`, materializes the
payload there, starts its own containerd, and unmounts the payload after
containerd stops. It also mounts a private BPF filesystem under the selected state
directory for the lifetime of the managed runtime.

The pinned containerd daemon, shim, and baseline CNI plugins are built from Go
source with cgo disabled; the pinned static runc release is checksum-verified.
Every embedded executable ELF is checked for dynamic interpreters and
shared-library dependencies, and the [Whistler](https://github.com/atgreen/Whistler) classifier is checked as an eBPF ELF
object. Build and verify the payload with:

```sh
make containerd-bundle
```

## The CRI boundary

The runtime client is Common Lisp too: gr8s uses ag-gRPC over a Unix-domain
socket and generated bindings for the pinned Kubernetes CRI v1 schema. The
checked-in [`proto/cri-v1.proto`](../proto/cri-v1.proto) is the full CRI v1 schema
pinned from Kubernetes `cri-api` v0.36.0; its generated Common Lisp bindings live
in `src/generated/cri-v1-generated.lisp`.

gr8s owns desired state, while each agent calls containerd's
`runtime.v1.RuntimeService` and `ImageService` directly over its private Unix
socket. containerd root, state, temporary files, CRI socket, runc state, shim
sockets, and logs are all configured as agent-owned paths. Verified CRI operations
include runtime version discovery, image pull, Pod sandbox creation, container
creation and start, status/exit-code observation, CRI log output, and clean
container/sandbox removal.

The dumped gr8s image is exposed to containerd under the `gr8s` CNI name, so a CNI
invocation is selected automatically when `CNI_COMMAND` is present. There is no
separate CNI helper binary.

For development against an already-running containerd, opt into external mode:

```sh
scripts/gr8s serve \
  --containerd-mode external \
  --containerd-socket /run/containerd/containerd.sock
```

## KubeVirt & device plugins

The node accepts kubelet v1beta1 device plugins, reports their healthy inventory,
checkpoints allocations, and passes device mappings and other allocation
artifacts to containerd. Managed emptyDir volumes also use the standard kubelet
paths that KubeVirt's handler needs to locate launcher sockets. See
[KubeVirt on gr8s](kubevirt.md) for installation and the
[native boot record](evidence/kubevirt-native-2026-11-09.json).

## CPU, NUMA, hugepages and PodResources

Managed nodes support static exclusive CPU allocation, strict Pod-scoped NUMA
alignment with device-plugin hints, hugepage requests and hugetlbfs volumes, and
the standard PodResources v1 Unix endpoint. See
[native resource management](resource-management.md) for policies, restart
behavior, supported scope and the disposable-VM test.

## RuntimeClass & pluggable runtimes

`RuntimeClass` admission resolves overhead and scheduling constraints, and the
handler reaches CRI `RunPodSandbox`, so an unconfigured handler leaves the Pod
pending with the runtime's error. The runtime-handler configuration is
**data-driven** (`extra-runtime-handlers`), so stronger-isolation runtimes
register as handlers. A Pod selects one with its `runtimeClassName`. The same
node can run one workload with the default `runc` and another in a sandbox or
microVM.

Two optional runtimes provide stronger workload isolation:

### Sandboxed runtimes: gVisor

**gVisor (`runsc`)** is a userspace application kernel that intercepts a
container's syscalls instead of passing them straight to the host kernel, shrinking
the host attack surface without a full VM.

### microVM runtimes: Kata Containers

**Kata Containers** runs Pods in lightweight virtual machines with their own
guest kernels, providing hardware-virtualized isolation. The installer supports
QEMU, Cloud Hypervisor, Firecracker, and Dragonball hypervisor configurations.

### Installation and use

`gr8s runtime install gvisor` and `gr8s runtime install kata` download,
checksum-verify, and stage the optional runtime. Both runtimes have been validated
end-to-end with Pods. Use `--state-directory` to select the agent's state
directory: the same `--state-directory` passed to `gr8s serve` or `gr8s agent`.
The local agent's containerd data lives under `<state>/agent`, while addons are
loaded from the node state root at `<state>/runtime-addons`.

Restart gr8s after installation so the agent loads the runtime addon, then create
a `RuntimeClass` with handler `gvisor` or `kata`. Set a Pod's `runtimeClassName`
to the name of that `RuntimeClass` to select its isolation runtime.

## Preloaded images (airgap)

An agent with its own managed containerd imports every `*.tar` image archive in
its `images/` state directory at startup, before any Pod can start, as k3s does
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

## Private registries and TLS trust

Every pull goes through the node's image mirror, which fetches from the
registry over https and verifies its certificate. A redirect, such as a blob
handed off to a CDN, is verified against its own host's trust. By default that
trust is the system roots, so a registry with a private or self-signed CA fails
the pull: the Pod sits in `ImagePullBackOff`, and the event or the gr8s journal
names the TLS error. There is no plain-http or skip-verify escape hatch.

Trust a private CA for named registries in either of two ways.

**Cluster-wide, with no restart.** Create a ClusterTrustBundle holding the CA
and list the registries it vouches for in the `gr8s.io/registries` annotation
(HOST or HOST:PORT, separated by commas or spaces):

```sh
kubectl get configmap kube-root-ca.crt -o jsonpath='{.data.ca\.crt}' > cluster-ca.pem
kubectl apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: ClusterTrustBundle
metadata:
  name: lab-registry
  annotations:
    gr8s.io/registries: "registry.lab.example:30500"
spec:
  trustBundle: |
$(sed 's/^/    /' cluster-ca.pem)
EOF
```

Every node verifies exactly those registries against the bundle from its next
snapshot; the CA is not trusted for any other host. Deleting the bundle, or
dropping a host from the annotation, withdraws the trust the same way. The API
server rejects a malformed or repeated host, and only this annotation crosses
to the nodes. Each node keeps the trust it last received in
`<state>/registry-trust/`, so it verifies the same way after a restart, before
its first snapshot. Several bundles may name one registry and are all
trusted, which lets a rotation add the new CA before removing the old.

**Per node.** `gr8s serve` and `gr8s agent` take `--registry-ca HOST=FILE`
(repeatable), and a bare `--registry-ca HOST` trusts the cluster CA. This needs
a restart to change, and every node that pulls needs it. A registry named both
ways trusts the CAs from both.

Either way, the registry's certificate must name the address images use: an
image reference by IP needs that IP in the certificate. For an in-cluster
registry, a cert-manager Certificate from the `ca` ClusterIssuer is signed by
the cluster CA in `kube-root-ca.crt`.

## A note on durability

`--containerd-no-sync` is off by default and is for disposable test machines only.
It makes the managed containerd skip fsync on its metadata database (bbolt
`no_sync`), shortening Pod startup on virtual disks where a flush takes hundreds of
milliseconds. The snapshotter and runc still sync. After a host crash or power
loss, containerd's metadata can be lost or corrupted; a gr8s process crash is
unaffected, and the flag changes nothing about how gr8s itself persists state.
