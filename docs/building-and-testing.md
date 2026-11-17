# Building, running & testing

The [README](../README.md#getting-started) shows a quick single-node start. This
guide covers requirements, multi-node clusters, the native payload, tests, and
live-process debugging.

## Release binaries

[Build and Release](../.github/workflows/release.yml) builds native Linux amd64
and arm64 executables on Ubuntu 24.04 runners. Pushing a `v*` tag builds both
architectures and publishes a GitHub release only after both builds succeed.
Running the workflow manually builds the selected ref and uploads artifacts
without publishing a release. Use a clean, committed ref for either path.

Each build includes the pinned containerd/runc/CNI payload, the Headlamp
dashboard, and collected third-party license notices. It checks the executable's
version, help, and embedded notices, verifies the runtime payload's static linkage,
and tests artifact packaging. These checks do not run Pods or establish Kubernetes
conformance; use the disposable-VM acceptance runners for that validation.

Release downloads include:

- `gr8s-linux-amd64` and `gr8s-linux-arm64`, with matching `.sha256` files. These
  are the filenames used by `install.sh`.
- `gr8s-<version>-linux-<arch>.tar.gz`, containing the executable as `gr8s`, the
  installer and cleanup scripts (`install.sh`, `gr8s-killall.sh`,
  `gr8s-uninstall.sh`), README, and license/notice files. The scripts ship only
  inside the tarball, not as loose release assets.
- RPM and DEB packages for both architectures, built by
  [`releng/build-packages.sh`](../releng/build-packages.sh) from the release
  binaries. A tag `v<k8s>-gr8s.<n>` becomes package version `<k8s>+gr8s.<n>`
  in both formats (RPM forbids `-` in versions); the package revision (`-1`)
  is the packaging revision alone, bumped only to respin unchanged upstream
  content. Packages install `/usr/bin/gr8s`, `gr8s-killall.sh`, and disabled
  `gr8s-server`/`gr8s-agent` systemd units driven by `/etc/gr8s/*.env`;
  `install.sh` and the packages are alternatives, not layers — don't mix them
  on one host.
- `LICENSE`, `NOTICE`, and `SHA256SUMS` for the complete download set.
- Per-architecture CycloneDX and SPDX files from ocicl. These describe the
  **Lisp dependencies**, rather than the entire native payload and web frontend.

The main SBCL executable uses the build host's libc: Ubuntu 24.04 provides a
glibc 2.39 baseline. The embedded runtime payload is static, but the gr8s executable
is not a fully static or musl build. Hosts also need the libzstd shared library and
the kernel/runtime requirements below.

The workflow pins SBCL, ocicl, and Headlamp source commits and the GitHub Actions
used to build them. Runtime versions remain pinned in
[`install-containerd.sh`](../scripts/install-containerd.sh), and Lisp versions in
`ocicl.csv`. Update these pins deliberately when changing the release toolchain.

To assemble the same assets locally, install the workflow's toolchain, configure
ocicl, check out the pinned Headlamp source, and run:

```sh
HEADLAMP=/path/to/headlamp scripts/build-release.sh
```

Artifacts appear in `build/release/`. The helper restores the pinned Lisp
dependencies, rebuilds dashboard assets and the native image, and rejects a dirty
version. Generated notices go to `build/release/NOTICES`, supplied to the image
builder through `GR8S_NOTICES_FILE`; ordinary native builds still read `NOTICES`.
Archive metadata is normalized to the source commit timestamp. This makes
packaging repeatable for identical inputs; it does not promise reproducible SBCL,
Go, or JavaScript builds.

### Cutting a release

1. Move the **Unreleased** entries in [`CHANGELOG.md`](../CHANGELOG.md) into a
   dated section for the new version, and add its compare link. That section
   becomes the GitHub release notes; the publish job fails if the tag has no
   section.
2. Pin the `gr8s-net` chart to the new image tag — `image.tag` in
   [`deploy/chart/gr8s-net/values.yaml`](../deploy/chart/gr8s-net/values.yaml)
   and `appVersion` in `Chart.yaml` — because a tag build publishes
   `ghcr.io/atgreen/gr8s-net:<tag>` without moving `:latest`.
3. Tag the release commit with the exact version and push the tag. The build
   fails unless `gr8s version` of the built binary equals the tag, and the tag
   must point at a clean, committed ref.
4. After both architecture builds succeed, the workflow publishes the GitHub
   release and the container image. Mark a trial with
   `gh release edit TAG --prerelease`.

## Requirements

Build on Linux with SBCL, ocicl, GNU Make, Git, Go, curl, CA certificates,
GNU coreutils (`sha256sum`, `install`), awk, grep, and binutils (`readelf`). The
native payload build compiles containerd, its shim, and CNI plugins from pinned
Go modules, and downloads a checksum-verified runc binary. It does not require
clang or LLVM. The payload installer supports x86-64 and AArch64.

The checkout includes `ocicl.csv`, a lockfile, **not** the dependency source tree.
`make deps` restores the pinned Lisp systems into `ocicl/`; `make native` also
invokes that dependency step automatically. Initial builds need access to GitHub,
the OCI dependency registry, Go modules/toolchains, and release downloads. An
airgap runtime payload does not make a fresh source build offline.

Running real Pods requires root, working cgroup v2, mount/network namespace
support, and Linux 6.6+ with TCX eBPF support. Install `kubectl` for the walkthrough.
The native build reserves a 2 GiB SBCL dynamic heap; leave additional host memory
for compilation and the Go build. This reservation is not a measured minimum RAM
requirement or cluster sizing recommendation.

The privileged Python runners also use Python 3, `ip`, `nsenter`, `nft`, and a
non-loopback upstream resolver. Run real-container/BPF tests in disposable root
VMs; ordinary unit tests do not need root.

### Example build host: Fedora 44

Fedora 44 is the guest OS used by the project's native acceptance VMs. The VMs
receive an already-built binary; the commands below describe source-build setup,
not an assertion that a fresh Fedora build has been acceptance-tested.

```sh
sudo dnf install -y sbcl make gcc git golang curl ca-certificates \
  coreutils gawk grep binutils python3 iproute util-linux nftables
```

Install [ocicl](https://github.com/ocicl/ocicl#installation), for example from
source as the ordinary build user:

```sh
git clone https://github.com/ocicl/ocicl.git /tmp/gr8s-ocicl
(cd /tmp/gr8s-ocicl && sbcl --load setup.lisp)
export PATH="$HOME/.local/bin:$PATH"
ocicl setup
```

Apply the Lisp startup configuration printed by `ocicl setup` to `~/.sbclrc`.
For this build shell, also make the project and restored systems visible to ASDF:

```sh
# Run from the gr8s repository root.
export CL_SOURCE_REGISTRY="$PWD/:$PWD/ocicl//:"
command -v sbcl ocicl go make curl readelf
sbcl --version
ocicl version
go version
make deps
make native
```

Go may select/download a newer toolchain required by the pinned modules; see
[Go toolchain selection](https://go.dev/doc/toolchain). If toolchain downloads
are disabled, install a sufficiently new Go toolchain explicitly. Install
[`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) before
starting the workload walkthrough.

### Dashboard assets

The dashboard command serves embedded Headlamp frontend assets, and they are a
hard prerequisite of `make native`: a gr8s without its dashboard is not a valid
build. The assets are extracted automatically from the digest-pinned upstream
Headlamp container image (`HEADLAMP_IMAGE` in the Makefile) using podman or
docker, then compressed for embedding — no Node.js required. `make
dashboard-assets` refreshes them explicitly.

To hack on Headlamp itself, build the assets from a local checkout instead:

```sh
git clone https://github.com/kubernetes-sigs/headlamp.git /tmp/gr8s-headlamp
make dashboard-assets-from-source HEADLAMP=/tmp/gr8s-headlamp
make native
```

That path needs Node.js/npm in addition to `cpio` and `gzip`. See
[the dashboard command](../README.md#dashboard) for usage.

### Network access

| Traffic | Default | When needed |
|---|---|---|
| Client → server | TCP 6443, authenticated HTTPS, listens on `0.0.0.0` | Kubernetes API |
| Agent → server | TCP 7443, mutual TLS after enrollment, listens on loopback until configured | Remote workers; set `--node-listen` |
| Node ↔ node | UDP 4789 | Default VXLAN overlay |
| Raft member ↔ member | TCP 7000, loopback until configured | HA only; set `--raft-listen` |
| Node kubelet-compatible API | TCP 10250 | Metrics/stats clients where the endpoint is enabled |
| Node → registries/resolvers | Registry HTTPS and DNS | Image pulls and upstream DNS |

WireGuard is opt-in with `--overlay-backend wireguard`. Allow the advertised UDP
endpoint ports; optional relaying also needs its configured UDP port range. See
[WireGuard configuration](networking.md#self-tuning-wireguard-overlay). These
replace VXLAN transport requirements for that backend. Gateway/Ingress, NodePort,
and LoadBalancer listeners additionally need the workload's configured ports.

## Build & run the self-contained server

Build the static runtime payload and dump it into the SBCL executable:

```sh
make native
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

Without `--kubeconfig`, `serve` writes an owner-only `kubeconfig` in the state
directory and prints its path. `gr8s kubeconfig [--server URL]` prints a
kubeconfig to standard output, or writes it with `--output FILE`. No system
containerd or host glibc is used by the embedded payload. Root is still required
for mounts, namespaces, cgroups, and the overlay snapshotter.

Continue with [Your first workload](getting-started.md), which includes the
complete manifest, node readiness, Deployment/Service/DNS checks, rollout, and
cleanup. Its `kubectl` commands use `sudo` because the generated kubeconfig is
owner-only and contains administrative credentials.

### Entry paths

- `gr8s serve` runs the authenticated HTTPS control plane and a private gRPC
  node endpoint, and
  optionally joins a Raft cluster with `--raft-init`/`--join` (see
  [high availability](high-availability.md)). It starts a local agent named
  `gr8s-local` by default. `--disable-agent` runs a control-plane-only process.
- `gr8s agent` enrolls with a one-time token, persists its node key and
  certificate, and maintains the revisioned desired-state session.
- `gr8s witness` runs a headless Raft voting member (a quorum tie-breaker).
- `gr8s version` prints the version; a CNI invocation is selected automatically
  when `CNI_COMMAND` is present.

The node endpoint defaults to loopback port 7443. Set `--node-listen` and
`--node-port` for a node-facing address. The Kubernetes API defaults to
HTTPS on `0.0.0.0:6443`; `--listen` and `--port` change its binding.
Agents advertise the source IPv4 address of their control connection for
VXLAN, or use an explicit `--node-address` on multi-interface hosts.

## A second node

Use two machines meeting the runtime requirements above, each with the native
binary. Replace the documentation addresses `192.0.2.10` and `192.0.2.11` with
reachable addresses on your machines. Start the server with its node endpoint
bound to the control node's reachable address:

```sh
sudo build/gr8s serve --state-directory /var/lib/gr8s-control \
  --node-listen 192.0.2.10 --node-address 192.0.2.10
```

Create the worker's join token from another terminal on the control node:

```sh
sudo build/gr8s join-token --state-directory /var/lib/gr8s-control \
  --node-name worker-b
```

`join-token` uses the existing cluster CA and prints JSON with a one-time,
node-bound `token` and its `caPin`. On the second node, use those values:

```sh
sudo build/gr8s agent --server 192.0.2.10:7443 --node-name worker-b \
  --state-directory /var/lib/gr8s-worker-b --node-address 192.0.2.11 \
  --token TOKEN --ca-pin CA_PIN
```

The two nodes need underlay connectivity for TCP 7443 and VXLAN UDP 4789.
The default overlay is VXLAN; WireGuard requires an explicit server option.
After enrollment, `sudo kubectl --kubeconfig /var/lib/gr8s-control/kubeconfig get nodes`
on the control node should show `gr8s-local` and `worker-b` becoming Ready.
Each agent receives its own Pod CIDR and the peer route set. No bridge or
host-local CNI configuration is required. Enrollment verifies the server
certificate against `--ca-pin` before sending the token, generates the private key
on the node, and stores `node.key`, `node.crt`, `ca.crt`, the assigned Pod CIDR,
and the last-applied revision below the agent state directory.

See [runtime.md](runtime.md) for **preloaded (airgap) images** and **external
containerd** mode.

## The native executable

SBCL dumps the loaded system and all runtime artifacts into a native image,
avoiding an ASDF load and external runtime installation on startup. `make native`
dumps straight into `build/gr8s` (no launcher script):

```sh
make native
build/gr8s --help
build/gr8s runtime-assets
```

Useful targets:

```text
make containerd-bundle   build and verify containerd, runc, and CNI payloads
make test                unit and HTTP tests
make test-containerd     include live CRI/containerd integration tests
make test-whistler-cni   build the eBPF object and test the Common Lisp CNI path
make check               shell syntax checks plus tests
make smoke               build normally, then sudo the embedded-containerd smoke
make run                 start the current server
make kubeconfig          write a loopback kubeconfig
make native              build the dumped SBCL executable
make clean               remove build outputs
```

## Test matrix

Ordinary Common Lisp and HTTP suite:

```sh
make test
make check
```

**Routed-veth backend** (no sudo on hosts allowing unprivileged user/network
namespaces) creates two isolated Pod namespaces. It verifies host-to-Pod and
routed Pod-to-Pod connectivity, repeated setup/deletion, and namespace restoration
on a worker thread:

```sh
make test-routed-network
```

**Native VXLAN** between two isolated node namespaces, each with its own Pod
namespace and CIDR:

```sh
make test-vxlan-network
```

**Agent CNI integration** tests the real Unix-socket client, durable IPAM restoration
across an agent restart, and Pod DNS over UDP and TCP (BPF policy ops are
substituted, since unprivileged user namespaces can't load those programs):

```sh
make test-agent-network
```

**Live node topology** uses real gRPC agent sessions in separate node network
namespaces: source-address discovery, snapshot publication, bidirectional VXLAN,
tunnel restoration before reconnect, a peer underlay change, and route withdrawal:

```sh
make test-node-topology
```

**Self-contained native smoke** builds the payload without privileges, then uses `sudo` only
to start the local agent's managed containerd and exercise a real Pod. Checks DNS,
logs, exec success/failure, source-spoof rejection, exported policy counters, and
namespace/pin/shim cleanup:

```sh
make smoke
```

**Two-node smoke** runs a control plane and two containerd agents with persistent,
separate mount/network namespaces. Routed underlay veths carry VXLAN without a
bridge. Verifies Pod connectivity, DNS, logs, exec, tunnel dependency/repair,
traffic while one agent is stopped, certificate-based restart, unchanged Pod
identities/IPs, fresh telemetry, live CNI CHECK, and cleanup:

```sh
make smoke-two-node
```

Set `GR8S_SMOKE_KEEP_WORKDIR=1` to keep harness logs.
`GR8S_TWO_NODE_FAIL_AFTER_CREATE=1` exercises failure cleanup after both Pods reach
Running.

**Service map restart recovery** runs in a disposable root VM. Copy
`scripts/test-service-restart.py`, `scripts/test-service-traffic.py` and
`scripts/smoke-two-node.py` together with the native binary. The regression stops
one agent while retaining its Pods, deletes a Service while it is offline, seeds
orphan entries in all six Service control maps, and checks map identity,
withdrawal, Pod identity and Service traffic after restart. This uses native
containers; it does not establish guest connection-state survival.

```sh
python3 test-service-restart.py --gr8s ./gr8s --report-directory ./restart-evidence
```

Optional `--ctr /path/to/ctr` preloads the test image through the managed
containerd socket when testing independently of the image mirror.

**Packet Service state collection** uses unprivileged bytecode tests for expiry,
paired ownership, reservation contention and capacity recovery:

```sh
make test-service-packet-gc
```

For actual kernel execution, copy both emitted fixtures plus
`scripts/test-service-packet-gc.py`, `scripts/test-service-packet-program.py` and
`scripts/test-endpoint-policy.py` to a disposable root VM, then run:

```sh
python3 test-service-packet-gc.py gr8s-service-packet-test.json gr8s-service-packet-gc-test.json --kernel
```

This includes simultaneous traffic and collector invocations. To test the running
agent's ordinary reconciliation worker, copy `scripts/test-service-state-gc.py`
and `scripts/test-service-traffic.py` together with the native binary:

```sh
python3 test-service-state-gc.py --gr8s ./gr8s --report-directory ./gc-evidence
```

No images or Pods are needed for this last test. It seeds 300 expired pairs,
a fresh pair and an orphan reverse entry, then checks reclamation, fresh-state
preservation, stable map IDs, diagnostics and normal shutdown.

**Direct containerd checks** (opt-in; require a prepared CRI socket with a working
CRI plugin, snapshotter, OCI runtime, pause image, and CNI configuration):

```sh
make test-containerd
```

## Conformance harness

Run the upstream PodTemplate lifecycle and chunking cases, or the entire certified
selection, in a disposable privileged Linux guest:

```sh
python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s --sonobuoy /path/to/sonobuoy

python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s --sonobuoy /path/to/sonobuoy \
  --certified-conformance --timeout 21600
```

The runner preserves the official Sonobuoy archive, native and worker logs, and
individual executed specs in its printed report directory. A passing result
requires every selected spec to execute and pass; running it does not establish
certification. `--image-archives DIRECTORY` stages preloaded images so specs don't
wait on cold pulls. See [CONFORMANCE.md](CONFORMANCE.md) for the current posture
and run records.

## Debugging a running cluster

The preferred debugger is opened on demand through the authenticated Kubernetes
API. It does not require a debugger flag at server startup:

```sh
gr8s debug slynk --node worker-a --kubeconfig /path/to/config
gr8s debug slynk --selector 'kubernetes.io/hostname=worker-a' --kubeconfig /path/to/config
gr8s debug slynk --member cp-2 --kubeconfig /path/to/config
```

The kubeconfig must contain a bearer token or client certificate authorized to
create the dedicated `nodes/slynk` or `controlplanemembers/slynk` subresource.
A selector must resolve to exactly one Ready node. The command listens only on
`127.0.0.1:4005` (override with `--local-port`), routes bytes to that exact gr8s
process over the existing authenticated cluster transports, and removes the
remote Slynk server when the client disconnects or the command is interrupted.
Only one on-demand Slynk session may exist in a target process at a time.

Connect SLY to the printed loopback endpoint. The API tunnel authenticates to
the private process-local Slynk listener internally, so no `.sly-secret` needs
to be copied to the operator workstation.

For compatibility, `gr8s serve --debug-slynk-port PORT` still starts an opt-in
[Slynk](https://github.com/joaotavora/sly) server for inspecting a live process.
This legacy startup listener is off by default and is for disposable
environments only: **it allows
arbitrary code execution as the gr8s user, normally root.** It binds to
`127.0.0.1` and requires a secret, newly generated at each start in
`<state>/debug/slynk.secret` (because `hostNetwork` Pods share loopback); a
connecting Emacs Sly client needs a matching `~/.sly-secret`.

Forms can also be evaluated from a shell, in the `gr8s` package:

```sh
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-threads)'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-backtraces "reconciler")'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-pod "default" "web")'
scripts/gr8s-debug.py --port PORT --state-directory DIR '(debug-journal 20)'
```

`*debug-store*` and `*debug-reconciler*` hold the live objects. The conformance
runner accepts `--debug-slynk-port PORT` and `--hold-on-failure SECONDS` to keep a
failed cluster running for inspection; both are refused with
`--certified-conformance`, because a process changed this way is not conformance
evidence.
