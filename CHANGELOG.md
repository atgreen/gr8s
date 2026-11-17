# Changelog

Notable changes to gr8s. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions combine
the Kubernetes API version with a gr8s release suffix (see
[Versioning](README.md#versioning)).

## [Unreleased]

### Fixed

- `gr8s status` and `gr8s member` now work against kubeconfigs with inline
  certificate data (`certificate-authority-data` and friends) — which
  `gr8s kubeconfig` itself emits. The CLI previously failed TLS
  verification with UNKNOWN-CA unless credentials were file paths; the
  inline data is now materialized into private temporary files for the
  duration of the call, as the slynk tunnel already did.
- A stuck API request can no longer turn HA checkpointing into a standing
  outage: when the pre-checkpoint drain times out, the journal now names
  each request still holding an access lease (method, path, age), the
  compaction worker backs off exponentially (60s doubling to a 600s cap)
  instead of immediately re-entering another 30-second drain window, and
  the Slynk debug tunnel no longer takes a store lease — so it stays
  usable precisely when the store is wedged.
- Refusals that cross the wire now carry and log their reasons
  (podster-ddc): a node-session handshake answered with a protocol-error
  reports the peer's own explanation instead of a bare
  ":PROTOCOL-ERROR"; a refused Raft admission names its reason in the
  leader's journal and in the JoinResponse (new `reason` field), and the
  joiner's failure message repeats it.
- HA replicas can no longer fork over the node lease clock (podster-uvs):
  the replicated-node conflict check now ignores `lastHeartbeat`,
  `leaseDeadline` and `readySince`, which renew every few seconds on the
  session-owning member — including them gave a write racing a heartbeat
  member-dependent verdicts, so some replicas silently skipped a
  committed delta, diverged, and then conflicted on every later delta
  from the forked side (observed live as a leader marking the author
  NotReady while its handshakes were refused once a second). A member
  that does skip a genuinely conflicting committed delta now says so in
  its journal instead of staying silent.
- `gr8s doctor` now preflights the host firewall against the member's
  recorded HA endpoint: it maps the member address to its interface and
  firewalld zone and FAILs with the exact `firewall-cmd` repair when the
  raft/node/API ports are dropped — the silent join-stall we hit when a
  WireGuard interface sat in no zone. `serve` also admits the raft port
  through firewalld alongside the node and API ports.
- A joining member's catch-up is now observable (podster-84o): the
  recovery-wait journal line reports snapshot-transfer progress (bytes
  received, time since the last chunk), and an admitted learner that has
  received nothing says so explicitly with a pointer at `gr8s doctor`'s
  firewall check — previously a healthy transfer and a firewalled stall
  logged identically. `gr8s member list` no longer presents healthy
  peers as ghosts when queried on a follower: contact is reported as
  `unknown` off-leader (followers rarely message each other), with a
  note naming the leader to query.

- HA control-plane shutdown now always completes: stopping a Raft member
  bounds every worker-thread join under one deadline (10s), abandoning a
  thread that will not exit with a warning instead of hanging until
  systemd kills the process — previously an unreachable peer during a
  membership change could wedge `systemctl stop` forever.

### Changed

- The dashboard is no longer optional: `make native` requires the
  embedded Headlamp frontend, which is now extracted automatically from
  the digest-pinned upstream container image (podman/docker, no Node.js)
  — previously a source build without a manual asset step silently
  shipped no dashboard. Release builds use the same pinned image instead
  of an npm build from a Headlamp checkout;
  `make dashboard-assets-from-source` remains for hacking on Headlamp.

- `gr8s doctor` gains `--fix`: pod-pool route overlaps caused by a killed
  instance's leftovers (stale `gr8s-vxlan`/`gr8s-gateway`/`gr8s-services`
  links, orphan pod veths) are deleted when the link is provably
  gr8s-owned, instead of crash-looping the next startup. The startup
  refusal now names the offending interface and points at the fix.
- The packaged and installer-generated systemd services report readiness
  (`Type=notify`): `active` now means the API or node is serving, not
  merely that the process started, and repeated startup failures stop in
  `failed` after five attempts instead of restarting forever. The RPM/DEB
  config files pin `--state-directory` to `/var/lib/gr8s/server` and
  `/var/lib/gr8s/agent` rather than inheriting root's XDG default.

### Added

- `gr8s serve --mtu N`: the Pod interface MTU handed to every node
  (default unchanged: 1450, or 1420 for the wireguard backend). Needed
  when the node underlay is itself a tunnel — over a WireGuard underlay
  (MTU 1420), the default overlay frames overflow and fragment; `--mtu
  1370` leaves room for the vxlan overhead.
- `gr8s member`: operator-facing HA membership. `list` shows every durable
  control-plane member with role, address, leadership and contact state —
  a voter never heard from is flagged as a ghost — and `remove NAME`
  proposes dropping a member through the leader (it commits once the
  remaining voters agree). Backed by
  `GET/DELETE /apis/gr8s.io/v1/controlplanemembers`.
- `gr8s serve --cluster-reset`: the escape hatch for an HA cluster whose
  voting majority is permanently gone. It rewrites the durable membership
  to the surviving member alone — committed application entries and the
  snapshot baseline are preserved, membership changes are neutralized so
  replay cannot resurrect the lost configuration — and continues serving
  as the sole voter. While recovery waits for a quorum, the journal now
  says why: the quorum arithmetic, each member, and which peers have not
  been heard from. See
  [disaster recovery](docs/backup-restore.md#disaster-recovery-a-quorum-lost-forever).
- `gr8s status`: one screen of cluster health from anywhere a kubeconfig
  reaches — API readiness, nodes, workload exceptions, Services without
  endpoints, storage, version skew, and deduplicated recent Warning
  events, each warn/fail line naming the next command to run. `--output
  json` for agents; exit 0/1/2 for healthy/warnings/failures.
- `gr8s backup` (`keygen`, `save`, `verify`) and `gr8s restore`: offline
  operator backup of a control-plane state directory — cluster identity,
  keys, and the Raft store — into one encrypted, authenticated bundle,
  and verify-then-publish restore into a fresh state directory
  ([guide](docs/backup-restore.md)).
- RPM and DEB packages for amd64 and arm64, attached to each release. They
  install `/usr/bin/gr8s`, `gr8s-killall.sh`, and disabled `gr8s-server` /
  `gr8s-agent` systemd units configured through `/etc/gr8s/*.env`. A tag
  `v<k8s>-gr8s.<n>` maps to package version `<k8s>+gr8s.<n>` with packaging
  revision 1 in both formats.

- ListenerSet support for foreign-cluster Gateways, with stable and experimental
  API discovery, explicit namespace admission, shared-port HTTPS certificates
  selected by SNI, isolated HTTP routing, incremental updates, and installed-state
  status. See the [setup and design notes](docs/design-listenersets.md).
  Small VM acceptance covers both APIs; full-scale benchmarking is deferred.

### Changed

- Gateway reconciliation reuses unchanged routing and discovery data and wakes
  promptly for committed updates, reducing repeated work as route counts grow.
- Foreign-cluster Gateways isolate listeners, routes, and TLS material even when
  they share ports and hostnames. Gateway HTTP handling now covers hostname
  intersection, listener admission, backend and certificate ReferenceGrants,
  and invalid-reference status; the recorded candidate passed all 36 Gateway
  API v1.6.3 HTTP core conformance tests.
- `gr8s serve` joins a control-plane cluster with the same flags as
  `gr8s agent` and `gr8s witness`: `--join HOST:PORT`, `--token`, and
  `--ca-pin`. The token is bound to `--node-name`, which also names the Raft
  member unless `--raft-id` is given. `--raft-join`, `--raft-token`,
  `--raft-ca-pin`, and `--raft-node-name` are removed.

## [v1.37.2-gr8s.0] — 2026-11-15

Initial release, marked pre-release as a trial.

gr8s arrives as a single-binary, Kubernetes-compatible cluster — control
plane (`gr8s serve`), worker agent, HA quorum witness, Raft datastore, and
embedded containerd/runc — that passed 100% of the upstream Kubernetes
v1.37 `certified-conformance` suite (462/462) in a recorded two-node run
([evidence](docs/CONFORMANCE.md)). The same binary provides network
services to clusters gr8s did not create: `gr8s net-agent` with
independently selectable features — `cni` (Pod networking, IPAM, VXLAN or
encrypted WireGuard overlay, eBPF NetworkPolicy, hostPort), `service-lb`
(an eBPF kube-proxy replacement), and `gateway` (Gateway API and Ingress)
— packaged as the `gr8s-net` Helm chart (0.2.0) and the
`ghcr.io/atgreen/gr8s-net` container image.

Running clusters are debuggable live through `gr8s debug slynk`
(authenticated Slynk tunnel), `gr8s debug icl` (ICL's browser IDE on a
node's live image), and `gr8s debug trace` (selector-scoped kernel tracing
in a bpftrace-compatible language, JIT-compiled to eBPF by Whistler), and
explorable through the integrated Headlamp dashboard (`gr8s dashboard`).
Internal TLS 1.3 is pure Lisp with hybrid X25519MLKEM768 key exchange; no
OpenSSL. Release artifacts cover Linux amd64 and arm64: binaries with
checksums, tarballs carrying the installer and lifecycle scripts, and
CycloneDX and SPDX SBOMs for the Lisp dependencies.

[Unreleased]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.0...HEAD
[v1.37.2-gr8s.0]: https://github.com/atgreen/gr8s/releases/tag/v1.37.2-gr8s.0
