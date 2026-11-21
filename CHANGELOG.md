# Changelog

Notable changes to gr8s. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions combine
the Kubernetes API version with a gr8s release suffix (see
[Versioning](README.md#versioning)).

## [Unreleased]

### Added

- `--registry-ca HOST[=FILE]` on `gr8s serve` and `gr8s agent` (repeatable)
  verifies registry HOST against FILE's CAs instead of the system roots. A
  bare HOST trusts the cluster CA, for an in-cluster registry serving a
  cert-manager certificate from the cluster's `ca` issuer.
- Cluster-wide registry trust: a ClusterTrustBundle annotated
  `gr8s.io/registries: "HOST[:PORT], ..."` makes its CAs trusted for exactly
  those registries on every node, with no restart. Adding, rotating or
  deleting the bundle takes effect from the next node snapshot; nodes keep the
  last trust they received across restarts. A host also named by a node's
  `--registry-ca` trusts both (podster-b0c).

### Fixed

- The Gateway proxies WebSocket upgrades. A handshake used to reach the
  backend with its `Connection` and `Upgrade` headers stripped, so the
  backend answered 400. It now replays the handshake to the backend and,
  once the backend answers 101, relays the connection both ways, past the
  listener's 20-second read timeout. The rule's rewrite and header filters
  apply as on any request (podster-1fk).
- A Certificate's `ipAddresses`, `uris` and `emailAddresses` reach the issued
  leaf's subjectAltName. They used to be dropped while the Certificate still
  reported Ready. Admission checks each IP address as cert-manager does, and
  accepts any of these lists as the subject. The controller records the
  identity a Secret was issued for, so a changed spec reissues at once
  instead of at renewal, and a Secret issued before this fix reissues once
  (podster-upj).

### Security

- The image mirror verifies every registry's TLS certificate. It used to
  accept any certificate, so anyone on the path could answer a pull with
  their own manifest for a tag. A registry must now present a certificate
  for its name from a CA in the system roots, or one trusted for it by a
  ClusterTrustBundle or `--registry-ca`.
  A blob redirect is verified against its own host's trust, and must stay
  on https (podster-sqb). **Upgrading:** pulls from a registry with a
  private or self-signed certificate fail with a TLS verification error
  until its CA is trusted: by a ClusterTrustBundle annotated
  `gr8s.io/registries`, which nodes honor once the leader runs this release,
  or by `--registry-ca` on each node, which also covers the rollout itself
  (docs/runtime.md, "Private registries and TLS trust").

## [v1.37.2-gr8s.2] — 2026-11-21

Third trial pre-release. A cluster doctor, miniwit as the witness of a
two-member control plane, and HA hardening from live operation: every member
shows the same `resourceVersion`s and Events, a leadership handover refuses no
write, and a witness stores the log sealed from its own host.

### Added

- `gr8s doctor diagnose [KIND/NAME]` reads a cluster through `kubectl` and
  says what is wrong and why. It links workloads to the Pods they own,
  Services to the Pods they select, and Pods to their Nodes, Secrets,
  ConfigMaps and claims, and reports each cause once, with the symptoms it
  explains beneath it, in the order to fix them. Each problem quotes its
  evidence (conditions, recent Events, the last lines a crashed container
  wrote) and suggests a next step. The report is styled for a terminal and
  plain text in a pipe; `--markdown` and `--json` write it for an issue or
  for tools. It only reads, and exits 0, 1 or 2 for no problems, problems
  or incomplete coverage. The rules are Prolog, compiled into the binary
  when it is built. See [Doctor](docs/doctor.md).
- `gr8s doctor impact KIND/NAME` says what would stop working if a node,
  workload, Secret, ConfigMap or claim went away, and where a drain would
  be stopped by a PodDisruptionBudget.
- `gr8s doctor host` times flushed writes in the state directory and names
  the filesystem when they are slow: every Raft commit waits for one, and a
  slow disk looks like a network fault. It also checks that the host's
  in-kernel NFS client is available, and describes how the host firewall
  admits the cluster ports.
- `gr8s member transfer-leadership NAME` hands the leadership to a named
  voter before the leader is restarted, so no election and no write waits
  on it. It waits until NAME leads (podster-f9u).
- `--dns-serve-zone ZONE` on `serve` and `agent` serves an external zone's
  Gateway hostnames authoritatively from each node's address, so one static
  forward replaces ExternalDNS. That listener refuses every name outside
  its zones (podster-iga).
- miniwit, a small Go Raft witness for a two-member control plane. It is
  pure Go, so it cross-compiles to a static binary for any platform Go
  targets, small enough for a home router such as pfSense, and renews its member certificate from a voter thirty days before it
  expires. See `miniwit/README.md`.
- `gr8s status` warns when an HA member is ready but stuck in an
  interrupted application restore, where store-backed work fails silently.

### Changed

- Release builds move `ghcr.io/atgreen/gr8s-net:latest` to the release's
  image as well as publishing its version tag.
- Dependencies are re-pinned: ironclad 20261114 (from 20240503) and a newer
  cl-cancel; unused pins are dropped.
- `gr8s doctor` on its own prints help. The host checks are
  `gr8s doctor host`; `gr8s doctor --state-directory DIR [--fix]` still runs
  them.
- A read that names no `resourceVersion` is confirmed with the leader, as
  Kubernetes does with a quorum read of etcd. A member cut off from the
  leader used to answer with state the cluster had moved past; it now
  answers 503 with `Retry-After`, and its `/readyz` fails (podster-gxi).
- A follower carries a write to the leader itself, as the client, instead
  of redirecting the client with a 307. A client no longer loses a request
  to its own timeout when the leader it was sent to has just stopped
  (podster-l8i).
- A request that arrives while a checkpoint has the store closed waits for
  it, up to twenty seconds, and is then answered 429 with `Retry-After`. It
  used to be answered 503, which Helm does not retry (podster-j76).
- A drain that waits more than one second names the requests it waits on;
  it used to wait five. The Raft clock thread reports each pass that runs
  half a second late, with which thread held the member lock, and every
  change of role, term or leader (podster-0tg).
- cl-raft prints a WAL record once instead of twice: appending a 518 kB
  entry falls from 155 ms to 23 ms, all of it under the member lock
  (podster-9wb). cl-safe-yaml reads a single-line JSON apply in linear time;
  large CRDs applied with server-side apply took 13 to 22 seconds each.
- `gr8s network explain` authenticates through `--kubeconfig` like the other
  operator commands, and `make kubeconfig` writes an `https://` URL.

### Fixed

- HA node sessions survive checkpoints. A checkpoint quiesces the store for a
  moment, and the leader took that for lost leadership: it closed every node's
  session and refused new ones until the checkpoint finished. Agent endpoint
  lists no longer include witnesses, which have no node listener, and a session
  dial gives up after ten seconds instead of the kernel's two minutes
  (podster-htq).
- Only the member that hears a node's heartbeats expires its lease, and only
  after listening for a whole lease period. Heartbeat renewals are not
  replicated, so a follower saw every ready node with a long-expired lease,
  marked it not ready, and that write overrode the leader's fresh record until
  the next heartbeat: nodes flapped NotReady every few seconds (podster-htq).
- A member that refuses a node session because it is not the leader now names
  the members that can admit it, and the agent goes there. An agent started
  with one `--server`, or a member's own agent started before the others
  joined, could not otherwise follow a leadership change. Every session hello
  also lists those members and the agent keeps the list on disk, so it finds
  another member when the one it was configured with is gone and can say
  nothing (podster-1t0).
- `metrics.k8s.io` requests and the HPA pass no longer wait on silent nodes.
  Node metrics are collected on their own thread and a reader waits two
  seconds at most before it is served the previous collection; a request used
  to hold its store lease for the per-node timeout times the number of silent
  nodes, stalling every checkpoint drain behind it (podster-9o6).
- `gr8s doctor --fix` removes a `gr8s-services` interface that another
  cluster left behind, which made `gr8s serve` exit with `service interface
  belongs to another cluster` after a rebuild in a wiped state directory.
  `gr8s-killall.sh` now ends the containers its shims started; they used to
  survive under init and hold their host ports (podster-mg4).
- A Pod spec field set to `null` is read as omitted, as Kubernetes reads it.
  A Deployment whose chart rendered `volumes: null` was accepted and then
  never got a Pod: `spec.volumes must be an array` (podster-crv).
- Workload reconciliation preserves typed Kubernetes and runtime failures until
  rendering status. Unexpected programming errors are logged at the controller
  boundary without being reported as ordinary replica failures, and other
  workloads continue reconciling (podster-kag).
- Keep HA node streams on the active publishing leader and reconnect them after
  demotion, preventing follower-owned agents from missing later Gateway routes.
  Fail queued operations if leadership changes during their handshake (podster-c28).
- CRD CEL admission shares one request-size bound across nested unbounded
  collections, matching Kubernetes cardinality accounting. This admits the
  upstream AlertmanagerConfig CRD without raising validation cost limits
  (podster-b85).
- HTTP probes accept `httpHeaders: null` as an absent optional list, including
  server-side applied DaemonSets such as node-exporter (podster-2zo).
- API and kubelet authentication accept case-insensitive Bearer scheme names.
  This supports the Python Kubernetes client's lowercase `bearer` header while
  retaining token validation and RBAC checks (podster-xnq).
- Restarting an HA control-plane member no longer risks a restart-loop: the
  committed-application recovery wait now extends the systemd start deadline
  while it runs (`sd_notify EXTEND_TIMEOUT_USEC`), and the packaged and
  installer-generated units set an explicit `TimeoutStartSec=120s` instead
  of inheriting the host's `DefaultTimeoutStartSec` (45s on some hosts).
  Previously a member restarted into recovery — which must wait for the
  leader's dead-peer detection to drop its prior session (~15s) before it
  can catch up — could overrun a 45s start timeout and, with `Restart=always`,
  re-enter the same too-short window repeatedly without ever finishing. The
  recovery wait is deliberately unbounded (an operator ends a permanently
  lost quorum with `--cluster-reset`), so it now tells systemd it is still
  making progress rather than being killed as a hung start (podster-lmm).
- Every HA member gives an object the same `resourceVersion`. Each member
  used to count revisions for itself, so a client that read through a
  follower and then updated was refused as a conflict. Revisions are now
  taken only when a committed write is applied, and a version a member has
  not reached is answered 504. Members that already differ compare what
  they hold at one place in the log and renumber until they agree, and a
  restart or a stopped member coming back no longer sets them apart again
  (podster-gts, podster-b5d, podster-69p, podster-eb0, podster-lgi).
- Every HA member shows the same Events. An Event was stored only on the
  member it was written to, so `kubectl get events` through a follower
  showed none of a node's. A kubelet publishes a repeating Event at once
  for its first ten occurrences and once a minute after that (podster-xm5).
- A leadership handover refuses no write. Under write load each handover
  used to fail one or two (podster-f9u).
- The `kubernetes` Service leads to every member that serves the API and is
  heard from, not only to the founding member. Pods lost the API whenever
  the founder stopped (podster-bn8).
- A wiped member rejoining a busy cluster becomes a voter, and a joiner
  that waits for recovery says why every thirty seconds; that report had
  never printed. A snapshot transfer that keeps failing is logged instead
  of retried in silence (podster-kiw).
- A member whose store stays closed for a restore with no leader for three
  minutes restarts itself, the manual fix for that wedge (podster-7l9).
- A voter paused with SIGSTOP during a TLS handshake no longer exits with
  `DEADLINE-TIMEOUT` when it resumes (podster-fao).
- A checkpoint no longer ends a watch with 410 Expired, and no watch, log
  follow, exec, attach, port-forward or proxy holds its store lease while it
  writes to its client. One slow client or one `kubectl logs -f` used to
  stall every checkpoint, failing writes for up to 30 seconds. A log follow
  now ends when its client goes (podster-bbv, podster-0o5).
- A valid token is not answered 401 while a checkpoint has the store
  closed; kube-state-metrics crash-looped on that (podster-j76).
- A webhook that exceeds its timeout is reported with one message, and a
  finished HTTPS request no longer waits out its deadline (cl-cancel).
- HTTPRoutes on a gr8s Gateway get `status`, with `Accepted` and
  `ResolvedRefs`; tools reported every route as having no controller.
- The Gateway forwards the client's `Authorization` header to the backend.
  Backends that authenticate the caller, such as S3 SigV4, refused every
  request through it (podster-8lq).
- Secrets accept the `type` field selector. The Prometheus operator's
  Secret informer never synced without it (podster-rml).
- The kubelet serving certificate covers every local IPv4 address, the
  node's InternalIP included, and the kubelet reviews its callers through
  the local API server, following an HA leader redirect. Prometheus scrapes
  and `kubectl` proxies to non-founding nodes failed TLS or timed out
  (podster-6ls, podster-pxb).
- A Pod can reach a service bound to another node's host address, such as
  node-exporter or the kubelet. gr8s now SNATs that traffic in its own nft
  table on every node, with or without firewalld (podster-v7c).
- A reboot that reports a few kB less memory no longer stops the node agent
  with `Resource policies or topology changed with live reservations`.

### Security

- An HA witness stores the log sealed with AES-256-GCM under a key only
  voters hold, so Secret contents and signing keys no longer sit in
  plaintext on the less-trusted witness host. A witness certificate can no
  longer propose writes or relay operations such as exec through a voter
  (podster-00c, podster-106).

## [v1.37.2-gr8s.1] — 2026-11-17

Second trial pre-release. Hardening from live multi-node HA operation on a
roaming WireGuard cluster, plus Kubernetes-native Pod failure reporting.

### Fixed

- Follower writes no longer break on a roaming cluster: the control-plane
  API is advertised on the node's own cluster interface. The advertise
  address now considers `--node-listen` (the WireGuard address chosen for
  roaming) before scanning the host's first non-loopback IPv4, which
  returned whatever LAN address came first and stranded every follower's
  redirect — and the dashboard's auth probe — on an address unreachable
  once the node roamed off that network (podster-1ig). The advertised API
  URL is also no longer pinned as consensus identity: only the member id
  and Raft endpoint are, so a member that moves can restart with its new
  address instead of being refused and forced to re-found, and the leader
  re-advertises its current URL to the cluster so followers redirect there.
- `gr8s dashboard` (and any client probing permissions against a
  follower) no longer fails with "Error Authenticating": the Headlamp
  login check POSTs a `SelfSubjectRulesReview`, which — being a POST —
  was redirected to the Raft leader like a write. Authorization and token
  reviews are read-only evaluations every member can answer from its
  replicated RBAC, so they are now served locally instead of redirected.

- Dead peers are detected in seconds, not minutes: every node and member
  channel now sets `TCP_USER_TIMEOUT` (15s) and keep-alive probes, so a
  suspended or vanished peer surfaces as a connection error within
  ~15 seconds instead of waiting out the kernel's retransmission
  patience — after a laptop resume, the agent previously wrote
  heartbeats into a dead session for 2m22s while its node sat NotReady.
  Session-stall reports also stopped dumping unbounded structure
  graphs into the journal.

- Workloads survive control-plane restarts and upgrades: the packaged
  and installer-generated systemd units use `KillMode=process` with
  `Delegate=yes` (k3s parity), so stopping `gr8s-server` kills only the
  gr8s process — managed containerd and the container shims survive, and
  the restarted gr8s reconnects and re-adopts the running containers.
  Previously every service restart SIGKILLed the shims (they live in the
  unit's cgroup), restarting every pod on the node. Verified live: the
  same container process survived a full `systemctl restart`.
  `gr8s-killall.sh` remains the way to stop workloads too.
- Replica readiness beliefs can no longer poison node-delta replication
  (follow-up to the lease-clock fix): the replicated-node conflict check
  also ignores `ready` and `runtimeDownMessage`, which every member's
  expiry monitor flips locally at its own pace. A replica that once
  marked a node NotReady used to skip every later heartbeat delta
  forever — even one freshly rebuilt from the leader's snapshot
  re-forked within seconds. A committed heartbeat now heals the
  skipping replica's belief instead.

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

- Pod failures now say why, in the status fields and Events `kubectl`
  already shows and worded as a kubelet words them. A missing ConfigMap
  or Secret volume — whose 404 used to escape every handler and surface
  only in the node log — now waits in `ContainerCreating` with a
  `FailedMount` Event (`configmap "x" not found`), as do other volume
  set-up failures; `CrashLoopBackOff` reports its back-off time with a
  `BackOff` Event; a failing pull is `ErrImagePull` then
  `ImagePullBackOff` (and `ErrImageNeverPull` under `imagePullPolicy:
  Never`); a container the runtime refuses to create is
  `CreateContainerError` instead of failing the whole Pod sync as
  `RuntimeError`; and an eviction raises an `Evicted` Event. The
  control-plane node-Event allowlist no longer drops `BackOff`,
  `FailedToRetrieveImagePullSecret` or `RestartingAllContainers`.

### Changed

- `gr8s skill` gains an HA troubleshooting playbook distilled from live
  incident experience: membership-first orientation, the journal lines
  that explain refusals and what each means, the member-failure decision
  tree (remove vs `--cluster-reset`), the wipe-and-rejoin checklist, and
  per-member replica forensics.

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

- Failure and pressure metrics: `/metrics` exports
  `gr8s_endpoint_policy_drops_total` (the NetworkPolicy drop counter the
  guards kept but never published; inbound policy drops now also count in
  `dropped_packets`, as outbound ones always did), and
  `/metrics/cadvisor` adds `container_oom_events_total` and the PSI
  pressure-stall series. Node pressure conditions now carry the kubelet's
  own messages.

- ListenerSet support for foreign-cluster Gateways, with stable and experimental
  API discovery, explicit namespace admission, shared-port HTTPS certificates
  selected by SNI, isolated HTTP routing, incremental updates, and installed-state
  status. See the [setup and design notes](docs/design-listenersets.md).
  Small VM acceptance covers both APIs; full-scale benchmarking is deferred.

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

[Unreleased]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.2...HEAD
[v1.37.2-gr8s.2]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.1...v1.37.2-gr8s.2
[v1.37.2-gr8s.1]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.0...v1.37.2-gr8s.1
[v1.37.2-gr8s.0]: https://github.com/atgreen/gr8s/releases/tag/v1.37.2-gr8s.0
