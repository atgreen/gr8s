# Historical compatibility review (2026-11-13)

This is an archived engineering inventory. Statements about current gaps and issue
status below reflect that review and may be superseded. Use the
[current compatibility inventory](../k3s-gap-inventory.md) and linked feature guides
for present support. Tracking IDs here are provenance, not a live work queue.

<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Functional gaps relative to Kubernetes and k3s

This is a difference-only inventory updated through 2026-11-13. It is not a feature
overview and does not score code quality, performance, maturity, or implementation
language. A capability appears here only when current gr8s documentation or an
open issue identifies a missing, partial, or incompatible behavior, or when a
documented k3s distribution feature has no gr8s equivalent.

The comparisons have different meanings:

- **Kubernetes parity** means API and workload behavior expected from a
  conformant Kubernetes implementation. These gaps affect portable Kubernetes
  clients and workloads.
- **Default k3s parity** means the installation and operational experience
  supplied by an ordinary k3s server. These items are not necessarily required
  by Kubernetes conformance.
- **Optional k3s parity** covers opt-in integrations. They are useful comparison
  points, not requirements for gr8s's core design.
- **Intentional differences** record places where gr8s supplies the same class
  of outcome through a different architecture. They must not be reported as
  missing features merely because they do not copy k3s internals.

## Update (2026-11-13): changes since the last reconciliation

Several items below moved materially between 2026-11-10 and 2026-11-13. The affected
rows and prose have been corrected in place; this summary records the deltas and their
evidence:

- **The certified-conformance suite now passes — the largest confidence blocker is
  retired.** gr8s passes every case of the upstream Kubernetes **v1.37
  `certified-conformance` suite — 462 of 462, 0 failures**, run via Sonobuoy against a
  native two-node cluster (build `v1.37.2-g6584550+dirty`). Evidence:
  [conformance-full-v1.37-2026-11-11.json](../evidence/conformance-full-v1.37-2026-11-11.json) and
  [CONFORMANCE.md](../CONFORMANCE.md). gr8s is **not yet a CNCF-submitted _Certified
  Kubernetes_ distribution**, so the trademark remains out of scope — but the inventory
  is no longer "source- and focused-test-based."
- **Automatic Raft compaction is now on by default.** HA servers enable automatic
  application checkpoints unless `--no-raft-compaction` is set, so the memory-safety
  P0's "compaction disabled by default" gate is removed. Sustained bounded-log
  operation still needs production acceptance before the gap fully closes (SHRUNK, not
  closed).
- **Encrypted backup *capture* now exists.** An authenticated bounded-chunk backup
  stream, offline stable-state inventory, and a capture/verify state bundle cover
  cluster identity, encryption material, and signing keys together. There is still no
  restore-to-live path, operator workflow, scheduled retention, or remote/S3 copy, so
  backup/restore is narrowed, not closed.
- **Opt-in API audit logging now exists** (Metadata-level `audit.k8s.io/v1` events to a
  `--audit-log-path` JSON sink). It is not policy-selected, has no levels above
  Metadata, and no retention/rotation, so the audit gap narrows rather than closes.
- **A round of security/reliability hardening landed** (k1 findings F1–F14, k2 findings
  N1–N4 / C1–C3 / R1–R3): e.g. F2 RBAC escalation prevention, F7 NetworkPolicy
  fail-closed, F8 audit logging, N1 relay sole-authority, request-body-size and
  per-source connection caps, leader-controller isolation, Raft apply-error
  containment, cross-Node claim uniqueness enforced at apply, and kubelet node-pressure
  eviction with per-QoS `oom_score_adj`. Five findings are recorded as deliberate
  deviations in [security-deviations.md](../security-deviations.md) (F5, F11, F14, C1, C3).
  These harden existing behavior and are tracked under epics `podster-5vz` (k1) and
  `podster-83n` (k2); they are not, by themselves, k3s feature gaps.

Bead-tracking note: the historical IDs cited in the tables below (`podster-ucm`,
`podster-gmx`, `podster-oime`, and siblings) remain absent from the live Dolt database;
the current security/reliability epics are `podster-5vz` and `podster-83n`. Per-row IDs
are retained for provenance only, as the next section already notes.

## Current tracking reconciliation (2026-11-09)

The historical IDs below are absent from the available local Dolt databases.
Current work is tracked by **`podster-ucm`**, with children `.1` (journal recovery),
`.2` (HA correctness), `.3` (backup/restore), `.4` (secrets encryption), `.5`
(certificates), `.6` (telemetry), `.7` (installation/upgrades), `.8` (IPv6
acceptance), `.9` (AddOn/Helm), and `.10` (audit). Child `.11` tracks bounded Raft
log retention and snapshot catch-up. `.12` tracks per-Pod transactions. Historical references remain for provenance,
not as evidence of their current status.

Source reconciliation found streamed checkpoints, per-key HA deltas, coalesced
AppendEntries outboxes, and condition-variable waits already implemented. Journal
recovery now streams records, trims history during replay, applies its byte budget,
and collects older-generation garbage under heap pressure. A [constrained-heap
recovery run](../evidence/core-recovery-validation-2026-11-09.json) replays 512 MiB of journal
within a 384 MiB heap using default retention settings. These changes address
specific allocation paths. They do not establish an unrestricted cluster size.
Replication retries now use bounded entry batches instead of serializing the
whole retained suffix. Compaction/truncation clear discarded backing-array slots,
and snapshot persistence precedes in-memory compaction. These primitive fixes do
not enable production snapshotting by themselves. Explicit file-backed compaction
now atomically replaces its WAL and reclaims discarded records. The
[checkpoint validation](../evidence/raft-checkpoint-validation-2026-11-09.json) covers repeated
reclamation, failure boundaries and tail recovery. Production HA has durable snapshot restore and committed-tail replay. Automatic
application checkpoints are now **enabled by default** (`--no-raft-compaction` to
disable), so the "compaction disabled by default" gate is removed; sustained
bounded-log operation still requires production acceptance before the P0 gap can close.
Live disconnected-peer acceptance and the other HA correctness items also remain open.

The core and peer transport now support configured snapshot catch-up with bounded
chunks. A [four-member mTLS validation](../evidence/raft-snapshot-transfer-validation-2026-11-09.json)
covers an interrupted transfer, restored voter leadership and continued learner
replication. Crash-abandoned transfer cleanup now preserves live owners, with
[native startup and SIGKILL validation](../evidence/raft-snapshot-scratch-validation-2026-11-09.json).
An internal [streamed store artifact writer and reader](../store-snapshot-artifacts.md) now exist.
[Production durable recovery](../evidence/production-ha-recovery-validation-2026-11-10.json)
now covers three voters and a witness, including leader loss and a full restart
with data and credentials preserved. The opt-in asynchronous compaction worker
releases live locks during artifact I/O. Its
[validation record](../evidence/async-compaction-validation-2026-11-10.json) covers full
single-member and three-member churn and recovery under constrained heaps.
The three-member run completed 128 MiB of churn, caught up its delayed voter,
and cold-loaded full retained history with data and credentials preserved.
Frequent leader changes under sustained load remain an availability follow-up;
automatic application checkpoints are now on by default. Production serve/VM acceptance
and bounded heartbeat disruption remain required before closing the broader gap.

Pod desired state and checkpoints now use per-key staged transactions instead of
complete Pod-index serialization. Desired UID/version preconditions are checked at
apply time, and status-only commands cannot resurrect deleted objects. A
[validation record](../evidence/pod-transactions-validation-2026-11-09.json) covers constrained
heap use, application conflicts, native leadership handoff and persisted Pod
recovery. Node writes also stage private records and publish only after consensus.
[validation](../evidence/node-transactions-validation-2026-11-09.json) covers failed proposals,
replica watch publication and enrollment persistence retries.
[Concurrent Node write validation](../evidence/node-conflicts-validation-2026-11-09.json) covers
stale-write conflicts, commit-ordered watch revisions, follower conflict responses
and heartbeat monitor retries. Cross-Node claim uniqueness is now enforced at apply (conflicting claims are rejected
during committed apply); general cross-resource transactions and production
crash-recovery integration remain open.

In-process patch trains now provide signed, journaled rolling Lisp updates. Full
binary upgrades (including incorporation of installed patches), installation,
service configuration, and uninstall remain separate lifecycle work.

## Required Kubernetes parity gaps

| Area | Current difference | Evidence / tracking |
|---|---|---|
| Conformance | gr8s now passes the upstream Kubernetes **v1.37 `certified-conformance`** suite — **462/462, 0 failures** — run via Sonobuoy against a native two-node cluster (2026-11-11). The residual is not a technical gap: gr8s is **not yet a CNCF-submitted _Certified Kubernetes_ distribution**, and this is one tested configuration, not a claim of every topology. | [v1.37 evidence](../evidence/conformance-full-v1.37-2026-11-11.json); [ledger](../CONFORMANCE.md) |
| IP families | Dual-stack and IPv6-only Service allocation, EndpointSlice/DNS publication, dual-family Pod CIDR enrollment, Pod IPAM, routed CNI interfaces, cross-node VXLAN/WireGuard transport, IPv6 Service load balancing, and stateful IPv6 NetworkPolicy are implemented and have focused native evidence. Combined IPv6-only/dual-stack acceptance and focused-upstream evidence still gate the end-to-end support claim. IPv6 extension-header transport matching and DNS interception are narrower follow-ups rather than broad family-support blockers. | `podster-n2iv`; remaining acceptance `.5`; follow-ups `podster-slt6` and `podster-yge` |

Registry credentials and resource metrics are no longer gaps. Pod and
ServiceAccount `imagePullSecrets`, node-wide Docker credential files, and
kubelet v1 executable credential providers are implemented. gr8s also serves
`metrics.k8s.io/v1beta1` natively for NodeMetrics, PodMetrics, `kubectl top`, and
dashboard CPU/MEM without a metrics-server deployment.

Dynamic Resource Allocation is also no longer a tracked parity gap. The API,
controller, scheduler, and node paths cover structured allocation, selectors,
constraints and configuration, per-device placement, taints and tolerations,
namespace-authorized admin access, consumable capacity, multiple allocations,
durable prepare/unprepare, and CDI injection. Process-boundary acceptance with
Kubernetes's upstream `dra-test-driver` proves registration, ResourceSlice
publication, scheduling, NodePrepareResources, CDI projection, and
NodeUnprepareResources against a real external plugin.

## Most material product gaps

These are not all Kubernetes API-surface gaps, but they are more material to a
real k3s replacement than several missing optional APIs. The ordering answers
"what most limits safe production use today?", not "what is the largest amount
of code?":

| Rank | Priority | Gap | Why it is material | Tracking |
|---:|---|---|---|---|
| 1 | P0 | Control-plane memory safety | The historical whole-state allocation paths have been replaced by streamed checkpoints and per-key HA deltas. Journal replay now streams and bounds retained history. HA servers now enable automatic application checkpoints **by default** (`--no-raft-compaction` to disable), so the "compaction off by default" risk is removed; sustained bounded-log operation under production VM/container acceptance is the remaining item before the P0 can close. | historical `podster-ucm.1`, `podster-ucm.11` (see bead-tracking note above) |
| 2 | P1 | HA availability and failover correctness | A disconnected follower caused an unbounded AppendEntries queue and founder OOM. Queue coalescing and blocking idle waits are implemented, Raft apply errors are now contained on the tick loop, follower-dispatch, and single-voter propose-sync paths (previously a whole-process crash), superseded node sessions are closed on reconnect, and voter/member hard-state restore is implemented and unit-verified — but it still lacks live-cluster/VM acceptance. Remaining open: image-tracker state is not consistent across members; a follower can lose its node-heartbeat monitor; Node mutations still publish locally before consensus; and live disconnected-peer closure is unproven. | historical `podster-8r7`/`uvi`/`i5vx`/`bwu.1` (see bead-tracking note) |
| 3 | P1 | Backup and restore | Encrypted **capture** now exists: an authenticated bounded-chunk backup stream plus a capture/verify state bundle that covers cluster identity, encryption material, and signing keys together (offline, excluding runtime/lock trees). What is still missing is the operator half — no restore-to-live path (verify only streams into private staging), no CLI/workflow wiring, no scheduled retention, and no remote/S3 copy. Until restore exists, a cluster still cannot be treated as recoverable. | historical `podster-oime` (see bead-tracking note) |
| 4 | P1 | Control-plane operational telemetry | gr8s already exports Kubernetes-compatible API-server, scheduler, kubelet/resource, DNS, Gateway, process, and eBPF endpoint metrics. It does not yet expose the Raft health, SBCL heap/GC pressure, datastore growth, disk/inode pressure, and reconciliation convergence signals needed to detect its demonstrated OOM and high-CPU failure modes before availability is lost. This is an operability prerequisite, not dashboard polish. | `podster-gmx`; especially `podster-gmx.1` through `.5` |
| 5 | P2 | IPv6 and dual-stack acceptance tail | Focused native evidence covers dual-family Pod networking, cross-node transport, IPv6 Service TCP/UDP load balancing, and stateful IPv6 NetworkPolicy. What remains is one combined IPv6-only/dual-stack runner, focused upstream evidence, IPv6 DNS interception, and extension-header transport matching. This is a completion/evidence tail, not a missing core dataplane. | `podster-n2iv.5`; `podster-yge`; `podster-slt6` |
| 6 | P2 | Managed AddOns and Helm lifecycle | gr8s has intentional in-process replacements for the ordinary default components, but no general declarative manifests directory, AddOn status model, or HelmChart lifecycle for operator-supplied components. | `podster-pve3` |
| 7 | P2 | Kubernetes audit policy and durable audit log | Opt-in **Metadata-level `audit.k8s.io/v1`** events (user/groups, verb, objectRef, source IP, user agent, URI, response code) now stream to a `--audit-log-path` JSON file sink. Still missing: audit Policy selection, levels above Metadata (Request/RequestResponse), and retention/rotation — so it is not yet a policy-selected, managed audit trail. | historical `podster-9fi4` (see bead-tracking note) |

Certified-conformance evidence is no longer a confidence blocker: gr8s passes the
upstream v1.37 `certified-conformance` suite 462/462 with zero failures (evidence
[conformance-full-v1.37-2026-11-11.json](../evidence/conformance-full-v1.37-2026-11-11.json)), so
this inventory is now grounded in a measured conformance result rather than inferred
surface area. The remaining confidence item is procedural, not technical: gr8s has not
been submitted to the CNCF for the official _Certified Kubernetes_ mark.

Zero-firewall-mutation networking is also no longer ranked as a k3s gap. Real
two-node firewalld acceptance passes through gr8s-managed coexistence rules, and
k3s itself documents host firewall requirements. The all-eBPF bypass and removal
of the trusted-zone integration remain worthwhile gr8s engineering work under
`podster-pnd` and `podster-ntp`, but they are not missing k3s behavior.

The open empirical compatibility map under `podster-bgn` contains narrower API
and wire-format defects found by running a real controller stack. Those issues
are required compatibility work when still reproducible, but they are not
duplicated row-by-row here because several titles describe fixes already present
in the working tree and their bead status has not yet been reconciled. The same
rule is why this inventory does not repeat stale statements in
`kubernetes-surface.md` and `networking.md`: current source already implements
Pod/Node watches, projected-volume refresh, readiness gates, Pod-level resources,
admission-policy type checking/authorizer support, workload finalizers, richer
DNS records, API Priority and Fairness, and bidirectional NetworkPolicy.

## Default k3s distribution gaps

k3s deploys CoreDNS, Traefik, local-path storage, and metrics-server as managed
AddOns and runs an embedded ServiceLB controller. It also watches a manifests
directory and represents those files as AddOn resources. See the official
[packaged-components documentation](https://docs.k3s.io/installation/packaged-components)
and [networking-services documentation](https://docs.k3s.io/networking/networking-services).

| k3s default capability | gr8s difference | Classification |
|---|---|---|
| Managed AddOn/manifests controller | There is no general manifests directory, AddOn resource/controller, or disable/uninstall lifecycle for packaged components. Runtime payload add-ons are a narrower mechanism. | Distribution gap (`podster-pve3`) |
| CoreDNS | gr8s embeds its own DNS server instead of deploying CoreDNS. Current source implements ordinary, headless, ExternalName, SRV, and reverse records; equivalence beyond covered behavior depends on a fresh conformance run. | Intentional replacement |
| Traefik Ingress | gr8s embeds its own Gateway/Ingress proxy instead of installing Traefik. `networking.k8s.io/v1` Ingress routes, TLS Secrets, status addresses, and listener lifecycle are reconciled directly by each agent. | Equivalent outcome; intentional replacement |
| local-path-provisioner | gr8s has an in-process default `local-path` provisioner rather than a provisioner Pod. | Equivalent outcome; intentional replacement |
| metrics-server | gr8s replaces the addon with an in-process `metrics.k8s.io/v1beta1` API backed by the same node summaries used for autoscaling. No metrics-server Pod, Service, or APIService is required for `kubectl top` or dashboard CPU/MEM. | Equivalent outcome; intentional replacement |
| Supervisor/component metrics | gr8s exposes many Kubernetes-compatible component and workload metrics, but not yet complete Raft, Lisp-runtime, datastore-capacity, or controller-convergence telemetry. | Partial operational parity (`podster-gmx`) |
| ServiceLB | gr8s implements node relays and eBPF Service forwarding rather than Klipper ServiceLB Pods. It publishes ready node InternalIPs in `status.loadBalancer.ingress` with `ipMode: Proxy` and serves each LoadBalancer Service port on those addresses; `scripts/test-service-traffic.py` covers the native path. | Equivalent outcome; intentional replacement |
| Helm controller | No HelmChart/HelmChartConfig controller or equivalent packaged chart lifecycle is documented. | Distribution gap (`podster-pve3`) |
| Install/service lifecycle | gr8s supplies a checksum-pinned installer, persistent systemd environment, verified upgrade with automatic rollback, scoped killall, and explicit uninstall/purge workflow. Its configuration surface is smaller than k3s and it has no channel-based automatic upgrade controller. | Partial operational parity; see [installation](../installing.md) |
| Datastore backup/restore | k3s documents SQLite copies and embedded-etcd snapshots, including S3 workflows. gr8s can now **capture and verify** an authenticated encrypted state bundle (identity, encryption material, signing keys), but has no restore-to-live path, operator CLI/workflow, scheduled snapshot, or remote/S3 workflow. | Operational gap, narrowed (capture only) |
| Certificate operations | gr8s provides expiry inventory and warning exit status, selective leaf/key replacement, automatic renewal, staged CA rotation, staged ServiceAccount signer rotation, and HA-replicated encrypted authority state. External CA integration remains absent. | Partial operational parity; see [certificate management](../certificate-management.md) |
| Secrets at rest | gr8s provides authenticated encryption at rest plus enable/disable and staged prepare/promote/reencrypt/finalize key rotation for stopped standalone state. Leader-routed HA key management and external KMS providers are not implemented. | Partial operational parity; see [Secret API](../configmap-secret-api.md) |
| Audit policy/logging | k3s can pass through Kubernetes audit policy and log configuration. gr8s now writes opt-in Metadata-level `audit.k8s.io/v1` events to a `--audit-log-path` file sink, but still has no audit Policy selection, no levels above Metadata, and no retention/rotation. | Partial; policy/levels/retention still a gap |

The operational comparison is based on k3s's current primary documentation for
[installation](https://docs.k3s.io/installation),
[backup and restore](https://docs.k3s.io/datastore/backup-restore),
[certificate management](https://docs.k3s.io/cli/certificate), and
[secrets encryption](https://docs.k3s.io/security/secrets-encryption), plus its
[supervisor and component metrics](https://docs.k3s.io/reference/metrics).

## Optional k3s features without a gr8s equivalent

These are not default-cluster blockers and should not be mixed into Kubernetes
conformance work.

- External SQL/etcd datastores. k3s supports SQLite by default and etcd, MySQL,
  and PostgreSQL alternatives; gr8s intentionally owns its Raft store.
- Kubernetes-native automated node upgrades through Rancher's
  system-upgrade-controller. See [automated upgrades](https://docs.k3s.io/upgrades/automated).
- Rootless/server-in-container modes, alternative CNI backends, and cloud-provider
  integrations. gr8s currently targets root on Linux with its own CNI and bare
  metal-style networking.

## Intentional architectural differences

The following differences are design choices, not missing functionality by
themselves:

- Pure-Lisp Raft replaces SQLite/Kine/etcd for durable control-plane state.
- The Whistler eBPF dataplane replaces Flannel plus kube-proxy/iptables.
- In-process DNS replaces the CoreDNS deployment.
- The in-agent Gateway and Ingress implementation replaces the default Traefik path.
- In-process local-path, NFS, Service, EndpointSlice, scheduler, and workload
  controllers replace separate upstream controller binaries or addon Pods.
- Strict authenticated peer-to-peer OCI distribution replaces the opt-in Spegel
  embedded registry mirror. It distributes verified image content directly
  between node caches rather than exposing a registry API.
- A single `gr8s` executable supplies server and agent roles instead of bundling
  upstream Kubernetes component binaries.

An intentional implementation choice ceases to be equivalent when it changes a
portable API outcome; the classifications above require the portable API result,
not merely an alternative internal architecture.

## Audit boundaries

This inventory reconciles the checked-in capability documents, current open
beads, and current official k3s documentation. It deliberately excludes:

- subjective claims about maturity, supportability, or production readiness;
- performance comparisons without a shared benchmark;
- implementation-detail differences that preserve observable Kubernetes
  behavior;
- closed historical bugs unless current documentation still describes the gap;
- a claim of exhaustive Kubernetes parity before a fresh conformance run.

The 2026-11-13 refresh incorporates the v1.37 `certified-conformance` pass (462/462),
the default-on Raft compaction change, the encrypted backup-capture work, and the
opt-in audit log, correcting the affected rows from measured results rather than
inferred surface area. The next audit should re-run `certified-conformance` against the
then-current binary, extend coverage beyond the single tested two-node topology
(including the IPv6-only/dual-stack runner), reconcile the per-row tracking IDs against
the live Dolt database (the cited historical IDs are absent; current epics are
`podster-5vz` and `podster-83n`), and record any CNCF _Certified Kubernetes_ submission
status.
