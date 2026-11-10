<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Functional gaps relative to Kubernetes and k3s

This is a difference-only inventory updated through 2026-11-10. It is not a feature
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
recovery run](core-recovery-validation-2026-11-09.json) replays 512 MiB of journal
within a 384 MiB heap using default retention settings. These changes address
specific allocation paths. They do not establish an unrestricted cluster size.
Replication retries now use bounded entry batches instead of serializing the
whole retained suffix. Compaction/truncation clear discarded backing-array slots,
and snapshot persistence precedes in-memory compaction. These primitive fixes do
not enable production snapshotting by themselves. Explicit file-backed compaction
now atomically replaces its WAL and reclaims discarded records. The
[checkpoint validation](raft-checkpoint-validation-2026-11-09.json) covers repeated
reclamation, failure boundaries and tail recovery. Production HA has durable snapshot restore and committed-tail replay. Automatic
compaction remains disabled by default, so sustained bounded-log operation still
requires acceptance before the P0 gap can close. Live disconnected-peer acceptance
and the other HA correctness items also remain open.

The core and peer transport now support configured snapshot catch-up with bounded
chunks. A [four-member mTLS validation](raft-snapshot-transfer-validation-2026-11-09.json)
covers an interrupted transfer, restored voter leadership and continued learner
replication. Crash-abandoned transfer cleanup now preserves live owners, with
[native startup and SIGKILL validation](raft-snapshot-scratch-validation-2026-11-09.json).
An internal [streamed store artifact writer and reader](store-snapshot-artifacts.md) now exist.
[Production durable recovery](production-ha-recovery-validation-2026-11-10.json)
now covers three voters and a witness, including leader loss and a full restart
with data and credentials preserved. The opt-in asynchronous compaction worker
releases live locks during artifact I/O. Its
[validation record](async-compaction-validation-2026-11-10.json) includes full
single-member churn and partial three-member acceptance; full sustained
three-member churn and recovery remain required before enabling it by default
and closing the retained-log gap.

Pod desired state and checkpoints now use per-key staged transactions instead of
complete Pod-index serialization. Desired UID/version preconditions are checked at
apply time, and status-only commands cannot resurrect deleted objects. A
[validation record](pod-transactions-validation-2026-11-09.json) covers constrained
heap use, application conflicts, native leadership handoff and persisted Pod
recovery. Node writes also stage private records and publish only after consensus.
[validation](node-transactions-validation-2026-11-09.json) covers failed proposals,
replica watch publication and enrollment persistence retries.
[Concurrent Node write validation](node-conflicts-validation-2026-11-09.json) covers
stale-write conflicts, commit-ordered watch revisions, follower conflict responses
and heartbeat monitor retries. Cross-Node claim uniqueness at apply, general
cross-resource transactions and production crash-recovery integration remain open.

In-process patch trains now provide signed, journaled rolling Lisp updates. Full
binary upgrades (including incorporation of installed patches), installation,
service configuration, and uninstall remain separate lifecycle work.

## Required Kubernetes parity gaps

| Area | Current difference | Evidence / tracking |
|---|---|---|
| Conformance | No current build has passed the certified-conformance suite. The checked-in ledger's newest full result is round 4 at 64/446 tests; it predates substantial current functionality, so it is evidence of neither current failure counts nor current parity. A fresh run is required before making a conformance claim. | [Conformance ledger](CONFORMANCE.md); documentation refresh `podster-9do` |
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
| 1 | P0 | Control-plane memory safety | The historical whole-state allocation paths have been replaced by streamed checkpoints and per-key HA deltas. Journal replay now streams and bounds retained history. Production HA still retains all committed Raft entries without automatic snapshot compaction/catch-up, so historical payload growth remains an availability risk. | `podster-ucm.1`, `podster-ucm.11`; historical `podster-061`, `podster-bwu.2` |
| 2 | P1 | HA availability and failover correctness | A disconnected follower caused an unbounded AppendEntries queue and founder OOM. Queue coalescing and blocking idle waits are implemented, but the incident still lacks live HA closure. Production voter hard-state/log recovery and witness WAL recovery are not wired; image-tracker state is not consistent across members; a follower can lose its node-heartbeat monitor; and Node mutations still publish locally before consensus. Pod changes now stage until commit, but durable application-boundary recovery remains incomplete. These are active availability/correctness risks in the k3s-comparable HA path. | `podster-8r7`; `podster-uvi`; `podster-i5vx`; `podster-7ni6.3.5`; `podster-bwu.1` |
| 3 | P1 | Backup and restore | Internal Raft snapshots are not an operator recovery workflow. There is no supported, tested way to capture and restore the datastore together with cluster identity, encryption material, and signing keys, nor scheduled retention and remote-copy support. Until this exists, a cluster cannot be treated as recoverable. | `podster-oime` |
| 4 | P1 | Control-plane operational telemetry | gr8s already exports Kubernetes-compatible API-server, scheduler, kubelet/resource, DNS, Gateway, process, and eBPF endpoint metrics. It does not yet expose the Raft health, SBCL heap/GC pressure, datastore growth, disk/inode pressure, and reconciliation convergence signals needed to detect its demonstrated OOM and high-CPU failure modes before availability is lost. This is an operability prerequisite, not dashboard polish. | `podster-gmx`; especially `podster-gmx.1` through `.5` |
| 5 | P2 | IPv6 and dual-stack acceptance tail | Focused native evidence covers dual-family Pod networking, cross-node transport, IPv6 Service TCP/UDP load balancing, and stateful IPv6 NetworkPolicy. What remains is one combined IPv6-only/dual-stack runner, focused upstream evidence, IPv6 DNS interception, and extension-header transport matching. This is a completion/evidence tail, not a missing core dataplane. | `podster-n2iv.5`; `podster-yge`; `podster-slt6` |
| 6 | P2 | Managed AddOns and Helm lifecycle | gr8s has intentional in-process replacements for the ordinary default components, but no general declarative manifests directory, AddOn status model, or HelmChart lifecycle for operator-supplied components. | `podster-pve3` |
| 7 | P2 | Kubernetes audit policy and durable audit log | Admission audit annotations reach process logs, but there is no policy-selected, structured, retained Kubernetes audit trail suitable for security review. | `podster-9fi4` |

Fresh certified-conformance evidence remains the largest **confidence blocker**,
but it is not itself a product feature gap. The only preserved result from the
192.168.1.10 attempt is a focused 8-test run (8 passed, 3,205 skipped), not a
certified run. Until `podster-7lq` produces a complete archive and `podster-9do`
updates the ledger, the parity inventory remains partly source- and focused-test-
based.

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
| Install/service lifecycle | gr8s supplies a checksum-pinned installer, persistent systemd environment, verified upgrade with automatic rollback, scoped killall, and explicit uninstall/purge workflow. Its configuration surface is smaller than k3s and it has no channel-based automatic upgrade controller. | Partial operational parity; see [installation](installing.md) |
| Datastore backup/restore | k3s documents SQLite copies and embedded-etcd snapshots, including S3 workflows. gr8s Raft has internal snapshots/compaction but no documented operator backup, restore, scheduled snapshot, or remote snapshot workflow. | Operational gap (`podster-oime`) |
| Certificate operations | gr8s provides expiry inventory and warning exit status, selective leaf/key replacement, automatic renewal, staged CA rotation, staged ServiceAccount signer rotation, and HA-replicated encrypted authority state. External CA integration remains absent. | Partial operational parity; see [certificate management](certificate-management.md) |
| Secrets at rest | gr8s provides authenticated encryption at rest plus enable/disable and staged prepare/promote/reencrypt/finalize key rotation for stopped standalone state. Leader-routed HA key management and external KMS providers are not implemented. | Partial operational parity; see [Secret API](configmap-secret-api.md) |
| Audit policy/logging | k3s can pass through Kubernetes audit policy and log configuration. gr8s has no durable Kubernetes audit-event pipeline or operator audit policy; admission audit annotations currently go only to the process log. | Security/operations gap (`podster-9fi4`) |

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

The next audit should begin with a fresh certified-conformance result, update
`CONFORMANCE.md`, reconcile stale open beads against the tested binary, and then
revise this document from measured failures rather than inferred surface area.
