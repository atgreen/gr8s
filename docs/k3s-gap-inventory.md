<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Functional gaps relative to Kubernetes and k3s

This is a difference-only inventory as of 2026-11-08. It is not a feature
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

## Required Kubernetes parity gaps

| Area | Current difference | Evidence / tracking |
|---|---|---|
| Conformance | No current build has passed the certified-conformance suite. The checked-in ledger's newest full result is round 4 at 64/446 tests; it predates substantial current functionality, so it is evidence of neither current failure counts nor current parity. A fresh run is required before making a conformance claim. | [Conformance ledger](CONFORMANCE.md); documentation refresh `podster-9do` |
| IP families | Allocated Pod and Service networking is IPv4-only. `PreferDualStack` is accepted but produces a single IPv4 family; `RequireDualStack` and IPv6-only Services are refused. IPv6 DNS enforcement is deferred with IPv6 Pod networking. | [Services](networking.md#services--load-balancing); `tests/services-test.lisp`; `podster-n2iv`; `podster-yge` |
| Dynamic Resource Allocation | The APIs exist, Pod/container claim references are validated, and direct or template-generated claims constrain scheduling and are reserved for the selected Pod. The scheduler can allocate unallocated ExactCount, All, and prioritized FirstAvailable requests from complete current-generation ResourceSlice pools, including DeviceClass/request CEL selectors, slice- or device-level node selection, class/claim allocation configuration, and `matchAttribute` and `distinctAttribute` constraints. Nodes discover DRA v1 plugins, prepare and durably checkpoint claims, pass driver-returned CDI devices to CRI containers, and unprepare after the final Pod is deleted. Taints, admin access, capacity and multiple-allocation semantics remain missing. | `src/resources/typed-apis.lisp`; `src/controllers/resource-claim-controller.lisp`; `src/controllers/scheduler.lisp`; `src/kubelet/dra-node.lisp`; `podster-08qi` |

Registry credentials and resource metrics are no longer gaps. Pod and
ServiceAccount `imagePullSecrets`, node-wide Docker credential files, and
kubelet v1 executable credential providers are implemented. gr8s also serves
`metrics.k8s.io/v1beta1` natively for NodeMetrics, PodMetrics, `kubectl top`, and
dashboard CPU/MEM without a metrics-server deployment.

## Most material product gaps

These are not all Kubernetes API-surface gaps, but they are more material to a
real k3s replacement than several missing optional APIs. The ordering answers
"what most limits safe production use today?", not "what is the largest amount
of code?":

| Priority | Gap | Why it is material | Tracking |
|---|---|---|---|
| P0 | Control-plane memory safety | Serializing the complete core-state blob has exhausted the SBCL heap and terminated `serve` under memory pressure. This is a demonstrated availability defect in the persistence/replication path, not merely a scaling optimization. The disconnected-follower AppendEntries OOM has a focused queue-coalescing fix, but still needs live HA revalidation before that incident is considered closed. | `podster-061`; `podster-8r7`; per-key replication `podster-bwu.2` |
| P1 | Backup and restore | Internal Raft snapshots are not an operator recovery workflow. There is no supported, tested way to capture and restore the datastore together with the cluster identity, encryption material, and signing keys, nor scheduled retention and remote-copy support. Until this exists, a cluster cannot be treated as recoverable. | `podster-oime` |
| P1 | Secrets at rest | Kubernetes Secret values are persisted without encryption. A stolen state directory or backup therefore exposes workload credentials, and there is no staged key-rotation or re-encryption workflow. | `podster-dcge`; [Secret API](configmap-secret-api.md) |
| P1 | HA state and failover consistency | Image tracker leases/swarms are not yet consistent across control-plane members, and a follower can lose its node-heartbeat monitor after a rejected consensus write. Pod replication also retains a narrower leader-crash-before-commit window. These can surface as stale availability or incorrect failover behavior. | `podster-i5vx`; `podster-7ni6.3.5`; `podster-bwu.1` |
| P1 | Installation, upgrade, and certificate lifecycle | There is no k3s-like installer, persistent service configuration, controlled upgrade/uninstall path, or cluster-wide certificate expiry/rotation workflow. This is the largest day-zero/day-two usability gap once data recovery is separated out. | `podster-7g65`; `podster-6l63` |
| P1 | IPv6 and dual-stack networking | IPv4-only networking excludes IPv6-only sites and does not honor portable `RequireDualStack` workloads. k3s supports both dual-stack and IPv6-only clusters, so this is a concrete portability and deployment gap. | `podster-n2iv` |
| P2 | Complete DRA workload lifecycle | Direct and template-generated claims participate in placement and reservation, including CEL-selected structured allocation, per-device placement, class/claim configuration, cross-request attribute constraints, and constraint-aware FirstAvailable fallback. The node lifecycle now includes plugin registration, prepare/unprepare, restart-safe checkpointing, and CDI injection. Remaining structured-allocation semantics and real external-driver acceptance still block a complete DRA claim, but affect fewer ordinary clusters than the P1 items above. | `podster-08qi` |
| P2 | Control-plane operational telemetry | gr8s already exports Kubernetes-compatible API-server, scheduler, kubelet/resource, DNS, Gateway, process, and eBPF endpoint metrics. It does not yet expose the Raft health, SBCL heap/GC pressure, datastore growth, disk/inode pressure, and reconciliation convergence signals needed to diagnose its distinctive failure modes. k3s exposes embedded Kubernetes-component, runtime, supervisor, and datastore metrics through its supervisor endpoint. | `podster-gmx`; especially `podster-gmx.1` through `.5` |
| P2 | Managed AddOns and Helm lifecycle | gr8s has intentional in-process replacements for the ordinary default components, but no general declarative manifests directory, AddOn status model, or HelmChart lifecycle for operator-supplied components. | `podster-pve3` |
| P2 | Kubernetes audit policy and durable audit log | Admission audit annotations reach process logs, but there is no policy-selected, structured, retained Kubernetes audit trail suitable for security review. | `podster-9fi4` |

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
| Install/service lifecycle | k3s provides an installer, persistent config files/drop-ins, system service management, uninstall/killall tooling, and upgrade workflows. gr8s currently documents a manual build and direct process invocation. | Distribution gap (`podster-7g65`) |
| Datastore backup/restore | k3s documents SQLite copies and embedded-etcd snapshots, including S3 workflows. gr8s Raft has internal snapshots/compaction but no documented operator backup, restore, scheduled snapshot, or remote snapshot workflow. | Operational gap (`podster-oime`) |
| Certificate operations | k3s exposes certificate status and leaf/CA rotation commands and restart-time renewal. gr8s documents automatic Raft-member renewal but no cluster-wide certificate inventory and rotation workflow. | Operational gap (`podster-6l63`) |
| Secrets at rest | k3s supports configurable secrets encryption and key rotation. gr8s persists Secret values without an equivalent encryption-at-rest or key-rotation facility. | Security/operations gap (`podster-dcge`) |
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
