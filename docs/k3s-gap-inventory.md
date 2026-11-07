<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Functional gaps relative to Kubernetes and k3s

This is a difference-only inventory as of 2026-11-07. It is not a feature
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
| IP families | Allocated Pod and Service networking is IPv4-only. `PreferDualStack` is accepted but produces a single IPv4 family; `RequireDualStack` and IPv6-only Services are refused. IPv6 DNS enforcement is deferred with IPv6 Pod networking. | [Services](networking.md#services--load-balancing); `tests/services-test.lisp`; `podster-yge` |
| Registry credentials | Pod and ServiceAccount `imagePullSecrets` and node-wide Docker credential files work, but executable kubelet credential-provider plugins are absent. | [Config, identity and secrets](kubernetes-surface.md#config-identity--secrets) |
| Dynamic Resource Allocation | ResourceClaim and ResourceClaimTemplate storage APIs exist, but there is no allocator/controller that turns claims into device allocations. | `src/resources/typed-apis.lisp`; no ResourceClaim controller |
| Metrics APIs | gr8s serves `metrics.k8s.io/v1beta1` natively from per-node CRI/cgroup statistics, so NodeMetrics, PodMetrics, `kubectl top`, and dashboard CPU/MEM do not require metrics-server. A standalone `gr8s agent` does not yet serve kubelet metrics endpoints, and HPA has no custom or external metrics source. | [Metrics and autoscaling](kubernetes-surface.md#metrics--autoscaling) |

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
| Managed AddOn/manifests controller | There is no general manifests directory, AddOn resource/controller, or disable/uninstall lifecycle for packaged components. Runtime payload add-ons are a narrower mechanism. | Distribution gap |
| CoreDNS | gr8s embeds its own DNS server instead of deploying CoreDNS. Current source implements ordinary, headless, ExternalName, SRV, and reverse records; equivalence beyond covered behavior depends on a fresh conformance run. | Intentional replacement |
| Traefik Ingress | gr8s embeds its own Gateway/Ingress proxy instead of installing Traefik. `networking.k8s.io/v1` Ingress routes, TLS Secrets, status addresses, and listener lifecycle are reconciled directly by each agent. | Equivalent outcome; intentional replacement |
| local-path-provisioner | gr8s has an in-process default `local-path` provisioner rather than a provisioner Pod. | Equivalent outcome; intentional replacement |
| metrics-server | gr8s replaces the addon with an in-process `metrics.k8s.io/v1beta1` API backed by the same node summaries used for autoscaling. No metrics-server Pod, Service, or APIService is required for `kubectl top` or dashboard CPU/MEM. | Equivalent outcome; intentional replacement |
| ServiceLB | gr8s implements node relays and eBPF Service forwarding rather than Klipper ServiceLB Pods. It publishes ready node InternalIPs in `status.loadBalancer.ingress` with `ipMode: Proxy` and serves each LoadBalancer Service port on those addresses; `scripts/test-service-traffic.py` covers the native path. | Equivalent outcome; intentional replacement |
| Helm controller | No HelmChart/HelmChartConfig controller or equivalent packaged chart lifecycle is documented. | Distribution gap |
| Install/service lifecycle | k3s provides an installer, persistent config files/drop-ins, system service management, uninstall/killall tooling, and upgrade workflows. gr8s currently documents a manual build and direct process invocation. | Distribution gap |
| Datastore backup/restore | k3s documents SQLite copies and embedded-etcd snapshots, including S3 workflows. gr8s Raft has internal snapshots/compaction but no documented operator backup, restore, scheduled snapshot, or remote snapshot workflow. | Operational gap |
| Certificate operations | k3s exposes certificate status and leaf/CA rotation commands and restart-time renewal. gr8s documents automatic Raft-member renewal but no cluster-wide certificate inventory and rotation workflow. | Operational gap |
| Secrets at rest | k3s supports configurable secrets encryption and key rotation. No equivalent encryption-at-rest or key-rotation facility is documented or found in gr8s. | Security/operations gap |
| Audit policy/logging | k3s can pass through Kubernetes audit policy and log configuration. No Kubernetes audit-event pipeline or operator audit policy is documented for gr8s. | Security/operations gap |

The operational comparison is based on k3s's current primary documentation for
[installation](https://docs.k3s.io/installation),
[backup and restore](https://docs.k3s.io/datastore/backup-restore),
[certificate management](https://docs.k3s.io/cli/certificate), and
[secrets encryption](https://docs.k3s.io/security/secrets-encryption).

## Optional k3s features without a gr8s equivalent

These are not default-cluster blockers and should not be mixed into Kubernetes
conformance work.

- External SQL/etcd datastores. k3s supports SQLite by default and etcd, MySQL,
  and PostgreSQL alternatives; gr8s intentionally owns its Raft store.
- The opt-in Spegel distributed OCI registry mirror. gr8s can preload images and
  use registry credentials, but has no peer-to-peer registry mirror. See the
  [k3s registry-mirror documentation](https://docs.k3s.io/installation/registry-mirror).
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
