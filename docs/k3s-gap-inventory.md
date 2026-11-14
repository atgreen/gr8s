# Compatibility and operational gaps

This inventory distinguishes Kubernetes behavior, operational readiness, and
intentional differences from k3s. Reconciled with source and committed records on
2026-11-14. For implemented APIs, see the [API reference](kubernetes-surface.md);
for familiar component names, see [gr8s for Kubernetes users](kubernetes-users.md).

## Compatibility evidence

The recorded native two-node run passed all **462 upstream Kubernetes v1.37
`certified-conformance` cases** on 2026-11-11. gr8s has not been submitted for CNCF
certification. The [result and methodology](CONFORMANCE.md) identify the tested
build and configuration. Passing that selection does not cover every optional API,
external integration, topology, failure mode, or later build.

| Area | Current boundary | Reference |
|---|---|---|
| IPv6 / dual stack | Allocation, Pod networking, Service forwarding, and policy have implementation and focused coverage. Combined IPv6-only/dual-stack and focused upstream acceptance remain separate from the recorded two-node result. | [Networking](networking.md) |
| Storage integrations | Local PV/hostPath has native evidence. Dynamic local-path, NFS, CSI, and image-volume paths have unit coverage; the storage guide still records real integration acceptance as outstanding. CSI expansion, driver volume stats, raw block, fsGroup delegation, and driver ServiceAccount tokens have explicit limits. | [Storage limits and evidence](persistent-storage.md) |
| Admission and authorization | Webhooks, CEL policies, controller admission, and RBAC are implemented. Deliberate security deviations remain, including owner-reference permission enforcement and egress exceptions for node/API/DNS traffic. | [API surface](kubernetes-surface.md), [security deviations](security-deviations.md) |
| Aggregated APIs | APIService discovery and proxying are implemented; aggregated OpenAPI is not merged for `kubectl explain`. | [API aggregation](kubernetes-surface.md#api-aggregation) |
| Autoscaling | HPA uses Resource and ContainerResource metrics; custom/external metric sources are unavailable. | [Metrics and autoscaling](kubernetes-surface.md#metrics--autoscaling) |

Source support and historical test outcomes are different kinds of evidence.
An old missing-feature note does not override an implementation that has since
landed; an implementation alone does not prove acceptance of every workload.

## Operational boundaries

| Area | Available now | Remaining boundary |
|---|---|---|
| HA and bounded recovery | Raft replication, learner admission, durable recovery, per-key transactions, streamed snapshots, and default-on automatic checkpoints | No general atomic transaction across all resource families. Focused recovery and constrained-heap results do not establish arbitrary crash safety, sustained availability, or cluster size. Follow [HA limits](high-availability.md#current-limits) and the run-specific evidence. |
| Operator backup/restore | Authenticated encrypted capture/verify primitives and state-bundle validation | No complete restore-to-live operator workflow, scheduled retention, or remote/S3 lifecycle. Raft snapshots alone do not back up cluster identity and keys. See [bundle evidence](https://github.com/atgreen/gr8s/blob/9928d73d274c0c4ad5adb889be2b2489d407e93c/docs/backup-bundle-validation-2026-11-11.json). |
| Telemetry | Lisp heap/GC, Raft/checkpoint, disk/inode, datastore growth, reconciliation, and Kubernetes-compatible metrics | Local sampled observations are not quorum health or an atomic cluster snapshot; alerts and capacity decisions must respect collector limits. See [control-plane metrics](control-plane-metrics.md) and [validation](https://github.com/atgreen/gr8s/blob/9928d73d274c0c4ad5adb889be2b2489d407e93c/docs/control-plane-telemetry-validation-2026-11-11.json). |
| Installation and upgrades | Checksum-pinned systemd installation, persisted configuration, upgrade rollback, scoped cleanup and uninstall | No channel-based automatic node-upgrade controller. See [installation](installing.md). |
| Certificates and Secrets | Leaf renewal/replacement, staged CA/ServiceAccount signer rotation, Secrets encryption and offline key rotation | External CA integration, external KMS, and leader-routed HA Secret-encryption key management remain outside documented support. See [certificates](certificate-management.md) and [Secrets](configmap-secret-api.md). |
| Audit logging | Opt-in Metadata-level `audit.k8s.io/v1` JSON sink via `--audit-log-path` | No audit Policy selection, Request/RequestResponse levels, or managed retention/rotation. |
| Live patches | Slynk inspection/evaluation and binary upgrade workflow | Signed managed patch rollouts are unavailable in this checkout; see [development boundary](development.md#live-patching-boundary). |

These limits explain why the project remains experimental despite the recorded
conformance pass. The [historical engineering inventory](history/compatibility-review-2026-11-13.md)
retains earlier investigations and issue IDs; it is not the current support matrix.
Use `bd ready` / `bd show` for live task status rather than inferring it from those IDs.

## How the k3s experience differs

k3s packages upstream Kubernetes components. Its documented
[AddOn mechanism](https://docs.k3s.io/installation/packaged-components) deploys
CoreDNS, Traefik, local storage, and metrics-server, and watches user manifests.
gr8s provides several of these responsibilities in process:

| Familiar outcome | gr8s mechanism | Classification |
|---|---|---|
| Cluster DNS | Embedded agent DNS | Intentional replacement |
| Ingress and Gateway routing | In-process controllers and agent proxies | Intentional replacement |
| Local-path storage | In-process provisioner | Intentional replacement |
| Resource metrics / `kubectl top` | Native `metrics.k8s.io` API | Intentional replacement |
| LoadBalancer Service ports | Node relays and eBPF forwarding | Intentional replacement |
| Arbitrary packaged AddOns / Helm lifecycle | No general manifests-directory/AddOn or HelmChart controller | Distribution gap; separate from running a Helm client against supported APIs |

An integrated implementation still needs to produce the expected API outcome;
a different architecture does not excuse incompatible behavior.

k3s documents [datastore-specific backup and restore](https://docs.k3s.io/datastore/backup-restore).
gr8s owns its store instead of offering interchangeable external SQL/etcd backends,
and its operator restore gap is listed above. For networking, gr8s defaults to
VXLAN with optional WireGuard; k3s also documents
[overlay and custom-CNI choices](https://docs.k3s.io/networking/basic-network-options).
gr8s supports explicit [external CNI mode](networking.md#cni-ipam--the-pod-gateway),
so alternative CNI integration should not be listed as wholly absent. Rootless
operation and a general cloud-provider integration are not documented workflows.

This is an inventory of documented differences, not an exhaustive ecosystem
compatibility certification or a performance comparison.
