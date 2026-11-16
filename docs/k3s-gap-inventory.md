# Kubernetes compatibility and operational reference

A Kubernetes gap in this inventory means missing or incompatible behavior that
upstream Kubernetes provides. Each gap should identify the upstream behavior and
the gr8s difference. Implementation details, validation coverage, and optional k3s
packaging workflows are documented separately. Reconciled with source and
committed records on 2026-11-16. For implemented APIs, see the
[API reference](kubernetes-surface.md);
for familiar component names, see [gr8s for Kubernetes users](kubernetes-users.md).

## Compatibility evidence

The recorded native two-node run passed all **462 upstream Kubernetes v1.37
`certified-conformance` cases** on 2026-11-11. gr8s has not been submitted for CNCF
certification. The [result and methodology](CONFORMANCE.md) identify the tested
build and configuration. Passing that selection does not cover every optional API,
external integration, topology, failure mode, or later build.

## Kubernetes behavior gaps

| Area | gr8s difference | Reference |
|---|---|---|
| CSI | Node expansion, driver volume statistics, raw block volumes, fsGroup delegation, and driver ServiceAccount tokens remain unsupported. | [Storage limits](persistent-storage.md#csi) |
| Owner-reference authorization | gr8s does not implement upstream `OwnerReferencesPermissionEnforcement`. | [Security behavior](security-deviations.md#no-owner-reference-permission-enforcement-c1) |
| Autoscaling | Kubernetes HPA can use custom/external metrics through installed providers. gr8s HPA implements Resource and ContainerResource metrics only. | [Upstream HPA](https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/), [gr8s metrics](kubernetes-surface.md#metrics--autoscaling) |
| Audit logging | Kubernetes supports audit Policy selection and Request/RequestResponse levels. gr8s provides an opt-in Metadata-level JSON sink without policy selection or managed retention/rotation. | [Upstream auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/), `--audit-log-path` |

## Validation coverage

| Area | Evidence scope | Reference |
|---|---|---|
| IPv6 / dual stack | Allocation, Pod networking, Service forwarding, and policy have implementation and focused coverage. Combined IPv6-only/dual-stack and focused upstream acceptance remain separate from the recorded two-node result. | [Networking](networking.md) |
| Storage integrations | Local PV/hostPath has native evidence. Dynamic local-path, NFS, CSI, and image-volume paths have unit coverage; the storage guide records real integration acceptance as outstanding. | [Storage evidence](persistent-storage.md#testing) |
| HA recovery | Native CLI recovery and compaction records use fake workloads with agents disabled. They identify tested recovery paths and topology. | [HA validation](high-availability.md#validation-coverage) |

An outstanding acceptance run tracks test coverage. Document a Kubernetes
behavior gap when a missing or incompatible outcome is identified.

Source support and historical test outcomes are different kinds of evidence.
An old missing-feature note does not override an implementation that has since
landed; an implementation alone does not prove acceptance of every workload.

## Operational reference

These entries describe how to operate gr8s and interpret its observations. Shared
Kubernetes behavior and differences in optional distribution tooling are not
classified as Kubernetes gaps here.

| Area | gr8s behavior | Reference and scope |
|---|---|---|
| HA and bounded recovery | Raft replication, learner admission, durable recovery, per-key transactions, streamed snapshots, and default-on automatic checkpoints | [Replication and recovery](high-availability.md#replication-and-recovery) explains the implementation; [validation coverage](high-availability.md#validation-coverage) identifies the tested scope. |
| Operator backup/restore | Offline `gr8s backup` (keygen/save/verify) and verify-then-publish `gr8s restore` over encrypted, authenticated bundles | No live capture from a running server yet, no scheduled retention, no remote/S3 lifecycle. Raft snapshots alone do not back up cluster identity and keys. See [backup and restore](backup-restore.md). |
| Telemetry | Lisp heap/GC, Raft/checkpoint, disk/inode, datastore growth, reconciliation, and Kubernetes-compatible metrics | Local sampled observations are not quorum health or an atomic cluster snapshot; alerts and capacity decisions must respect collector limits. See [control-plane metrics](control-plane-metrics.md) and [validation](https://github.com/atgreen/gr8s/blob/9928d73d274c0c4ad5adb889be2b2489d407e93c/docs/control-plane-telemetry-validation-2026-11-11.json). |
| Installation and upgrades | Checksum-pinned systemd installation, persisted configuration, upgrade rollback, scoped cleanup and uninstall | No channel-based automatic node-upgrade controller. See [installation](installing.md). |
| Certificates and Secrets | Leaf renewal/replacement, staged CA/ServiceAccount signer rotation, Secrets encryption and offline key rotation | External CA integration, external KMS, and leader-routed HA Secret-encryption key management remain outside documented support. See [certificates](certificate-management.md) and [Secrets](configmap-secret-api.md). |

gr8s remains experimental. The [historical engineering inventory](history/compatibility-review-2026-11-13.md)
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
| Arbitrary packaged AddOns / Helm lifecycle | No general manifests-directory/AddOn or HelmChart controller | k3s-specific workflow; not required by Kubernetes. Helm clients can use supported APIs. |

An integrated implementation still needs to produce the expected API outcome;
a different architecture does not excuse incompatible behavior.

k3s documents [datastore-specific backup and restore](https://docs.k3s.io/datastore/backup-restore).
gr8s owns its store instead of offering interchangeable external SQL/etcd backends,
and its current operator restore workflow is described above. For networking,
gr8s defaults to VXLAN with optional WireGuard; k3s also documents
[overlay and custom-CNI choices](https://docs.k3s.io/networking/basic-network-options).
gr8s supports explicit [external CNI mode](networking.md#cni-ipam--the-pod-gateway),
so alternative CNI integration should not be listed as wholly absent. Rootless
operation and a general cloud-provider integration are not documented workflows.

This is an inventory of documented differences, not an exhaustive ecosystem
compatibility certification or a performance comparison.
