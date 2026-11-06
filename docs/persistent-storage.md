# Persistent storage

## What works out of the box

| Volume | How to use it | Sharing | Reclaim |
|---|---|---|---|
| Node-local directory | Default class `local-path`, or a class using `gr8s.io/local-path` | One node | `Delete` or `Retain` |
| NFS, dynamic | A class using `gr8s.io/nfs` | Many nodes | `Delete` or `Retain`, or `onDelete: archive` |
| NFS, static | A PV or Pod with an `nfs` source | Many nodes | `Retain` |
| `local` and `hostPath` | A PV or Pod with that source | One node | `Retain` |
| `emptyDir` | A Pod volume, on disk or `medium: Memory` | One Pod | Removed with the Pod |
| Generic ephemeral | A Pod `ephemeral` volume using any dynamic class | One Pod | Removed with the Pod |
| CSI | A driver you install, as a PV or an inline Pod volume | Set by the driver | Set by the driver |
| OCI image | A Pod `image` volume | One Pod, read-only | Unmounted with the Pod |

No helper Pod, image or NFS client package is needed for the built-in kinds.

PV and PVC `v1` and the `storage.k8s.io/v1` StorageClass, VolumeAttributesClass,
CSIDriver, CSINode, VolumeAttachment and CSIStorageCapacity APIs support durable CRUD,
JSON/merge/strategic patches, optimistic resource versions, selectors, paginated
lists, JSON watches and typed Kubernetes protobuf requests. PV, PVC, CSINode and
VolumeAttachment status subresources preserve specification fields. CSINode
`status.storageHealth` is dropped, as Kubernetes does while its alpha
`CSIVolumeHealth` gate is off. A VolumeAttributesClass carries the
`kubernetes.io/vac-protection` finalizer, which holds its deletion while a PV or PVC
names it. gr8s doesn't yet act on a claim's `volumeAttributesClassName`.

## Volume statistics

The kubelet `/metrics` endpoint reports `kubelet_volume_stats_capacity_bytes`,
`_available_bytes`, `_used_bytes`, `_inodes`, `_inodes_free` and `_inodes_used` for
each claim a running container mounts, labelled by `namespace` and
`persistentvolumeclaim`, as the Persistent Volumes dashboard expects. Each is
measured with `statvfs(3)` on the mounted path, as the kubelet does for local and
NFS volumes. Two things differ from Kubernetes:

- **Whole filesystem:** a `local-path` or `hostPath` directory reports its whole
  filesystem, because its capacity isn't enforced. The kubelet reports nothing for
  `hostPath`.
- **CSI:** a CSI volume is measured at its published path, rather than through the
  driver's `NodeGetVolumeStats`.

The record of each mounted claim is kept with the Pod's volumes, so it survives an agent restart.

## Node-local volumes

`gr8s serve` creates the default `local-path` class once, using
`WaitForFirstConsumer` and `Delete`. Deleting the class is respected on later
starts. `--local-storage-path DIR` sets its directory, which defaults to
`/var/lib/gr8s/storage`, and a class can set its own with the `path` parameter.

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast
provisioner: gr8s.io/local-path
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
parameters:
  path: /mnt/ssd/volumes
```

A claim gets a `pvc-<uid>` directory on the node its first consumer is scheduled
to, and its Pods stay on that node. The agent creates the directory with mode
`0777`, so a workload can run as any user. `ReadWriteMany` and `ReadOnlyMany`
claims stay Pending, because one node's directory can't serve other nodes.

## NFS

An existing share can be used directly from a PV or a Pod:

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: media
spec:
  capacity:
    storage: 100Gi
  accessModes: [ReadWriteMany]
  mountOptions: [nconnect=4, noatime]
  nfs:
    server: nas.example.test
    path: /export/media
```

For a directory per claim, use a dynamic class. `server` and `share` are required,
and `onDelete` is `delete` (the default), `retain` or `archive`, which renames the
directory to `archived-<name>`:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: shared
provisioner: gr8s.io/nfs
allowVolumeExpansion: true
mountOptions: [hard, nconnect=4]
parameters:
  server: nas.example.test
  share: /export/k8s
  onDelete: delete
```

The agent mounts through `mount(2)`, so hosts need the kernel NFS client but not
`mount.nfs` or `nfs-common`:

- **Versions:** it tries NFSv4.2, 4.1, 4.0 and then NFSv3 unless `vers` or `nfsvers`
  is set, as `mount.nfs` does. NFSv4 moves on to NFSv3 when the path isn't found,
  which happens with a Linux server exporting it with `fsid=0`.
- **NFSv3:** this defaults to `nolock`, because `rpc.statd` isn't assumed. Add the
  `lock` option only if the host runs it. NFSv4 has no such limit.
- **Server names:** these are resolved by the host, so a cluster Service name or
  ClusterIP won't work as a server.
- **Mount options:** unknown options are rejected when the object is created.
  `nosuid` and `nodev` are always set.
- **Dead servers:** each mount call waits up to five seconds and then keeps going in
  the background, so a dead server holds up only the Pods that use it. On Pod
  deletion, a blocked unmount is forced and detached.

Each Pod gets its own mount, removed when the Pod ends.

## Reclaim

A provisioned volume is released when its claim is deleted and no running Pod uses
it. With `Delete`, the control plane asks an agent to remove the directory, then
deletes the PV. A failure is retried with a delay that doubles from 1 second to 5
minutes, for example while the volume's node is down. Removal never follows symbolic
links or crosses into another filesystem, and only touches a `pvc-*` directory
matching the PV's name.

Deletions run in lanes: one for local disks, with 4 at a time on each node, and one
for each NFS server, with 2 at a time. A call to a dead NFS server can block
indefinitely and can't be cancelled, so lanes keep it from holding up local volumes
or other servers. The control plane never waits on an agent, and keeps at most 8
requests outstanding per node and lane. A request stays outstanding until the agent
answers or its session ends, and the agent runs each volume's deletion only once.
After a failed NFS deletion, the next attempt goes to another Ready node if there is
one, which helps when a single node can't reach the share. It can't help with a call
that hangs rather than fails, because that request stays outstanding.

To see what reclaim is doing, use `kubectl describe pv` or these metrics on `/metrics`:

| Report | Meaning |
|---|---|
| `VolumeFailedDelete` Warning event | An attempt failed, and says when the next one is |
| `VolumeReclaimStalled` Warning event | A request has gone 5 minutes unanswered. It's reported once per request and not retried, because the agent may still be working. |
| `gr8s_volume_reclaim_failures_total` | Failed attempts since this control plane started |
| `gr8s_volume_reclaim_waiting` | Released volumes with no request outstanding |
| `gr8s_volume_reclaim_outstanding{node,lane}` | Requests awaiting an answer |
| `gr8s_volume_reclaim_oldest_outstanding_seconds` | Age of the oldest of those requests |

The PV stays `Released` during retries, unlike upstream's built-in deleters, which
move it to `Failed`.

`Retain` keeps the data and the old claim UID, so a new claim with the same name
can't take it over. An administrator must clear the PV's `claimRef` to reuse it.
A static PV with `Delete` or `Recycle` becomes `Failed` with `ReclaimUnsupported`,
and its data is kept.

## Expansion and capacity

A bound claim can grow only if its class sets `allowVolumeExpansion`, and it can
never shrink. For the built-in provisioners, growth updates the recorded capacity.

**Capacity isn't enforced for `local-path` or NFS:** a volume can outgrow its
request until the disk or share is full. k3s's local-path provisioner has the same
limit. Treat these sizes as requests rather than quotas.

## emptyDir and generic ephemeral volumes

A disk-backed `emptyDir` may set `sizeLimit`. The node measures usage every ten
seconds and evicts a Pod that exceeds it. A `medium: Memory` volume is a tmpfs
sized by the smaller of `sizeLimit` and the Pod's total memory limit.

A generic ephemeral volume is a PV-backed scratch space. gr8s creates a claim called
`<pod>-<volume>`, owned by the Pod, and it's deleted with the Pod, which also
reclaims its volume under a `Delete` class. An existing claim with that name is
never adopted: the Pod fails to start with an error instead.

## OCI image volumes

A Pod can mount the contents of a container image read-only, which suits models,
datasets and config that ship separately from the application:

```yaml
volumes:
- name: model
  image:
    reference: registry.example.test/models/small:v2
    pullPolicy: IfNotPresent
```

- **Pull policy:** as for a container image, this defaults to `Always` for an
  untagged or `:latest` image and `IfNotPresent` otherwise.
- **Pulling:** the image is pulled only if a container mounts the volume. Until it
  arrives the container waits, and a failed pull is reported as `ErrImagePull` and
  retried, without using up a restart.
- **`subPath` and `subPathExpr`:** these select a directory inside the image. The
  container fails to start if it isn't there.
- **Private registries:** the Pod's `imagePullSecrets` apply to these pulls, as they
  do for its containers.

## CSI

Install a driver with its usual manifests, using its sidecars. gr8s plays the
kubelet's part and the Kubernetes controllers' part:

- **Registration:** the agent watches `/var/lib/kubelet/plugins_registry`, which
  `node-driver-registrar` uses, and publishes a CSINode object for each node.
- **Provisioning:** claims of a class with a third-party provisioner get the
  annotations `external-provisioner` watches for, including the selected node for
  `WaitForFirstConsumer`. It creates the PV, which then binds as normal.
- **Attaching:** gr8s creates a VolumeAttachment for `external-attacher` and waits
  for `status.attached`. A CSIDriver with `attachRequired: false` skips this, and
  as in Kubernetes, a driver with no CSIDriver object is assumed to need it.
- **Mounting:** the agent calls `NodeStageVolume` and `NodePublishVolume` at the
  kubelet's own paths, then unpublishes when the Pod ends. It unstages when the last
  Pod on the node stops using the volume.
- **Inline volumes:** a Pod `csi` volume needs a CSIDriver listing `Ephemeral`.

`mountPropagation` is supported on volume mounts, and `Bidirectional` needs a
privileged container, as upstream requires. `/var/lib/kubelet` must be on a shared
mount, which is the systemd default. Leases are served for sidecar leader election.

Not implemented yet: `NodeExpandVolume`, `NodeGetVolumeStats`, raw block volumes, `fsGroup`
delegation, service account tokens for drivers and Node topology labels. Snapshot
and clone data sources are passed through to `external-provisioner`, but gr8s
doesn't serve the snapshot APIs, which come from a driver's own CRDs.

## Binding and protection

The controller matches capacity, access modes, class, selector, node affinity and
claim identity, preferring an existing PV over provisioning. Binding commits both
objects atomically and persists the exact claim UID. `WaitForFirstConsumer` waits
for a consumer on a compatible node, and class topology and PV node affinity
constrain scheduling. `ReadWriteOnce` consumers must share a node, and
`ReadWriteOncePod` allows one consumer.

Binding reserves storage; it doesn't assert that a node mounted it. Sources the
agent can't mount can still bind, and then the Pod reports the mount failure. Read
`Bound` with that in mind for raw block volumes and other unsupported PV sources.

A static `hostPath` PV without node affinity has one directory per node. A
replacement Pod on another node sees a different directory, and with
`DirectoryOrCreate` that directory is silently empty, so set node affinity.

PVC protection retains a deleting claim while nonterminal Pods reference it, and PV
protection retains a deleting volume while its exact claimant exists. Additional
user finalizers remain in effect. `subPath` and `subPathExpr` mounts are supported.

## Testing

Run these as root on a disposable Linux node with kubectl, as described in
`AGENTS.md`:

```sh
python3 scripts/test-storage-native.py --executable /path/to/gr8s
python3 scripts/test-storage-dynamic-native.py --executable /path/to/gr8s \
  --nfs-server 192.0.2.5 --nfs-share /export/k8s
```

The first passed on a VM on 2026-11-04: real local PV/PVC and direct hostPath writes,
read-only enforcement, restart preservation without restarting the consumer, claim
protection, Retain UID ownership, explicit reclamation and clean native exit.

**The dynamic, NFS, CSI and image volume paths have unit tests only so far.** They
run through injected mount and image calls and a fake driver, and haven't yet been
run against a real kernel NFS mount, a real CSI driver, real sidecars or containerd's
image mounts. The second script above covers the NFS and local-path half. Its
`--nfs-*` options are optional, and it needs a share the node can write to. For image
volumes, run the upstream `ImageVolume` spec with `scripts/test-podtemplates-sonobuoy.py`.
