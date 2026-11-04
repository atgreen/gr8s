# Persistent storage

PV and PVC `v1` and StorageClass `storage.k8s.io/v1` APIs support durable CRUD,
JSON/merge/strategic patches, optimistic resource versions, selectors, paginated
lists, JSON watches and typed Kubernetes protobuf requests. PVs and StorageClasses
are cluster scoped; PVCs are namespace scoped. PV/PVC status subresources preserve
specification fields. Ordinary writes preserve controller-owned status.

The controller binds administrator-provided filesystem `hostPath` and `local`
PVs to matching claims. Capacity, access modes, class, selector, node affinity,
claim identity and reservations constrain selection. Binding commits both objects
atomically and persists the exact claim UID. `WaitForFirstConsumer` classes defer
allocation until a consumer has a compatible assigned node. Class topology and
PV node affinity constrain scheduling. RWO consumers must use the same node.

Native consumers receive the actual backing path through CRI bind mounts.
`local` sources require node affinity and an existing directory. `hostPath` type
checks run on the real node; directories/files are created only for the explicit
`DirectoryOrCreate`/`FileOrCreate` types. Direct Pod `hostPath` sources are also
supported. Pod PVC source `readOnly` and container `volumeMount.readOnly` produce read-only
mounts. Access modes constrain binding without changing these mount flags. A control
plane restart preserves healthy native consumers and existing backing data.

PVC protection retains a deleting claim while nonterminal Pods reference it.
PV protection retains a deleting volume while its exact claimant exists. Retain
leaves the backing data and old claim UID intact after claim deletion; creating
a new claim with the same name cannot take ownership. An administrator must
explicitly clear the old PV claim reference before reuse. Additional user
finalizers remain in effect.

CSI drivers, dynamic provisioners, raw block devices, `ReadWriteOncePod`, volume
mount options, snapshots/clones and automatic expansion are not implemented.
Unsupported sources/modes remain Pending and are never reported as successfully
mounted. A Delete or Recycle reclaim policy without a backend deleter becomes
Failed with `ReclaimUnsupported`; backing data is retained. Storing a
StorageClass does not install a provisioner. Server-side apply and `subPath`
mounts remain unsupported.

Run the native smoke as root in a disposable Linux node with kubectl available:

```sh
python3 scripts/test-storage-native.py --executable /path/to/gr8s.bin
```

The 2026-11-04 VM run passed real local PV/PVC and direct hostPath writes,
read-only enforcement, restart preservation without restarting the consumer,
claim protection, Retain UID ownership, explicit reclamation and clean native
exit with zero owned shims. Its isolated state directory was
`/tmp/gr8s-storage-native-mfmh70zs`. The host suite passed 1,993 checks with five
optional integration skips (1,998 total).
