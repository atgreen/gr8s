# Backup and restore

`gr8s backup` captures a control-plane state directory into one encrypted,
authenticated bundle, and `gr8s restore` rebuilds a state directory from it.
The bundle covers what Raft snapshots alone do not: cluster identity — the
cluster CA, the ServiceAccount signer, and Secret-encryption key state —
alongside the Raft store that holds every Kubernetes object.

Backups taken this way are **offline**: capture takes the same lock as
`gr8s serve`, so stop the server (or run on a stopped replica) first. Live
capture from a running server is planned on top of the store's frozen
snapshots.

## Workflow

```sh
# Once: create a private 32-byte key, stored as 64 hex characters, mode 0600.
gr8s backup keygen --key-file /root/gr8s-backup.key

# Capture. The server must be stopped; an existing output file is never
# overwritten. Prints the published path with file and byte counts.
systemctl stop gr8s-server
gr8s backup save --state-directory /var/lib/gr8s/server \
  --output /backups/cluster-$(date +%Y%m%d).gr8s-backup \
  --key-file /root/gr8s-backup.key
systemctl start gr8s-server

# Authenticate a bundle end to end without restoring it. Prints the release
# that wrote it, its creation time, and verified totals.
gr8s backup verify --input /backups/cluster-20261116.gr8s-backup \
  --key-file /root/gr8s-backup.key

# Rebuild a state directory. The target must not exist; nothing is published
# unless the whole bundle authenticates through its final marker.
gr8s restore --input /backups/cluster-20261116.gr8s-backup \
  --state-directory /var/lib/gr8s/server --key-file /root/gr8s-backup.key
```

Keep the key file with the same care as the state directory it unlocks: a
bundle is useless without it and readable with it. The key file must stay a
private regular file (no group/other access) or the commands refuse it.

## What a bundle contains

Everything under the state directory except reconstructible runtime trees
(`agent/containerd/`, `agent/runtime/`, `agent/pods/`, `containerd/`,
`raft/transfers/`) and lock files. The excluded names are recorded in the
bundle and checked again on verify and restore.

The format (`GR8SBK01`) encrypts every record with AES-256-GCM under a key
derived from your key file and a per-bundle salt. Frame counters are
authenticated, so a bundle cannot be reordered, truncated, or spliced
without detection; each member file additionally carries its SHA-256.
Capture refuses symlinks, hard links, and files that changed while being
read, and publishes the output atomically without overwriting.

## Restore semantics

Restore stages every file privately while the stream verifies, and only
renames the staged tree into place after the final authenticated marker,
counts, and digests all agree. A tampered, truncated, or wrongly keyed
bundle publishes nothing and leaves nothing behind. Restored files are
mode `0600` under `0700` directories, matching what `gr8s serve` expects.

After restoring on a new host, start the server against the restored
directory; agents reconnect once the control plane serves the same CA.
The directory holding backups and restore targets must itself be owned by
the caller and not group/other-writable.

## Relation to HA snapshots

Raft snapshots and automatic checkpoints (see
[high availability](high-availability.md)) are replication machinery, not
operator backups: they move application state between members but do not
carry cluster identity. A bundle restores a complete control plane;
snapshots restore a member's store. Validation evidence for the bundle
format is recorded in the
[bundle validation record](https://github.com/atgreen/gr8s/blob/9928d73d274c0c4ad5adb889be2b2489d407e93c/docs/backup-bundle-validation-2026-11-11.json).

## Disaster recovery: a quorum lost forever

An HA cluster that loses a majority of its voting members permanently —
hosts destroyed, a member's state directory wiped — cannot elect a leader,
so nothing commits: not application writes, and not the membership change
that would remove the dead voters. A restarted survivor blocks at

```
gr8s HA: waiting for committed application recovery
gr8s HA: waiting for a quorum: 2 of 2 voting members needed; ...
```

and the API never starts. The journal lines name each member and whether
it has been heard from since startup.

First check whether the survivors still hold a quorum: `gr8s member list`
marks members never heard from as ghosts, and while a quorum of live
voters remains, `gr8s member remove NAME` is the ordinary cure — no reset
needed (see [membership maintenance](high-availability.md#membership-maintenance)).

If the missing members are gone for good **and** the survivors cannot form
a quorum, reset the surviving member to a one-voter cluster:

```sh
# On the surviving voter, with gr8s stopped:
gr8s serve --state-directory /var/lib/gr8s/server --raft-init --cluster-reset ...
```

`--cluster-reset` rewrites the durable membership to the local member
alone, keeps every committed application entry and the retained snapshot
baseline, discards the uncommitted tail, and then continues serving as
the sole voter. It refuses to run with `--join`, and it is idempotent —
but remove the flag from the service arguments once the member is
healthy, or a later restart will silently evict any members you have
added since. Re-add replacement members afterwards with fresh
`gr8s join-token --role control-plane` tokens; a lost member's old name
may be reused once the reset has removed it.

Run the reset on a surviving **voter** (voters hold the Raft CA). If no
voter survived, restore the newest backup bundle instead — that is what
`gr8s backup` exists for.
