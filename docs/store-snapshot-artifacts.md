# Production store snapshot artifacts

The internal artifact writer captures application records without constructing a
whole-store JSON string, byte vector, or Lisp snapshot. It is a foundation for Raft
snapshot integration; production transport, durable restore and automatic
compaction are still tracked by `podster-ucm.11.3`. This is not an operator backup
command.

`gr8s.resources::capture-store-snapshot` takes a store, a new destination pathname,
and the Raft applied index and term. Its caller must hold the member lock and
supply the exact applied boundary. The writer takes the raw store lock, so it sees
committed records rather than a speculative transaction. It rejects calls from
inside a speculative store transaction. Holding these locks while writing is a
current latency limitation to address in production capture scheduling.

The artifact is UTF-8 JSON Lines, version 1. Each line is serialized directly to
the file stream. Extra serialization memory depends on the current record rather
than the combined payload of all resources. Resource and Node iteration order is
unspecified. History retains its existing newest-first order.

| Record kind | Contents |
|---|---|
| `header` | Format name `gr8s-store-snapshot`, version, applied index and term |
| `clocks` | Resource and Pod/Node revisions, resource history start, history floor and shared template token key |
| `resource` | Collection, namespace, name and one built-in or custom resource |
| `workloadDeletion` | One controller deletion-state key and value |
| `jobControllerState` | One Job controller-state key and value |
| `history` | One retained resource history entry |
| `pod` | Desired object, observation/condition/finalization checkpoint and published status/revision |
| `node` | One Node record, including replicated runtime health |
| `end` | Count of preceding records |

Local Events and their history are excluded. The writer enumerates store indexes;
it does not recursively copy directories or include member-private PKI, Raft WAL,
transfer scratch, or arbitrary files. Kubernetes Secret resources and the shared
template token key are application state and are included. Cluster identity and
other shared signing credentials require the separate enrollment/recovery
integration; this artifact alone cannot restore a cluster's identity.

The file is created privately with mode `0600`. Publication synchronizes the file,
uses Linux `renameat2(RENAME_NOREPLACE)` to preserve any existing destination, and
synchronizes the containing directory. Serialization failures remove the private
temporary file and leave the destination absent. A directory synchronization error
can leave a complete published file but returns an error; no Raft descriptor has
been published by this helper. Durable generation ownership, checksums, restore
intent, interrupted-install recovery and reclamation belong to the pending
integration.

Run the writer tests with the `store-snapshot` FiveAM suite. For the memory probe:

```sh
sbcl --dynamic-space-size 384 --noinform --non-interactive \
  --load scripts/test-store-snapshot-memory.lisp
```

`GR8S_SNAPSHOT_RECORDS` controls the number of 64 KiB resource payloads. Setting
`GR8S_SNAPSHOT_LEGACY=1` selects whole-state JSON materialization for comparison.
The [validation record](store-snapshot-artifact-validation-2026-11-09.json)
distinguishes capture evidence from the remaining restore and transport work.
