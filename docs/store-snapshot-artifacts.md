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
unspecified. History retains its existing newest-first order. The default record
limit is 16 MiB of UTF-8 JSON, enforced before writer publication and while reading.
JSON parsing also limits strings to 2 MiB and nesting to 128 levels.

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

`gr8s.resources::map-store-snapshot-records` reads one bounded record at a time.
Pass `nil` as its callback for a validation pass, with `:expected-index` and
`:expected-term` to bind the artifact to a Raft snapshot. It requires a header,
clocks, newline-terminated data records and a final record with the exact count;
truncated, oversized, unknown or trailing data is rejected. It checks individual
resource identities/revisions, Pod parsing/checkpoints/publications, Node parsing,
controller record shape and history fields. Pod UIDs and Node IDs must be safe
basenames for the existing durable layout.

Callbacks receive provisional records, including the header, clocks and trailer.
They may populate a staging destination; successful callbacks alone do not prove
that the complete artifact is valid. Do not mutate the live store during this
pass. Cross-record checks, including duplicate identities, Node claim uniqueness
and custom resources' CRD relationships, still belong to the pending staged restore
implementation. Checksums and durable generation publication are also pending.
The reader returns header, clocks and count without collecting the data records.
The [reader validation record](store-snapshot-reader-validation-2026-11-09.json)
covers malformed artifacts and constrained-heap capture plus validation.

Run the capture and reader tests with the `store-snapshot` FiveAM suite. For the memory probe:

```sh
sbcl --dynamic-space-size 384 --noinform --non-interactive \
  --load scripts/test-store-snapshot-memory.lisp
```

The default probe captures and validates the artifact while keeping the source
store resident. `GR8S_SNAPSHOT_RECORDS` controls the number of 64 KiB resource payloads. Setting
`GR8S_SNAPSHOT_LEGACY=1` selects whole-state JSON materialization for comparison.
The [validation record](store-snapshot-artifact-validation-2026-11-09.json)
distinguishes capture evidence from the remaining restore and transport work.
