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
pass. The higher-level `gr8s.resources::validate-store-snapshot` also checks
cross-record identities and relationships; use it before completing a staged
generation. Artifact checksum verification and durable restore remain pending.
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

## Application generation selection

Application paths now use `gr8s.store:store-data-path`. With no selector, this is
exactly the legacy member root. `pod-store-path` continues to identify the stable
member root for PKI, signing keys, issuer records and Raft state.

| Data | Location after generation selection |
|---|---|
| Desired Pods, Nodes and observation checkpoints | Selected application generation |
| Core checkpoint/journal and Pod/Node revision files | Selected application generation |
| PKI and ServiceAccount private signing key | Stable member root |
| Server-owned credential issuer records | Stable member root |
| Raft WAL, transfer scratch and snapshot artifacts | Stable member root |

A generation lives under `application-generations/<UUID>/` in a private owned
`0700` namespace. Its `generation.meta` completion marker records the version,
UUID, originating snapshot index/term and artifact SHA-256. This is an origin
marker, not the latest applied Raft index: the selected application files continue
to change as commands commit. The marker is immutable and its filename is outside
the desired Pod `*.json` scan.

The private `metadata/application-generation.json` selector must match the complete
marker exactly. Startup resolves and validates it before loading any application
files. Invalid selectors, mismatched boundaries/digests, linked metadata,
nonregular or oversized descriptors, public generation directories and unsafe
identities fail closed. Legacy stores need no migration or selector.

The internal generation helpers create staging directories, publish completion
metadata and select complete generations. The caller must first validate and
synchronize every staged file and subdirectory, quiesce the member, manage restore
intent, and reload the live indexes. Selection does not change an existing store
object's indexes or application root. These helpers are not a live restore command;
staged artifact materialization, crash recovery and Raft integration remain under
`podster-ucm.11.3.3`.

Metadata publication synchronizes its private temporary file, renames it, then
synchronizes the parent directory. Failure before rename preserves the prior
selector. Failure after rename reports uncertainty: the new selector may already
be visible, and neither completed generation is removed or rolled back. Power-loss
recovery must inspect the durable selection and restore intent. Generation garbage
collection is not enabled.

The [generation selection validation](store-generation-validation-2026-11-09.json)
covers reopen, write routing, credential preservation, publication failures and
native startup/restart with a prebuilt generation. Reproduce the native check with
`python3 scripts/test-store-generation-native.py --gr8s build/gr8s`.

## Snapshot-wide validation

`gr8s.resources::validate-store-snapshot` accepts the artifact pathname and optional
`:expected-index`, `:expected-term`, `:max-record-bytes`, and `:function` staging
callback. It returns the same header, clocks and count as the record reader. The
callback receives provisional records; the final `end` callback is delivered only
after the complete artifact passes validation. No callback may mutate live state.

This pass rejects duplicate resource keys, Pod UIDs or namespace/name pairs, Node
IDs or names, and controller-map keys. Node underlay addresses are canonicalized
for identity checks, WireGuard public keys must be canonical 32-byte encodings,
and Pod CIDRs cannot overlap, including IPv6 spelling aliases and either order
of nested networks. CIDR lookup costs at most the address width per claim.

Custom objects may precede their definitions. After reading the entire artifact,
the validator checks each distinct custom collection/kind/version/scope against
its CRD descriptor. Missing definitions, conflicting collection mappings, invalid
storage-version counts, mismatched CRD names and mismatched object shapes fail.
This is a restore consistency check, not a rerun of admission or conversion
webhooks. It does not retain CRD schemas or application payloads.

The validator retains identity indexes proportional to object count, small CRD
descriptors and distinct custom-object shapes. Record parsing remains bounded by
the configured record limit. The constrained-heap probe now exercises this full
validation pass with the source store still resident. The `store-snapshot-index`
FiveAM suite covers these cross-record checks. The [validation evidence](store-snapshot-index-validation-2026-11-09.json)
records the focused suites and constrained-heap probe. Artifact materialization, durable
restore intent, live reload and Raft/WAL coordination remain the next integration
work; this validator does not select or restore a generation.
