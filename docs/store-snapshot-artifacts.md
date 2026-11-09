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
been published by this helper. Private generation ownership and checksum verification are handled by the
materializer described below. Live restore intent, interrupted-install recovery
and reclamation remain pending.

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
generation. The materializer verifies the artifact checksum; live restore remains pending.
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
| Desired Pods, Nodes, observation and publication checkpoints | Selected application generation |
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
live restore, crash recovery and Raft integration remain under
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
records the focused suites and constrained-heap probe. The materializer below
consumes validated records. Coordination of restore intent with live reload and
Raft/WAL recovery remains pending; this validator does not select or restore a generation.

## Durable Pod publications

Pod observation checkpoints describe what the runtime reported. The API's last
published status and revision are stored separately in private
`publications/<UID>.json` files under the application data root. A version-1
publication contains the Pod UID, namespace/name, desired resourceVersion,
published resourceVersion and status. Snapshot materialization must restore both
observation and publication records; writing desired Pods and observations alone
would lose the captured API view on restart.

Status and specification publication paths write these records, including Raft
application and idempotent retries. Speculative HA transactions only stage their
changes. A publication file is written privately, synchronized, atomically renamed
and followed by directory synchronization before its watch event is announced.
A pre-publication write failure leaves the previous published status and watch
journal unchanged for a local status update. A failure after rename can leave the
new file visible and must be treated as uncertain, as with generation selection.
This is per-file durability, not an atomic transaction across Pod desired state,
observations and Raft metadata; production WAL recovery remains required.

Startup restores matching UID and desired revisions after loading revision clocks.
Obsolete publications are ignored, so a stale checkpoint cannot apply to a new
Pod or desired revision. Malformed, linked, nonprivate or oversized files and a
matching publication beyond the durable revision clock fail startup. Parsing is
bounded by a 16 MiB file size, 2 MiB strings and depth 128. Older stores without
publication files remain readable. Normal Pod deletion removes its publication.

Run the `pod-publications` FiveAM suite for restart, consensus application,
specification changes, deletion, stale records, unsafe links and write-failure
coverage. The [publication validation evidence](pod-publication-validation-2026-11-09.json)
includes a native API status/revision round trip across process restart, broader
watch/status/failover checks and the constrained-heap probe. The materializer
restores publication files; live restore intent remains pending.

## Materializing a completed generation

`gr8s.resources::materialize-store-snapshot` takes the existing member root, source
artifact pathname and expected lowercase SHA-256. Optional `:expected-index` and
`:expected-term` bind the header to the caller's Raft descriptor; `:generation-id`
can supply a fresh UUID. It returns the completed generation pathname, its
completion descriptor and the artifact record count. It never changes the active
selector or an existing store object's indexes. This is an internal staging
operation, not an operator backup/restore command.

The materializer first copies a regular, non-symlink source through a 64 KiB
buffer into the private pending generation and hashes the exact bytes copied.
Changes to the source size or a digest mismatch fail. Validation and application
file generation then read only that private copy, so later changes to the caller's
pathname cannot substitute a different artifact.

Pod desired objects, observation checkpoints, API publications and Node records
are written individually. Observations omit absent optional fields to remain
compatible with the existing checkpoint loader. Core resources, custom resources,
controller maps and retained history are streamed into temporary fragments. After
snapshot-wide validation succeeds, these fragments are copied through a fixed
character buffer into the ordinary core checkpoint format. No combined resource
array, whole-store JSON string or second live application index is constructed.
The identity validation index still grows with object count.

The materializer preserves resource/Pod revisions, retained history floors and the
shared template token key. Pod and Node watches restart at the captured committed
clock because their transient journals are not included. Local Events remain
excluded. Stable member credentials, signing keys, PKI and Raft files are neither
copied nor changed.

Every resulting payload file is private and synchronized. Temporary fragments and
the private artifact copy are removed, affected directories are synchronized, and
only then is the immutable completion marker published. A failure before this
last step leaves an incomplete, unselectable generation for diagnostics. Retry
with a fresh UUID; automatic reclamation of incomplete generations remains pending.
A completion-marker directory synchronization failure may leave the fully
validated marker visible even though the call reports an error. The active
selector is unchanged in every case.

Run the `store-snapshot-materialize` FiveAM suite for round-trip and failure tests.
The [materialization evidence](store-snapshot-materialization-validation-2026-11-09.json)
records round-trip/failure coverage and the heap result, including its cold-compilation
setup limitation. To include materialization in the constrained-heap probe:

```sh
GR8S_SNAPSHOT_MATERIALIZE=1 sbcl --dynamic-space-size 384 \
  --noinform --non-interactive --load scripts/test-store-snapshot-memory.lisp
```

The startup intent protocol below handles interrupted application selection. Atomic
live selection/reload, production WAL integration, full interrupted-install recovery
and automatic compaction remain separate required work.

## Recovering an interrupted application selection

`gr8s.store::begin-store-restore` takes a member root and a completed generation
UUID. It synchronizes a private `metadata/application-restore.json` intent naming
the exact target descriptor. Calling it again for the same target is idempotent;
a different pending target is rejected. The caller must first quiesce live access
and coordinate the member's applied/WAL boundary. Beginning an intent does not
change the selector or an existing store object's application indexes.

`open-store` checks for an intent before loading any application files. It verifies
that the target still has its matching completion marker, publishes the target
selector, and loads that generation's application state and clocks. Only after
loading succeeds does it unlink the intent and synchronize the metadata directory.
Invalid intents or a failed reload stop startup instead of exposing the old data.
A later startup retries the same target; an intent is never rolled back to an old
generation. Selection helpers reject targets that conflict with a pending intent.

These operations use the same bounded, owned, mode-0600 metadata format and
no-symlink validation as generation selection. A directory synchronization failure
after a rename or unlink reports uncertainty: publication or removal may already
be visible. A retained intent is resumed on the next open; an already removed
intent leaves the complete selected generation in place. `finish-store-restore`
can be retried after a successful reload, but refuses to acknowledge an existing
store object still pointing at another generation.

The `store-restore-intent` suite exercises selection, reload and metadata failure
boundaries. The [restore intent evidence](store-restore-intent-validation-2026-11-09.json)
records the focused checks, native pending-intent startup and heap probe. The native probe accepts `--pending-restore` to seed an intent instead
of a selector, then checks startup recovery and the next process restart:

```sh
python3 scripts/test-store-generation-native.py --gr8s build/gr8s --pending-restore
```

This acknowledges application startup loading only. It does not update a Raft
member's stable snapshot descriptor, applied index or WAL, and it does not block
readers of an already running store. Durable live restore, reader blocking/reload,
member/WAL recovery coordination, reclamation and power-loss acceptance remain
required before production snapshot installation can use this path.
