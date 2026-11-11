# Production store snapshot artifacts

The internal artifact writer captures application records without constructing a
whole-store JSON string, byte vector, or Lisp snapshot. Production HA uses these
artifacts for snapshot catch-up and durable recovery. Automatic checkpoints are
available through `serve --raft-compaction`. Operator backups also need the stable
member identity, signing/encryption keys and patch state; an application artifact
alone does not include them.

`gr8s.resources::capture-store-snapshot` takes a store, a new destination pathname,
and the Raft applied index and term. Its caller must hold the member lock and
supply the exact applied boundary. The writer takes the raw store lock, so it sees
committed records rather than a speculative transaction. It rejects calls from
inside a speculative store transaction. Production checkpoint scheduling freezes
an immutable application view under the verified barriers and streams that view
after reopening ingress; the frozen-view path avoids holding the live member
lock through serialization.

The artifact is UTF-8 JSON Lines, version 1. Each line is serialized directly to
the file stream. Extra serialization memory depends on the current record rather
than the combined payload of all resources. Resource and Node iteration order is
unspecified. History retains its existing newest-first order. The default record
limit is 16 MiB of UTF-8 JSON. The writer enforces it before publication and while reading.
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

Local Events and their history are excluded. The writer enumerates store indexes.
it does not recursively copy directories or include member-private PKI, Raft WAL,
transfer scratch, or arbitrary files. Kubernetes Secret resources and the shared
template token key are application state and are included. Cluster identity and
other shared signing credentials require the separate enrollment/recovery
integration. This artifact alone cannot restore a cluster's identity.

The file is created privately with mode `0600`. Publication synchronizes the file,
uses Linux `renameat2(RENAME_NOREPLACE)` to preserve any existing destination, and
synchronizes the containing directory. Serialization failures remove the private
temporary file and leave the destination absent. A directory synchronization error
can leave a complete published file but returns an error. No Raft descriptor has
been published by this helper. Private generation ownership and checksum verification are handled by the
materializer described below. Live restore intent, interrupted-install recovery
and reclamation remain pending.

`gr8s.resources::map-store-snapshot-records` reads one bounded record at a time.
Pass `nil` as its callback for a validation pass, with `:expected-index` and
`:expected-term` to bind the artifact to a Raft snapshot. It requires a header,
clocks, newline-terminated data records and a final record with the exact count.
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

Before replacing an existing selection or publishing a restore intent, gr8s
synchronizes the selected predecessor's exact descriptor in
`metadata/retired-generations/<UUID>.json`. The record uses the same private,
bounded, no-symlink metadata checks as the selector. Retries preserve the record;
a retirement-write failure prevents the new intent or selection from being
published. Initial selection from the legacy layout, selecting the same UUID,
and unrelated staged generations do not create retirement records.

A retirement record proves that a generation was previously selected; it does
not by itself make that generation safe to delete. An interrupted transition
can leave it selected or in use. HA generation maintenance uses the protected-root
checks below before reclaiming retired application generations. Keep these records with the member state;
do not remove generation directories based solely on their presence.

The internal `reap-retired-store-generations` maintenance helper verifies the
selected generation, live store root, pending restore and reader pins before
atomically moving one retired generation to `.retired-<UUID>/` under the store
mutex. It then prunes a batch outside the store and Raft locks. Each pass visits
at most 64 application entries by default, plus fixed metadata and empty-directory
cleanup. Metadata records are enumerated separately. Interrupted moves and partial
deletions resume from the durable retirement descriptor. Unrecognized contents,
links, files writable by others and executable files remain; older 0644 application
files are eligible inside the verified private 0700 generation directories.

Filesystem readers that outlive the raw store mutex must use
`call-with-store-data-reader`, which pins the current generation until the reader
returns or unwinds. Synchronous application loading and normal writes already use
the raw mutex. Pins and reclamation coordination survive application reload. This
helper requires exclusive member-root ownership and must run outside a Raft
critical section.

HA starts a joined generation maintenance worker independently of automatic
compaction. It attempts one batch each second, including on receivers that never
produce their own checkpoint. Shutdown joins this worker before stopping Raft or
releasing member ownership. Maintenance does not enable compaction or change its
retained-log budgets. A failed attempt retains an error and retries; a subsequent
successful attempt clears the error. The local metrics are
`gr8s_generation_reaped_files_total`, `gr8s_generation_reclamation_worker_up` and
`gr8s_generation_reclamation_error`.

Generations without retirement records, including generations superseded before
this protocol was introduced, remain untouched. The same joined worker reclaims
obsolete snapshot-registry artifacts independently of local checkpoint creation.
It validates durable/pending/bootstrap/pinned/outbound roots under the member
mutex, renames at most one unreferenced canonical file to unique private trash,
and deletes up to eight trash files outside that mutex. A new copy of the same
digest uses its canonical pathname and is unaffected by deleting the old trash.
Interrupted claims and deletions resume after restart. Generation failures do not
starve artifact cleanup, and artifact failures have their own error gauge.
Repeated full-scale physical-disk acceptance remains separate work.

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

## Quiescing routed requests before live reload

`gr8s.store::quiesce-store-access` closes an application access gate and waits for
routed API request leases to drain. New routed requests and ordinary
`with-store-lock` operations receive Kubernetes `503 ServiceUnavailable`. Existing
leased requests may finish their transactions while draining; the gate stays
closed once they have all returned. Nested routing shares its outer lease, and
handler errors release leases during unwinding.

The default drain timeout is 30 seconds and `:timeout` can select a shorter bound.
If draining fails or times out, the gate reopens without changing application
state. Long-lived watch, exec or streaming requests can therefore defer a restore;
this helper does not forcibly terminate them. It cannot be called from its own
leased request. A restore API must hand work to a control-plane worker after its
request returns.

`resume-store-access` refuses to reopen a gate that is still draining, has a
pending restore intent, or belongs to a store object whose data root differs from
the selected generation. A separate successful `open-store` does not reload an
older store object. The caller must complete that object's application reload and
recovery before reopening access. While blocked, `/readyz` reports unavailable;
`/livez` remains healthy.

This gate covers routed HTTP request lifetimes and ordinary store transactions.
It does not stop raw consensus application, node RPC ingress, controller work
outside store transactions, or already retained external object references.
The live restore caller still needs a consensus-writer/member-lock barrier and
quiescence for those remaining paths before clearing indexes. No production live
reload or automatic compaction is enabled by this access gate alone.

Run the `store-access-gate` FiveAM suite for concurrent drain, rejected reads and
writes, error cleanup, timeout recovery, generation checks and HTTP readiness.
The [access gate evidence](store-access-gate-validation-2026-11-09.json) records the
concurrency and HA proposal checks, adjacent suites, native smoke and heap probe.

## Reloading the existing store object

`gr8s.store::reload-store-application` takes the existing store and completed
generation UUID. The access gate must already be fully drained and blocked. It
preserves the store object, member paths, locks, configuration, signing-key object,
consensus callback and watch configuration. It replaces application tables,
controller state and transient watch journals, and invalidates verified-token,
projected-token and Pod certificate caches. Local Events are discarded and may be
regenerated. A test requires every store slot to have an explicit reload policy.

The helper takes locks in this order: workload, credentials, consensus writer,
caller-supplied member barrier, then raw store. It durably begins/selects the
restore before dropping old application references. It resets application fields,
runs a full GC, and loads the selected files into the same object. This avoids
constructing a second fully loaded store. Load or recovery failures retain the
intent and keep access blocked; retries use the same store and target generation.

For an HA store, `:call-with-member-lock`, `:validate-recovery` and
`:commit-recovery` are required function arguments. The first must invoke its
thunk synchronously exactly once under the member lock. Validation receives the
target descriptor and store before intent or selection changes and must return
`T`; a false return or error leaves the existing application selected. The final
callback receives the target descriptor and reloaded store under the barriers; it must durably coordinate snapshot/applied-index/WAL
recovery and must not reenter public store operations. The intent is removed only
after that callback succeeds. Production member recovery supplies these callbacks together with the outer
writer and member barriers.

Successful reload also leaves access blocked. The caller reopens it only after
all recovery work succeeds. An explicit loaded-state flag prevents reopening
following a partial reload, including failures after the intent was removed but
before its directory synchronization completed. Derived caches and journals reset
before loading; member identity files remain at the stable root.

Callers quiesce node ingress and controller/external object references before
invoking this helper. Production artifact dispatch coordinates applied boundaries,
revision minima, watch resynchronization and WAL publication. The helper also
supports explicitly staged standalone generations, but does not provide an
operator backup/restore command or infer a disaster-restore revision bump.

Run `store-application-reload` for same-object state, cache/identity preservation,
failure retry, HA callback requirements and post-reload consensus-write/reopen
coverage. To run capture, validation, materialization and same-object reload in the
constrained-heap probe:

```sh
GR8S_SNAPSHOT_RELOAD=1 sbcl --dynamic-space-size 384 \
  --noinform --non-interactive --load scripts/test-store-snapshot-memory.lisp
```

In reload mode, the old application is released before loading the target. The
probe checks the restored resource count and a payload after reopening access;
it does not claim that old and new full application heaps remain resident together.

The [application reload evidence](store-application-reload-validation-2026-11-09.json)
records the focused checks, same-object heap result, and the distinct scope of the
native startup smoke. Production ingress and member/WAL integration remain pending.

## Replicated image tracker state

Snapshots include `imageTrackerConfig`, `imageTrackerOrigin`,
`imageTrackerSwarm`, and `imageTrackerPeer` records. These preserve lease and peer
expiry policy, origin tokens and expiry times, verified BEP52 metainfo and
infohashes, and peer endpoints, identities, completion flags and last-seen times.
Capture records committed state without expiring entries as a side effect.
Validation rejects duplicate identities, peers without a swarm, origin leases
that conflict with a published swarm, missing policy, and invalid binary or
metainfo fields. Binary values use canonical base64.

Materialization writes a private, synced `image-tracker/state.jsonl` file in the
application generation. Startup and same-object reload reconstruct the tracker
from that file. Reload preserves the tracker object, mutex and clock because the
running node RPC server retains the object; it replaces the contained application
state. Older artifacts without tracker records load an empty tracker with default
policy. This compatibility behavior cannot recover tracker state absent from an
older artifact.

The snapshot limits remain 16 MiB per record and 2 MiB per JSON string.
Metainfo up to 1,572,864 bytes (1.5 MiB) uses the inline `imageTrackerSwarm` representation.
Larger metainfo uses a swarm header with `metainfoFormat: "chunks-v1"`,
`metainfoBytes`, `metainfoSha256`, and `infohash`, followed immediately by
`imageTrackerMetainfoChunk` records. Each chunk names the swarm digest and its
byte offset; `data` contains at most 49,152 decoded bytes, or 65,536 base64
characters. Chunk sequences must be contiguous and ordered. Legacy inline
swarm and peer records retain their existing ordering rules.

Validation writes one active metainfo sequence to an anonymous, private,
close-on-exec file on the source filesystem. It checks offsets, total size and
SHA-256, then validates canonical bencoding, the OCI filename, BEP52 version and
infohash using file offsets and fixed buffers. Dictionary keys are compared as
byte ranges without allocating their contents. Missing, duplicate, reordered,
corrupt or semantically invalid sequences fail before the successful final
record is delivered. Every exit closes the spool, including staging callback
failures; no scratch pathname survives process termination. Chunked validation
requires Linux anonymous-file support on that filesystem and available space
for the active blob.

Materialization preserves bounded chunk records in the generation's tracker
file. Reload and startup assemble each validated raw metainfo vector once as
live tracker state. Serialization and validation avoid a base64 string covering
the entire blob. The live metainfo itself remains resident and contributes to
normal application heap requirements.

Tracker publication uses the same canonical validator over a seekable view of
owned input bytes. It copies caller data before validation, then stores that
validated copy. Validation does not build a decoded metainfo tree or re-encode
the entire blob, and caller mutation after validation cannot change the bytes
published in the swarm.

Readers that support only inline metainfo reject chunked swarm headers. Before
a member can receive such an artifact, its binary must support `chunks-v1`.
This includes rollback targets reading the selected generation's tracker file;
retain a compatible binary or restore a pre-upgrade backup. Artifacts without
chunked metainfo retain the inline representation. The format does not replace
node RPC and background-writer barriers or Raft/WAL recovery hooks.

The developer probe `scripts/test-tracker-metainfo-memory.lisp` has separate
`capture NEW_ROOT` and `verify NEW_ROOT` modes. Run them in separate SBCL
processes with `--dynamic-space-size 384` and cached dependencies. Capture
requires a nonexistent state directory under an existing parent. It publishes
four canonical torrents with 16 MiB of metainfo padding each, then captures,
validates, materializes and reloads the store. Verify reopens the persisted
selected generation and compares each metainfo's size and SHA-256. The probe
preserves its state and artifact for inspection.

The [chunked metainfo validation](tracker-metainfo-chunks-validation-2026-11-11.json)
records the parser-limit baseline, publication allocation failure, corrected
capture/reload and fresh-process verification, and the restore integration
checks. Four 16 MiB metainfo payloads fit the probe's unchanged 384 MiB heap;
this is source-loaded SBCL validation, distinct from production CLI and VM tests.

Established watches cooperate with the access gate. When draining begins, Pod,
Node and durable-resource watches emit a Kubernetes `ERROR` event with status
`410 Expired`, close their streams, and release their request leases. Clients
must relist after access resumes. This avoids waiting for the watch's normal
five-minute timeout before a restore can acquire its barrier. A blocked socket
write can still delay a request; the gate's drain timeout remains authoritative
and leaves the application unchanged if requests cannot drain.

Stream termination releases request leases. Revision safety additionally depends
on validation against the member's committed/applied boundary and
fresh revision epochs. Production member recovery supplies those checks and
barriers as described below. A standalone operator restore workflow must also
choose an explicit revision bump when rolling back to an older backup.

Secret encryption policy is application state and reloads from the selected
checkpoint, including its active key identifier and public salts. The member's
CA private key remains at the stable member root. Captured Secret data and Secret
history use encrypted envelopes when encryption is enabled; materialization keeps
those envelopes on disk and application loading authenticates and decrypts them.
Reload must replace a previously loaded policy rather than retain it across a
generation change. A generation's encrypted data requires the corresponding
cluster identity key; an artifact alone is not an identity backup.

## Local revisions for a live restore

`materialize-store-snapshot` accepts `:minimum-resource-revision` and
`:minimum-pod-revision` for a live restore. Supply values strictly above the
member's current resource revision and its Pod revision reservation ceiling,
respectively. The caller must quiesce all ingress before taking these values;
if writes overtake a staged generation, rematerialize it with fresh minima.

A resource minimum places the retained history interval above the old local
clock, shifting revisions upward when needed while preserving the interval's
width and events. Current objects and history's old/new object versions use the
same offset; versions preceding the interval clamp to the requested minimum.
History byte estimates are invalidated after translation. Old watches and signed
continuation pages expire at the fresh floor. Generic reload and member-boundary
checks continue to require a fresh epoch; sharing a Raft log does not establish
that public revision numbers are interchangeable between replicas.

Pod minima advance local publication clocks when needed. Canonical Pod desired
and observation revisions support replicated delta preconditions and agent
acknowledgments, while the durable local Pod API epoch rejects pre-restore client
versions. The source artifact and digest stay intact: materialization translates
one validated record at a time, with checked revision arithmetic.

A private `metadata/snapshot-boundary.json` records the materialized clocks and
artifact index/term. Live reload checks it under the barriers before creating an
intent or changing selection, rejects clocks overtaken by the running member,
and verifies the loaded clocks before acknowledging recovery. A failed partial
load can retry the same selected generation. Standalone writes after restore
maintain the durable committed Pod clock so they can survive reopening.

These local revision checks do not prove the artifact is newer than the member's
applied Raft state. Production snapshot installation must also validate its
index/term against the actual member and coordinate WAL recovery. Older
artifacts and manually prepared generations can still be opened at startup;
they need rematerialization before using this live reload path.

`gr8s.ha::make-member-generation-validator` creates the pre-intent callback for
an actual Raft member. Its inputs are the authenticated transfer's sender term,
snapshot index/term and artifact digest, obtained independently of the generation
being checked. Validation requires the calling thread to own the member lock.
For a fresh installation it requires a follower still in the transfer's term and
a snapshot ahead of both committed and applied state, with a compatible log term.
The descriptor must match the expected index, term and digest. The callback reads
current member state at invocation, so advancing the member after staging does
not leave a stale validation decision usable.

An exact durable pending snapshot may resume after a later election term, but its
index, term and application artifact digest must still match, and its boundary
cannot precede the member's committed/applied state. A different pending install
is rejected. These checks do not acquire ingress barriers, write a WAL snapshot,
or enable production restore automatically. The optional dispatch barrier
described below establishes outer application writer locks before member locking; production startup must configure it together
with the application restore callback.

For startup recovery, the validator's explicit `:recover t` mode accepts an exact
published snapshot already loaded from the WAL, before its suffix is applied. It
checks the member's snapshot index/term and full application reference rather
than treating an equal applied index as a fresh transfer. Recovery is rejected
if the member has already committed or applied a newer boundary.

The application reference is a small, readable Lisp value suitable for the WAL:
`(:gr8s-store-artifact 1 :index INDEX :term TERM :sha256 DIGEST)`. The reference
binds the artifact identity; it does not contain the artifact bytes. Pending and
published recovery also validate the enclosing Raft configuration envelope.
Production startup wires artifact transport, durable placement, restore and WAL
recovery together through `start-store-member-from-wal`. Both preflight and
post-load callbacks run under the member and raw store barriers and must not
reenter public store operations.

Durable artifact storage is available through the internal
`gr8s.resources::retain-store-snapshot-artifact` function. Supply the stable member
root, source pathname, expected index, term and lowercase SHA256. It copies and
hashes bytes in 64 KiB buffers into a private staging file, synchronizes the file,
and validates the complete snapshot and its boundary before publication. It
atomically links the file to `snapshot-artifacts/SHA256.jsonl` without overwriting
an existing artifact, checks the published copy, then synchronizes the directory.
Only successful return supplies a pathname and reference eligible for a future
WAL snapshot. An error after publication may leave a valid file visible; retry
verifies and synchronizes it before acknowledging durability.

`checked-store-snapshot-artifact-path` resolves a reference after restart. It
rejects missing files, symlinks, unsafe ownership/permissions, changed bytes, and
mismatched index/term. Registry directories are mode 0700 and files are mode 0600.
Published files are immutable; these APIs assume exclusive management of the
member root by its process. Lookup rehashes and validates the artifact without
assembling its complete payload in memory.

Transfer scratch can be deleted after retention succeeds. HA maintenance claims
unreferenced registry artifacts under member/WAL ownership and removes recognized
private trash outside the member lock. It protects current, pending, bootstrap,
pinned, queued and active-transfer references, and runs independently of local
checkpoint creation. Interrupted staging files are ignored by reference lookup.
Artifact retention itself does not change application selection or write the WAL.
Those production paths must call it before persisting an artifact reference.

The internal `gr8s.resources::configure-store-artifact-transport` function binds
registry source and retention callbacks to a Raft member and its stable member
root. With these callbacks installed, an application reference uses the
`:artifact-v1` transfer mode: the registry file's raw JSONL bytes travel in chunks
of at most 64 KiB. The first chunk carries a separate configuration/reference
header of at most 64 KiB. Its sender, election term, snapshot index/term and
artifact digest must match the transfer identity. The complete file checksum is
checked before the receiver invokes its durable registry retainer.

Artifact chunks use a binary frame with the eight-byte magic `GR8SCK01`, three
big-endian 32-bit lengths (metadata, envelope, data), then those byte sections.
Each section is limited to 64 KiB; lengths must exactly match the received frame.
The data section is decoded directly into an octet vector, avoiding Lisp reader
allocation for tens of thousands of printed byte numbers. Ordinary Raft messages
and generic snapshots keep their existing encoding. Members lacking artifact
support reject this transfer; no mixed-version capability negotiation is enabled.

Only a literal successful retention acknowledgement permits Raft to write the
artifact reference to its WAL and invoke its restore callback. A failed restore
can leave a durable pending snapshot; its retained artifact survives transfer
scratch cleanup and is available to WAL recovery. Reference-only legacy snapshot
transfers are rejected because they would not establish artifact availability.
The final artifact RPC has a 60-second completion budget for verification and
retention; intermediate chunk calls retain their two-second budget.

Retention runs under the member mutex and must perform filesystem work only.
It must not acquire application ingress/writer locks or invoke live application
reload. Installing these callbacks does not install a production application
restore callback or enable compaction. Production startup and its use of the
restore barriers, artifact retention rules and automatic compaction still require coordination.

`gr8s.resources::configure-member-store-restore` opts a running member and store
into live application installation. It requires an open file WAL and no pending
installation, binds the artifact registry, and installs an application restore
callback plus an outer dispatch barrier. It does not configure application-voter
startup recovery or automatic compaction.

An incoming final snapshot chunk that advances the committed boundary, a durable
pending installation, or an unfinished gate resume enters this barrier. Dispatch
releases the member mutex before rejecting new application requests and draining
existing leases. Normal Raft messages continue during that drain and while the
barrier waits for an outstanding consensus writer. The barrier then takes the
workload, credential and consensus-writer locks before taking the member mutex.
Live reload reuses these locks only after verifying current-thread ownership of
all three; it does not acquire them again inside the Raft callback.

Under those barriers, the receiver retains the artifact, writes the WAL snapshot,
materializes a generation above its local revision clocks and reloads the same
store object. Its pre-intent and post-load callbacks validate the actual durable
pending snapshot identity. Raft then publishes configuration and the applied
boundary and clears its pending install. Only after both application loading and
Raft publication can the barrier reopen its own access gate.

A failure before WAL adoption can reopen the unchanged application if its WAL
remains usable. A durable pending install or incomplete application load keeps
access blocked. An ordinary subsequent Raft RPC retries the pending install under
the same outer barriers. A failed gate resume after Raft publication also remains
marked for retry even when no Raft snapshot is pending. The barrier never opens
a gate that was already blocked by another operation before it arrived.

The memory probe supports `GR8S_SNAPSHOT_LIVE_TRANSFER=1`: it starts a separate
receiver process with a 384 MiB heap and checks that its live store loads the
complete payload and publishes the applied boundary. Add
`GR8S_SNAPSHOT_RECOVER_RECEIVER=1` to restart that receiver from its retained WAL
artifact and confirm catch-up without retransmitting the artifact. Add
`GR8S_SNAPSHOT_BOOTSTRAP=1` to publish a fresh founder WAL from the resident store,
reload that exact baseline and verify its current-term commit/readiness gate in the
same constrained process. For example:

```sh
GR8S_SNAPSHOT_LIVE_TRANSFER=1 GR8S_SNAPSHOT_RECOVER_RECEIVER=1 \
  GR8S_SNAPSHOT_RELOAD=1 GR8S_SNAPSHOT_BOOTSTRAP=1 \
  sbcl --dynamic-space-size 384 --noinform --non-interactive \
  --load scripts/test-store-snapshot-memory.lisp
```

This probe uses controlled snapshot boundaries and loopback peer traffic. It does
not prove unmodified `gr8s serve` startup recovery, active native-agent reference
drain, or production failover after an interrupted installation. Those paths
remain acceptance requirements before enabling application compaction.
