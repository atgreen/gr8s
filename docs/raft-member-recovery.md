# Raft member recovery

The witness command reopens `raft/witness.log` under its state directory before
accepting peer RPCs. WAL open synchronizes the file and its parent directory
before startup continues. Recovery loads the durable term, vote, snapshot/configuration
and remaining log. It restores the durably proven committed prefix, including
membership, before listening. Retained entries beyond that boundary still require
leader confirmation. The witness has no application payload to replay, but its
committed membership must be restored before voting.

A witness starts with the witness role and completes its join handshake before
starting the election clock. It reuses its saved member certificate on restart.
a new enrollment token is unnecessary when those credentials remain usable.
Restart with the same member ID, state directory and advertised listening
address. The member owns the recovered WAL stream and closes it after its server
and worker threads stop.

The transport API exposes this lifecycle as
`start-raft-member :storage-path PATH :initial-role :witness`. Recovery runs under
the member mutex before constructing the RPC listener. `:storage-path` and an
externally supplied `:storage` are mutually exclusive. Only storage opened via
`:storage-path` is closed by member shutdown. Callers retain ownership of storage
they explicitly supply. A malformed WAL aborts startup before the listener opens.

Each writable WAL holds a nonblocking exclusive process lock on a stable
`WAL.lock` sidecar. A second opener is rejected before WAL recovery or application
restore, including a second opener in the same process. The lock survives atomic
checkpoint replacement. Read-only `load-raft-log` inspection remains available.
Explicit storage close or process death releases ownership; leave the sidecar in
place. An uncertain checkpoint failure retains ownership until explicit close.
Validation and restore failures release the newly acquired lease. This protects
the WAL lifecycle; callers must still coordinate the rest of the state directory.

New writes and checkpoints use `@GR8SWAL1` frames: a fixed 157-byte ASCII header
contains a 16-digit hexadecimal UTF-8 payload length, a SHA-256 payload checksum
and a SHA-256 checksum of the header fields. The payload is one readable Lisp
record followed by a newline. Printing uses a bounded counting/digest sink before
writing, then verifies the actual output against that first pass before fsync.
Payload validation uses a 64 KiB read buffer before parsing; it does not allocate
a second whole-record string.

Writable recovery holds the WAL lease before scanning. It can discard a final
partial frame header whose bytes match the header grammar, or a short payload
with a complete valid header. Truncation is fsynced before the member can append
or construct its listener. Read-only inspection reports an incomplete frame
without changing it. Complete header/payload corruption, invalid Lisp records
and ambiguous short payloads containing another valid frame header fail closed.
A repair sync failure seals the writable stream and aborts recovery.

Existing unframed Lisp WAL records remain readable and can precede new frames.
Their incomplete tails cannot be distinguished safely from interior corruption,
so recovery refuses to truncate them. A successful checkpoint replaces retained
history with framed records. Binaries that predate framing cannot read newly
written frames. Do not point an older binary at a state directory containing
frames. Automated persistent-format checks before upgrade/rollback remain tracked
as `podster-ucm.7.1`.
These checks protect against interrupted append writes and detected corruption;
they do not reconstruct acknowledged data lost to arbitrary storage failure.

Commit progress is recorded as `(:commit INDEX)` frames before the member
publishes the new boundary, applies commands, or acknowledges application to its
leader/client. Checkpoints retain this watermark even when a committed suffix
remains beyond the snapshot. Recovery rejects regressing boundaries, missing
committed prefixes, and attempts to overwrite/truncate committed entries.

This is necessary for membership safety: a snapshot may describe the original
single-voter founder while later committed entries add voters. Reopening with
only the old snapshot configuration could incorrectly restore a one-voter quorum.
The committed configuration is now replayed before elections or peer traffic;
a retained, uncommitted removal is not applied.

A configuration append first records the previously proven boundary, even when
the new configuration never commits. Legacy logs with a configuration tail and
no commit watermark are ambiguous and are refused during writable recovery;
read-only inspection remains available. Recover them from a trusted snapshot
rather than guessing which membership committed. Older readers without commit
record support also cannot read newly written `:commit` frames, even if they
understand framing. Upgrade/rollback capability checks remain `podster-ucm.7.1`.

The regression records a committed voter addition followed by an uncommitted
removal. Before the fix, restart recovered quorum1 with no applied suffix; now it
recovers quorum2 at committed/applied index1 and retains the removal at index2
without applying it. The six Raft/recovery suites pass 4,772 checks, including
repeated process kills and confirmed application replay before listener creation.
The rebuilt interrupted native 64 MiB learner probe also passes at 384 MiB per
process. Source hashes, the standalone reproducer and measurements are in
`raft-commit-recovery-validation-2026-11-10.json`. Production integration and its separate native acceptance are described below.

The internal `gr8s.resources::start-store-member-from-wal` function recovers a
store from a WAL with a retained application artifact. It drains application
access, acquires the outer writer barriers and installs callbacks before the
peer listener is constructed. Recovery validates the WAL's configuration and
artifact reference, restores that exact baseline and only then attaches the
remaining log. It replays the durably proven committed suffix before opening the
listener and leaves unconfirmed entries unapplied. Selected application files can
contain later updates; the retained baseline remains the starting state for replay.
Member identity and private keys stay at their existing root paths.

For a fresh member, the same internal startup helper accepts
`:bootstrap-role :founder` or `:bootstrap-role :learner`, with the WAL at
`raft/control-plane.log`. Bootstrap requires drained application access and outer
writer barriers. It fsyncs `raft/bootstrap.json` under the WAL ownership lease
before creating the data file, retains an exact application artifact, records
that reference in the journal, and publishes the initial WAL through atomic
checkpoint replacement. It then marks publication durable. A restart can resume
at each boundary without recapturing an already retained baseline from later files.
Published WALs that disappear, become empty or gain later hard/log state are never
reinitialized. Bootstrap identity and API URL changes are refused.

The founder baseline is index1/term0 with one voter. A learner starts at
index0/term0 and cannot campaign. Its local zero-index artifact supports restart;
live snapshot installation still requires a positive index. Catch-up must install
the founder's baseline before applying later entries, preserving application state
that existed before founding. The internal bootstrap helper does not publish API
endpoints, acquire process-wide application ownership or enable compaction.

API access remains blocked after the listener starts. An authenticated leader's
AppendEntries must confirm a current-term committed boundary that this member
has fully applied. Vote requests and stale-term heartbeats cannot open access.
A recovered sole voter can elect itself; its startup monitor proposes one no-op
recovery barrier per term and waits for that entry to commit and apply. A failed
suffix application retries against the existing barrier without appending a new
entry on every tick.

The helper installs the same application and durable-write dispatchers used by
HA control planes. The caller starts the member's tick clock and publishes its
application endpoints. Missing or corrupt artifacts, absent artifact baselines
and rejected WAL validation abort startup before opening the peer listener.
Startup failures leave application access blocked.

`start-raft-member` supports `:prepare-fn` for callback installation before WAL
recovery and `:validate-recovery-fn` for checking recovered state before it mutates
the node. The latter must return exactly T. Direct `recover-raft-node` callers
can supply the corresponding `:validate-fn` callback. `open-file-raft-storage`
also accepts `:prepare-fn` for journal publication under its lease before data-file
creation; errors release that newly acquired lease.

Production `start-ha-control-plane` does not invoke this recovery helper yet.
Production callers must acquire state-directory ownership before opening the
application, use the durable bootstrap/recovery path, and admit new voters as
learners until they catch up. Capture registration, native multi-voter acceptance
and automatic compaction remain unfinished.

`serve` acquires exclusive ownership of its canonical state directory before
opening the application store, pool or PKI. The CLI acquires that ownership
before evaluating startup patches and retains it through patch shutdown and
server teardown. Initialization failures release ownership; process death also
releases the kernel lock. A second process or an alias of the same directory
cannot acquire ownership. The stable `.gr8s-serve.lock` file remains in place:
do not delete it to bypass an active owner.

`metadata/server-mode.json` records standalone or HA intent atomically before
application initialization. Explicit `--raft-init` or `--raft-join` can transition
standalone state to HA. Once HA intent is recorded, restart with the appropriate
Raft options; omitting them is refused, including after failed HA initialization.
Existing Raft WAL, bootstrap or PKI evidence also prevents standalone fallback.
A witness WAL is rejected by `serve`. These guards do not yet establish shared
ownership across every administrative command.

HA startup also persists `metadata/server-ha-endpoint.json`, binding member ID,
Raft host/port and API URL to the state directory before startup patch evaluation.
The production Raft default is port 7000; internal transport callers may still
request an ephemeral port for isolated tests. Restart with the original endpoints.
Changes and malformed or nonprivate descriptors are refused before application
initialization.

A learner-to-voter configuration change now requires an applied-progress receipt.
Successful AppendEntries replies report `:applied-index` only after application
succeeds, bounded by the acknowledged log match. The leader tracks receipts for
its current term and clears them when assuming leadership. Promotion requires
that the leader has applied a current-term committed boundary and the learner
has both replicated and acknowledged application through that boundary. A new
commit can make an older receipt insufficient. Missing receipts from older
binaries, failed application, stale terms and invalid applied indices cannot
establish readiness; rejected promotions return `:learner-not-ready`.

Join and transport admission add requested voters as learners with committed
promotion intent. The member clock promotes them only after current-term applied
progress qualifies. A successful Join accepts admission; it does not establish
that the joining member already votes. Repeated joins preserve an existing voter
and reject conflicting endpoints or role changes. An unrelated admission is
refused while another configuration change is unapplied, including retained
prior-term configuration entries and removals.

After leader handoff, a current-term entry establishes a committed barrier before
promotion. The driver appends a protocol barrier only when no current-term entry
already exists, so a disconnected quorum cannot cause one new entry per tick.
The protocol barrier does not enter the application state machine. Native slow
snapshot/interrupted-join acceptance remains under `podster-ucm.2.9`.

Production `serve` now starts HA members through the durable store recovery
adapter. Fresh founders and learners publish bootstrap journals; published
members recover committed membership and application state without founding a
new quorum. A recovered voter uses its durable peer address book instead of
repeating Join. The Raft listener remains available during recovery, while the
API and application services wait until a current-term committed boundary has
been applied. Shutdown keeps the store gated and its stopped consensus hook
attached, preventing accidental standalone writes.

Fresh HA startup atomically records serve-mode version 2 before publishing its
endpoint or initializing credentials. This distinguishes an interrupted durable
genesis from older in-memory HA state. A legacy HA directory without a bootstrap
journal is refused and requires explicit cluster migration; restarting it with
`--raft-init` must not silently create a one-voter quorum. Older binaries that
only understand mode version 1 also refuse this descriptor.

Snapshot capture is registered under the outer store barriers before member
locking. Automatic compaction is opt-in with `serve --raft-compaction`.
Witness peers receive a durable
configuration-only projection of store snapshots, without application artifacts
or an application artifact retainer. Voters and learners retain the full
application snapshot path.

Snapshot installation retains the bounded resource history while translating
its revision interval into a fresh local watch epoch. Public resource versions
are member-local, so sharing a Raft log alone does not justify reusing another
member's numbering. Existing watch cursors expire at the new epoch floor;
history entries, their old/new object versions, and current objects are rebased
consistently. Versions older than the retained interval clamp to the requested
minimum. The interval width remains unchanged, and overflow is rejected before
the generation is completed or selected. Generic application reloads retain
their existing resource and Pod epoch fences.

Internal admission callers can propose a learner with `:promotion-role :voter`
to record its requested eventual role. The intent becomes effective with the
committed `:raft-config` entry, alongside the learner membership. Subsequent
configuration entries preserve outstanding intents; promotion or removal drops
the affected intent. Snapshot envelopes carry the same `:promotions` metadata,
so checkpoint recovery and later log replay retain pending work. Envelopes and
legacy configuration entries without this metadata represent no promotion intent.

Intent validation requires distinct learner IDs and voter targets and runs before
configuration mutation or snapshot application restore. Recovery does not restore
applied-progress receipts: a new leader must obtain fresh current-term evidence
before proposing promotion. Join admission and the automatic promotion driver
use this metadata to resume outstanding work. Learners without applied-progress
receipts remain learners.

The native learner probe builds an instrumented executable from the same gr8s
systems and exercises the internal artifact-backed startup/admission path:

```sh
sbcl --noinform --non-interactive --load scripts/build-learner-native-harness.lisp
python3 scripts/test-learner-native.py
```

The default payload is 1024 records of 64 KiB each, with a 384 MiB heap per
process. The runner throttles snapshot chunks, verifies that the existing voter
continues committing writes, checks the blocked receiver's incomplete snapshot
file, kills the receiver with SIGKILL, restarts from its WAL and rejoins. It then
checks automatic promotion, preserved payload and intervening writes, and a
repeated Join without additional configuration entries. Logs, state and a JSON
report remain in the printed temporary evidence directory, including on failure.
`--records 64` runs a smaller smoke check and marks large-payload acceptance false.

This probe uses unprivileged loopback plaintext transport and ordinary files.
Its JSON scope distinguishes the instrumented harness from production `serve`.
VM execution, authenticated native transport and leader handoff during catch-up
remain separate acceptance requirements under `podster-ucm.2.9.4`. Production
voter startup integration remains under `podster-ucm.2.1.4`.

The first 2026-11-10 native runs passed the 4 MiB smoke case but exhausted the
64 MiB receiver's 384 MiB heap. Unary gRPC dispatch retained complete request
bodies in closed HTTP/2 stream records. The fix consumes the body before dispatch
and releases the consumed backing allocation. The interrupted 64 MiB case now
passes at the same 384 MiB limit on both the fixed and rebuilt merged images,
including committed writes during disconnection, recovery, promotion and repeat
Join. Both processes exit cleanly.

`learner-native-validation-2026-11-10.json` preserves the original failures;
`http2-request-retention-validation-2026-11-10.json` records the fix and passing
native runs. Completed unary calls now retire their stream records on both sides
of a live connection. Per-parity stream ID high-water marks keep retired IDs
closed without retaining one tombstone per call; unread client responses remain
available until application finalization. A further interrupted native 64 MiB run
passes at the same heap limit with this change. The retirement, late-frame,
shutdown, snapshot and node-session checks total 392 passing assertions; evidence
is in `http2-stream-retirement-validation-2026-11-10.json`.

The streaming error-path and native memory follow-up is recorded under
`podster-ucm.2.10`; see cancellation validation below. Native leader handoff, authenticated transport,
VM execution and production voter startup remain separate work; these runs do
not establish their completion.


### Long-lived RPC memory probe

Build and run the native, unprivileged loopback probe:

```sh
sbcl --noinform --non-interactive --load scripts/build-http2-lifetime-harness.lisp
build/gr8s-http2-lifetime --dynamic-space-size 384
```

It keeps one client/server connection open for 6,000 RPCs using 750 ms deadlines,
samples live heap after
full GC every 1,000 calls, and checks that growth after the warm-up sample stays
within 1 MiB. It also runs 300 direct cancellations and 300 aborted bidirectional
scopes over that connection. Successful RPCs after each cancellation batch ensure
its reset frames have been processed before sampling. Its JSON includes retained
stream counts and pending deadline timer entries. TCP_NODELAY is enabled on the probe's sockets to avoid packet-coalescing
delays; it does not change production socket configuration.

This probe found retention outside HTTP/2: canceled deadline contexts remained
in the timer heap, and popped heap entries retained references beyond the array's
fill pointer. Indexed cancellation now removes timer entries immediately and
clears vacated slots. Before the fix, post-GC live heap grew by 5.6 MB over the
measured calls. Two fixed runs stay within 0.11 MB across their samples, with zero
retained stream records and zero pending timers. The rebuilt interrupted 64 MiB
learner probe also passes at 384 MiB per process.

`deadline-retention-validation-2026-11-10.json` records those runs, 430 passing
gRPC/Raft/node-session integration checks, and 22 focused timer checks. It also
records seven failures in the bundled cancellation library's 316-check suite;
the same failures reproduced against the unchanged library. They are resolved
under `podster-ucm.2.11`, as described below. Direct channel cancellation and
abnormal bidirectional scope exits are covered by the final lifetime validation
under `podster-ucm.2.10`. These probes do not establish production HA or VM
acceptance.


### Fractional deadlines

Timeout durations are normalized before adding epoch time, and fractional
gRPC timeout units are parsed as exact rational seconds. This prevents single
precision rounding from turning a short future deadline into a past timestamp.
Absolute timestamps already rounded by a caller cannot be repaired; use rational
offsets when constructing them directly.

Deadline context scopes check cancellation before the body and after a normal
return, preserve multiple values and original errors/nonlocal exits, and always
release their timer registration. Their cancellation remains cooperative.

All 781 checks in the combined cancellation, transport, Raft, snapshot and
node-session run pass, including the cancellation library's 336 checks. The
rebuilt native 6,000-RPC probe also passes at 384 MiB with 750 ms deadlines,
zero retained stream records and zero pending deadline entries at each sample.
See `deadline-precision-validation-2026-11-10.json` for source and binary hashes,
the test runner and native measurements. Production HA integration remains
separate work.


### Cancellation and stream lifetime

Direct channel cancellation releases local state even if writing the reset frame
fails. Repeated cancellation is harmless. Bidirectional stream scopes cancel on
body errors, nonlocal exits and failed half-close writes; normal returns preserve
multiple values and the existing send-side half-close behavior. Unread responses
remain available until a call is consumed or explicitly canceled.

The concurrent cancellation regression exposed a deadline-construction race:
children became visible to their parents before their timer slots were fully
initialized. Deadline children are now constructed in their final class before
parent registration. The regression runs 20 rounds of 1,000 concurrent creations,
and a separate test observes parent-visible children under the parent lock.

All 839 integration checks pass. The rebuilt native probe passes 6,000 successful
RPCs, 300 direct cancellations and 300 aborted scopes on one connection at the
384 MiB heap limit. Every post-GC sample has zero retained stream records and
zero pending timers; live heap varies by 33,968 bytes across the samples.
`cancellation-lifetime-validation-2026-11-10.json` records source/binary hashes,
the regression failure, test runner and measurements. This completes the retired
stream-metadata follow-up (`podster-ucm.2.10`) and construction-race fix
(`podster-ucm.2.10.2`), with production durable HA startup, authenticated native
recovery/leader handoff and VM acceptance remaining separate requirements.

Production native acceptance is recorded in
`production-ha-recovery-validation-2026-11-10.json`. Three actual `serve`
processes use mutually authenticated Raft and 384 MiB heaps, with agents
disabled and the fake runtime. The run verifies leader SIGKILL and rejoin,
complete voter shutdown/restart, a lone founder remaining application-gated
with its recovered three-voter membership, preserved data and key identities,
witness SIGKILL/restart, and a committed write requiring two surviving voters
plus the witness. All final shutdowns return zero. This is loopback native
acceptance; VM dataplane and Kubernetes conformance acceptance remain open.

To exercise leader loss during a large learner transfer, build the instrumented
native harness and run:

```sh
sbcl --noinform --non-interactive --load scripts/build-learner-native-harness.lisp
python3 scripts/test-learner-handoff-native.py
```

The probe establishes three voters with 64 MiB of application payload, admits a
fourth member, verifies a partial artifact and gated learner, then kills the
leader. It requires a higher-term replacement to retain the three-voter quorum,
commit a write, finish the learner transfer without another Join, promote only
after application readiness, and recover the old leader. Each process has a
384 MiB heap. `--records` and `--chunk-delay` control payload size and transfer
pacing; fewer than 1,024 records do not qualify as large-payload acceptance.
The JSON report includes partial-transfer evidence, membership, application
progress, binary digest and shutdown results. This harness uses internal
plaintext transport; authenticated production startup is covered separately by
`test-ha-production-native.py --witness`. VM acceptance remains separate.

The 2026-11-10 default-size run passed; see
`learner-handoff-native-validation-2026-11-10.json`. The killed leader had three
voters and a pending learner; the learner held a partial snapshot and remained
gated at applied index 0. The replacement advanced to term 2, committed the
post-loss write, and completed catch-up without another Join. The learner
finished at committed/applied index 10 with four voters and 1,026 application
resources. The old leader recovered, all four nodes retained the write, and
all shutdowns returned zero. This closes native plaintext handoff acceptance;
the combined authenticated large-transfer scenario and VM execution remain open.

Add `--tls` to the learner handoff probe to run the same scenario over mutually
authenticated Raft connections. Before launching members, the instrumented
binary prepares a private test CA and distinct member certificates. Only the
fixture founder retains the CA private key; peers receive their own keys and
certificates plus the CA certificate. Each status check requires TLS credentials
on the member, and the report verifies certificate/key hashes across recovery.
These offline fixtures exercise authenticated replication and Join, rather than
production token enrollment. The existing production native probe covers token
enrollment separately.

The default-size `--tls` run also passed on 2026-11-10; see
`learner-handoff-tls-native-validation-2026-11-10.json`. Four native processes
used 384 MiB heaps and per-member TLS credentials. After leader loss during
the partial 64 MiB transfer, the replacement committed the write in term 2
and completed catch-up without another Join. The learner applied through
index 10 and became the fourth voter. The old leader recovered; all four
retained the write, all credential hashes were preserved, and all shutdowns
returned zero. The existing plaintext interrupted-transfer probe also passed
with a 4 MiB compatibility fixture. Authenticated large-transfer handoff is
therefore verified in the instrumented harness; VM acceptance remains open.

Artifact reclamation now has an explicit internal entry point,
`gr8s.resources::reap-store-snapshot-artifacts-unlocked`. It requires the
member mutex and that member's open, owned application WAL. It preserves the
current snapshot, unfinished snapshot install, original bootstrap baseline,
and every queued or active outbound snapshot. A sender publishes ownership
under its link lock before dequeuing, closing the gap before source lookup;
normal delivery and failures both release ownership after the batch finishes.
Reclamation acquires locks in member-then-link order.

Only unreferenced canonical digest filenames that are private, owned,
single-link regular files are unlinked. Directory changes are fsynced. Invalid
bootstrap metadata prevents deletion; symlinks, hard links, unexpected modes
and unknown filenames are preserved. Publication `.part` files and abandoned
capture temporaries require the separate orphan-cleanup work in
`podster-ucm.11.3.7`. This helper does not schedule reclamation or enable
automatic compaction; that integration remains under `podster-ucm.11.3`.

Reclamation validation is recorded in
`artifact-lifetime-validation-2026-11-10.json`: 137 focused transport/registry
checks and 298 snapshot, TLS and HA integration checks pass. The broader run
exposed a certificate-test witness that declared a no-op application callback
without a restore callback. Making that fixture stateless restored snapshot
catch-up and verified that removed members cannot renew their certificates;
the product's application-restore requirement remains enforced. These checks
do not establish native automatic-compaction or VM acceptance.

An internal compaction worker is available through
`start-ha-control-plane` with an explicit positive `:compaction-interval`.
The production default remains `nil`, so ordinary `serve` does not start it.
Its policy triggers when either the retained WAL or a conservative estimate of
retained command memory reaches `:compaction-bytes` (16 MiB by default), or the
applied prefix reaches `:compaction-entries` (256 by default). The WAL check uses
the open descriptor; the memory check scans retained commands until the budget
is reached. This accounts for Lisp strings occupying more memory than their
UTF-8 representation on disk without scanning resource watch history.

The separate worker drains ingress while the Raft clock continues, acquires
outer application barriers before the member mutex, rechecks eligibility, and
freezes exactly last-applied with its Raft metadata. It reopens its healthy gate
and releases the live locks before serialization, hashing, registry copying and
validation. It pins the artifact, drains again, and publishes the prepared
boundary while preserving newer committed/uncommitted suffix entries. Finally
it reclaims obsolete artifacts. Only one capture per control plane can run,
including manual invocations, so overlapping workers cannot retain extra views.
While the automatic worker runs, application admission also bounds the complete
retained log, including committed entries awaiting compaction. Its conservative
budget is twice `:compaction-bytes`, with a 32 MiB minimum (32 MiB at the default
trigger); an existing stricter budget is preserved. Capacity refusals return
503 before append and release as checkpoints catch up. Recovery barriers and
membership changes remain available. Stopping the worker restores its previous
admission policy. The separate 16 MiB uncommitted-proposal limit still applies.
Followers also check the retained budget before adding a replicated application
suffix. Matching retransmissions consume no additional budget, and conflicting
uncommitted tails reuse the space they replace. A capacity refusal can still
commit the matching previous prefix, making it eligible for compaction; it
returns a retry index without acknowledging the refused entries. Recovery-only
traffic remains available. The cluster probe holds one follower's capture while
the other two voters continue, verifies actual replication refusals and the
follower's budget, then releases it for catch-up and restart validation.
A capture failure with healthy storage reopens only the worker's own gate;
uncertain WAL failure leaves application access blocked. Shutdown wakes and
joins the worker before stopping Raft. Internal counters record successful
cycles, reclaimed artifacts and the most recent error.

The opt-in worker's HA tests cover repeated byte-triggered checkpoints and
recovery, capture failure, uncertain storage failure and waking a long-interval
worker at shutdown. They also cover live writes during capture and recovery of
the newer committed suffix. Production activation still requires capture-pause and
multi-member availability validation (`podster-ucm.11.3.9`). Retained watch
history remains part of the snapshot: a tiny live resource set does not imply a
tiny snapshot, and an overly aggressive trigger can repeatedly serialize that
history. Uncommitted proposals also need separate admission backpressure
(`podster-ucm.11.4`), since compaction cannot discard them safely.

The internal Raft core also supports preparing a compaction boundary before
application I/O. Under the member lock, `raft-prepare-compaction` captures the
applied index, its term and membership metadata without invoking the snapshot
callback. The caller must freeze its application view at that same boundary.
After serializing and retaining the artifact, `raft-commit-prepared-compaction`
revalidates the prefix under the lock and publishes the frozen metadata with
the artifact. It preserves newer committed and uncommitted log entries, current
term/vote, and live membership. A superseding snapshot or pending installation
causes publication to return `nil`; the caller still owns artifact retention
and cleanup. The opt-in worker uses these helpers; automatic compaction remains
disabled by default pending sustained heap and multi-member availability proof.

Image-tracker snapshot iteration freezes policy, leases, swarms and peers under
the tracker mutex, then encodes records and invokes the writer after releasing
that live mutex. Immutable tracker-owned torrent payloads are shared with the
frozen view rather than copied. Live lease renewal, peer replacement or tracker
reset cannot change the captured records.

The application layer also provides a private frozen view. With ingress drained,
the caller holds the outer application barriers and member mutex, prepares the
Raft boundary, and calls `freeze-store-snapshot` with that index and term. The
freeze copies resource indexes and the history list while sharing their immutable
payloads. It copies mutable Pod, Node and controller containers and freezes the
tracker. Secret configuration and derived encryption keys are pinned before
releasing the credential barrier; later serialization does not reread the CA key.
`capture-frozen-store-snapshot` streams this view without live application locks,
using the same immutable-file publication protocol as ordinary capture. Freezing
still takes time proportional to the indexes and mutable containers. A frozen
view can coexist with newer live history and log entries during capture; their
combined retention must be included in the concurrent-churn memory validation.

`call-with-store-artifact-pin` protects an unpublished portable artifact reference
before its file appears in the registry. It registers a private reference under
the member mutex, runs the retention/publication callback outside that mutex,
and removes only its own pin on unwind. Cleanup preserves pinned files alongside
the durable, pending, bootstrap and outbound roots. The callback must publish its
durable Raft reference before returning; abandoned files become reclaimable.
Pins are transient: after a crash, the WAL and other durable roots decide which
artifacts remain necessary. The worker uses this scope across retention and
prepared publication.

For a standalone full-history memory probe, build with
`sbcl --noinform --non-interactive --load scripts/build-snapshot-freeze-native-harness.lisp`
and run `python3 scripts/test-snapshot-freeze-native.py --checkpoint STATE_JSON
--journal JOURNAL_JSONL --history-clock CLOCK`. Inputs must be a quiescent,
unencrypted core store containing the probe's `sentinel` ConfigMap. The runner
copies only these two files, retains input and executable hashes, and freezes,
writes and validates an artifact with a 384 MiB dynamic heap. It checks that a
post-freeze write remains live but absent from the artifact. This does not test
multi-member heartbeat availability or production `serve` startup.

The [frozen-view validation](snapshot-freeze-validation-2026-11-10.json) retained
the full 100,656,464-byte history estimate at a 384 MiB dynamic heap, streamed and
validated 1,978 history records, and excluded a later live write. The standalone
probe passed in 29.86 seconds, including store load and artifact validation.
That standalone probe does not cover concurrent writes during worker capture.
The first asynchronous-worker churn run exhausted its heap as the committed log
grew during I/O; whole-log admission addresses that separate retention source
and was followed by a fresh full churn/recovery run.
The bounded-log attempt subsequently reached the full history budget but also
exhausted its heap during concurrent encoding/validation. Snapshot streams, core
checkpoint writing and live delta encoding now use the existing recovery memory
pressure policy: above two-thirds of dynamic-space usage, collect older garbage
before allocating the next streamed record. This changes production allocation
handling without changing the probe's heap, history, workload or WAL bounds.
The [async-worker validation](async-compaction-validation-2026-11-10.json)
passes the complete single-member workload and both recovery phases: 128 MiB
of churn, 79 checkpoints, sampled WAL below 6.4 MiB, and the full
100,656,464-byte history estimate, all within a 384 MiB dynamic heap.
A separate 128-round three-process mTLS smoke test keeps one follower's capture
held while the other voters continue writing. The follower refuses replication
above its 32 MiB retained-log budget, then catches up after release. All three
processes restart with markers and credential hashes preserved. This partial
cluster run does not establish full-history cluster memory acceptance.
The first full three-process attempt stopped at round 916 after a leadership
change: the load generator treated a committed no-op transaction conflict as
fatal. The probe now rebuilds and retries only that specific conflict, counts
those retries, and continues to reject unrelated conflicts and AlreadyExists.
The failed run is retained in the async-worker evidence. It also exposed
repeated snapshot catch-up on the delayed follower; full cluster acceptance
remains open under `podster-ucm.11.3.9.10`.

The [three-voter smoke validation](compaction-cluster-smoke-validation-2026-11-10.json)
uses three separate 384 MiB processes and offline mTLS fixtures. It holds all
three capture writers for two seconds, commits a new marker while they remain
held, verifies unchanged election terms, then releases capture and restarts all
processes with the marker and credential hashes preserved. Its 64 rounds are
partial evidence, not the full retained-history memory acceptance.
The first complete 2,048-round cluster churn reached the full history budget on
the healthy voters without heap or worker errors, but failed its final catch-up
deadline. The delayed voter repeatedly installed snapshots while newer
checkpoints removed the suffix it needed. This failed run remains in the
async-worker evidence; it does not prove restart acceptance.

The worker now enables a separate disk catch-up window, capped at 128 MiB and
128 anonymous segments per member. Before replacing a local checkpoint, Raft
streams the discarded committed prefix into checksummed segments. A lagging
peer can receive ordinary bounded AppendEntries from these segments even after
the live log has been trimmed. No old command objects remain in the heap. Gaps,
eviction, corruption, or unsupported anonymous-file storage fall back to the
ordinary snapshot protocol; cache errors cannot change the durable WAL.
Segments have no filesystem names and their descriptors are close-on-exec.
Storage close, worker disable, or process exit releases them. Backup/recovery
continues to use the current WAL and application artifact; this cache is
expendable and is not a new recovery format. The worker restores the previous
cache policy when stopped, respecting a stricter existing policy.

For canonical checksummed WALs, cache construction copies the selected durable
entry frames through a fixed 64 KiB buffer. A private index holds only terms and
byte offsets for current WAL entries; it never retains command payloads. Durable
append, truncation, checkpoint replacement, and recovery maintain that index.
Checkpoint replacement also copies available durable suffix frames into its
private replacement file. Boundary records and entries lacking frame metadata
use the serializer; switching between binary copying and text output flushes
and resynchronizes the private file descriptors. The replacement index is
adopted with its WAL, preserving the existing fsync/rename failure behavior.
Missing or legacy frame metadata uses the original serializer. The archive
reader still verifies framing and checksums before replication. This removes
repeated payload printing from cache creation; it does not by itself establish
a bound on checkpoint pauses or prove leadership stability.
The disk window and frame-copy optimization passed full three-member churn,
stable-leadership, and cold-recovery acceptance: all 2,048 rounds completed in
the original term with 96 MiB retained history per member and 384 MiB heaps.
The [validation record](async-compaction-validation-2026-11-10.json) preserves
the full result; the [diagnostic record](compaction-phase-diagnostics-2026-11-10.json)
records the earlier failures and the reduction from seconds to milliseconds.
Production/VM acceptance remains separate; automatic compaction stays disabled
by default.

Production HA startup reclaims recognized abandoned snapshot publication and
capture scratch after validated WAL recovery and before listening. Cleanup
requires state/WAL ownership and application barriers; unsafe or unknown files
and all published artifacts are preserved. A
[three-cycle SIGKILL validation](snapshot-startup-scratch-validation-2026-11-10.json)
checks live-owner protection, restart cleanup, and retained data/artifacts.

Operators can opt in on each HA server by adding `--raft-compaction` to the
existing `gr8s serve` command, alongside `--raft-init` or `--raft-join HOST:PORT`.
The switch starts that server's checkpoint worker with the normal thresholds
and a one-second check interval. Omit it to keep automatic compaction disabled.
It is rejected outside HA mode. This exposes the opt-in production startup path;
it does not replace the separate production/VM and sustained-availability gates.

Build this internal harness with
`sbcl --noinform --non-interactive --load scripts/build-compaction-cluster-native-harness.lisp`.
Run `python3 scripts/test-compaction-cluster-native.py` for 2,048 rounds and
full-history checks. Add `--require-stable-leadership` to fail on an unforced
term change during workload execution and final convergence; elections during
cold restart remain allowed. Use `--smoke --rounds 128` for the explicitly partial
probe, including asymmetric follower retention. The full run checks each member's history budget before shutdown and
cold-loads that history before startup establishes a new watch epoch. This
harness uses the store-member/HCP-worker APIs; it does not run `serve` or certify
node enrollment, VM execution or conformance.

Build the internal native retention probe with
`scripts/build-compaction-native-harness.lisp`, then run the resulting
`build/gr8s-compaction-acceptance --dynamic-space-size 384 PRIVATE_ROOT 2048`.
Use a new private directory for `PRIVATE_ROOT`. The probe creates/deletes 2,048
64 KiB objects (128 MiB of payload), retains the normal 96 MiB watch-history
byte budget, uses the 16 MiB disk/command-memory trigger, samples retained
WAL/artifact counts and recovers a sentinel after restart. Its process-local
history clock is frozen so a slow host cannot make history expire before the
byte cap is exercised; a pass requires sampled history within 128 KiB of that
cap. This is an internal single-member native probe rather
than production CLI, multi-member or VM acceptance.

For retained logs, binary identity and a JSON result on success, failure or
timeout, run `python3 scripts/test-compaction-native.py` after building. It
creates a new private evidence directory and allows 30 minutes by default;
`--timeout SECONDS` changes only the observation deadline. A timeout leaves
acceptance unproven and preserves the last progress samples.

The Python runner requires both in-place member recovery and cold recovery in
a separate 384 MiB process. Before the in-place recovery advances the watch
epoch, the probe preserves a quiescent disk copy with full retained history.
Cold recovery loads that copy using the same frozen clock and checks the full
history budget before HA establishes its new watch epoch. The in-place fixture
owns shutdown's drained gate and releases it through the checked access API so
startup can acquire its own gate; the stopped consensus hook remains attached
throughout the handoff. The fixture neither clears application payloads nor
invokes GC itself. Production recovery retains its normal pressure collection
and application-replacement collection policies. Running the native executable
directly covers only the first phase.

The [native retention validation](compaction-native-validation-2026-11-10.json)
passes this workload and both recovery phases at a 384 MiB dynamic heap limit:
93 checkpoints, sampled WAL below 3 MiB, at most two retained artifacts, and
full watch-history retention before recovery. The cold input includes a
130 MB checkpoint followed by a 59 MB journal. This proves the recorded
single-member memory/recovery path; multi-member capture availability remains
unverified, and automatic compaction remains disabled by default.

History's byte estimate includes array headers and whole GC pages occupied by
large strings. On this SBCL build, a 64 KiB base string occupies three 32 KiB
pages, so payload length alone substantially understates its cost. The 96 MiB
history budget therefore retains fewer objects when allocation overhead is
large. Cached weights from older checkpoints are remeasured under the current
policy without mutating published entries. This bounds retained history; live
objects themselves still require memory proportional to the current cluster.

Checkpoint recovery reads encryption metadata first, then streams collections
and history from the same open file. It restores sharing between identical
versions, authenticates entries before discarding them, and applies history
limits while reading. Schema 1/2 and root-field ordering remain supported.
Duplicate known fields, truncated JSON and invalid encrypted data are rejected.
An older checkpoint's understated history weights can advance the retained
history floor during recovery; older watches then receive the usual expired
resource-version response.

Production HA members apply a 16 MiB retained-memory admission budget to
uncommitted application commands. The estimator reserves four bytes per
character for decoding plus allocator/waiter overhead. Wire escaping is a
separate cost: a valid full-size Secret update remains supported. Pending
capacity returns HTTP 503 before WAL append or callback retention; a single
command above the budget returns HTTP 413. Committing the tail releases
admission capacity; committed-log reclamation still needs compaction. Exact
Raft/store recovery barriers and membership changes remain available at capacity.
Generic Raft callers retain their defaults and may supply a command estimator.

Build the native admission probe with
`sbcl --noinform --non-interactive --load scripts/build-proposal-admission-native-harness.lisp`,
then run `python3 scripts/test-proposal-admission-native.py`. In one 384 MiB
process it first verifies plain/encrypted 1 MiB Secret create/update/reopen, then
starts three voters and a non-voting learner over real loopback connections.
With two voters stopped, 2,048 attempted 64 KiB writes must fail without further
WAL/callback growth once the budget fills. A learner-forwarded capacity refusal,
quorum return, new writes and durable reopening of all four members are checked.
Production proposal timeouts remain unchanged. Private logs, binary identity
and a JSON result are retained. This is internal plaintext store/transport
acceptance; production serve, TLS and VM evidence have separate scope.

The [native admission validation](proposal-admission-validation-2026-11-10.json)
records the bounded minority-write tail, forwarded refusal, quorum recovery,
full member reopening, and plain/encrypted 1 MiB Secret boundary. The test uses
four loopback members in one 384 MiB process; it does not certify production
serve, TLS, or VM execution.

