# Raft member recovery

The witness command reopens `raft/witness.log` under its state directory before
accepting peer RPCs. WAL open synchronizes the file and its parent directory
before startup continues. Recovery loads the durable term, vote, snapshot/configuration
and remaining log. It does not treat every retained entry as committed: the live
leader supplies the committed boundary during catch-up. The witness has no
application state machine to replay.

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

The internal `gr8s.resources::start-store-member-from-wal` function recovers a
store from a WAL with a retained application artifact. It drains application
access, acquires the outer writer barriers and installs callbacks before the
peer listener is constructed. Recovery validates the WAL's configuration and
artifact reference, restores that exact baseline and only then attaches the
remaining log. Selected application files can contain later updates; restoring
the retained baseline provides the starting state for deterministic suffix replay.
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
ownership across every administrative command or enable production voter WAL
recovery.

HA startup also persists `metadata/server-ha-endpoint.json`, binding member ID,
Raft host/port and API URL to the state directory before startup patch evaluation.
The production Raft default is port 7000; internal transport callers may still
request an ephemeral port for isolated tests. Restart with the original endpoints.
Changes and malformed or nonprivate descriptors are refused before application
initialization. Endpoint publication does not enable production WAL recovery.

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
snapshot/interrupted-join acceptance remains under `podster-ucm.2.9`; production
durable voter recovery remains disabled pending complete startup integration.

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

The broader streaming error-path audit and long-running native memory plateau
remain under `podster-ucm.2.10`. Native leader handoff, authenticated transport,
VM execution and production voter startup remain separate work; these runs do
not establish their completion.
