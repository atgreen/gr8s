# Raft member recovery

The witness command reopens `raft/witness.log` under its state directory before
accepting peer RPCs. WAL open synchronizes the file and its parent directory
before startup continues. Recovery loads the durable term, vote, snapshot/configuration
and remaining log. It does not treat every retained entry as committed: the live
leader supplies the committed boundary during catch-up. The witness has no
application state machine to replay.

A witness starts with the witness role and completes its join handshake before
starting the election clock. It reuses its saved member certificate on restart;
a new enrollment token is unnecessary when those credentials remain usable.
Restart with the same member ID, state directory and advertised listening
address. The member owns the recovered WAL stream and closes it after its server
and worker threads stop.

The transport API exposes this lifecycle as
`start-raft-member :storage-path PATH :initial-role :witness`. Recovery runs under
the member mutex before constructing the RPC listener. `:storage-path` and an
externally supplied `:storage` are mutually exclusive. Only storage opened via
`:storage-path` is closed by member shutdown; callers retain ownership of storage
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
can supply the corresponding `:validate-fn` callback.

Production `start-ha-control-plane` does not invoke this recovery helper yet.
Genesis/bootstrap needs to establish a durable baseline, and production callers
must coordinate state-directory ownership and membership readiness before
enabling automatic compaction.
