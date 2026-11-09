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

This does not yet enable durable application-voter recovery in
`start-ha-control-plane`. Voters must coordinate their already-durable application
files with an exact applied Raft boundary, restore artifacts and suffix replay.
Simply attaching this WAL API to a loaded store would risk replaying effects
against the wrong application state. Production snapshot transport and automatic
compaction remain unfinished as well.
