# High availability (pure-Lisp Raft)

The control plane can run with multiple masters on a Raft consensus layer written
from scratch in Common Lisp. It needs **no etcd or external database**. Members
use the same ag-gRPC transport as the rest of gr8s. One Raft implementation runs
under real gRPC and a deterministic in-process simulator. The simulator tests
leader election, log replication, the §5.4.2 commit rule, ordered application,
failover, and partitions. The core includes a durable write-ahead log and
snapshot recovery. Production voters and witnesses recover their durable state
before serving. Automatic application checkpoints are available through an explicit
opt-in; their production acceptance and current limits are described below.

## The consistency plane

gr8s splits state along a **consistency plane**: durable desired state (the
stored API resources) is proposed through Raft so every member converges, while
self-expiring Events and endpoint telemetry stay local. Pod observations and
published status, and node heartbeat/readiness deltas, also replicate so a newly
elected leader can serve current API state. Agents reconnect and re-report after
failover.

What is replicated, and verified to survive a leader kill with its identity
intact: core API resources (including controller-written status, Job accounting,
EndpointSlices, CSR/certificate issuance state), **Pods**, and a Node's assigned
PodCIDR. Events are deliberately local.

## Around the datastore

- **Controllers are leader-gated.** Reconciliation runs only on the leader. A
  follower idles until promotion.
- **Leader-aware HTTP.** A follower answers a mutating API request with a 307 to
  the current leader and preserves the path and query. It returns 503 when it
  does not know the leader. Followers serve reads locally.
- **Agents reconnect across failover.** Given more than one control-plane
  endpoint, a node agent rotates through them on reconnect and resumes against the
  new leader.
- **Membership is dynamic.** Single-member, effective-on-commit changes grow or
  shrink the cluster. A **witness** votes for quorum but never leads, so a
  two-node + witness topology survives one node loss. New members enroll with a
  one-time token, then join with the certificate they receive (a follower
  redirects to the leader).
- **Members use mutual TLS.** Replication carries every Secret, so each member
  needs a certificate from the cluster's own Raft CA, and a message must come from
  the member it names. Worker certificates and tokens aren't accepted, because
  they come from a separate CA and token store. A joiner checks the CA against its
  pin before sending anything. Voters hold the CA key so they can admit
  replacements after a failover; witnesses don't, but their log does hold
  replicated state, which is why it's created with mode `0600`. Member certificates
  last a year and renew themselves in their last 30 days: a voter signs its own,
  and a witness asks a voter, so a witness that stays offline past expiry has to
  enroll again.
- **Voters share the node CA.** A joining control plane receives the cluster's
  node CA when it enrolls, so agents and API clients keep working after a failover.
  Join with a new state directory, because one that already has a different CA is
  refused rather than orphaning the certificates it issued.

## Commands

```sh
# Found a cluster.
gr8s serve --raft-init --raft-id cp1 --raft-port 7000 ...

# On cp1, create a token for each new member. This prints its token and caPin.
gr8s join-token --role control-plane --node-name cp2

# Join through the member that created the token.
gr8s serve --raft-join 10.0.0.1:7000 --raft-id cp2 --raft-port 7000 \
  --raft-node-name cp2 --raft-token "$TOKEN" --raft-ca-pin "$CA_PIN" ...

# A headless quorum tie-breaker (no API, no workloads).
gr8s witness --join 10.0.0.1:7000 --node-name arb --token "$TOKEN" --ca-pin "$CA_PIN"
```

Requested voters first join as learners. Existing voters keep their quorum while
the learner installs application state and catches up. The leader automatically
promotes the learner after it acknowledges application through a current-term
committed boundary. Join success means admission was accepted; promotion follows
asynchronously. Repeating the same Join preserves an already promoted voter;
conflicting endpoints are refused.

HA is **opt-in** for a fresh state directory. Once HA intent is persisted,
restart with the appropriate `--raft-init` or `--raft-join` options; omitting them
is refused before application initialization.

The production Raft port defaults to **7000**. Use `--raft-port` to select another
port, and `--raft-listen` to select the reachable member address. The address
must not be a wildcard bind address. Each HA state directory records its member
ID, Raft address and port, and API URL in `metadata/server-ha-endpoint.json`
before startup patches or application files are opened. Restarts must use the
same identity and endpoints, including after an interrupted first startup. A
changed configuration fails before startup instead of publishing a new address
that other members cannot reach. This release has no endpoint migration command.

The [production recovery validation](production-ha-recovery-validation-2026-11-10.json)
uses three real CLI processes and a witness with authenticated Raft. It verifies
leader loss, rejoin, full restart, preserved credentials and writes with a witness
participating in quorum. That run disables agents and uses the fake runtime; it
does not establish container, VM or conformance acceptance.

## Current limits

Core API resources and Pods replicate as per-key transactions. Pod changes are
staged under the store lock, frozen into a command, and removed from the local
published view before proposing. Committed application publishes the files,
indexes, status checkpoints, and watch transitions. Failed proposals leave the
previous Pod state visible and durable. Speculative revisions are rolled back
before proposing. A durable committed revision clock prevents unused reservation
ceilings from changing resource versions after restart; replicated Node changes
also advance this shared clock.

Pod UID/version preconditions are checked at application time. Status-only
commands cannot create desired objects, and unmentioned Pods are never removed.
Forwarded writes carry the application conflict result separately from consensus
commit. A single store operation can still propose core, Pod, and Node changes
separately; this is not a general transaction across all resource families.
Focused failover tests do not prove arbitrary crash/restart safety.
Production startup restores the persisted application baseline and committed WAL
suffix before opening application services. Raft remains available while a member
waits for committed current-term recovery. A lone member of a saved three-voter
cluster cannot become a new one-voter cluster by restarting. Witness recovery
restores voting state without replicating application payloads. State ownership,
endpoint checks and legacy-state refusal are described in
[Raft member recovery](raft-member-recovery.md).

Node writes now stage private records, defer file changes, and restore committed
pointers, revisions and watch journals before proposing to Raft. Committed deltas
publish Node watch transitions on every replica; lease-only renewals do not create
client events. Runtime-down reports also replicate. Enrollment retries finish a
previously failed Node file write before acknowledging success. See the
[Node transaction validation](node-transactions-validation-2026-11-09.json).
Node deltas include their expected committed record. Apply rejects stale writes
before changing any key, assigns successful public changes revisions in commit
order, and returns those revisions to the author. Follower proposals return the
application conflict result too. Exact retries do not duplicate watch events.
Lease parsing during apply preserves committed readiness independently of replica
wall clocks; the heartbeat monitor retries conflicts and unavailable consensus.
The [concurrency validation](node-conflicts-validation-2026-11-09.json) covers these
paths. Legacy version-1 deltas remain readable; these guarantees require all
members to run the updated implementation. Cross-Node identity and network-claim
uniqueness at apply time remains under `podster-ucm.2.6`.
These transactions do not provide cross-resource atomicity.

The Raft core preserves its vote when stepping down within the same term, and
persists new terms and votes before publishing them in memory. A failed storage
write leaves the preceding term, vote and role intact and sends no vote grant or
election request. This primitive guarantee does not supply the missing production
recovery integration.

Replication retries use bounded batches: at most 64 entries and a conservative
1 MiB command-weight budget. A single oversized existing command travels alone.
Compaction/truncation release discarded backing-array references, and persistence
errors leave their old in-memory log intact. Current-state snapshot callbacks must
capture exactly the applied boundary. See the
[primitive validation record](raft-memory-validation-2026-11-09.json).

Explicit file-backed compaction replaces the WAL with the current hard state,
snapshot, and retained suffix. The replacement is written to a private sibling
file, synchronized, renamed, and followed by a directory synchronization. Failure
before rename preserves the old WAL. Failure after rename closes the backend;
recovery must establish its durable outcome before further writes. The write path
does not reread discarded WAL history, and recovery disables reader evaluation.
The [checkpoint validation record](raft-checkpoint-validation-2026-11-09.json)
includes repeated reclamation, fault injection, and constrained-heap tail recovery.

The core and peer transport support configured snapshot catch-up after explicit
compaction. Snapshots preserve voter, witness and learner membership, peer
addresses and API URLs. Installation retains a matching suffix or discards a
conflicting one, persists the replacement before restoring application state,
and acknowledges only after restore succeeds. Failed restore blocks voting and
the logical clock until a retry succeeds; restore callbacks must be retryable.

Transfer uses ordered chunks containing at most 64 KiB of file data, authenticated
by the existing member mTLS connection. SHA-256 and header checks precede install.
One private partial file is retained per member; retries replace it and abandoned
files expire after 60 seconds. Control-plane transfers use the state filesystem;
other members default to their WAL directory, or a temporary directory for
volatile test members. Each transfer is limited to 16 GiB. A log-only checkpoint
without an application snapshot callback cannot be transferred as application state.
Transfer files live in private, versioned directories with lifetime ownership locks.
Startup and subsequent allocations reclaim abandoned directories while preserving
live transfers. Cleanup does not follow symlinks or remove unknown contents;
legacy unmarked directories are preserved. The
[scratch cleanup validation](raft-snapshot-scratch-validation-2026-11-09.json)
covers process death, live-owner exclusion and native startup.
The [snapshot-transfer validation record](raft-snapshot-transfer-validation-2026-11-09.json)
covers interrupted mTLS transfer, voter/learner catch-up and leadership handoff
with a witness. Run `make test-raft-snapshots` for the focused suite.

## Automatic checkpoints and heap sizing

Automatic checkpointing is disabled by default. Add `--raft-compaction` to each
member's existing `gr8s serve` command to opt in. The flag requires `--raft-init`
or `--raft-join`; retain the member's original state directory, identity and
endpoints. The worker periodically checks size and entry thresholds, captures a
streamed application artifact, and publishes a durable checkpoint. It does not
checkpoint on every write.

The streamed path avoids constructing a complete serialized application in the
Lisp heap. It preserves durable application generations and bounds retained
catch-up data. A returning member can require artifact installation after older
log entries have been compacted. When an updated receiver reports that cached
log replay has filled its retention budget, the leader prefers a newer checkpoint
instead of continuing the replay. Keep members on a version that supports this
capacity hint; it does not raise the memory budget or bypass the recovery gate.
Do not delete WALs, selected generations,
metadata, credentials or snapshot artifacts to reclaim space by hand.

[Constrained-heap validation](async-compaction-validation-2026-11-10.json) covers
large churn, bounded retention, catch-up and cold recovery in an internal
three-process harness. Full production CLI compaction acceptance and VM validation
remain in progress. The opt-in is not a claim that these remaining gates passed.
With checkpointing disabled, the production WAL can continue growing.

The native binary defaults to a 2 GiB Lisp dynamic heap. Override it by placing
`--dynamic-space-size SIZE` before `serve`, with SIZE in MiB. The 384 MiB limits
used in validation are stress-test settings, not a recommended production size.
Size the machine for the Lisp heap plus native allocations, thread stacks,
containerd and workload memory; the Lisp limit is not a total process or host
memory limit.

Scrape each member's authenticated `/metrics` endpoint. Compare
`gr8s_lisp_heap_after_gc_bytes` with `gr8s_lisp_heap_limit_bytes` to distinguish
retained memory pressure from transient allocation. Also watch
`gr8s_raft_retained_bytes`, replication lag, and `gr8s_compaction_error`.
[Control-plane metrics](control-plane-metrics.md) documents their meanings and
sampling limits. Preserve logs and state when recovery remains blocked; repeatedly
restarting or removing files does not establish a safe recovery boundary.

Application snapshots support Raft recovery; they are not an operator backup of
cluster identity, signing/encryption keys or patch state. A complete operator
backup/restore workflow remains separate work. gr8s has not passed Kubernetes
conformance.
