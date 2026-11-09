# High availability (pure-Lisp Raft)

The control plane can run multi-master on a Raft consensus layer written from
scratch in Common Lisp — **no etcd, no external database**. Members talk over the
same ag-gRPC transport as everything else. The Raft core (leader election, log
replication, the §5.4.2 commit rule, apply-once-in-order) runs under a
deterministic in-process simulator for failover/partition tests *and* under real
gRPC, from one implementation. The core provides a durable write-ahead-log backend
and snapshot/recovery primitives. Wiring durable recovery into every production
role, and automatic snapshot compaction/catch-up, remain active work; see the
scope below.

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

- **Controllers are leader-gated** — reconciliation runs only on the leader; a
  follower idles until promoted.
- **Leader-aware HTTP** — a follower answers a mutating API request with a 307 to
  the current leader (preserving path and query), or 503 when no leader is known;
  reads are served locally.
- **Agents reconnect across failover** — given more than one control-plane
  endpoint, a node agent rotates through them on reconnect and resumes against the
  new leader.
- **Membership is dynamic** — single-member, effective-on-commit changes grow or
  shrink the cluster; a **witness** votes for quorum but never leads, so a
  two-node + witness topology survives one node loss. New members enroll with a
  one-time token, then join with the certificate they receive (a follower
  redirects to the leader).
- **Members use mutual TLS** — replication carries every Secret, so each member
  needs a certificate from the cluster's own Raft CA, and a message must come from
  the member it names. Worker certificates and tokens aren't accepted, because
  they come from a separate CA and token store. A joiner checks the CA against its
  pin before sending anything. Voters hold the CA key so they can admit
  replacements after a failover; witnesses don't, but their log does hold
  replicated state, which is why it's created with mode `0600`. Member certificates
  last a year and renew themselves in their last 30 days: a voter signs its own,
  and a witness asks a voter, so a witness that stays offline past expiry has to
  enroll again.
- **Voters share the node CA** — a joining control plane receives the cluster's
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

HA is **opt-in**: with no `--raft-*` flag, `gr8s serve` runs exactly as the
single-node path always has — no Raft member starts. An HA acceptance smoke test
stands up a three-member cluster over HTTP, creates a resource through the leader,
kills the leader, and requires the survivors to keep serving the committed data
and accept new writes.

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
Node mutations still need the same staging guarantees, tracked separately under
`podster-ucm.2.3`.

The production voter startup does not yet attach/recover the core's durable Raft
backend. Witnesses write a private WAL but do not yet recover its previous hard
state and log on startup. These are active correctness gaps under
`podster-ucm.2.1`, not established crash-safety guarantees. The core's tested WAL
and snapshot helpers alone do not close those integration gaps.

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

Production store snapshot capture/restore integration and automatic compaction remain
under `podster-ucm.11`. An internal [streamed artifact writer](store-snapshot-artifacts.md)
now captures and validates application records without whole-store materialization; transport,
durable restore and generation ownership are still pending. The generic callback path reconstructs an opaque Lisp application
snapshot on receipt: bounded RPC chunks alone do not bound that reconstruction's
heap usage. Large production stores need streamed application artifacts before
automatic compaction can be enabled. The retained production log is therefore not yet bounded over
the lifetime of a cluster. Operator backup/restore is separate work under
`podster-ucm.3`. gr8s has not passed Kubernetes conformance.
