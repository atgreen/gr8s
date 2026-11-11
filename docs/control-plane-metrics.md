# Control-plane metrics

Scrape the authenticated API endpoint with `kubectl get --raw /metrics`, or use
the same credentials and authorization as other non-resource API requests.
These families describe the process answering the scrape. Scrape every
control-plane member to observe each member's memory independently.

| Metric | Type | Meaning |
|---|---|---|
| `gr8s_lisp_heap_used_bytes` | Gauge | Current SBCL dynamic heap usage, including garbage awaiting collection |
| `gr8s_lisp_heap_limit_bytes` | Gauge | Configured dynamic heap limit |
| `gr8s_lisp_heap_after_gc_bytes` | Gauge | Usage immediately after the latest observed GC; absent until a GC has been observed |
| `gr8s_lisp_allocated_bytes_total` | Counter | Bytes allocated by Lisp since program startup |
| `gr8s_lisp_gc_cpu_seconds_total` | Counter | CPU time spent in GC since process startup; not elapsed pause duration |
| `gr8s_watch_history_bytes{kind=...}` | Gauge | Estimated retained history bytes for each of the three fixed kinds |
| `gr8s_watch_history_entries{kind=...}` | Gauge | Retained history entries for each kind |

The `kind` label has exactly three possible values: `pods`, `resources`, and
`nodes`. Object names, namespaces, keys, and payloads are not labels. Resource
history estimates include the allocator overhead used by its retention budget;
the estimates for different history kinds follow their respective accounting.

Dynamic heap usage excludes native buffers, thread stacks, mapped files, and
other process allocations. Use `process_resident_memory_bytes` alongside these
metrics when sizing machines. High post-GC usage indicates retained objects;
high allocation rate with lower post-GC usage indicates allocation churn.
A starting heap-pressure query is
`gr8s_lisp_heap_used_bytes / gr8s_lisp_heap_limit_bytes`; sustained high
`gr8s_lisp_heap_after_gc_bytes / gr8s_lisp_heap_limit_bytes` needs investigation.
`rate(gr8s_lisp_gc_cpu_seconds_total[5m])` measures GC CPU consumption.

A scrape does not force a collection or serialize the datastore. History counts
and byte totals are sampled together under the raw store mutex without opening
a store transaction. Heap counters are sampled separately, so they are not an
atomic application snapshot. History series are omitted when no store is
attached. Counters reset with the process. Restoring an application or starting
a new watch epoch can reduce the history gauges.

These metrics complement API server, scheduler, dataplane, and process metrics.
Raft health, disk/inode capacity, and reconciliation convergence are tracked
separately under `podster-ucm.6`; these memory families do not establish that
broader telemetry work as complete.

## Raft and checkpoint worker

HA API listeners additionally expose these local families. Single-node listeners
omit them. A scrape reads local state; it does not contact peers or establish
quorum. A leader gauge of one alone is not proof that writes can commit.

| Metric | Meaning |
|---|---|
| `gr8s_raft_term` | Current local Raft term |
| `gr8s_raft_is_leader` | One while this member believes it is leader |
| `gr8s_raft_commit_index` | Local committed index |
| `gr8s_raft_applied_index` | Local applied index |
| `gr8s_raft_snapshot_index` | Durable snapshot index |
| `gr8s_raft_apply_lag_entries` | Committed entries not yet applied |
| `gr8s_raft_retained_entries` | Entries retained in the local log |
| `gr8s_raft_uncommitted_entries` | Entries beyond the local commit index |
| `gr8s_raft_retained_bytes` | Retained command estimate using the same estimator as admission |
| `gr8s_raft_retained_limit_bytes` | Retained-log admission budget; omitted when no policy is configured |
| `gr8s_raft_catchup_cache_bytes` | Physical disk bytes in anonymous committed-prefix segments |
| `gr8s_raft_catchup_cache_segments` | Open anonymous segment descriptors |
| `gr8s_raft_catchup_cache_limit_bytes` | Disk cache budget; omitted when disabled |
| `gr8s_raft_catchup_cache_error` | One after a cache error, cleared by a successfully retained segment |
| `gr8s_raft_peer_replication_lag_entries{peer=...}` | Leader's last index minus peer acknowledged match index; omitted on followers |
| `gr8s_raft_peer_outbox_messages{peer=...}` | Queued plus sender-owned messages on each configured peer link |
| `gr8s_compaction_completed_total` | Successful checkpoints through the local worker/manual worker API |
| `gr8s_compaction_in_flight` | One while worker capture or publication is running |
| `gr8s_compaction_error` | One while the worker retains an error since its last successful checkpoint |

Checkpoint phase measurements use the four fixed `phase` labels `freeze`,
`capture`, `retain`, and `publish`:

| Metric | Meaning |
|---|---|
| `gr8s_compaction_phase_observations_total{phase=...}` | Executed attempts, including failures and superseded publications |
| `gr8s_compaction_phase_duration_seconds_total{phase=...}` | Cumulative monotonic execution time |
| `gr8s_compaction_phase_duration_seconds_max{phase=...}` | Longest execution since control-plane startup |
| `gr8s_compaction_phase_duration_seconds_last{phase=...}` | Latest execution time |

`freeze` measures the application-view copy under the member lock; `capture`
measures artifact serialization; `retain` measures registry retention and
validation; `publish` measures prepared Raft publication, including disk cache
and WAL persistence, under the member lock. Gate draining, waiting to acquire
locks, digest calculation, artifact reaping, and cleanup are outside these phase
timings. They are execution durations, not a complete measure of request latency
or heartbeat interruption. GC pauses during a phase contribute to its elapsed
time. All four labels are emitted with zero values before observation.

Each phase also reports `gr8s_compaction_phase_gc_seconds_total`,
`gr8s_compaction_phase_gc_seconds_max`, and
`gr8s_compaction_phase_gc_seconds_last`, with the same `phase` labels. These
measure changes in SBCL's process-wide cumulative GC CPU time during the phase.
They do not directly measure stop-the-world pause durations.
Other threads can trigger that GC. Nested or overlapping intervals count the
same GC time, so do not add these series to estimate total process GC time or
subtract them from wall time to infer exclusive compaction CPU time.

The `gr8s_compaction_member_lock_` families measure compaction's member-lock
critical sections, using the fixed `section` labels `check`, `freeze`, `publish`,
and `resume`. Each has the suffixes `observations_total`,
`duration_seconds_total`, `duration_seconds_max`, `duration_seconds_last`,
`gc_seconds_total`, `gc_seconds_max`, and `gc_seconds_last`.

- `check` includes the initial trigger and readiness checks.
- `freeze` includes trigger rechecking, prepared-boundary construction, the
  application-view copy, and gate reopening.
- `publish` includes readiness rechecking, checkpoint publication, artifact
  reaping and successful-checkpoint bookkeeping.
- `resume` includes the cleanup path's readiness check and gate reopening.

Timing starts after acquiring the member lock and ends after the section body,
including abnormal exits. It excludes acquisition wait and the timing-counter
update just before lock release. These measurements cover the compaction pass;
they do not measure every member-lock holder, worker startup/shutdown, outer
barrier waits, gate-drain time, thread scheduling delays or end-to-end heartbeat
latency. GC deltas have the same process-wide attribution limits as phase GC
measurements. All section labels emit zero before their first observation.

All these families are gauges except the phase and member-lock observation,
execution-time and GC-time totals and
`gr8s_compaction_completed_total`, which are counters scoped to the control-plane instance. Peer labels use
configured peer IDs; no command payloads or error messages are exposed. Peer series disappear
when their links are removed. Replication lag reflects acknowledged log
positions, not confirmed application convergence on that peer. An empty outbox
can mean either a healthy idle peer or an unreachable peer whose latest attempt
finished; it is not a connectivity test.

The collector copies Raft scalars and outbox lengths under member-then-link
locks, reads worker counters under the worker lock, and formats text after
releasing those locks. Worker and Raft samples can represent slightly different
instants. Comparing retained bytes with the configured budget helps identify
write backpressure; sustained apply or peer replication lag needs investigation.
Peer receipt freshness uses current configured members, including learners:

| Metric | Meaning |
|---|---|
| `gr8s_raft_peer_received_messages_total{peer=...}` | Recognized current-term messages whose dispatch returned normally; counter for the physical link lifetime |
| `gr8s_raft_peer_receive_observed{peer=...}` | One after such a receipt in the current local term; zero before observation or after a term change |
| `gr8s_raft_peer_last_receive_age_seconds{peer=...}` | Monotonic age of the latest such receipt; omitted when the observation gauge is zero |

The production Deliver handler authenticates the sender before dispatch. Stale
terms, unconfigured peers, pre-vote traffic, unknown types and dispatch errors do
not refresh these observations. A received current-term vote request may be
denied and an AppendEntries request may fail its log-match check; both still
show that the peer sent a message. This is receipt telemetry, not proof of a
successful write, quorum reachability, application convergence or readiness.

Counters and timestamps reset on process restart or physical link replacement.
A retained old link produces no receipt series while its member is outside the
current configuration. If the same link is reused after readmission, its counter
and last current-term receipt can remain. No per-message or object labels are
allocated. Only local monotonic time is used; remote wall clocks are irrelevant.

## State filesystem capacity

Each API process with a store reports the filesystem holding its stable state
directory. These unlabelled gauges are local to the answering process:

| Metric | Meaning |
|---|---|
| `gr8s_datastore_filesystem_stats_available` | One when the current filesystem sample succeeded, zero when it failed |
| `gr8s_datastore_filesystem_capacity_bytes` | Total filesystem capacity |
| `gr8s_datastore_filesystem_available_bytes` | Bytes available to unprivileged allocation, excluding reserved blocks |
| `gr8s_datastore_filesystem_used_bytes` | Bytes used across the filesystem |
| `gr8s_datastore_filesystem_inodes` | Total filesystem inodes |
| `gr8s_datastore_filesystem_inodes_free` | Free filesystem inodes |
| `gr8s_datastore_filesystem_inodes_used` | Used filesystem inodes |

Sampling uses `statvfs`; it does not walk directories or enter a datastore
transaction. On failure, capacity and inode series are omitted rather than
reported as zero. A process without a store omits the entire set. Filesystems
that report no inode accounting can return zero inode totals; avoid dividing by
zero when building alerts.

These values include other applications using the same filesystem. They are not
the size of gr8s's data and do not account for separate filesystems mounted below
the state directory. Scrape each member and monitor any additional mounts
separately. Falling available bytes or free inodes can prevent WAL and snapshot
publication even while the Lisp heap has space. Check
`gr8s_datastore_filesystem_stats_available == 0` separately from low-capacity
alerts so failed sampling cannot appear healthy.

## Datastore file growth

The API process also samples three known files. The `file` label has exactly
these values:

| File label | Location |
|---|---|
| `core_checkpoint` | `objects/state.json` in the selected application generation |
| `core_journal` | `objects/journal.jsonl` in the selected application generation |
| `raft_wal` | `raft/control-plane.log` in the stable member state directory |

| Gauge | Meaning |
|---|---|
| `gr8s_datastore_file_stats_available{file=...}` | One when metadata was sampled, including a confirmed absence; zero on failure |
| `gr8s_datastore_file_present{file=...}` | One for an existing regular file, zero for a confirmed absence; omitted on measurement failure |
| `gr8s_datastore_file_size_bytes{file=...}` | Apparent file length; emitted only for an existing regular file |

A missing core journal after checkpointing is normal. A standalone server has
no production Raft WAL. These absences have availability one and presence zero,
with no size sample. Permission failures and non-regular paths produce
availability zero rather than a false zero-byte file. A process without a store
omits these families.

The collector copies the current paths under the raw store mutex, then performs
at most three metadata queries outside that lock. It reads no file contents and
scans no directories. The samples are not an atomic filesystem snapshot;
checkpointing and generation changes can occur between queries. File lengths
can shrink after checkpointing, so these gauges are not cumulative write counts.

Use these series to identify growth in the main core and Raft files, alongside
filesystem availability and Raft retention metrics. They exclude snapshot
artifacts, catch-up cache files, temporary files, Pod/Node records and workload
logs. Apparent length also differs from allocated disk blocks for sparse files.
They are not total gr8s disk usage.

## Reconciliation execution and generation progress

Once `serve` attaches its reconciliation worker, its local API exposes these
unlabelled families. Counters reset when the worker is recreated:

| Metric | Type | Meaning |
|---|---|---|
| `gr8s_reconciliation_attempts_total` | Counter | Pass attempts admitted by the leader gate |
| `gr8s_reconciliation_completed_total` | Counter | Passes that returned normally |
| `gr8s_reconciliation_failures_total` | Counter | Passes that raised an error or unwound abnormally |
| `gr8s_reconciliation_in_flight` | Gauge | Passes currently executing, normally zero or one |
| `gr8s_reconciliation_worker_running` | Gauge | One while the worker thread is alive and not stopping |
| `gr8s_reconciliation_duration_seconds_total` | Counter | Cumulative elapsed pass time, including failed attempts |
| `gr8s_reconciliation_duration_seconds_last` | Gauge | Latest elapsed pass duration |
| `gr8s_reconciliation_duration_seconds_max` | Gauge | Longest pass duration since worker creation |
| `gr8s_reconciliation_last_success_age_seconds` | Gauge | Monotonic time since the latest normally returned pass; absent before the first one |

Duration and in-flight measurements include waiting for patch-domain admission.
Followers normally keep a running worker but skip passes, so their counters can
stay at zero and their last-success age can grow. Apply stale-pass alerts to the
current leader; use Raft leadership metrics to interpret each member's sample.
Single-node servers have no Raft leadership series.

A completed pass does not establish readiness: per-Pod errors can be handled
inside a pass, and an unavailable runtime can cause Pod synchronization to skip.
Use Pod conditions and workload status to assess whether workloads are ready.

Two additional gauges describe controller observation of desired specifications:

| Metric | Meaning |
|---|---|
| `gr8s_workload_objects{kind=...}` | Number of locally stored workload objects of a fixed kind |
| `gr8s_workload_generation_lag_objects{kind=...}` | Number whose `status.observedGeneration` is missing or older than `metadata.generation` |

The five `kind` values are `deployments`, `replicasets`,
`replicationcontrollers`, `statefulsets`, and `daemonsets`. All five are emitted,
including zero counts. Jobs, CronJobs and custom controllers are outside these
families. A controller can observe the latest generation while replicas remain
unready; generation lag is not a ready-replica count.

The generation collector reads existing scalar metadata under the raw store
mutex. Its work scales with the local resource index; it neither encodes payloads
nor opens a datastore transaction, including while application access is gated.
Names, namespaces, payloads and UIDs are not labels. Followers report their local
replicated view, which can lag the leader. Loop measurements use the worker mutex
and are rendered after releasing it; the loop and generation samples are not an
atomic application snapshot. Processes without the corresponding worker or store
omit those families.

Generation maintenance exposes `gr8s_generation_reaped_files_total` (application
files reclaimed, excluding directory and retirement metadata cleanup),
`gr8s_generation_reclamation_worker_up`, and
`gr8s_generation_reclamation_error` (the last attempt failed). These series have
no generation or path labels. The worker runs on HA members even with automatic
compaction disabled; it handles retired application generations independently of
local checkpoint creation. Unknown files and links remain protected and are not
counted as reclaimed. A successful attempt clears the error gauge, including an
idle attempt that finds no eligible generation. See
[application generation maintenance](store-snapshot-artifacts.md#recovering-an-interrupted-application-selection).
