# Control-plane memory metrics

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

All these families are gauges except `gr8s_compaction_completed_total`, which is
a counter scoped to the control-plane instance. Peer labels use configured peer
IDs; no command payloads or error messages are exposed. Peer series disappear
when their links are removed. Replication lag reflects acknowledged log
positions, not confirmed application convergence on that peer. An empty outbox
can mean either a healthy idle peer or an unreachable peer whose latest attempt
finished; it is not a connectivity test.

The collector copies Raft scalars and outbox lengths under member-then-link
locks, reads worker counters under the worker lock, and formats text after
releasing those locks. Worker and Raft samples can represent slightly different
instants. Comparing retained bytes with the configured budget helps identify
write backpressure; sustained apply or peer replication lag needs investigation.
Disk/inode capacity, heartbeat freshness, and reconciliation convergence remain
separate telemetry work under `podster-ucm.6`.
