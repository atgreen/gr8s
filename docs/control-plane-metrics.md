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
