# Selector-scoped kernel tracing

> **Status:** implemented. This records the design; where the shipped behavior
> diverges from the original plan, the text below states what the code does.

## Goal

`gr8s debug trace` accepts programs written in a bpftrace-compatible language and
sends them to nodes hosting Pods selected through the Kubernetes API. The node
agent uses [Whistler](https://github.com/atgreen/Whistler) to JIT-compile the source
to eBPF, load it, and attach its probes in-process. It streams node-labelled
output and removes the probes when the duration expires or the client disconnects.
No separate bpftrace binary, compiler toolchain, or DaemonSet is needed.

The first supported command shape is:

```text
gr8s debug trace --server URL --namespace default --selector app=api \
  --duration 30s 'kprobe:tcp_sendmsg { @[comm] = count(); }'
```

## Client and authorization boundary

The CLI opens an authenticated WebSocket request to the API server. It does not
need direct access to a control-plane process. The endpoint is the namespaced
`traces.gr8s.io` virtual resource. The WebSocket upgrade is a GET
on the wire but is authorized as `create`, like Kubernetes exec and port-forward.
The first client WebSocket frame carries the request body and source, not the URL.
The API uses the same certificate or bearer-token authentication as the
Kubernetes listener. Authorization requires the `create` verb on `traces` in the requested
namespace.  Trace requests are ephemeral and are never stored as API objects.
The CLI accepts a bearer token and CA file directly in the first cut; kubeconfig
credential loading can be added without changing the server protocol.

The request contains a namespace, Kubernetes label selector, bpftrace-compatible source,
and duration.  The server enforces source and duration limits before dispatch.
The CLI prints every received UTF-8 record, always prefixing it with its
`[node]` name, even when only one node participates.  The terminal frame
carries only the counts of completed and failed nodes (`completedNodes`,
`failedNodes`); a disconnected outcome appears only in the server's audit
line, not in the client summary.

## Control-plane coordinator

The API handler resolves the selector against the current Pod store, groups
running, scheduled Pods by node, and starts one ordinary node operation per
node through the existing pending-operation machinery.  This deliberately
reuses its HA routing, bounded output queue, disconnect handling, and
cancellation protocol.

Each request carries only the Pod UIDs assigned to that node.  The authenticated
agent session already binds the receiving node identity; the agent validates
that every requested UID is in its current desired-state cache before touching
BPF.  Node output is framed as JSON lines with `node`, `stream`, and `data`
fields.  The coordinator drains each operation concurrently into one serialized
WebSocket writer.  Client close, timeout, or a fatal coordinator error cancels
every unfinished node operation.

An empty selector result is an error.  A Pod without a node assignment is
silently filtered out of the selection (`running-pod-p` requires one), and a
selected node without a live agent session has its operation queued until the
agent connects — neither case is reported to the client, diverging from the
original intent to surface both explicitly.

## Node trace session

The node agent resolves each requested Pod UID to all live container and sandbox
cgroups.  It derives their cgroup-v2 IDs from each directory's inode (the same
identity returned by `bpf_get_current_cgroup_id`) and injects this predicate into every
kernel probe before [Whistler](https://github.com/atgreen/Whistler) code generation:

```text
cgroup == ID1 || cgroup == ID2 || ...
```

The predicate is ANDed with any predicate already present in the script.  This
is necessary because kprobes and tracepoints attach globally; merely resolving
the selector at the control plane would not scope what executes in-kernel.
The allowed cgroup IDs are fixed when the operation starts.  A container that
restarts during a trace is not silently broadened into the session; the client
can start another trace to include its new cgroup.

Compilation and runtime output are redirected into an operation-owned stream.
The operation emits `ACCEPTED` only after compilation and all attachments have
succeeded.  A worker drains output with the existing acknowledgement window.
Cancellation interrupts the [Whistler](https://github.com/atgreen/Whistler) polling thread; its `unwind-protect`
detaches links and closes every map and program descriptor before the terminal
response is emitted.

## Limits and safety

The first implementation applies hard limits (constants, covered by tests).
The API server enforces the 64 KiB source size, the 30-second default and
300-second maximum duration, and the eight cluster-wide session cap; the node
agent enforces the rest — one trace session per node, 256 matching Pods **per
node** (not cluster-wide), 128 generated programs, and 16 MiB output per node
(see [`trace.lisp`](../src/agent/trace.lisp)). Further restrictions:

- no `uprobe`/`uretprobe`, child-process (`-c`), or arbitrary file input;
- kprobe, kretprobe, tracepoint, kfunc, kretfunc, profile, and interval probes;
- no persistent trace resources or historical output.

[Whistler](https://github.com/atgreen/Whistler) verifier rejection and attach errors are returned verbatim but do not
leave partial attachments behind.  The server records requester identity,
selector, participating nodes, start/end time, and terminal status as a line on
its standard error stream — not in the API audit log — without recording
potentially sensitive trace output.

## Protocol changes

The node protocol gains `OPERATION_KIND_TRACE` and trace-specific request fields:
bpftrace-compatible source, repeated Pod UIDs, and duration milliseconds.  Trace output
uses the existing stdout/stderr `OperationStream` channels, acknowledgement
window, `OperationCancel`, HA `RelayOperation`, and terminal
`OperationResponse`; no second streaming protocol is introduced.

## Explicitly out of scope

Persistent Trace custom resources, stored history, a UI, live selector
membership, cross-node map merging, and uprobes are deferred.  Multi-node
aggregation in this version means one ordered client stream with node identity,
not semantic merging of independent BPF maps.
