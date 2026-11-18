# miniwit

**miniwit is a tiny Go program with minimal memory/CPU/storage needs.** You run
two full [gr8s](https://github.com/atgreen/gr8s) master nodes plus miniwit as
the third Raft-cluster participant — it provides the deciding vote for leader
election and split-brain scenarios without running the control-plane dataplane.
It cross-compiles to FreeBSD and is small enough to run on a home router
(pfSense).

miniwit joins a gr8s HA control plane as a **`:witness`** — a voting Raft member
that contributes to quorum but runs **no dataplane** (no containerd, eBPF,
kubelet, or application store). It cross-compiles to `freebsd/amd64` (and
`arm64`, `linux/*`) from any host, so a small always-on box can be the
odd-numbered third vote.

> **Status.** The wire codec, the mutual-TLS RaftTransport (server +
> fire-and-forget Deliver clients), enrollment + join (with leader redirect),
> the non-campaigning follower core, snapshot-chunk handling (including the
> witness config-snapshot format), and byte-bounded log compaction are
> implemented and unit/integration-tested — including a real mutual-TLS Deliver
> round-trip between two Go endpoints. What is *not* yet done: certificate
> renewal (`RenewMember`) and the end-to-end test that confirms wire fidelity
> against a live gr8s cluster. **Do not point this at a production cluster**
> until it has run against a throwaway gr8s cluster. See *Roadmap* below.

## Why a witness can be this small

A gr8s witness is a full **voting** member for quorum purposes (gr8s counts
`:voter` and `:witness` identically — `src/raft/transport/cluster.lisp`), but it
holds **no application state machine**. That lets this implementation be a
deliberately minimal Raft participant:

- It **grants votes** and **acknowledges AppendEntries**, so the real voters can
  always reach a majority as long as one of them is alive.
- It **never campaigns.** A witness that cannot serve the application must never
  become leader, and a non-campaigning follower is still fully sufficient for
  liveness: if a voter dies, the surviving voter campaigns and the witness's vote
  elects it. So this program implements only the four *receive* handlers and the
  four *reply* messages — no leader, candidate, or replication-sending logic.
- It **persists the Raft log for quorum but never applies commands.** Log entries
  are stored opaquely `(index, term, command)` so the witness can answer the
  leader's log-match checks and report `match-index`; it never interprets a
  command, because it has nothing to apply them to.

## The protocol (reverse-engineered from gr8s + cl-raft)

### Transport: `RaftTransport` gRPC over mutual TLS

Defined in `proto/gr8s/node/v1/node.proto` (vendored). Methods a witness uses:

| RPC | Direction | Role |
|-----|-----------|------|
| `EnrollMember` | witness → any member | Exchange a one-time join token for a member certificate. `role="witness"`. Returns only `certificate` + `ca_certificate` (witnesses get **no** CA key, node CA, or SA signing key — voters only). |
| `Join` | witness → any member | Ask to be admitted. A follower replies `accepted=false` with the leader's address (redirect); the leader proposes the membership change and returns the peer **address book**. |
| `Deliver(RaftEnvelope) → RaftAck` | both ways | Carries **one** serialized Raft message. Fire-and-forget: replies come back as the peer's own `Deliver` calls. |
| `Propose`, `RelayOperation`, `PatchManagement`, `RenewMember`, … | served by witness | **Stub.** A witness never originates writes, serves nodes, or issues certs. `Propose` → not-leader; the operation/patch calls → rejected; `Join`/`EnrollMember` served by the witness → rejected (it is never leader, holds no CA). `RenewMember` (self-renewal, client side) is needed eventually for cert rotation. |

`RaftEnvelope = { protocol_version, payload }`. `payload` is the Raft message,
encoded as below. Every call is authenticated by the peer's mTLS client
certificate *before* the payload is decoded (`member.lisp`).

### Payload codec: readable Lisp forms

`payload` is a Raft message **plist** printed with `prin1` under
`with-standard-io-syntax` plus `*print-readably*`/`*print-circle*`/`*print-pretty*`
bound off, then UTF-8 encoded; the reader uses `*read-eval* nil`
(`src/raft/transport/member.lisp: raft-lisp-message->octets`). Because
`with-standard-io-syntax` upcases symbols, keywords print as `:TYPE`,
`:REQUEST-VOTE`, and booleans as `T` / `NIL`. Log entries are flattened to
`(index term command)` triples.

Implemented and **validated against SBCL output** in `internal/lispwire`
(`wire_test.go` round-trips the real golden strings byte-for-byte).

Artifact/snapshot chunks use a separate bounded **binary** frame
(`GR8SCK01` magic + three u32 lengths + header/envelope/data) — see
`raft-message->octets`. A witness's config-only snapshot can also arrive as a
Lisp form whose `:DATA` is an octet vector; the receiver accepts either
(`internal/raftcore/snapshot.go`).

### Messages a witness handles

Incoming (→ reply), with their plist fields (from `cl-raft/src/core.lisp`):

- `:REQUEST-VOTE` `:term :from :last-log-index :last-log-term :leader-transfer`
  → `:REQUEST-VOTE-REPLY :term :from :granted`. Grant iff `term == currentTerm`,
  `votedFor ∈ {nil, candidate}`, and the candidate's log is at least as
  up-to-date (§5.4.1). On grant: persist `(term, votedFor)`, reset election timer.
- `:PRE-VOTE` `:term :from :last-log-index :last-log-term`
  → `:PRE-VOTE-REPLY :term :pre-term :from :granted`. Grant iff not leader, our
  leader-contact timer has expired, `msg.term > currentTerm`, and log up-to-date.
  Changes **no** persistent state.
- `:APPEND-ENTRIES` `:term :from :prev-log-index :prev-log-term :entries :leader-commit :read-seq`
  → `:APPEND-ENTRIES-REPLY :term :from :read-seq :success :match-index` (plus
  `:next-index`/`:applied-index`/`:capacity-limited` on the relevant paths).
  Step down if stale; reject if `term < currentTerm` or the log-match check fails;
  else append/overwrite, advance `commitIndex = min(leader-commit, last-new)`.
- `:INSTALL-SNAPSHOT` `:term :from :last-index :last-term :state`
  → `:INSTALL-SNAPSHOT-REPLY :term :from :success :match-index`. The transport
  reassembles the binary chunks (and the witness config-snapshot form) into the
  boundary before it reaches the handler.

### Durable state (fsync before ack — Raft safety)

- **Hard state:** `currentTerm`, `votedFor` — persisted *before* replying to a
  vote or accepting a higher term.
- **Log:** entries `(index, term, command-blob)` — persisted *before* a successful
  AppendEntries reply.
- **Snapshot boundary:** `lastIncludedIndex`, `lastIncludedTerm` (the application
  payload is discarded — a witness has nothing to restore it into; only the
  boundary matters for log matching).

The on-disk log is compacted once it passes a byte bound, keeping only the most
recent slice. Both bounds are tunable with `-max-log-bytes` and
`-retain-log-bytes` (see flags below).

## Build

```sh
go test ./...
go build -o miniwit ./cmd/miniwit                                   # host
GOOS=freebsd GOARCH=amd64 go build -o miniwit ./cmd/miniwit         # pfSense/FreeBSD
```

Pure Go (`CGO_ENABLED=0` automatically when cross-compiling): the FreeBSD binary
is static and self-contained.

## Run

A single invocation enrolls for a member certificate, starts the RaftTransport
server, and joins the cluster; from then on it follows the leader. Point it at
any current cluster member and give it a one-time witness join token (from
`gr8s join-token --role witness`):

```sh
miniwit \
  -join-address master-1.example:7000 \
  -join-token   <one-time-token> \
  -ca-pin       <sha256-hex-of-cluster-CA> \
  -member-id    witness-1 \
  -node-name    witness-1 \
  -advertise    witness-1.example:7000
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-join-address` | — | `host:port` of a current cluster member to enroll and join through. |
| `-join-token` | — | One-time Raft join token (from `gr8s join-token --role witness`). |
| `-ca-pin` | — | SHA-256 hex fingerprint of the cluster CA (the join token's `caPin`). |
| `-member-id` | — | This witness's member id (becomes its certificate CN). |
| `-node-name` | — | The node name the join token is bound to. |
| `-listen` | `0.0.0.0:7000` | `host:port` to serve RaftTransport on. |
| `-advertise` | `-listen` | `host:port` peers use to reach this witness. |
| `-join-role` | `witness` | Membership role: `witness`, or `learner` (no quorum impact, for safe validation). |
| `-data-dir` | `/var/lib/miniwit` | Directory for credentials and the Raft log. |
| `-max-log-bytes` | `4 MiB` | Compact the on-disk log once it passes this many bytes. |
| `-retain-log-bytes` | `1 MiB` | Bytes of the most recent log to keep after compaction. |
| `-version` | — | Print version and exit. |

## Operational caveats (read before deploying)

- A witness's vote **decides quorum**. A bug here (voting twice in a term, acking
  an entry it did not durably store) is a cluster-wide safety problem, not a local
  one. This is why the codec is validated against real output and why the follower
  core must be tested exhaustively before it joins a real cluster.
- On pfSense specifically: firmware upgrades wipe non-package files, and you are
  tying quorum to your firewall. A tiny dedicated always-on box is safer.

## Roadmap

- ① wire codec ✅ — `internal/lispwire`, validated byte-for-byte against SBCL.
- ② mTLS transport + Deliver server/client ✅ — `internal/transport`
  (`tls.go`, `server.go`, `client.go`); integration-tested over real mutual TLS.
- ③ EnrollMember + Join with leader redirect ✅ — `internal/transport`
  (`enroll.go`, `join.go`). CSR/cert logic matches gr8s; the live handshake is
  confirmed in ⑦.
- ④ non-campaigning follower core ✅ — `internal/raftcore`; the four handlers
  mirror `cl-raft/src/core.lisp`, durable hard-state + log, unit-tested.
- ⑤ snapshot chunk reassembly + boundary install ✅ — `internal/raftcore`
  (`snapshot.go`), including the witness config-snapshot form and byte-bounded
  log compaction (`-max-log-bytes`/`-retain-log-bytes`).
- ⑥ certificate renewal (`RenewMember`) — **pending**.
- ⑦ end-to-end test against a throwaway 2-voter + 1-witness cluster — **pending**;
  this is where enroll/join wire fidelity is finally confirmed. Required before
  any production use.
