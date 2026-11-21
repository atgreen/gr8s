# miniwit

**miniwit is a tiny Go program with minimal memory/CPU/storage needs.** You run
two full [gr8s](https://github.com/atgreen/gr8s) master nodes plus miniwit as
the third Raft-cluster participant — it provides the deciding vote for leader
election and split-brain scenarios without running the control-plane dataplane.
It cross-compiles to any platform Go targets, so you can put the third vote
almost anywhere: a small cloud VM, a Raspberry Pi, or even a home router (the
author runs it on a FreeBSD pfSense router).

miniwit joins a gr8s HA control plane as a **`:witness`** — a voting Raft member
that contributes to quorum but runs **no dataplane** (no containerd, eBPF,
kubelet, or application store). It is pure Go, so it cross-compiles from any
host to any `GOOS`/`GOARCH` Go supports, and any small always-on box can be
the odd-numbered third vote.

> **Status.** The wire codec, the mutual-TLS RaftTransport (server +
> fire-and-forget Deliver clients), enrollment + join (with leader redirect),
> the follower core, snapshot-chunk handling (including the witness
> config-snapshot format), and byte-bounded log compaction are implemented and
> unit/integration-tested — including a real mutual-TLS Deliver round-trip
> between two Go endpoints. So is certificate renewal. It is the witness of a
> live two-voter gr8s cluster in ongoing use, where it has been through
> enrollment, join, replication, a five-minute leader outage in which its vote
> elected the other voter, a restart, and a renewal signed by a real voter.
> What is *not* yet done is an automated end-to-end test against a throwaway
> cluster that anyone can re-run. The stand-in (below) is newer still: it is tested
> against a scripted voter and its messages match SBCL's output byte for byte,
> but it has not yet run against a real gr8s voter. See *Roadmap* below.

## Why a witness can be this small

A gr8s witness is a full **voting** member for quorum purposes (gr8s counts
`:voter` and `:witness` identically — `src/raft/transport/cluster.lisp`), but it
holds **no application state machine**. That lets this implementation be a
deliberately minimal Raft participant:

- It **grants votes** and **acknowledges AppendEntries**, so the real voters can
  always reach a majority as long as one of them is alive.
- It **never campaigns on its own.** It has no election timer. If a voter dies,
  the surviving voter campaigns and the witness's vote elects it.
- It **stands in when its own log is what blocks that election.** A witness
  acknowledges an entry once it is stored; a voter must also apply it. So when a
  leader fails under write load, the surviving voter is often an entry behind the
  witness. The witness must refuse that voter (the entry may be committed), and
  then nobody could win until the failed leader returned. Instead the witness
  gets itself elected, sends the voter the entries it lacks, and tells the first
  voter that holds its whole log to take over (`TIMEOUT-NOW`). This is ordinary
  Raft, and mirrors `raft-witness-should-stand-in-p` in cl-raft. While it leads
  it accepts no proposal, appends nothing (not even the usual no-op), and
  commits nothing; it stands down after one election timeout if no voter has
  replaced it, and stands in again when a voter next asks.
- It **persists the Raft log for quorum but never applies commands.** Log entries
  are stored opaquely `(index, term, command)` so the witness can answer the
  leader's log-match checks and report `match-index`. The one command it reads
  is a committed `:RAFT-CONFIG`, for the membership: it has to know who the
  voters and witnesses are to count a majority when it stands in.

## The protocol (reverse-engineered from gr8s + cl-raft)

### Transport: `RaftTransport` gRPC over mutual TLS

Defined in `proto/gr8s/node/v1/node.proto` (vendored). Methods a witness uses:

| RPC | Direction | Role |
|-----|-----------|------|
| `EnrollMember` | witness → any member | Exchange a one-time join token for a member certificate. `role="witness"`. Returns only `certificate` + `ca_certificate` (witnesses get **no** CA key, node CA, or SA signing key — voters only). |
| `Join` | witness → any member | Ask to be admitted. A follower replies `accepted=false` with the leader's address (redirect); the leader proposes the membership change and returns the peer **address book**. |
| `Deliver(RaftEnvelope) → RaftAck` | both ways | Carries **one** serialized Raft message. Fire-and-forget: replies come back as the peer's own `Deliver` calls. |
| `Propose`, `RelayOperation`, `PatchManagement`, `RenewMember`, … | served by witness | **Stub.** A witness never originates writes, serves nodes, or issues certs. `Propose` → not-leader, also while it stands in; the operation/patch calls → rejected; `Join`/`EnrollMember` served by the witness → rejected (it admits nobody, holds no CA). `RenewMember` is used from the client side only (see *Certificate renewal*). |

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

A higher `:term` in any message but `:PRE-VOTE` (whose term is hypothetical) is
adopted first: the vote is cleared, any stand-in ends, and the new term is on
disk before anything is sent.

Incoming (→ reply), with their plist fields (from `cl-raft/src/core.lisp`):

- `:REQUEST-VOTE` `:term :from :last-log-index :last-log-term :leader-transfer`
  → `:REQUEST-VOTE-REPLY :term :from :granted`. Grant iff `term == currentTerm`,
  `votedFor ∈ {nil, candidate}`, and the candidate's log is at least as
  up-to-date (§5.4.1). On grant: persist `(term, votedFor)`, reset election timer.
- `:PRE-VOTE` `:term :from :last-log-index :last-log-term`
  → `:PRE-VOTE-REPLY :term :pre-term :from :granted`. Grant iff not leader, our
  leader-contact timer has expired, `msg.term > currentTerm`, and log up-to-date.
  Changes **no** persistent state. A refusal for the last reason alone starts
  the stand-in (below).
- `:APPEND-ENTRIES` `:term :from :prev-log-index :prev-log-term :entries :leader-commit :read-seq`
  → `:APPEND-ENTRIES-REPLY :term :from :read-seq :success :match-index` (plus
  `:next-index`/`:applied-index`/`:capacity-limited` on the relevant paths).
  Step down if stale; reject if `term < currentTerm` or the log-match check fails;
  else append/overwrite, advance `commitIndex = min(leader-commit, last-new)`.
- `:INSTALL-SNAPSHOT` `:term :from :last-index :last-term :state`
  → `:INSTALL-SNAPSHOT-REPLY :term :from :success :match-index`. The transport
  reassembles the binary chunks (and the witness config-snapshot form) into the
  boundary before it reaches the handler. The snapshot's membership is kept.
- `:TIMEOUT-NOW` `:term :from` → nothing. Only a voter takes over on request.

### Messages a witness originates when it stands in

It stands in when it refuses a `:PRE-VOTE` and all of this holds: the
membership is known and lists it as a witness; the candidate is a voter; no
leader has been heard for an election timeout; the candidate's term is ahead;
the candidate's log is behind the witness's (the only reason for refusing); and
the candidate's last index is not below the witness's snapshot index, so the
witness still holds every entry the candidate lacks.

| Sent | When | Fields |
|------|------|--------|
| `:PRE-VOTE` to every voter and witness | on standing in (and again on each later refused `:PRE-VOTE`, which is how a lost message is recovered) | `:term` (current + 1) `:from :last-log-index :last-log-term` |
| `:REQUEST-VOTE` to the same members | a majority granted the pre-vote; term + 1 and a vote for itself are on disk first | `:term :from :last-log-index :last-log-term :leader-transfer NIL` |
| `:APPEND-ENTRIES` to every voter | a majority voted for it; then on each reply that leaves more to send, and every 100 ms | `:term :from :prev-log-index :prev-log-term :entries :leader-commit :read-seq 0`. At most 64 entries and about 1 MiB a batch; entries are the stored commands, unchanged. Nothing is sent to a voter that needs entries below the snapshot index. |
| `:TIMEOUT-NOW` to one voter | the first voter whose `:match-index` reaches the witness's last index | `:term :from` |

Replies it acts on: `:PRE-VOTE-REPLY` and `:REQUEST-VOTE-REPLY` (counted once
per member, from voters and witnesses only; majority is ⌊n/2⌋+1 of those) and
`:APPEND-ENTRIES-REPLY` (success moves `match`/`next` forward; failure backs
`next` up to the reply's `:next-index`, or by one).

### Durable state (fsync before ack — Raft safety)

- **Hard state:** `currentTerm`, `votedFor` — persisted *before* replying to a
  vote, accepting a higher term, or asking for votes.
- **Membership:** member id → `voter` / `witness` / `learner`, in the same
  `hardstate.json`. It comes from the Join response, from each `:RAFT-CONFIG`
  entry once it is committed, and from the membership inside an installed
  snapshot. If the witness cannot be sure of it (a config or snapshot it cannot
  read) it forgets it, and does not stand in until it learns it again: counting
  a majority against too small a membership is the one unsafe direction.
- **Log:** entries `(index, term, command-blob)` — persisted *before* a successful
  AppendEntries reply.
- **Snapshot boundary:** `lastIncludedIndex`, `lastIncludedTerm` (the application
  payload is discarded — a witness has nothing to restore it into; only the
  boundary matters for log matching).

A crash can fall between any two writes, so their order is part of the format.
The boundary is written before the log file is trimmed to match it, and a
restart skips entries at or below the boundary; the reverse order once left a
file that read back as an empty log. Entries past a boundary this witness does
not hold are removed before that boundary is written. A write that fails leaves
memory as it was, so a retry is never acknowledged for entries that are not on
disk, and a torn line is trimmed at restart before anything is appended after it.

The on-disk log is compacted once it passes a byte bound, keeping only the most
recent slice. Both bounds are tunable with `-max-log-bytes` and
`-retain-log-bytes` (see flags below).

## Build

```sh
go test ./...
go build -o miniwit ./cmd/miniwit                                   # host
GOOS=freebsd GOARCH=amd64 go build -o miniwit ./cmd/miniwit         # pfSense/FreeBSD
GOOS=linux GOARCH=arm64 go build -o miniwit ./cmd/miniwit           # Raspberry Pi
```

Pure Go (`CGO_ENABLED=0` automatically when cross-compiling): set `GOOS` and
`GOARCH` for the target, and the binary is static and self-contained.
`go tool dist list` prints every target.

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
| `-renew-before` | `720h` | Renew the member certificate once it is this close to expiry. |
| `-version` | — | Print version and exit. |

## Certificate renewal

A member certificate lasts a year. A gr8s voter holds the cluster CA and signs
its own replacement; a witness holds no CA, so it asks a voter, as a gr8s
witness does (`src/security/raft-tls.lisp`).

miniwit looks at its certificate when it starts and every hour after. Once the
certificate is within `-renew-before` of expiry (30 days, the window gr8s
members use) it sends a signing request for its existing key to each peer it
knows in turn, over the mutual-TLS connection it already has. Another witness
refuses and the next peer is tried. The voter checks that the caller is still
a member of the cluster, so a removed witness cannot renew.

The reply replaces `pki/member.crt` only if it is for this member's id and key,
signed by the cluster CA already on disk, and expires later than the
certificate it replaces. The file is replaced atomically, and new connections
present the new certificate at their next handshake, without a restart.

A renewal that fails is logged with the days left and tried again at the next
hourly look, so there are about 720 attempts before the certificate runs out.
A witness that was offline past its expiry cannot renew: its certificate no
longer authenticates it. Remove it from the cluster and enroll it again with a
fresh `gr8s join-token --role witness`.

To see a renewal without waiting eleven months, start miniwit once with
`-renew-before 9000h`, then restart it without the flag; left in place it
would renew every hour.

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
- ④ follower core ✅ — `internal/raftcore`; the four handlers mirror
  `cl-raft/src/core.lisp`, durable hard-state + log, unit-tested.
- ⑤ snapshot chunk reassembly + boundary install ✅ — `internal/raftcore`
  (`snapshot.go`), including the witness config-snapshot form and byte-bounded
  log compaction (`-max-log-bytes`/`-retain-log-bytes`).
- ⑥ certificate renewal ✅ — `internal/transport` (`renew.go`). See *Certificate
  renewal* above.
- ⑦ automated end-to-end test against a throwaway 2-voter + 1-witness cluster —
  **pending**. Enroll, join, replication, failover and renewal have each been
  exercised by hand against a live cluster, which confirms wire fidelity for
  those paths but is not a test anyone can re-run.
- ⑧ stand-in for a voter that is behind the witness ✅ — `internal/raftcore`
  (`standin.go`, `membership.go`); unit-tested, and run over mutual TLS against
  a scripted voter. Not yet run against a real gr8s voter: that belongs in ⑦.
