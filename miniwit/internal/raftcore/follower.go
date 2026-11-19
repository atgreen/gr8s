// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"fmt"
	"sync"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// Reply is a message to send back to a peer, fire-and-forget, as its own Deliver
// call (gr8s's send model). To is the peer id; Payload is the encoded message.
type Reply struct {
	To      string
	Payload []byte
}

// Follower is a non-campaigning Raft member. It mirrors the follower-side logic
// of cl-raft/src/core.lisp: step down on a newer term, grant votes under the
// §5.4.1 up-to-date rule, append/overwrite under the log-match rule, and install
// snapshot boundaries. It never starts an election, so it can never become
// leader — which is exactly what a witness must guarantee.
type Follower struct {
	mu    sync.Mutex
	id    string // this witness's member id == its certificate CN == its :FROM
	store Store
	st    *State

	leaderID          string
	clock             func() time.Time
	electionTimeout   time.Duration
	lastLeaderContact time.Time         // for Pre-Vote: grant only when no leader seen recently
	recv              *snapshotReceiver // in-progress chunked snapshot transfer, if any
}

// NewFollower loads durable state and returns a ready follower. electionTimeout
// gates Pre-Vote grants (a witness grants only when it has heard no leader for at
// least this long); it never drives an election here.
func NewFollower(id string, store Store, electionTimeout time.Duration) (*Follower, error) {
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	return &Follower{
		id:              id,
		store:           store,
		st:              st,
		clock:           time.Now,
		electionTimeout: electionTimeout,
	}, nil
}

// Step decodes one incoming RaftEnvelope payload and returns the reply to send,
// or nil when the message warrants none. Messages a follower never originates
// (vote/append replies) are ignored; snapshot chunks are phase 5.
func (f *Follower) Step(payload []byte) (*Reply, error) {
	msg, err := lispwire.DecodePayload(payload)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch msg.Type {
	case "REQUEST-VOTE":
		return f.handleRequestVote(msg)
	case "PRE-VOTE":
		return f.handlePreVote(msg)
	case "APPEND-ENTRIES":
		return f.handleAppendEntries(msg)
	case "INSTALL-SNAPSHOT":
		return f.handleInstallSnapshot(msg)
	case "SNAPSHOT-CHUNK":
		return f.handleSnapshotChunk(msg)
	case "REQUEST-VOTE-REPLY", "PRE-VOTE-REPLY", "APPEND-ENTRIES-REPLY", "INSTALL-SNAPSHOT-REPLY":
		return nil, nil // a non-campaigning, non-leading witness never acts on these
	default:
		return nil, fmt.Errorf("raftcore: unexpected message type %q", msg.Type)
	}
}

// --- log helpers ----------------------------------------------------------

func (f *Follower) lastLogIndex() int64 {
	if n := len(f.st.Log); n > 0 {
		return f.st.Log[n-1].Index
	}
	return f.st.SnapshotIdx
}

func (f *Follower) lastLogTerm() int64 {
	if n := len(f.st.Log); n > 0 {
		return f.st.Log[n-1].Term
	}
	return f.st.SnapshotTrm
}

// logTerm returns the term of the entry at index, matching cl-raft's raft-log-term:
// 0 at index 0, the snapshot term at the snapshot boundary, else the stored term.
func (f *Follower) logTerm(index int64) (int64, bool) {
	if index == 0 {
		return 0, true
	}
	if index == f.st.SnapshotIdx {
		return f.st.SnapshotTrm, true
	}
	if index > f.st.SnapshotIdx && index <= f.lastLogIndex() {
		off := index - f.st.SnapshotIdx - 1
		if off >= 0 && off < int64(len(f.st.Log)) {
			return f.st.Log[off].Term, true
		}
	}
	return 0, false
}

// --- term / persistence ---------------------------------------------------

// stepDownIfStale adopts a newer term and reverts to follower (clearing the
// vote), persisting the hard state before returning (Raft safety).
func (f *Follower) stepDownIfStale(term int64) error {
	if term > f.st.CurrentTerm {
		f.st.CurrentTerm = term
		f.st.VotedFor = ""
		f.leaderID = ""
		return f.store.PutHardState(f.st.HardState)
	}
	return nil
}

func (f *Follower) upToDate(msgLastTerm, msgLastIndex int64) bool {
	return msgLastTerm > f.lastLogTerm() ||
		(msgLastTerm == f.lastLogTerm() && msgLastIndex >= f.lastLogIndex())
}

// --- handlers (mirror cl-raft/src/core.lisp) ------------------------------

func (f *Follower) handleRequestVote(msg *lispwire.Msg) (*Reply, error) {
	term, _ := msg.Int("TERM")
	candidate, _ := msg.Str("FROM")
	lastIdx, _ := msg.Int("LAST-LOG-INDEX")
	lastTrm, _ := msg.Int("LAST-LOG-TERM")
	if err := f.stepDownIfStale(term); err != nil {
		return nil, err
	}
	grant := term == f.st.CurrentTerm &&
		(f.st.VotedFor == "" || f.st.VotedFor == candidate) &&
		f.upToDate(lastTrm, lastIdx)
	if grant {
		f.st.CurrentTerm = term
		f.st.VotedFor = candidate
		if err := f.store.PutHardState(f.st.HardState); err != nil {
			return nil, err
		}
	}
	payload := lispwire.NewReply("REQUEST-VOTE-REPLY").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("GRANTED", grant).Encode()
	return &Reply{To: candidate, Payload: payload}, nil
}

func (f *Follower) handlePreVote(msg *lispwire.Msg) (*Reply, error) {
	term, _ := msg.Int("TERM")
	from, _ := msg.Str("FROM")
	lastIdx, _ := msg.Int("LAST-LOG-INDEX")
	lastTrm, _ := msg.Int("LAST-LOG-TERM")
	// Grant only when no leader has been heard for at least an election timeout,
	// the candidate's hypothetical term is ahead of ours, and its log is at least
	// as up-to-date. A witness is never leader, so that clause is always satisfied.
	// Pre-Vote changes no persistent state.
	grant := f.leaderContactElapsed() >= f.electionTimeout &&
		term > f.st.CurrentTerm &&
		f.upToDate(lastTrm, lastIdx)
	payload := lispwire.NewReply("PRE-VOTE-REPLY").
		Int("TERM", f.st.CurrentTerm).Int("PRE-TERM", term).
		Str("FROM", f.id).Bool("GRANTED", grant).Encode()
	return &Reply{To: from, Payload: payload}, nil
}

func (f *Follower) leaderContactElapsed() time.Duration {
	if f.lastLeaderContact.IsZero() {
		return 1<<62 - 1 // never heard a leader: treat as long past the timeout
	}
	return f.clock().Sub(f.lastLeaderContact)
}

func (f *Follower) handleAppendEntries(msg *lispwire.Msg) (*Reply, error) {
	term, _ := msg.Int("TERM")
	leader, _ := msg.Str("FROM")
	readSeq, hasReadSeq := msg.Int("READ-SEQ")
	if err := f.stepDownIfStale(term); err != nil {
		return nil, err
	}
	reply := func(success bool, matchIndex int64, extra func(*lispwire.Builder)) *Reply {
		b := lispwire.NewReply("APPEND-ENTRIES-REPLY").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id)
		if hasReadSeq {
			b.Int("READ-SEQ", readSeq)
		}
		b.Bool("SUCCESS", success).Int("MATCH-INDEX", matchIndex)
		if extra != nil {
			extra(b)
		}
		return &Reply{To: leader, Payload: b.Encode()}
	}
	if term < f.st.CurrentTerm {
		return reply(false, 0, nil), nil
	}
	// Valid leader for our term.
	f.leaderID = leader
	f.lastLeaderContact = f.clock()
	prevIndex, _ := msg.Int("PREV-LOG-INDEX")
	prevTerm, _ := msg.Int("PREV-LOG-TERM")
	leaderCommit, _ := msg.Int("LEADER-COMMIT")

	if prevIndex < f.st.SnapshotIdx {
		return reply(false, 0, func(b *lispwire.Builder) { b.Int("NEXT-INDEX", f.st.SnapshotIdx+1) }), nil
	}
	if prevIndex > f.lastLogIndex() {
		// Our log is too short: hint the leader straight to our end instead of
		// making it back up one index per round (standard Raft fast-backup, which
		// gr8s's leader honors via :next-index). For a fresh witness this jumps
		// the leader to the snapshot it must send to catch us up.
		return reply(false, 0, func(b *lispwire.Builder) { b.Int("NEXT-INDEX", f.lastLogIndex()+1) }), nil
	}
	if pt, ok := f.logTerm(prevIndex); prevIndex > 0 && (!ok || pt != prevTerm) {
		// Term conflict within our log: reject so the leader backs up a step.
		return reply(false, 0, nil), nil
	}

	// Append/overwrite, skipping a matching prefix and truncating one conflict.
	// Persist only what changed: a plain extension appends just the new entries
	// (the hot path), a conflict rewrites the log, and a commit-index advance is
	// in-memory only (Raft treats commitIndex as volatile).
	entries := msg.Entries
	var toAppend []lispwire.Entry
	truncated := false
	for k, e := range entries {
		i := prevIndex + 1 + int64(k)
		if i > f.lastLogIndex() {
			toAppend = entries[k:]
			break
		}
		if et, ok := f.logTerm(i); !ok || et != e.Term {
			f.truncateFrom(i)
			truncated = true
			toAppend = entries[k:]
			break
		}
	}
	if len(toAppend) > 0 {
		f.appendFrom(toAppend)
	}
	switch {
	case truncated:
		if err := f.store.RewriteLog(f.st.Log); err != nil {
			return nil, err
		}
	case len(toAppend) > 0:
		newStored := f.st.Log[int64(len(f.st.Log))-int64(len(toAppend)):]
		if err := f.store.AppendLog(newStored); err != nil {
			return nil, err
		}
	}

	lastNew := prevIndex + int64(len(entries))
	if leaderCommit > f.st.CommitIndex {
		f.st.CommitIndex = min64(leaderCommit, lastNew)
	}
	// Keep the log bounded. A caught-up witness only ever receives AppendEntries
	// (the leader never re-snapshots it), so without this its log would grow
	// without end.
	if err := f.maybeCompact(); err != nil {
		return nil, err
	}
	// A witness applies nothing, so everything committed is trivially applied.
	applied := min64(lastNew, f.st.CommitIndex)
	return reply(true, lastNew, func(b *lispwire.Builder) { b.Int("APPLIED-INDEX", applied) }), nil
}

// appendFrom appends the given wire entries (converted to stored entries). The
// caller has already ensured they begin exactly after the current last index.
func (f *Follower) appendFrom(entries []lispwire.Entry) {
	for _, e := range entries {
		f.st.Log = append(f.st.Log, Entry{
			Index:   e.Index,
			Term:    e.Term,
			Command: lispwire.Write(e.Command),
		})
	}
}

// truncateFrom drops every stored entry at index >= from.
func (f *Follower) truncateFrom(from int64) {
	keep := from - f.st.SnapshotIdx - 1
	if keep < 0 {
		keep = 0
	}
	if keep < int64(len(f.st.Log)) {
		f.st.Log = f.st.Log[:keep]
	}
}

func (f *Follower) handleInstallSnapshot(msg *lispwire.Msg) (*Reply, error) {
	term, _ := msg.Int("TERM")
	leader, _ := msg.Str("FROM")
	index, _ := msg.Int("LAST-INDEX")
	lastTerm, _ := msg.Int("LAST-TERM")
	if err := f.stepDownIfStale(term); err != nil {
		return nil, err
	}
	fail := func() *Reply {
		return &Reply{To: leader, Payload: lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", false).Int("MATCH-INDEX", 0).Encode()}
	}
	if term < f.st.CurrentTerm {
		return fail(), nil
	}
	f.leaderID = leader
	f.lastLeaderContact = f.clock()
	if index < 1 || lastTerm < 0 || lastTerm > term {
		return nil, fmt.Errorf("raftcore: invalid snapshot boundary index=%d last-term=%d term=%d", index, lastTerm, term)
	}
	if index > f.st.CommitIndex {
		if err := f.installBoundary(index, lastTerm); err != nil {
			return nil, err
		}
	}
	return &Reply{To: leader, Payload: lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", true).Int("MATCH-INDEX", index).Encode()}, nil
}

// installBoundary advances the snapshot boundary to (index, lastTerm): it keeps
// any log suffix consistent with the boundary and discards the rest, then
// persists. A witness stores only the boundary — the application payload has
// nothing here to be restored into — so match-index/up-to-date checks stay
// correct without holding the data.
func (f *Follower) installBoundary(index, lastTerm int64) error {
	if bt, ok := f.logTerm(index); ok && bt == lastTerm {
		f.truncateBefore(index)
	} else {
		f.st.Log = nil
	}
	f.st.SnapshotIdx = index
	f.st.SnapshotTrm = lastTerm
	if index > f.st.CommitIndex {
		f.st.CommitIndex = index
	}
	// Rewrite the log first: if we crash between the two, a log whose entries sit
	// beyond an un-advanced boundary is still consistent, whereas a boundary ahead
	// of a stale log would orphan entries. Then record the new boundary.
	if err := f.store.RewriteLog(f.st.Log); err != nil {
		return err
	}
	return f.store.PutHardState(f.st.HardState)
}

// Log-compaction thresholds in bytes (vars so tests can lower them). Entry sizes
// vary wildly — a witness in a Kubernetes-style cluster stores full object JSON in
// its commands — so bounding bytes, not entry count, is what actually bounds disk.
// Once the log passes compactWhenLogBytes, discard committed entries from the low
// end until the retained tail is about retainLogBytes.
var (
	compactWhenLogBytes int64 = 4 << 20 // 4 MiB
	retainLogBytes      int64 = 1 << 20 // 1 MiB
)

// SetCompactionBytes configures the log-compaction thresholds: the log compacts
// once it passes maxBytes, keeping roughly retainBytes of the most recent entries.
// Invalid values (retain not below max, or non-positive) are ignored.
func SetCompactionBytes(maxBytes, retainBytes int64) {
	if maxBytes > 0 && retainBytes > 0 && retainBytes < maxBytes {
		compactWhenLogBytes, retainLogBytes = maxBytes, retainBytes
	}
}

// entryBytes is a cheap estimate of an entry's on-disk cost (its command plus
// JSON framing), enough to drive the byte-based thresholds.
func entryBytes(e Entry) int64 { return int64(len(e.Command)) + 32 }

func (f *Follower) logBytes() int64 {
	var n int64
	for _, e := range f.st.Log {
		n += entryBytes(e)
	}
	return n
}

// maybeCompact advances the local snapshot boundary to discard committed log
// entries from the low end once the log grows past the byte threshold, keeping the
// most recent ~retainLogBytes. A witness never serves or re-applies these entries,
// so dropping committed ones is safe; the retained tail keeps the boundary below
// the leader's prev-log-index (which tracks the head), so no snapshot resend is
// triggered. RewriteLog replaces log.jsonl with the smaller file, freeing the disk.
func (f *Follower) maybeCompact() error {
	if f.logBytes() <= compactWhenLogBytes {
		return nil
	}
	// Walk from the head, keeping uncommitted entries and the most recent committed
	// ones up to retainLogBytes; everything older is discarded.
	keepFrom := f.lastLogIndex() + 1
	var kept int64
	for i := len(f.st.Log) - 1; i >= 0; i-- {
		e := f.st.Log[i]
		if e.Index > f.st.CommitIndex {
			keepFrom = e.Index
			continue
		}
		if kept > retainLogBytes {
			break
		}
		kept += entryBytes(e)
		keepFrom = e.Index
	}
	cut := keepFrom - 1
	if cut <= f.st.SnapshotIdx {
		return nil
	}
	cutTerm, ok := f.logTerm(cut)
	if !ok {
		return nil
	}
	f.truncateBefore(cut)
	f.st.SnapshotIdx = cut
	f.st.SnapshotTrm = cutTerm
	if err := f.store.RewriteLog(f.st.Log); err != nil {
		return err
	}
	return f.store.PutHardState(f.st.HardState)
}

// truncateBefore drops stored entries at index <= boundary, keeping the suffix.
func (f *Follower) truncateBefore(boundary int64) {
	kept := f.st.Log[:0:0]
	for _, e := range f.st.Log {
		if e.Index > boundary {
			kept = append(kept, e)
		}
	}
	f.st.Log = kept
}

// LeaderID returns the leader this follower last heard from, or "" if none. The
// witness uses it to redirect a Join RPC it receives toward the real leader.
func (f *Follower) LeaderID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leaderID
}

// Snapshot of observable state, for tests and status reporting.
func (f *Follower) snapshotState() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.st
	cp.Log = append([]Entry(nil), f.st.Log...)
	return cp
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
