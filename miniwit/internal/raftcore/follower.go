// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// Reply is a message to send to a peer, fire-and-forget, as its own Deliver call
// (gr8s's send model). To is the peer id; Payload is the encoded message.
type Reply struct {
	To      string
	Payload []byte
}

// raftRole is the Raft role (follower/candidate/leader), as distinct from the
// membership role (voter/witness/learner) recorded in HardState.Members.
type raftRole int

const (
	roleFollower raftRole = iota
	roleCandidate
	roleLeader
)

// Follower is a witness Raft member. It mirrors cl-raft/src/core.lisp: step down
// on a newer term, grant votes under the §5.4.1 up-to-date rule, append/overwrite
// under the log-match rule, and install snapshot boundaries. It has no election
// timer, so it never campaigns on its own. The one exception is the stand-in
// (standin.go): when it has to refuse a voter's Pre-Vote only because that voter
// is behind its own log, it gets itself elected, copies its log to the voter and
// hands leadership over. It never accepts a proposal and never applies a command.
type Follower struct {
	mu    sync.Mutex
	id    string // this witness's member id == its certificate CN == its :FROM
	store Store
	st    *State

	leaderID          string
	clock             func() time.Time
	electionTimeout   time.Duration     // Pre-Vote grants, and how long a stand-in may lead
	lastLeaderContact time.Time         // for Pre-Vote: grant only when no leader seen recently
	recv              *snapshotReceiver // in-progress chunked snapshot transfer, if any

	// Stand-in state (standin.go). All of it is volatile: a restart mid-election
	// just comes back as a follower that has voted for itself in that term.
	role        raftRole
	preVoteTerm int64               // term of the pre-election in flight; 0 when none
	preVotes    map[string]struct{} // members that granted that pre-election, self included
	votes       map[string]struct{} // members that voted for us in CurrentTerm, self included
	nextIndex   map[string]int64    // leader only: per voter peer
	matchIndex  map[string]int64    // leader only: per voter peer
	successor   string              // leader only: the voter already sent TIMEOUT-NOW
	leaderSince time.Time           // when this stand-in won; it leads one election timeout at most
	lastAppend  time.Time           // when AppendEntries last went out to every voter

	out         []Reply                          // messages produced by the Step/Tick in progress
	logf        func(format string, args ...any) // transition log
	onAddresses func(map[string]string)          // peer endpoints learned with a membership
}

// NewFollower loads durable state and returns a ready follower. electionTimeout
// gates Pre-Vote grants (a witness grants only when it has heard no leader for at
// least this long) and bounds how long a stand-in leads; it never starts an
// election by itself.
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
		logf:            log.Printf,
	}, nil
}

// Step decodes one incoming RaftEnvelope payload and returns the messages to
// send in response, in order. There may be none, one (a reply), or several (a
// refused Pre-Vote that starts a stand-in also asks every peer for its
// pre-vote). Messages returned alongside an error were made before the failure
// and are safe to send.
func (f *Follower) Step(payload []byte) ([]Reply, error) {
	msg, err := lispwire.DecodePayload(payload)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = nil
	switch msg.Type {
	case "REQUEST-VOTE":
		err = f.handleRequestVote(msg)
	case "PRE-VOTE":
		err = f.handlePreVote(msg)
	case "APPEND-ENTRIES":
		err = f.handleAppendEntries(msg)
	case "INSTALL-SNAPSHOT":
		err = f.handleInstallSnapshot(msg)
	case "SNAPSHOT-CHUNK":
		err = f.handleSnapshotChunk(msg)
	case "PRE-VOTE-REPLY":
		err = f.handlePreVoteReply(msg)
	case "REQUEST-VOTE-REPLY":
		err = f.handleRequestVoteReply(msg)
	case "APPEND-ENTRIES-REPLY":
		err = f.handleAppendEntriesReply(msg)
	case "TIMEOUT-NOW", "INSTALL-SNAPSHOT-REPLY":
		// Only a voter takes over on request (raft-handle-timeout-now), and a
		// witness sends no snapshot for anyone to answer. Either can still carry
		// a newer term.
		term, _ := msg.Int("TERM")
		err = f.stepDownIfStale(term)
	default:
		err = fmt.Errorf("raftcore: unexpected message type %q", msg.Type)
	}
	out := f.out
	f.out = nil
	return out, err
}

// send queues a message for the caller of Step or Tick to deliver. Anything that
// must be durable before the message reveals it is persisted before this call.
func (f *Follower) send(to string, payload []byte) {
	f.out = append(f.out, Reply{To: to, Payload: payload})
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
// vote), persisting the hard state before returning (Raft safety). Whatever this
// member was doing in the old term -- a pre-election, a candidacy, leading as a
// stand-in -- ends here.
func (f *Follower) stepDownIfStale(term int64) error {
	if term <= f.st.CurrentTerm {
		return nil
	}
	hs := f.st.HardState
	hs.CurrentTerm = term
	hs.VotedFor = ""
	if err := f.store.PutHardState(hs); err != nil {
		return err
	}
	f.st.HardState = hs
	f.becomeFollower("")
	return nil
}

// becomeFollower drops every candidate and leader role in the current term,
// like raft-become-follower. With no known leader the contact time goes back to
// "never", so a Pre-Vote can be granted at once; a caller that knows the leader
// records the contact itself. The term and vote are the caller's business.
func (f *Follower) becomeFollower(leader string) {
	f.role = roleFollower
	f.leaderID = leader
	f.preVoteTerm = 0
	f.preVotes, f.votes = nil, nil
	f.nextIndex, f.matchIndex = nil, nil
	f.successor = ""
	if leader == "" {
		f.lastLeaderContact = time.Time{}
	}
}

func (f *Follower) upToDate(msgLastTerm, msgLastIndex int64) bool {
	return msgLastTerm > f.lastLogTerm() ||
		(msgLastTerm == f.lastLogTerm() && msgLastIndex >= f.lastLogIndex())
}

// --- handlers (mirror cl-raft/src/core.lisp) ------------------------------

func (f *Follower) handleRequestVote(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	candidate, _ := msg.Str("FROM")
	lastIdx, _ := msg.Int("LAST-LOG-INDEX")
	lastTrm, _ := msg.Int("LAST-LOG-TERM")
	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	// While this member is a candidate or a stand-in leader it has voted for
	// itself in this term, so the vote check alone refuses a rival.
	grant := term == f.st.CurrentTerm &&
		(f.st.VotedFor == "" || f.st.VotedFor == candidate) &&
		f.upToDate(lastTrm, lastIdx)
	if grant {
		hs := f.st.HardState
		hs.VotedFor = candidate
		if err := f.store.PutHardState(hs); err != nil {
			return err
		}
		f.st.HardState = hs
	}
	f.send(candidate, lispwire.NewReply("REQUEST-VOTE-REPLY").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("GRANTED", grant).Encode())
	return nil
}

func (f *Follower) handlePreVote(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	from, _ := msg.Str("FROM")
	lastIdx, hasLastIdx := msg.Int("LAST-LOG-INDEX")
	lastTrm, _ := msg.Int("LAST-LOG-TERM")
	// Grant only when this member is not leading, no leader has been heard for at
	// least an election timeout, the candidate's hypothetical term is ahead of
	// ours, and its log is at least as up-to-date. Pre-Vote changes no persistent
	// state, and the term it names is hypothetical, so there is no step-down.
	quiet := f.role != roleLeader &&
		f.leaderContactElapsed() >= f.electionTimeout &&
		term > f.st.CurrentTerm
	upToDate := f.upToDate(lastTrm, lastIdx)
	grant := quiet && upToDate
	f.send(from, lispwire.NewReply("PRE-VOTE-REPLY").
		Int("TERM", f.st.CurrentTerm).Int("PRE-TERM", term).
		Str("FROM", f.id).Bool("GRANTED", grant).Encode())
	// Refused for one reason only -- the candidate is behind our log -- and it is
	// a voter we can serve from that log: stand in for it (standin.go).
	if quiet && !upToDate && hasLastIdx && f.canStandInFor(from, lastIdx) {
		return f.beginPreElection(from)
	}
	return nil
}

func (f *Follower) leaderContactElapsed() time.Duration {
	if f.lastLeaderContact.IsZero() {
		return 1<<62 - 1 // never heard a leader: treat as long past the timeout
	}
	return f.clock().Sub(f.lastLeaderContact)
}

func (f *Follower) handleAppendEntries(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	leader, _ := msg.Str("FROM")
	readSeq, hasReadSeq := msg.Int("READ-SEQ")
	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	reply := func(success bool, matchIndex int64, extra func(*lispwire.Builder)) error {
		b := lispwire.NewReply("APPEND-ENTRIES-REPLY").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id)
		if hasReadSeq {
			b.Int("READ-SEQ", readSeq)
		}
		b.Bool("SUCCESS", success).Int("MATCH-INDEX", matchIndex)
		if extra != nil {
			extra(b)
		}
		f.send(leader, b.Encode())
		return nil
	}
	if term < f.st.CurrentTerm {
		return reply(false, 0, nil)
	}
	// Valid leader for our term. If we were a candidate in it, the election is
	// decided and we lost.
	if f.role != roleFollower {
		f.becomeFollower(leader)
	}
	f.leaderID = leader
	f.lastLeaderContact = f.clock()
	prevIndex, _ := msg.Int("PREV-LOG-INDEX")
	prevTerm, _ := msg.Int("PREV-LOG-TERM")
	leaderCommit, _ := msg.Int("LEADER-COMMIT")

	if prevIndex < f.st.SnapshotIdx {
		return reply(false, 0, func(b *lispwire.Builder) { b.Int("NEXT-INDEX", f.st.SnapshotIdx+1) })
	}
	if prevIndex > f.lastLogIndex() {
		// Our log is too short: hint the leader straight to our end instead of
		// making it back up one index per round (standard Raft fast-backup, which
		// gr8s's leader honors via :next-index). For a fresh witness this jumps
		// the leader to the snapshot it must send to catch us up.
		return reply(false, 0, func(b *lispwire.Builder) { b.Int("NEXT-INDEX", f.lastLogIndex()+1) })
	}
	if pt, ok := f.logTerm(prevIndex); prevIndex > 0 && (!ok || pt != prevTerm) {
		// Term conflict within our log: reject so the leader backs up a step.
		return reply(false, 0, nil)
	}

	// Append/overwrite, skipping a matching prefix and truncating one conflict.
	// Persist only what changed: a plain extension appends just the new entries
	// (the hot path), a conflict rewrites the log, and a commit-index advance is
	// in-memory only (Raft treats commitIndex as volatile) unless it commits a
	// membership change, which is written to the hard state.
	//
	// The log in memory must never run ahead of the log on disk. If a write
	// fails, memory goes back to what it was: otherwise the leader's retry would
	// find the entries already "held", append nothing, and be told they are
	// stored when they are not (podster-9m0).
	entries := msg.Entries
	var toAppend []lispwire.Entry
	truncated := false
	held := f.st.Log // appending leaves these elements alone; truncating does not
	for k, e := range entries {
		i := prevIndex + 1 + int64(k)
		if i > f.lastLogIndex() {
			toAppend = entries[k:]
			break
		}
		if et, ok := f.logTerm(i); !ok || et != e.Term {
			held = append([]Entry(nil), f.st.Log...)
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
			f.st.Log = held
			return err
		}
	case len(toAppend) > 0:
		newStored := f.st.Log[int64(len(f.st.Log))-int64(len(toAppend)):]
		if err := f.store.AppendLog(newStored); err != nil {
			f.st.Log = held
			return err
		}
	}

	lastNew := prevIndex + int64(len(entries))
	if err := f.advanceCommit(min64(leaderCommit, lastNew)); err != nil {
		return err
	}
	// Keep the log bounded. A caught-up witness only ever receives AppendEntries
	// (the leader never re-snapshots it), so without this its log would grow
	// without end.
	if err := f.maybeCompact(); err != nil {
		return err
	}
	// A witness applies nothing, so everything committed is trivially applied.
	applied := min64(lastNew, f.st.CommitIndex)
	return reply(true, lastNew, func(b *lispwire.Builder) { b.Int("APPLIED-INDEX", applied) })
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

func (f *Follower) handleInstallSnapshot(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	leader, _ := msg.Str("FROM")
	index, _ := msg.Int("LAST-INDEX")
	lastTerm, _ := msg.Int("LAST-TERM")
	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	if term < f.st.CurrentTerm {
		f.send(leader, lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", false).Int("MATCH-INDEX", 0).Encode())
		return nil
	}
	if f.role != roleFollower {
		f.becomeFollower(leader)
	}
	f.leaderID = leader
	f.lastLeaderContact = f.clock()
	if index < 1 || lastTerm < 0 || lastTerm > term {
		return fmt.Errorf("raftcore: invalid snapshot boundary index=%d last-term=%d term=%d", index, lastTerm, term)
	}
	if index > f.st.CommitIndex {
		state, _ := msg.Raw("STATE")
		if err := f.installBoundary(index, lastTerm, state); err != nil {
			return err
		}
	}
	f.send(leader, f.snapshotReply(index))
	return nil
}

// installBoundary advances the snapshot boundary to (index, lastTerm): it keeps
// any log suffix consistent with the boundary and discards the rest, then
// persists. A witness stores only the boundary — the application payload has
// nothing here to be restored into — so match-index/up-to-date checks stay
// correct without holding the data. The one part of a snapshot a witness does
// need is the membership frozen at the boundary; state is the snapshot envelope
// when the transfer carried one this program could read, else nil.
func (f *Follower) installBoundary(index, lastTerm int64, state lispwire.Value) error {
	bt, ok := f.logTerm(index)
	held := ok && bt == lastTerm
	hs := f.st.HardState
	addrs := f.membershipAcrossSnapshot(&hs, index, held, state)
	hs.SnapshotIdx = index
	hs.SnapshotTrm = lastTerm
	// Order matters, because a crash can fall between any two writes
	// (podster-sjl). Load skips entries at or below the boundary and keeps what
	// follows it, so the boundary is written first and the log trimmed after: a
	// crash in between leaves the new boundary with the old file, which reads
	// back as exactly the new log. The old order (log, then boundary) left a
	// file starting past the old boundary, and Load returned an empty log: the
	// witness forgot entries it had acknowledged.
	//
	// The one thing that must go before the boundary is a suffix that disagrees
	// with it. Entries past a boundary we do not hold were written by a leader
	// the snapshot's leader has superseded; once the boundary is on disk Load
	// would take them for its continuation.
	var kept []Entry
	if held {
		kept = entriesAfter(f.st.Log, index)
	} else if f.lastLogIndex() > index {
		upTo := entriesThrough(f.st.Log, index)
		if err := f.store.RewriteLog(upTo); err != nil {
			return err
		}
		f.st.Log = upTo
	}
	if err := f.store.PutHardState(hs); err != nil {
		return err
	}
	f.st.HardState = hs
	f.st.Log = kept
	if err := f.store.RewriteLog(kept); err != nil {
		// The state is durable and correct; only the file is longer than it
		// needs to be, and Load trims it.
		f.logf("could not trim the log after installing boundary %d: %v", index, err)
	}
	if index > f.st.CommitIndex {
		f.st.CommitIndex = index
	}
	f.learnAddresses(addrs)
	return nil
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
	// Boundary first, then the file: see installBoundary.
	hs := f.st.HardState
	hs.SnapshotIdx = cut
	hs.SnapshotTrm = cutTerm
	if err := f.store.PutHardState(hs); err != nil {
		return err
	}
	f.st.HardState = hs
	f.st.Log = entriesAfter(f.st.Log, cut)
	if err := f.store.RewriteLog(f.st.Log); err != nil {
		f.logf("could not trim the log after compacting to %d: %v", cut, err)
	}
	return nil
}

// entriesAfter returns a copy of the entries with index > boundary.
func entriesAfter(log []Entry, boundary int64) []Entry {
	var kept []Entry
	for _, e := range log {
		if e.Index > boundary {
			kept = append(kept, e)
		}
	}
	return kept
}

// entriesThrough returns a copy of the entries with index <= boundary.
func entriesThrough(log []Entry, boundary int64) []Entry {
	var kept []Entry
	for _, e := range log {
		if e.Index <= boundary {
			kept = append(kept, e)
		}
	}
	return kept
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
