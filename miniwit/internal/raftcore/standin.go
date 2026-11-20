// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"sort"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// The stand-in (podster-f15), mirroring cl-raft's raft-witness-should-stand-in-p
// and the functions around it.
//
// A witness acknowledges an entry as soon as it is stored; a voter also has to
// apply what it stores. So when a leader fails under load, the surviving voter is
// often an entry or two behind the witness. The witness is right to refuse that
// voter's Pre-Vote -- the leader and the witness were a majority, so those
// entries may be committed and acknowledged to a client -- but if the witness
// then does nothing, no member can win and the cluster waits for the failed
// leader to come back.
//
// The witness holds the entries the voter lacks. So it stands for election
// itself, which it can win because its log is the most up to date; replicates
// its stored log to the voter as any leader does; and sends TIMEOUT-NOW to the
// first voter that holds all of it, which then campaigns and wins. Nothing here
// is outside ordinary Raft: any member whose log is up to date may lead, and a
// leader may hand over. The witness accepts no proposal meanwhile (Propose still
// answers not-leader) and appends nothing to its own log.
//
// There is no election timer. Every step is a reaction to a message, and a lost
// message is recovered by the voter's next Pre-Vote, which starts the stand-in
// again. The only clock is Tick: heartbeats while leading, and an upper bound on
// how long that lasts.

const (
	// heartbeatInterval is how often a stand-in leader resends AppendEntries to
	// each voter: gr8s's own heartbeat, two 50 ms ticks. Sends are fire-and-forget,
	// so this is also what recovers a lost AppendEntries or reply.
	heartbeatInterval = 100 * time.Millisecond

	// One AppendEntries carries at most this many entries and about this many
	// bytes of commands (cl-raft's append-entry-limit and append-byte-budget), so
	// a retry never encodes the whole retained log.
	appendEntryLimit       = 64
	appendByteBudget int64 = 1 << 20
)

// canStandInFor says whether this witness may stand in for candidate, whose
// Pre-Vote it has just refused only because candidate's log is behind its own
// (handlePreVote has checked that, and that no leader has been heard lately).
// The membership must be known and list this member as a witness, the candidate
// must be a voter, and every entry the candidate lacks must still be in our log:
// a candidate behind our snapshot boundary can only be helped by a voter's
// snapshot.
func (f *Follower) canStandInFor(candidate string, candidateLastIndex int64) bool {
	return f.st.Members[f.id] == RoleWitness &&
		candidate != f.id &&
		f.st.Members[candidate] == RoleVoter &&
		candidateLastIndex >= f.st.SnapshotIdx
}

// beginPreElection asks every voter and witness whether this member could win
// at the next term (raft-begin-pre-election). It changes no persistent state:
// only a majority of grants leads to a real candidacy. It may run again for the
// same term on a later Pre-Vote, which is how a lost message is recovered.
func (f *Follower) beginPreElection(candidate string) error {
	preTerm := f.st.CurrentTerm + 1
	if f.preVoteTerm != preTerm {
		f.logf("standing in for %s, which is behind this witness's log (index %d): asking for pre-votes at term %d",
			candidate, f.lastLogIndex(), preTerm)
	}
	f.preVoteTerm = preTerm
	f.preVotes = map[string]struct{}{f.id: {}}
	if len(f.preVotes) >= f.majority() {
		return f.becomeCandidate()
	}
	f.broadcast(lispwire.NewReply("PRE-VOTE").
		Int("TERM", preTerm).Str("FROM", f.id).
		Int("LAST-LOG-INDEX", f.lastLogIndex()).Int("LAST-LOG-TERM", f.lastLogTerm()).Encode())
	return nil
}

func (f *Follower) broadcast(payload []byte) {
	for _, peer := range f.quorumPeers() {
		f.send(peer, payload)
	}
}

func (f *Follower) handlePreVoteReply(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	from, _ := msg.Str("FROM")
	preTerm, hasPreTerm := msg.Int("PRE-TERM")
	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	// Count a grant for the round in flight only, and only from a member of the
	// quorum; a map cannot count the same member twice.
	if f.preVoteTerm == 0 || !hasPreTerm || preTerm != f.preVoteTerm ||
		!msg.Bool("GRANTED") || f.role == roleLeader || from == f.id || !f.inQuorum(from) {
		return nil
	}
	f.preVotes[from] = struct{}{}
	if len(f.preVotes) >= f.majority() {
		return f.becomeCandidate()
	}
	return nil
}

// becomeCandidate starts the real election (raft-become-candidate): next term,
// vote for self, and that hard state on disk before any REQUEST-VOTE reveals it.
func (f *Follower) becomeCandidate() error {
	hs := f.st.HardState
	hs.CurrentTerm++
	hs.VotedFor = f.id
	if err := f.store.PutHardState(hs); err != nil {
		return err
	}
	f.st.HardState = hs
	f.preVoteTerm, f.preVotes = 0, nil
	f.role = roleCandidate
	f.leaderID = ""
	f.votes = map[string]struct{}{f.id: {}}
	f.broadcast(lispwire.NewReply("REQUEST-VOTE").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).
		Int("LAST-LOG-INDEX", f.lastLogIndex()).Int("LAST-LOG-TERM", f.lastLogTerm()).
		Bool("LEADER-TRANSFER", false).Encode())
	f.maybeBecomeLeader()
	return nil
}

func (f *Follower) handleRequestVoteReply(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	from, _ := msg.Str("FROM")
	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	if f.role != roleCandidate || term != f.st.CurrentTerm || !msg.Bool("GRANTED") ||
		from == f.id || !f.inQuorum(from) {
		return nil
	}
	f.votes[from] = struct{}{}
	f.maybeBecomeLeader()
	return nil
}

func (f *Follower) maybeBecomeLeader() {
	if f.role == roleCandidate && len(f.votes) >= f.majority() {
		f.becomeLeader()
	}
}

// becomeLeader takes the leadership this member was elected to, for as long as
// it takes a voter to catch up.
//
// Unlike raft-become-leader it appends no barrier entry for the new term. A
// leader can only commit an entry of its own term, so this leader commits
// nothing; it does not need to, because the voter it hands over to appends its
// own barrier and commits everything before it. Leaving the barrier out keeps
// the witness's log a pure copy of what real leaders wrote, and lets "the voter
// holds our whole log" mean exactly that.
func (f *Follower) becomeLeader() {
	f.role = roleLeader
	f.leaderID = f.id
	f.successor = ""
	f.leaderSince = f.clock()
	f.nextIndex = make(map[string]int64)
	f.matchIndex = make(map[string]int64)
	for _, peer := range f.quorumPeers() {
		if f.st.Members[peer] == RoleVoter {
			f.nextIndex[peer] = f.lastLogIndex() + 1
			f.matchIndex[peer] = 0
		}
	}
	f.logf("elected for term %d to hand this witness's log (through index %d) to a voter",
		f.st.CurrentTerm, f.lastLogIndex())
	f.broadcastAppend()
}

// broadcastAppend sends every voter an AppendEntries from its next-index.
func (f *Follower) broadcastAppend() {
	f.lastAppend = f.clock()
	peers := make([]string, 0, len(f.nextIndex))
	for peer := range f.nextIndex {
		peers = append(peers, peer)
	}
	sort.Strings(peers)
	for _, peer := range peers {
		f.sendAppend(peer)
	}
}

// sendAppend sends peer one bounded batch starting at its next-index
// (raft-append-message). Entries leave as the Lisp forms they arrived as: the
// stored command is the printed form, read back and printed again.
func (f *Follower) sendAppend(peer string) {
	next := f.nextIndex[peer]
	if next <= f.st.SnapshotIdx {
		// A witness holds a log and no application state. A peer that needs
		// entries it has already discarded can only be helped by a voter.
		return
	}
	prev := next - 1
	prevTerm, _ := f.logTerm(prev)
	var entries []lispwire.Value
	var bytes int64
	for i := next; i <= f.lastLogIndex() && len(entries) < appendEntryLimit; i++ {
		e := f.st.Log[i-f.st.SnapshotIdx-1]
		weight := int64(len(e.Command)) + 128
		// One oversized command travels alone, so every stored entry stays
		// deliverable.
		if len(entries) > 0 && bytes+weight > appendByteBudget {
			break
		}
		command, err := lispwire.Read(e.Command)
		if err != nil {
			f.logf("cannot send entry %d to %s: stored command does not read back: %v", e.Index, peer, err)
			return
		}
		bytes += weight
		entries = append(entries, lispwire.List{Items: []lispwire.Value{
			lispwire.Int(e.Index), lispwire.Int(e.Term), command}})
	}
	// An empty list is NIL in Lisp, and prints as NIL.
	var wireEntries lispwire.Value = lispwire.Sym("NIL")
	if len(entries) > 0 {
		wireEntries = lispwire.List{Items: entries}
	}
	// :LEADER-COMMIT is what this member last heard was committed; it never
	// advances it. :READ-SEQ is 0 because a witness serves no reads.
	f.send(peer, lispwire.NewReply("APPEND-ENTRIES").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).
		Int("PREV-LOG-INDEX", prev).Int("PREV-LOG-TERM", prevTerm).
		Raw("ENTRIES", wireEntries).
		Int("LEADER-COMMIT", f.st.CommitIndex).Int("READ-SEQ", 0).Encode())
}

func (f *Follower) handleAppendEntriesReply(msg *lispwire.Msg) error {
	term, _ := msg.Int("TERM")
	peer, _ := msg.Str("FROM")
	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	if f.role != roleLeader || term != f.st.CurrentTerm {
		return nil
	}
	next, tracked := f.nextIndex[peer]
	if !tracked {
		return nil
	}
	last := f.lastLogIndex()
	if !msg.Bool("SUCCESS") {
		// Back up: to the peer's hint when it gives one, else one entry, and never
		// below what it has already proven to hold.
		back, hinted := msg.Int("NEXT-INDEX")
		if !hinted {
			back = next - 1
		}
		back = min64(last+1, max64(f.matchIndex[peer]+1, back))
		f.nextIndex[peer] = back
		// Retry at once -- the voter is waiting on us -- unless the reply taught us
		// nothing new; then it is a duplicate, and the heartbeat is the retry.
		if back != next {
			f.sendAppend(peer)
		}
		return nil
	}
	match, ok := msg.Int("MATCH-INDEX")
	if !ok || match < 0 || match > last {
		return nil
	}
	// A successful acknowledgement cannot revoke already proven progress, so
	// match/next never move backward.
	match = max64(f.matchIndex[peer], match)
	f.matchIndex[peer] = match
	f.nextIndex[peer] = max64(next, match+1)
	switch {
	case match == last && f.successor == "" && f.st.Members[peer] == RoleVoter:
		// The first voter to hold our whole log takes over
		// (raft-witness-choose-successor). TIMEOUT-NOW is sent once; if it is
		// lost, Tick gives up and the voter's next Pre-Vote is granted, because
		// it is no longer behind.
		f.successor = peer
		f.send(peer, lispwire.NewReply("TIMEOUT-NOW").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Encode())
		f.logf("handed over to %s, which holds the whole log through index %d", peer, last)
	case f.nextIndex[peer] <= last:
		f.sendAppend(peer) // more to send: do not wait for the heartbeat
	}
	return nil
}

// Tick advances the clock and returns the messages to send. Only a stand-in
// leader has anything to do on the clock: it resends AppendEntries every
// heartbeat, and it leads for at most one election timeout. If no voter has
// replaced it by then, leading on would help nobody -- it cannot commit or serve
// -- so it stands down and stands in again when a voter next asks for a vote
// (raft-tick).
func (f *Follower) Tick() []Reply {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.role != roleLeader {
		return nil
	}
	f.out = nil
	now := f.clock()
	switch {
	case now.Sub(f.leaderSince) >= f.electionTimeout:
		if f.successor != "" {
			f.logf("gave up leading term %d: %s did not take over within %s", f.st.CurrentTerm, f.successor, f.electionTimeout)
		} else {
			f.logf("gave up leading term %d: no voter caught up within %s", f.st.CurrentTerm, f.electionTimeout)
		}
		// The term and the vote stay: this member did vote for itself in it.
		f.becomeFollower("")
	case now.Sub(f.lastAppend) >= heartbeatInterval:
		f.broadcastAppend()
	}
	out := f.out
	f.out = nil
	return out
}
