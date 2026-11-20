// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// lastCommand is the entry the surviving voter lacks in these tests. It has an
// escaped quote, a dotted pair and a vector in it, so sending it on unchanged is
// not trivially true.
const lastCommand = `(:PUT "key" "va\"lue" (1 . 2) #(3 4) NIL)`

var threeMembers = map[string]string{"gvision": RoleVoter, "gr8s2": RoleVoter, "wit": RoleWitness}

// standInState is the lab situation of podster-f15: term 4, five entries stored,
// four known committed, and a voter (gr8s2) that holds only the first four.
func standInState(members map[string]string) *State {
	st := &State{HardState: HardState{CurrentTerm: 4, VotedFor: "gvision", Members: members}}
	for i := int64(1); i <= 4; i++ {
		st.Log = append(st.Log, Entry{Index: i, Term: 4, Command: fmt.Sprintf(`(:PUT "k%d" "v")`, i)})
	}
	st.Log = append(st.Log, Entry{Index: 5, Term: 4, Command: lastCommand})
	return st
}

// newWitness returns a witness in standInState with a clock the test moves and a
// record of what it logged.
func newWitness(t *testing.T, members map[string]string) (f *Follower, ms *memStore, now *time.Time, logged *[]string) {
	t.Helper()
	f, ms = newTestFollower(t, standInState(members))
	f.st.CommitIndex = 4
	clock := time.Unix(1000, 0)
	f.clock = func() time.Time { return clock }
	var lines []string
	f.logf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	return f, ms, &clock, &lines
}

// sent renders messages as "to <- payload", the form the tests compare.
func sent(out []Reply) []string {
	var s []string
	for _, r := range out {
		s = append(s, r.To+" <- "+string(r.Payload))
	}
	return s
}

func expectSent(t *testing.T, what string, out []Reply, want ...string) {
	t.Helper()
	if got := sent(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: sent\n  %s\nwant\n  %s", what, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func step(t *testing.T, f *Follower, payload string) []Reply {
	t.Helper()
	out, err := f.Step([]byte(payload))
	if err != nil {
		t.Fatalf("Step(%s): %v", payload, err)
	}
	return out
}

// Golden wire strings for every message a stand-in originates, as cl-raft would
// print the same plists (raft-begin-pre-election, raft-become-candidate,
// raft-append-message, raft-maybe-send-timeout-now) under gr8s's bindings.
const (
	goldenPreVote      = `(:TYPE :PRE-VOTE :TERM 5 :FROM "wit" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4)`
	goldenRequestVote  = `(:TYPE :REQUEST-VOTE :TERM 5 :FROM "wit" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4 :LEADER-TRANSFER NIL)`
	goldenHeartbeat    = `(:TYPE :APPEND-ENTRIES :TERM 5 :FROM "wit" :PREV-LOG-INDEX 5 :PREV-LOG-TERM 4 :ENTRIES NIL :LEADER-COMMIT 4 :READ-SEQ 0)`
	goldenAppendOne    = `(:TYPE :APPEND-ENTRIES :TERM 5 :FROM "wit" :PREV-LOG-INDEX 4 :PREV-LOG-TERM 4 :ENTRIES ((5 4 ` + lastCommand + `)) :LEADER-COMMIT 4 :READ-SEQ 0)`
	goldenTimeoutNow   = `(:TYPE :TIMEOUT-NOW :TERM 5 :FROM "wit")`
	goldenPreVoteReply = `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "wit" :GRANTED NIL)`
)

// The whole handover, against a scripted voter that is one entry behind.
func TestStandInHandsItsLogToTheVoterThatIsBehind(t *testing.T) {
	f, ms, _, logged := newWitness(t, threeMembers)
	saves := ms.saves

	// The surviving voter asks for a pre-vote with a log one entry short. The
	// refusal still goes back; the witness also asks every peer for a pre-vote.
	out := step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	expectSent(t, "refused pre-vote", out,
		"gr8s2 <- "+goldenPreVoteReply,
		"gr8s2 <- "+goldenPreVote,
		"gvision <- "+goldenPreVote)
	if ms.saves != saves || f.st.CurrentTerm != 4 || f.role != roleFollower {
		t.Fatalf("a pre-election must change no persistent state (saves %d->%d, term %d)", saves, ms.saves, f.st.CurrentTerm)
	}

	// The voter grants: with itself that is 2 of 3. A real candidacy at term 5,
	// on disk before the REQUEST-VOTE that reveals it.
	out = step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
	expectSent(t, "pre-vote granted", out,
		"gr8s2 <- "+goldenRequestVote,
		"gvision <- "+goldenRequestVote)
	if ms.hs.CurrentTerm != 5 || ms.hs.VotedFor != "wit" {
		t.Fatalf("candidacy not persisted: term %d voted-for %q", ms.hs.CurrentTerm, ms.hs.VotedFor)
	}
	if f.role != roleCandidate {
		t.Fatalf("role = %v, want candidate", f.role)
	}

	// The voter votes for it: leader of term 5. No barrier is appended, so the
	// first AppendEntries is an empty one at the witness's own last index.
	out = step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
	expectSent(t, "elected", out,
		"gr8s2 <- "+goldenHeartbeat,
		"gvision <- "+goldenHeartbeat)
	if f.role != roleLeader || f.LeaderID() != "wit" {
		t.Fatalf("role = %v leader = %q, want leader/wit", f.role, f.LeaderID())
	}
	if n := len(f.st.Log); n != 5 || len(ms.log) != 5 {
		t.Fatalf("the stand-in must append nothing to its log (%d in memory, %d stored)", n, len(ms.log))
	}

	// The voter does not have index 5 and says where it is. The missing entry
	// goes out exactly as it was stored.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 5)`)
	expectSent(t, "backed up", out, "gr8s2 <- "+goldenAppendOne)
	m, err := lispwire.Decode(out[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got := lispwire.Write(m.Entries[0].Command); got != ms.log[4].Command {
		t.Fatalf("entry 5 went out as\n  %s\nstored as\n  %s", got, ms.log[4].Command)
	}

	// The voter now holds the whole log: it is told to take over.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 5 :APPLIED-INDEX 4)`)
	expectSent(t, "caught up", out, "gr8s2 <- "+goldenTimeoutNow)

	// A repeated acknowledgement sends neither a second TIMEOUT-NOW nor an
	// AppendEntries that would be answered by another acknowledgement for ever.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 5 :APPLIED-INDEX 4)`)
	expectSent(t, "acknowledged again", out)

	// The voter campaigns at term 6. Its log is no longer behind, so it gets the
	// vote, and the witness is a follower again.
	out = step(t, f, `(:TYPE :REQUEST-VOTE :TERM 6 :FROM "gr8s2" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4 :LEADER-TRANSFER T)`)
	expectSent(t, "voter campaigns", out, `gr8s2 <- (:TYPE :REQUEST-VOTE-REPLY :TERM 6 :FROM "wit" :GRANTED T)`)
	if f.role != roleFollower || f.nextIndex != nil || f.successor != "" || f.LeaderID() != "" {
		t.Fatalf("not a plain follower again: role %v next %v successor %q leader %q", f.role, f.nextIndex, f.successor, f.LeaderID())
	}
	if ms.hs.CurrentTerm != 6 || ms.hs.VotedFor != "gr8s2" {
		t.Fatalf("vote not persisted: term %d voted-for %q", ms.hs.CurrentTerm, ms.hs.VotedFor)
	}
	if out := f.Tick(); len(out) != 0 {
		t.Fatalf("a follower's tick sends nothing, got %v", sent(out))
	}

	// And it follows the new leader, whose first entry is its barrier.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES :TERM 6 :FROM "gr8s2" :PREV-LOG-INDEX 5 :PREV-LOG-TERM 4 :ENTRIES ((6 6 (:RAFT-BARRIER))) :LEADER-COMMIT 5 :READ-SEQ 1)`)
	expectSent(t, "follows", out, `gr8s2 <- (:TYPE :APPEND-ENTRIES-REPLY :TERM 6 :FROM "wit" :READ-SEQ 1 :SUCCESS T :MATCH-INDEX 6 :APPLIED-INDEX 5)`)

	// Each transition is logged once.
	for _, want := range []string{"standing in for gr8s2", "elected for term 5", "handed over to gr8s2"} {
		n := 0
		for _, line := range *logged {
			if strings.Contains(line, want) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q logged %d times, want once; log:\n  %s", want, n, strings.Join(*logged, "\n  "))
		}
	}
}

// Every case here gets exactly one message back -- the Pre-Vote reply -- and no
// pre-election.
func TestDoesNotStandIn(t *testing.T) {
	behind := `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`
	cases := []struct {
		name    string
		members map[string]string
		prepare func(t *testing.T, f *Follower)
		preVote string
		granted bool
	}{
		{name: "it heard a leader recently", members: threeMembers,
			prepare: func(t *testing.T, f *Follower) {
				step(t, f, `(:TYPE :APPEND-ENTRIES :TERM 4 :FROM "gvision" :PREV-LOG-INDEX 5 :PREV-LOG-TERM 4 :ENTRIES NIL :LEADER-COMMIT 4 :READ-SEQ 1)`)
			},
			preVote: behind},
		{name: "the candidate is up to date: it grants instead", members: threeMembers,
			preVote: `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4)`, granted: true},
		{name: "the candidate is below the snapshot index", members: threeMembers,
			prepare: func(t *testing.T, f *Follower) {
				// Entries 1..3 are compacted away; the candidate lacks entry 3.
				f.st.Log = f.st.Log[3:]
				f.st.SnapshotIdx, f.st.SnapshotTrm = 3, 4
			},
			preVote: `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 2 :LAST-LOG-TERM 4)`},
		{name: "the candidate names no last index", members: threeMembers,
			preVote: `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-TERM 3)`},
		{name: "the pre-vote term is not ahead of ours", members: threeMembers,
			preVote: `(:TYPE :PRE-VOTE :TERM 4 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`},
		{name: "membership unknown", members: nil, preVote: behind},
		{name: "self is not in the membership",
			members: map[string]string{"gvision": RoleVoter, "gr8s2": RoleVoter}, preVote: behind},
		{name: "self is a learner",
			members: map[string]string{"gvision": RoleVoter, "gr8s2": RoleVoter, "wit": RoleLearner}, preVote: behind},
		{name: "self is recorded as a voter",
			members: map[string]string{"gvision": RoleVoter, "gr8s2": RoleVoter, "wit": RoleVoter}, preVote: behind},
		{name: "the candidate is a learner",
			members: map[string]string{"gvision": RoleVoter, "gr8s2": RoleLearner, "wit": RoleWitness}, preVote: behind},
		{name: "the candidate is another witness",
			members: map[string]string{"gvision": RoleVoter, "gr8s2": RoleWitness, "wit": RoleWitness}, preVote: behind},
		{name: "the candidate is not a member",
			members: map[string]string{"gvision": RoleVoter, "other": RoleVoter, "wit": RoleWitness}, preVote: behind},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, ms, _, logged := newWitness(t, c.members)
			if c.prepare != nil {
				c.prepare(t, f)
			}
			saves := ms.saves
			out := step(t, f, c.preVote)
			if len(out) != 1 || out[0].To != "gr8s2" {
				t.Fatalf("want only the reply to gr8s2, got %v", sent(out))
			}
			m := decodeReply(t, &out[0])
			if m.Type != "PRE-VOTE-REPLY" || m.Bool("GRANTED") != c.granted {
				t.Fatalf("reply %s, want PRE-VOTE-REPLY granted=%v", out[0].Payload, c.granted)
			}
			if f.preVoteTerm != 0 || f.role != roleFollower || ms.saves != saves {
				t.Fatalf("stood in: pre-vote term %d role %v", f.preVoteTerm, f.role)
			}
			for _, line := range *logged {
				if strings.Contains(line, "standing in") {
					t.Fatalf("logged %q", line)
				}
			}
		})
	}
}

// The majority comes from the membership: voters and witnesses count, learners
// do not, and nobody counts twice.
func TestMajorityComesFromTheMembership(t *testing.T) {
	five := map[string]string{
		"a": RoleVoter, "b": RoleVoter, "c": RoleVoter, "d": RoleVoter,
		"wit": RoleWitness, "l": RoleLearner,
	}
	f, _, _, _ := newWitness(t, five)
	if got := f.majority(); got != 3 {
		t.Fatalf("majority of 5 quorum members (and a learner) = %d, want 3", got)
	}
	out := step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "a" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	if got := len(out); got != 5 { // the reply, and a PRE-VOTE to each of a b c d
		t.Fatalf("sent %d messages, want 5: %v", got, sent(out))
	}
	for _, r := range out {
		if r.To == "l" || r.To == "wit" {
			t.Fatalf("asked %s for a pre-vote", r.To)
		}
	}
	grant := func(from string) []Reply {
		return step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "`+from+`" :GRANTED T)`)
	}
	// One grant is 2 of 5. The same member again, the learner, a stranger, the
	// witness's own id, a grant for another round and a refusal add nothing.
	for _, from := range []string{"a", "a", "l", "stranger", "wit"} {
		if out := grant(from); len(out) != 0 || f.role != roleFollower {
			t.Fatalf("became a candidate after a grant from %q: %v", from, sent(out))
		}
	}
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 6 :FROM "b" :GRANTED T)`)
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "b" :GRANTED NIL)`)
	if f.role != roleFollower || f.st.CurrentTerm != 4 {
		t.Fatalf("role %v term %d after grants that must not count", f.role, f.st.CurrentTerm)
	}
	// A second member makes 3 of 5.
	if out := grant("b"); len(out) != 4 || f.role != roleCandidate {
		t.Fatalf("want a REQUEST-VOTE to each of 4 voters, got %v (role %v)", sent(out), f.role)
	}

	// The same rules for the real votes.
	vote := func(term int64, from string, granted string) {
		step(t, f, fmt.Sprintf(`(:TYPE :REQUEST-VOTE-REPLY :TERM %d :FROM "%s" :GRANTED %s)`, term, from, granted))
	}
	vote(5, "c", "T")
	vote(5, "c", "T")
	vote(5, "l", "T")
	vote(5, "stranger", "T")
	vote(5, "wit", "T")
	vote(4, "d", "T") // a vote from an older term
	vote(5, "d", "NIL")
	if f.role != roleCandidate {
		t.Fatalf("role %v: one vote is 2 of 5, not a majority", f.role)
	}
	vote(5, "d", "T")
	if f.role != roleLeader {
		t.Fatalf("role %v: self + c + d is 3 of 5", f.role)
	}
	// It replicates to voters only.
	if _, ok := f.nextIndex["l"]; ok || len(f.nextIndex) != 4 {
		t.Fatalf("next-index tracks %v, want the four voters", f.nextIndex)
	}
}

// REQUEST-VOTE is fire-and-forget and may be lost. Nothing times out on a
// witness; the voter's next Pre-Votes bring the stand-in back.
func TestLostRequestVoteIsRecoveredByALaterPreVote(t *testing.T) {
	f, ms, _, _ := newWitness(t, threeMembers)
	step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
	if f.role != roleCandidate || f.st.CurrentTerm != 5 {
		t.Fatalf("setup: role %v term %d", f.role, f.st.CurrentTerm)
	}
	// Both REQUEST-VOTEs are lost. The voter, still at term 4, asks again for
	// term 5. That is not ahead of the witness any more: it is refused, and the
	// reply tells the voter the term is 5.
	out := step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	expectSent(t, "pre-vote at our own term", out,
		`gr8s2 <- (:TYPE :PRE-VOTE-REPLY :TERM 5 :PRE-TERM 5 :FROM "wit" :GRANTED NIL)`)
	// The voter adopts term 5 and asks for term 6: the stand-in starts again.
	out = step(t, f, `(:TYPE :PRE-VOTE :TERM 6 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	preVote6 := `(:TYPE :PRE-VOTE :TERM 6 :FROM "wit" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4)`
	expectSent(t, "pre-vote ahead again", out,
		`gr8s2 <- (:TYPE :PRE-VOTE-REPLY :TERM 5 :PRE-TERM 6 :FROM "wit" :GRANTED NIL)`,
		"gr8s2 <- "+preVote6, "gvision <- "+preVote6)
	out = step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 5 :PRE-TERM 6 :FROM "gr8s2" :GRANTED T)`)
	requestVote6 := `(:TYPE :REQUEST-VOTE :TERM 6 :FROM "wit" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4 :LEADER-TRANSFER NIL)`
	expectSent(t, "second candidacy", out, "gr8s2 <- "+requestVote6, "gvision <- "+requestVote6)
	if ms.hs.CurrentTerm != 6 || ms.hs.VotedFor != "wit" {
		t.Fatalf("second candidacy not persisted: term %d voted-for %q", ms.hs.CurrentTerm, ms.hs.VotedFor)
	}
	// A late vote for the abandoned term 5 elects nobody.
	step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
	if f.role != roleCandidate {
		t.Fatalf("role %v after a vote for an older term", f.role)
	}
}

// A lost Pre-Vote is recovered the same way: the trigger fires again for the
// same term, and starts the count again.
func TestRepeatedPreVoteRestartsThePreElection(t *testing.T) {
	f, _, _, logged := newWitness(t, threeMembers)
	behind := `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`
	if out := step(t, f, behind); len(out) != 3 {
		t.Fatalf("first: %v", sent(out))
	}
	if out := step(t, f, behind); len(out) != 3 {
		t.Fatalf("second: %v", sent(out))
	}
	n := 0
	for _, line := range *logged {
		if strings.Contains(line, "standing in") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("one stand-in for one term is logged once, got %d", n)
	}
}

// electWitness drives a witness to stand-in leader of term 5 for gr8s2.
func electWitness(t *testing.T, f *Follower) {
	t.Helper()
	step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
	step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
	if f.role != roleLeader {
		t.Fatalf("setup: role %v, want leader", f.role)
	}
}

func TestTickResendsAndThenGivesUp(t *testing.T) {
	f, ms, now, logged := newWitness(t, threeMembers)
	electWitness(t, f)
	saves := ms.saves

	// Before a heartbeat interval has passed: nothing.
	*now = now.Add(50 * time.Millisecond)
	expectSent(t, "tick at 50ms", f.Tick())
	// At the interval: every voter again, since any message may have been lost.
	*now = now.Add(50 * time.Millisecond)
	expectSent(t, "tick at 100ms", f.Tick(), "gr8s2 <- "+goldenHeartbeat, "gvision <- "+goldenHeartbeat)
	*now = now.Add(50 * time.Millisecond)
	expectSent(t, "tick at 150ms", f.Tick())
	*now = now.Add(50 * time.Millisecond)
	expectSent(t, "tick at 200ms", f.Tick(), "gr8s2 <- "+goldenHeartbeat, "gvision <- "+goldenHeartbeat)

	// A Pre-Vote while leading is refused, and starts nothing.
	out := step(t, f, `(:TYPE :PRE-VOTE :TERM 6 :FROM "gr8s2" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4)`)
	expectSent(t, "pre-vote while leading", out,
		`gr8s2 <- (:TYPE :PRE-VOTE-REPLY :TERM 5 :PRE-TERM 6 :FROM "wit" :GRANTED NIL)`)

	// Nobody replaced it within the election timeout: it stands down. Same term,
	// same vote, nothing to persist, nothing to send.
	*now = now.Add(800 * time.Millisecond)
	expectSent(t, "tick at 1s", f.Tick())
	if f.role != roleFollower || f.LeaderID() != "" || !f.lastLeaderContact.IsZero() || f.nextIndex != nil {
		t.Fatalf("did not stand down: role %v leader %q contact %v", f.role, f.LeaderID(), f.lastLeaderContact)
	}
	if f.st.CurrentTerm != 5 || f.st.VotedFor != "wit" || ms.saves != saves {
		t.Fatalf("standing down changed hard state: term %d voted-for %q", f.st.CurrentTerm, f.st.VotedFor)
	}
	if got := strings.Join(*logged, "\n"); strings.Count(got, "gave up") != 1 {
		t.Fatalf("want one 'gave up' line, log:\n%s", got)
	}
	*now = now.Add(time.Second)
	expectSent(t, "tick as follower", f.Tick())

	// It voted for itself in term 5, so a rival for term 5 is still refused...
	out = step(t, f, `(:TYPE :REQUEST-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4 :LEADER-TRANSFER NIL)`)
	expectSent(t, "rival for our term", out, `gr8s2 <- (:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "wit" :GRANTED NIL)`)
	// ...and a voter that has caught up gets its pre-vote at once.
	out = step(t, f, `(:TYPE :PRE-VOTE :TERM 6 :FROM "gr8s2" :LAST-LOG-INDEX 5 :LAST-LOG-TERM 4)`)
	expectSent(t, "pre-vote after standing down", out,
		`gr8s2 <- (:TYPE :PRE-VOTE-REPLY :TERM 5 :PRE-TERM 6 :FROM "wit" :GRANTED T)`)
}

// A newer term in any message ends whatever the witness was doing, on disk
// before anything else happens.
func TestHigherTermEndsTheStandIn(t *testing.T) {
	messages := map[string]string{
		"pre-vote reply":       `(:TYPE :PRE-VOTE-REPLY :TERM 9 :PRE-TERM 5 :FROM "gvision" :GRANTED NIL)`,
		"request-vote reply":   `(:TYPE :REQUEST-VOTE-REPLY :TERM 9 :FROM "gvision" :GRANTED NIL)`,
		"append-entries reply": `(:TYPE :APPEND-ENTRIES-REPLY :TERM 9 :FROM "gvision" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0)`,
		"timeout-now":          `(:TYPE :TIMEOUT-NOW :TERM 9 :FROM "gvision")`,
		"request-vote":         `(:TYPE :REQUEST-VOTE :TERM 9 :FROM "gvision" :LAST-LOG-INDEX 9 :LAST-LOG-TERM 8 :LEADER-TRANSFER NIL)`,
		"append-entries":       `(:TYPE :APPEND-ENTRIES :TERM 9 :FROM "gvision" :PREV-LOG-INDEX 5 :PREV-LOG-TERM 4 :ENTRIES NIL :LEADER-COMMIT 5 :READ-SEQ 3)`,
	}
	stages := map[string]func(t *testing.T, f *Follower){
		"pre-candidate": func(t *testing.T, f *Follower) {
			step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
		},
		"candidate": func(t *testing.T, f *Follower) {
			step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
			step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
		},
		"leader": electWitness,
	}
	for stage, reach := range stages {
		for name, message := range messages {
			t.Run(stage+"/"+name, func(t *testing.T) {
				f, ms, _, _ := newWitness(t, threeMembers)
				reach(t, f)
				out := step(t, f, message)
				if f.role != roleFollower || f.preVoteTerm != 0 || f.votes != nil || f.nextIndex != nil {
					t.Fatalf("still role %v pre-vote term %d", f.role, f.preVoteTerm)
				}
				if ms.hs.CurrentTerm != 9 {
					t.Fatalf("persisted term %d, want 9", ms.hs.CurrentTerm)
				}
				wantVote := ""
				if name == "request-vote" {
					wantVote = "gvision" // up to date, and our vote in term 9 is free
				}
				if ms.hs.VotedFor != wantVote {
					t.Fatalf("persisted vote %q, want %q", ms.hs.VotedFor, wantVote)
				}
				for i := range out {
					if m := decodeReply(t, &out[i]); m.Type != "REQUEST-VOTE-REPLY" && m.Type != "APPEND-ENTRIES-REPLY" {
						t.Fatalf("sent %s after stepping down", out[i].Payload)
					} else if term, _ := m.Int("TERM"); term != 9 {
						t.Fatalf("reply carries term %d", term)
					}
				}
				// Late answers to the abandoned term change nothing.
				step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
				step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
				late := step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 5)`)
				if f.role != roleFollower || f.st.CurrentTerm != 9 || len(late) != 0 {
					t.Fatalf("late replies revived the stand-in: role %v term %d", f.role, f.st.CurrentTerm)
				}
			})
		}
	}
}

// If the new term cannot be written down, nothing that reveals it may be sent.
func TestCandidacyIsNotAnnouncedUnlessPersisted(t *testing.T) {
	f, ms, _, _ := newWitness(t, threeMembers)
	step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	ms.failPut = errors.New("disk full")
	out, err := f.Step([]byte(`(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`))
	if err == nil || len(out) != 0 {
		t.Fatalf("want an error and no messages, got %v / %v", err, sent(out))
	}
	if f.st.CurrentTerm != 4 || f.st.VotedFor != "gvision" || f.role != roleFollower {
		t.Fatalf("memory moved ahead of disk: term %d voted-for %q role %v", f.st.CurrentTerm, f.st.VotedFor, f.role)
	}
	// Nor is a newer term adopted in memory only.
	out, err = f.Step(rvPayload(9, "gr8s2", 5, 4))
	if err == nil || len(out) != 0 || f.st.CurrentTerm != 4 {
		t.Fatalf("want an error, no reply and term 4; got %v / %v / term %d", err, sent(out), f.st.CurrentTerm)
	}
}

func TestCandidateAndLeaderRefuseARivalInTheirOwnTerm(t *testing.T) {
	rival := `(:TYPE :REQUEST-VOTE :TERM 5 :FROM "gvision" :LAST-LOG-INDEX 9 :LAST-LOG-TERM 4 :LEADER-TRANSFER NIL)`
	refused := `gvision <- (:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "wit" :GRANTED NIL)`

	f, _, _, _ := newWitness(t, threeMembers)
	step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
	expectSent(t, "candidate", step(t, f, rival), refused)
	if f.role != roleCandidate || f.st.VotedFor != "wit" {
		t.Fatalf("role %v voted-for %q", f.role, f.st.VotedFor)
	}

	f, _, _, _ = newWitness(t, threeMembers)
	electWitness(t, f)
	expectSent(t, "leader", step(t, f, rival), refused)
	if f.role != roleLeader || f.st.VotedFor != "wit" {
		t.Fatalf("role %v voted-for %q", f.role, f.st.VotedFor)
	}
}

// Another member won the term the witness was a candidate in.
func TestCandidateFollowsALeaderOfItsOwnTerm(t *testing.T) {
	f, _, _, _ := newWitness(t, threeMembers)
	step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 4 :LAST-LOG-TERM 4)`)
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
	out := step(t, f, `(:TYPE :APPEND-ENTRIES :TERM 5 :FROM "gvision" :PREV-LOG-INDEX 5 :PREV-LOG-TERM 4 :ENTRIES NIL :LEADER-COMMIT 5 :READ-SEQ 2)`)
	expectSent(t, "append at our term", out,
		`gvision <- (:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "wit" :READ-SEQ 2 :SUCCESS T :MATCH-INDEX 5 :APPLIED-INDEX 5)`)
	if f.role != roleFollower || f.LeaderID() != "gvision" || f.votes != nil || f.lastLeaderContact.IsZero() {
		t.Fatalf("role %v leader %q", f.role, f.LeaderID())
	}
	// It voted for itself in term 5 and that stands.
	if f.st.CurrentTerm != 5 || f.st.VotedFor != "wit" {
		t.Fatalf("term %d voted-for %q", f.st.CurrentTerm, f.st.VotedFor)
	}
	step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
	if f.role != roleFollower {
		t.Fatal("a late vote made a follower the leader")
	}
}

func TestBacksUpWithoutAHintAndIgnoresBadReplies(t *testing.T) {
	f, _, _, _ := newWitness(t, threeMembers)
	electWitness(t, f)
	fail := `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0)`

	// cl-raft's follower gives no hint when its log is merely short: one entry
	// back per refusal, resent at once.
	out := step(t, f, fail)
	if m := decodeReply(t, &out[0]); len(out) != 1 || len(m.Entries) != 1 || m.Entries[0].Index != 5 {
		t.Fatalf("first refusal: %v", sent(out))
	}
	out = step(t, f, fail)
	m := decodeReply(t, &out[0])
	if prev, _ := m.Int("PREV-LOG-INDEX"); prev != 3 || len(m.Entries) != 2 {
		t.Fatalf("second refusal: %v", sent(out))
	}

	// A hint beyond our log is clamped to it; a reply that changes nothing is a
	// duplicate and is left to the heartbeat.
	step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 99)`)
	if f.nextIndex["gr8s2"] != 6 {
		t.Fatalf("next-index %d, want 6", f.nextIndex["gr8s2"])
	}
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 6)`)
	expectSent(t, "duplicate refusal", out)

	// Partial progress: more to send, sent at once, and no handover yet.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 3)`)
	if f.matchIndex["gr8s2"] != 3 || f.successor != "" {
		t.Fatalf("match %d successor %q", f.matchIndex["gr8s2"], f.successor)
	}
	// next-index was 6 and never moves backward on a success, so nothing is due.
	expectSent(t, "partial success", out)
	// A refusal cannot push next-index below what the peer has proven to hold.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 1)`)
	m = decodeReply(t, &out[0])
	if prev, _ := m.Int("PREV-LOG-INDEX"); prev != 3 || len(m.Entries) != 2 || f.nextIndex["gr8s2"] != 4 {
		t.Fatalf("refusal below match: %v", sent(out))
	}

	// A match-index beyond our log, a reply from a member we do not replicate
	// to, and a reply for another term are all ignored.
	for _, bad := range []string{
		`(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 6)`,
		`(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX -1)`,
		`(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T)`,
		`(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "stranger" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 5)`,
		`(:TYPE :APPEND-ENTRIES-REPLY :TERM 4 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 5)`,
	} {
		if out := step(t, f, bad); len(out) != 0 || f.matchIndex["gr8s2"] != 3 || f.successor != "" {
			t.Fatalf("%s was not ignored: %v", bad, sent(out))
		}
	}
	// A stale acknowledgement cannot take progress back.
	step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 2)`)
	if f.matchIndex["gr8s2"] != 3 {
		t.Fatalf("match-index went back to %d", f.matchIndex["gr8s2"])
	}
}

// Only the first voter to hold the whole log is told to take over.
func TestOnlyOneSuccessorIsChosen(t *testing.T) {
	f, _, _, _ := newWitness(t, threeMembers)
	electWitness(t, f)
	ack := func(from string) []Reply {
		return step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "`+from+`" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 5)`)
	}
	expectSent(t, "first voter", ack("gvision"), "gvision <- "+goldenTimeoutNow)
	expectSent(t, "second voter", ack("gr8s2"))
	if f.successor != "gvision" {
		t.Fatalf("successor %q", f.successor)
	}
}

// A witness holds a log and no application state: a voter that needs entries
// the witness has compacted away gets nothing from it.
func TestSendsNothingToAPeerBelowTheSnapshot(t *testing.T) {
	st := standInState(threeMembers)
	st.Log = st.Log[2:] // entries 3..5 remain
	st.SnapshotIdx, st.SnapshotTrm = 2, 4
	f, _ := newTestFollower(t, st)
	f.logf = func(string, ...any) {}
	// gr8s2 is at index 2, exactly the boundary: it can still be served.
	step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 2 :LAST-LOG-TERM 4)`)
	step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
	step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
	out := step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 3)`)
	m := decodeReply(t, &out[0])
	prev, _ := m.Int("PREV-LOG-INDEX")
	prevTerm, _ := m.Int("PREV-LOG-TERM")
	if prev != 2 || prevTerm != 4 || len(m.Entries) != 3 {
		t.Fatalf("from the boundary: %v", sent(out))
	}
	// gvision turns out to need index 2 itself, which is gone.
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gvision" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 2)`)
	expectSent(t, "below the snapshot", out)
	f.clock = func() time.Time { return time.Unix(1000, 0).Add(heartbeatInterval) }
	for _, r := range f.Tick() {
		if r.To == "gvision" {
			t.Fatalf("heartbeat to a peer we cannot serve: %s", r.Payload)
		}
	}
}

func TestAppendBatchIsBounded(t *testing.T) {
	build := func(n int, size int) *Follower {
		st := &State{HardState: HardState{CurrentTerm: 4, Members: threeMembers}}
		for i := 1; i <= n; i++ {
			st.Log = append(st.Log, Entry{Index: int64(i), Term: 4,
				Command: `(:PUT "k" "` + strings.Repeat("x", size) + `")`})
		}
		f, _ := newTestFollower(t, st)
		f.logf = func(string, ...any) {}
		step(t, f, `(:TYPE :PRE-VOTE :TERM 5 :FROM "gr8s2" :LAST-LOG-INDEX 0 :LAST-LOG-TERM 0)`)
		step(t, f, `(:TYPE :PRE-VOTE-REPLY :TERM 4 :PRE-TERM 5 :FROM "gr8s2" :GRANTED T)`)
		step(t, f, `(:TYPE :REQUEST-VOTE-REPLY :TERM 5 :FROM "gr8s2" :GRANTED T)`)
		return f
	}
	fromStart := `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS NIL :MATCH-INDEX 0 :NEXT-INDEX 1)`
	count := func(out []Reply) int {
		t.Helper()
		if len(out) != 1 {
			t.Fatalf("want one AppendEntries, got %d", len(out))
		}
		return len(decodeReply(t, &out[0]).Entries)
	}

	// Many small entries: 64 at a time, and the next batch follows the ack.
	f := build(150, 10)
	if n := count(step(t, f, fromStart)); n != appendEntryLimit {
		t.Fatalf("first batch %d entries, want %d", n, appendEntryLimit)
	}
	out := step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 64)`)
	m := decodeReply(t, &out[0])
	if prev, _ := m.Int("PREV-LOG-INDEX"); prev != 64 || len(m.Entries) != appendEntryLimit {
		t.Fatalf("second batch prev %d with %d entries", prev, len(m.Entries))
	}
	out = step(t, f, `(:TYPE :APPEND-ENTRIES-REPLY :TERM 5 :FROM "gr8s2" :READ-SEQ 0 :SUCCESS T :MATCH-INDEX 128)`)
	if n := count(out); n != 22 {
		t.Fatalf("last batch %d entries, want 22", n)
	}

	// 300 KiB entries: three fit in about 1 MiB, a fourth would not.
	f = build(10, 300<<10)
	if n := count(step(t, f, fromStart)); n != 3 {
		t.Fatalf("byte-bounded batch %d entries, want 3", n)
	}
	// An entry larger than the whole budget still travels, alone.
	f = build(3, 2<<20)
	if n := count(step(t, f, fromStart)); n != 1 {
		t.Fatalf("oversized entry batch %d entries, want 1", n)
	}
}
