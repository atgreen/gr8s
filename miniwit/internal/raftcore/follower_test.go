// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// memStore is an in-memory Store that counts durable writes, so tests can assert
// persistence happened before an ack and can reload to check durability.
type memStore struct {
	hs    HardState
	log   []Entry
	saves int
}

func (m *memStore) Load() (*State, error) {
	return &State{HardState: m.hs, CommitIndex: m.hs.SnapshotIdx, Log: append([]Entry(nil), m.log...)}, nil
}
func (m *memStore) PutHardState(hs HardState) error { m.hs = hs; m.saves++; return nil }
func (m *memStore) AppendLog(e []Entry) error        { m.log = append(m.log, e...); m.saves++; return nil }
func (m *memStore) RewriteLog(e []Entry) error {
	m.log = append([]Entry(nil), e...)
	m.saves++
	return nil
}

func newTestFollower(t *testing.T, init *State) (*Follower, *memStore) {
	t.Helper()
	if init == nil {
		init = &State{}
	}
	ms := &memStore{hs: init.HardState, log: append([]Entry(nil), init.Log...)}
	f, err := NewFollower("wit", ms, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.clock = func() time.Time { return time.Unix(1000, 0) }
	return f, ms
}

func decodeReply(t *testing.T, r *Reply) *lispwire.Msg {
	t.Helper()
	if r == nil {
		t.Fatal("expected a reply, got nil")
	}
	m, err := lispwire.Decode(r.Payload)
	if err != nil {
		t.Fatalf("reply did not decode as a Raft message: %v", err)
	}
	return m
}

func rvPayload(term int64, from string, lastIdx, lastTrm int64) []byte {
	return lispwire.NewReply("REQUEST-VOTE").Int("TERM", term).Str("FROM", from).
		Int("LAST-LOG-INDEX", lastIdx).Int("LAST-LOG-TERM", lastTrm).Encode()
}

func TestGrantsVoteThenRefusesSecondCandidateSameTerm(t *testing.T) {
	f, ms := newTestFollower(t, nil)

	r, err := f.Step(rvPayload(5, "gvision", 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	m := decodeReply(t, r)
	if m.Type != "REQUEST-VOTE-REPLY" || r.To != "gvision" {
		t.Fatalf("reply type=%q to=%q", m.Type, r.To)
	}
	if !m.Bool("GRANTED") {
		t.Fatal("first vote should be granted")
	}
	if term, _ := m.Int("TERM"); term != 5 {
		t.Errorf("reply term = %d", term)
	}
	if ms.saves == 0 {
		t.Error("a granted vote must be persisted before the reply")
	}

	// Same term, a different candidate: already voted, so refuse.
	r2, _ := f.Step(rvPayload(5, "gr8s2", 0, 0))
	if decodeReply(t, r2).Bool("GRANTED") {
		t.Fatal("must not grant a second vote in the same term")
	}
}

func TestRefusesVoteWithStaleLog(t *testing.T) {
	// Our log is at index 10, term 4; a candidate behind that must be refused.
	f, _ := newTestFollower(t, &State{CurrentTerm: 4, SnapshotIdx: 10, SnapshotTrm: 4})
	r, _ := f.Step(rvPayload(5, "gvision", 9, 4)) // lower last-log-index
	if decodeReply(t, r).Bool("GRANTED") {
		t.Fatal("must refuse a candidate whose log is less up-to-date")
	}
}

func TestStepsDownOnHigherTerm(t *testing.T) {
	f, _ := newTestFollower(t, &State{CurrentTerm: 3, VotedFor: "old"})
	_, _ = f.Step(rvPayload(9, "gvision", 0, 0))
	st := f.snapshotState()
	if st.CurrentTerm != 9 {
		t.Errorf("term = %d, want 9", st.CurrentTerm)
	}
}

func TestPreVoteGrantedOnlyWithoutRecentLeader(t *testing.T) {
	f, _ := newTestFollower(t, &State{CurrentTerm: 5})
	pv := lispwire.NewReply("PRE-VOTE").Int("TERM", 6).Str("FROM", "gvision").
		Int("LAST-LOG-INDEX", 0).Int("LAST-LOG-TERM", 0).Encode()

	// No leader heard yet -> grant.
	if !decodeReply(t, mustStep(t, f, pv)).Bool("GRANTED") {
		t.Fatal("pre-vote should be granted when no leader is seen")
	}
	// Hear a leader via a heartbeat, then a pre-vote must be refused (healthy leader).
	hb := appendPayload(6, "gvision", 0, 0, nil, 0, 1)
	_, _ = f.Step(hb)
	if decodeReply(t, mustStep(t, f, pv)).Bool("GRANTED") {
		t.Fatal("pre-vote must be refused right after hearing a leader")
	}
}

func appendPayload(term int64, from string, prevIdx, prevTrm int64, entries []lispwire.Value, leaderCommit, readSeq int64) []byte {
	b := lispwire.NewReply("APPEND-ENTRIES").Int("TERM", term).Str("FROM", from).
		Int("PREV-LOG-INDEX", prevIdx).Int("PREV-LOG-TERM", prevTrm)
	// entries is encoded by hand as a list of (index term command) triples.
	b.Raw("ENTRIES", lispwire.List{Items: entries})
	b.Int("LEADER-COMMIT", leaderCommit).Int("READ-SEQ", readSeq)
	return b.Encode()
}

func entryTriple(index, term int64, command lispwire.Value) lispwire.Value {
	return lispwire.List{Items: []lispwire.Value{lispwire.Int(index), lispwire.Int(term), command}}
}

func TestAppendEntriesAppendsAndCommits(t *testing.T) {
	f, ms := newTestFollower(t, nil)
	// First establish the leader's term so prev-index 0 matches our empty log.
	e1 := entryTriple(1, 2, lispwire.List{Items: []lispwire.Value{lispwire.Sym(":RAFT-BARRIER")}})
	e2 := entryTriple(2, 2, lispwire.List{Items: []lispwire.Value{lispwire.Sym(":PUT"), lispwire.Str("k"), lispwire.Str("v")}})
	r, err := f.Step(appendPayload(2, "gvision", 0, 0, []lispwire.Value{e1, e2}, 2, 7))
	if err != nil {
		t.Fatal(err)
	}
	m := decodeReply(t, r)
	if !m.Bool("SUCCESS") {
		t.Fatal("append should succeed on a matching empty log")
	}
	if mi, _ := m.Int("MATCH-INDEX"); mi != 2 {
		t.Errorf("match-index = %d, want 2", mi)
	}
	if rs, _ := m.Int("READ-SEQ"); rs != 7 {
		t.Errorf("read-seq echo = %d, want 7", rs)
	}
	st := f.snapshotState()
	if len(st.Log) != 2 || st.CommitIndex != 2 {
		t.Fatalf("log=%d commit=%d", len(st.Log), st.CommitIndex)
	}
	if ms.saves == 0 {
		t.Error("appended entries must be persisted before the success reply")
	}
	// Durability: a fresh follower over the same store sees the entries.
	f2, _ := NewFollower("wit", ms, time.Second)
	if f2.lastLogIndex() != 2 {
		t.Errorf("reloaded last-log-index = %d, want 2", f2.lastLogIndex())
	}
}

func TestAppendEntriesRejectsLogMismatch(t *testing.T) {
	// We hold index 5 @ term 3; leader claims prev-index 5 @ term 4 -> mismatch.
	f, _ := newTestFollower(t, &State{CurrentTerm: 4, SnapshotIdx: 5, SnapshotTrm: 3})
	r, _ := f.Step(appendPayload(4, "gvision", 5, 4, nil, 5, 1))
	m := decodeReply(t, r)
	if m.Bool("SUCCESS") {
		t.Fatal("append must be rejected when prev-log-term mismatches")
	}
}

func TestInstallSnapshotSetsBoundary(t *testing.T) {
	f, ms := newTestFollower(t, &State{CurrentTerm: 6})
	is := lispwire.NewReply("INSTALL-SNAPSHOT").Int("TERM", 6).Str("FROM", "gvision").
		Int("LAST-INDEX", 100).Int("LAST-TERM", 5).
		Raw("STATE", lispwire.Sym("NIL")).Encode()
	r, err := f.Step(is)
	if err != nil {
		t.Fatal(err)
	}
	m := decodeReply(t, r)
	if !m.Bool("SUCCESS") {
		t.Fatal("snapshot install should succeed")
	}
	if mi, _ := m.Int("MATCH-INDEX"); mi != 100 {
		t.Errorf("match-index = %d, want 100", mi)
	}
	st := f.snapshotState()
	if st.SnapshotIdx != 100 || st.SnapshotTrm != 5 || st.CommitIndex != 100 {
		t.Errorf("boundary snap=%d/%d commit=%d", st.SnapshotIdx, st.SnapshotTrm, st.CommitIndex)
	}
	if ms.saves == 0 {
		t.Error("snapshot boundary must be persisted")
	}
}

// The structural witness guarantee: Step only ever produces follower replies,
// never a REQUEST-VOTE or APPEND-ENTRIES — so this member can never become leader.
func TestNeverOriginatesElectionOrReplication(t *testing.T) {
	f, _ := newTestFollower(t, nil)
	inputs := [][]byte{
		rvPayload(5, "gvision", 0, 0),
		appendPayload(5, "gvision", 0, 0, nil, 0, 1),
	}
	for _, in := range inputs {
		r, err := f.Step(in)
		if err != nil {
			t.Fatal(err)
		}
		if r == nil {
			continue
		}
		m := decodeReply(t, r)
		switch m.Type {
		case "REQUEST-VOTE", "PRE-VOTE", "APPEND-ENTRIES", "INSTALL-SNAPSHOT":
			t.Fatalf("witness must never originate %s", m.Type)
		}
	}
}

func bigEntries(n int64, termArg int64) []lispwire.Value {
	var entries []lispwire.Value
	for i := int64(1); i <= n; i++ {
		entries = append(entries, entryTriple(i, termArg, lispwire.Str(strings.Repeat("x", 100))))
	}
	return entries
}

func TestCompactionBoundsTheLog(t *testing.T) {
	oldMax, oldKeep := compactWhenLogBytes, retainLogBytes
	compactWhenLogBytes, retainLogBytes = 2000, 500
	defer func() { compactWhenLogBytes, retainLogBytes = oldMax, oldKeep }()

	f, _ := newTestFollower(t, &State{CurrentTerm: 3})
	// 150 entries of ~130 bytes each (~19 KB) far exceed the 2 KB threshold.
	r, err := f.Step(appendPayload(3, "gvision", 0, 0, bigEntries(150, 3), 150, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !decodeReply(t, r).Bool("SUCCESS") {
		t.Fatal("append should succeed")
	}
	if f.logBytes() > compactWhenLogBytes {
		t.Errorf("log not bounded: %d bytes", f.logBytes())
	}
	if f.snapshotState().SnapshotIdx == 0 {
		t.Error("snapshot boundary did not advance")
	}
	if f.lastLogIndex() != 150 {
		t.Errorf("head moved: last-log-index = %d, want 150", f.lastLogIndex())
	}
	// A follow-up append at the head still matches after compaction.
	more := []lispwire.Value{entryTriple(151, 3, lispwire.Sym("NIL"))}
	r2, _ := f.Step(appendPayload(3, "gvision", 150, 3, more, 151, 2))
	if !decodeReply(t, r2).Bool("SUCCESS") {
		t.Fatal("append at the head should still match after compaction")
	}
}

// Compaction must actually reclaim disk: after feeding far more than the
// threshold, the on-disk log file is small, not the full fed size.
func TestCompactionFreesDiskStorage(t *testing.T) {
	oldMax, oldKeep := compactWhenLogBytes, retainLogBytes
	compactWhenLogBytes, retainLogBytes = 2000, 500
	defer func() { compactWhenLogBytes, retainLogBytes = oldMax, oldKeep }()

	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFollower("wit", fs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.clock = func() time.Time { return time.Unix(1000, 0) }

	if _, err := f.Step(appendPayload(3, "gvision", 0, 0, bigEntries(150, 3), 150, 1)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(logPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	// 150 * ~130 bytes ≈ 19 KB raw; compacted it should be a small multiple of the
	// retained budget, nowhere near the full fed size.
	if info.Size() > 4*compactWhenLogBytes {
		t.Errorf("on-disk log was not reclaimed: %d bytes", info.Size())
	}
}

func mustStep(t *testing.T, f *Follower, payload []byte) *Reply {
	t.Helper()
	r, err := f.Step(payload)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
