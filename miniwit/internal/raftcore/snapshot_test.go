// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"encoding/binary"
	"testing"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// buildChunkFrame assembles a GR8SCK01 binary snapshot-chunk frame the way
// member.lisp does: magic + u32 header/envelope/data lengths + the Lisp header.
func buildChunkFrame(from string, term, index, lastTerm, offset, total int64, data []byte, done bool) []byte {
	header := lispwire.NewReply("SNAPSHOT-CHUNK").
		Int("TERM", term).Str("FROM", from).Int("LAST-INDEX", index).Int("LAST-TERM", lastTerm).
		Int("OFFSET", offset).Int("TOTAL", total).Str("TOKEN", "tk").
		Str("DIGEST", "0123456789012345678901234567890123456789012345678901234567890123").
		Bool("DONE", done).Raw("FORMAT", lispwire.Sym(":ARTIFACT-V1")).Encode()
	frame := make([]byte, 20+len(header)+len(data))
	copy(frame, []byte("GR8SCK01"))
	binary.BigEndian.PutUint32(frame[8:], uint32(len(header)))
	binary.BigEndian.PutUint32(frame[12:], 0)
	binary.BigEndian.PutUint32(frame[16:], uint32(len(data)))
	copy(frame[20:], header)
	copy(frame[20+len(header):], data)
	return frame
}

func TestSnapshotChunksReassembleAndInstallBoundary(t *testing.T) {
	f, ms := newTestFollower(t, &State{CurrentTerm: 7})
	// A 9-byte snapshot in three 3-byte chunks; the witness discards the payload.
	chunks := []struct {
		offset int64
		data   []byte
		done   bool
	}{
		{0, []byte{1, 2, 3}, false},
		{3, []byte{4, 5, 6}, false},
		{6, []byte{7, 8, 9}, true},
	}
	for i, c := range chunks {
		frame := buildChunkFrame("gvision", 7, 120, 6, c.offset, 9, c.data, c.done)
		r, err := stepOne(f, frame)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if !c.done {
			if r != nil {
				t.Fatalf("chunk %d (intermediate) should produce no reply", i)
			}
			continue
		}
		// Final chunk: install-snapshot-reply success, match-index == boundary.
		m := decodeReply(t, r)
		if m.Type != "INSTALL-SNAPSHOT-REPLY" || !m.Bool("SUCCESS") {
			t.Fatalf("final reply type=%q success=%v", m.Type, m.Bool("SUCCESS"))
		}
		if mi, _ := m.Int("MATCH-INDEX"); mi != 120 {
			t.Errorf("match-index = %d, want 120", mi)
		}
	}
	st := f.snapshotState()
	if st.SnapshotIdx != 120 || st.SnapshotTrm != 6 || st.CommitIndex != 120 {
		t.Errorf("boundary snap=%d/%d commit=%d", st.SnapshotIdx, st.SnapshotTrm, st.CommitIndex)
	}
	if ms.saves == 0 {
		t.Error("installed boundary must be persisted")
	}
	// After the snapshot, the witness's log is anchored at 120 for matching.
	if f.lastLogIndex() != 120 || f.lastLogTerm() != 6 {
		t.Errorf("post-snapshot last-log = %d/%d", f.lastLogIndex(), f.lastLogTerm())
	}
}

func TestSnapshotEarlyAckWhenAlreadyCommitted(t *testing.T) {
	// The witness already has index 120 committed: it acks the first chunk at once
	// without the rest of the transfer.
	f, _ := newTestFollower(t, &State{CurrentTerm: 7, SnapshotIdx: 120, SnapshotTrm: 6, CommitIndex: 120})
	r, err := stepOne(f, buildChunkFrame("gvision", 7, 120, 6, 0, 9, []byte{1, 2, 3}, false))
	if err != nil {
		t.Fatal(err)
	}
	m := decodeReply(t, r)
	if m.Type != "INSTALL-SNAPSHOT-REPLY" || !m.Bool("SUCCESS") {
		t.Fatalf("early-ack reply type=%q success=%v", m.Type, m.Bool("SUCCESS"))
	}
	if mi, _ := m.Int("MATCH-INDEX"); mi != 120 {
		t.Errorf("match-index = %d, want 120", mi)
	}
}

// A witness's config-only snapshot arrives as a Lisp form (not a binary frame)
// with :DATA as an octet vector. It must install the boundary just the same.
func TestWitnessLispFormSnapshotChunk(t *testing.T) {
	f, _ := newTestFollower(t, &State{CurrentTerm: 7})
	payload := lispwire.NewReply("SNAPSHOT-CHUNK").
		Int("TERM", 7).Str("FROM", "gvision").Int("LAST-INDEX", 500).Int("LAST-TERM", 6).
		Int("OFFSET", 0).Int("TOTAL", 3).Str("TOKEN", "tk").
		Str("DIGEST", "0123456789012345678901234567890123456789012345678901234567890123").
		Raw("DATA", lispwire.Vec{Items: []lispwire.Value{lispwire.Int(1), lispwire.Int(2), lispwire.Int(3)}}).
		Bool("DONE", true).Encode()
	r, err := stepOne(f, payload)
	if err != nil {
		t.Fatal(err)
	}
	m := decodeReply(t, r)
	if m.Type != "INSTALL-SNAPSHOT-REPLY" || !m.Bool("SUCCESS") {
		t.Fatalf("reply type=%q success=%v", m.Type, m.Bool("SUCCESS"))
	}
	if mi, _ := m.Int("MATCH-INDEX"); mi != 500 {
		t.Errorf("match-index = %d, want 500", mi)
	}
	if st := f.snapshotState(); st.SnapshotIdx != 500 || st.SnapshotTrm != 6 {
		t.Errorf("boundary = %d/%d", st.SnapshotIdx, st.SnapshotTrm)
	}
}

func TestSnapshotRejectsOutOfOrderChunk(t *testing.T) {
	f, _ := newTestFollower(t, &State{CurrentTerm: 7})
	// A chunk at offset 3 with no prior offset-0 chunk must be rejected.
	_, err := stepOne(f, buildChunkFrame("gvision", 7, 120, 6, 3, 9, []byte{4, 5, 6}, false))
	if err == nil {
		t.Fatal("expected an error for an out-of-order snapshot chunk")
	}
}
