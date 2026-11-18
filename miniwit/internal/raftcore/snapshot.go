// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"fmt"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// snapshotReceiver tracks an in-progress chunked snapshot transfer. A witness
// discards the application payload (it has no state machine to restore it into)
// and keeps only the boundary, so it counts bytes to detect completion rather
// than writing them anywhere.
type snapshotReceiver struct {
	from     string
	term     int64
	index    int64
	lastTerm int64
	token    string
	total    int64
	received int64
}

// handleSnapshotChunk consumes one binary snapshot chunk (lispwire decoded the
// GR8SCK01 frame, so msg.Data holds the chunk bytes). It mirrors
// raft-member-receive-snapshot-chunk: reply failure on a stale term, ack
// immediately if the boundary is already committed, otherwise accumulate chunks
// in order and, on the final one, install the boundary and reply success. Only
// the final chunk, the early-ack, and the stale case produce a reply.
func (f *Follower) handleSnapshotChunk(msg *lispwire.Msg) (*Reply, error) {
	from, _ := msg.Str("FROM")
	term, _ := msg.Int("TERM")
	index, _ := msg.Int("LAST-INDEX")
	lastTerm, _ := msg.Int("LAST-TERM")
	offset, _ := msg.Int("OFFSET")
	total, _ := msg.Int("TOTAL")
	token, _ := msg.Str("TOKEN")
	done := msg.Bool("DONE")
	// A learner/voter snapshot arrives as a binary artifact frame (msg.Data); a
	// witness's config-only snapshot arrives as a Lisp form with :DATA as an octet
	// vector. Accept either.
	dataLen := int64(len(msg.Data))
	if dataLen == 0 {
		if b, ok := msg.Bytes("DATA"); ok {
			dataLen = int64(len(b))
		}
	}

	if index < 1 || lastTerm < 0 || lastTerm > term || offset < 0 || total < 1 ||
		dataLen < 1 || offset+dataLen > total || done != (offset+dataLen == total) {
		return nil, fmt.Errorf("raftcore: invalid snapshot chunk (index=%d total=%d offset=%d len=%d)", index, total, offset, dataLen)
	}

	if err := f.stepDownIfStale(term); err != nil {
		return nil, err
	}
	fail := func() *Reply {
		return &Reply{To: from, Payload: lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", false).Int("MATCH-INDEX", 0).Encode()}
	}
	if term < f.st.CurrentTerm {
		f.recv = nil
		return fail(), nil
	}
	f.leaderID = from
	f.lastLeaderContact = f.clock()

	// Already have this boundary committed: ack without the transfer.
	if index <= f.st.CommitIndex {
		f.recv = nil
		return f.snapshotReply(from, index), nil
	}

	// Start a fresh transfer on the first chunk; otherwise it must continue the
	// one in progress in order. Anything else resets and waits for a restart.
	if offset == 0 {
		f.recv = &snapshotReceiver{from: from, term: term, index: index, lastTerm: lastTerm, token: token, total: total}
	} else if f.recv == nil || f.recv.token != token || f.recv.index != index ||
		f.recv.total != total || f.recv.received != offset {
		f.recv = nil
		return nil, fmt.Errorf("raftcore: out-of-order or mismatched snapshot chunk at offset %d", offset)
	}
	f.recv.received += dataLen

	if !done {
		return nil, nil // intermediate chunk: no reply, like gr8s
	}
	if f.recv.received != total {
		f.recv = nil
		return nil, fmt.Errorf("raftcore: snapshot done at %d but total is %d", f.recv.received, total)
	}
	f.recv = nil
	if err := f.installBoundary(index, lastTerm); err != nil {
		return nil, err
	}
	return f.snapshotReply(from, index), nil
}

func (f *Follower) snapshotReply(to string, index int64) *Reply {
	return &Reply{To: to, Payload: lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", true).Int("MATCH-INDEX", index).Encode()}
}
