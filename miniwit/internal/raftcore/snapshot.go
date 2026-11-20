// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"fmt"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// maxSnapshotFormBytes bounds how much of a Lisp-form snapshot transfer is kept
// in memory to read the membership from. A witness's config-only snapshot is a
// few hundred bytes; a larger transfer is counted and discarded as before.
const maxSnapshotFormBytes = 1 << 20

// snapshotReceiver tracks an in-progress chunked snapshot transfer. A witness
// discards the application payload (it has no state machine to restore it into)
// and keeps only the boundary, so it counts bytes to detect completion rather
// than writing them anywhere. The exception is the membership, which travels in
// the INSTALL-SNAPSHOT message the transfer stands for: that message is the
// artifact header of a binary transfer, and the whole body of a Lisp-form one.
type snapshotReceiver struct {
	from     string
	term     int64
	index    int64
	lastTerm int64
	token    string
	total    int64
	received int64
	header   []byte // the INSTALL-SNAPSHOT message, or what has arrived of it
	binary   bool   // header is a complete artifact envelope, not accumulated chunks
}

// handleSnapshotChunk consumes one binary snapshot chunk (lispwire decoded the
// GR8SCK01 frame, so msg.Data holds the chunk bytes). It mirrors
// raft-member-receive-snapshot-chunk: reply failure on a stale term, ack
// immediately if the boundary is already committed, otherwise accumulate chunks
// in order and, on the final one, install the boundary and reply success. Only
// the final chunk, the early-ack, and the stale case produce a reply.
func (f *Follower) handleSnapshotChunk(msg *lispwire.Msg) error {
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
	var form []byte
	if dataLen == 0 {
		if b, ok := msg.Bytes("DATA"); ok {
			form = b
			dataLen = int64(len(b))
		}
	}

	if index < 1 || lastTerm < 0 || lastTerm > term || offset < 0 || total < 1 ||
		dataLen < 1 || offset+dataLen > total || done != (offset+dataLen == total) {
		return fmt.Errorf("raftcore: invalid snapshot chunk (index=%d total=%d offset=%d len=%d)", index, total, offset, dataLen)
	}

	if err := f.stepDownIfStale(term); err != nil {
		return err
	}
	if term < f.st.CurrentTerm {
		f.recv = nil
		f.send(from, lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
			Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", false).Int("MATCH-INDEX", 0).Encode())
		return nil
	}
	if f.role != roleFollower {
		f.becomeFollower(from)
	}
	f.leaderID = from
	f.lastLeaderContact = f.clock()

	// Already have this boundary committed: ack without the transfer.
	if index <= f.st.CommitIndex {
		f.recv = nil
		f.send(from, f.snapshotReply(index))
		return nil
	}

	// Start a fresh transfer on the first chunk; otherwise it must continue the
	// one in progress in order. Anything else resets and waits for a restart.
	if offset == 0 {
		f.recv = &snapshotReceiver{from: from, term: term, index: index, lastTerm: lastTerm, token: token, total: total}
		if len(msg.Envelope) > 0 {
			f.recv.header, f.recv.binary = msg.Envelope, true
		}
	} else if f.recv == nil || f.recv.token != token || f.recv.index != index ||
		f.recv.total != total || f.recv.received != offset {
		f.recv = nil
		return fmt.Errorf("raftcore: out-of-order or mismatched snapshot chunk at offset %d", offset)
	}
	f.recv.received += dataLen
	if !f.recv.binary && form != nil && total <= maxSnapshotFormBytes {
		f.recv.header = append(f.recv.header, form...)
	}

	if !done {
		return nil // intermediate chunk: no reply, like gr8s
	}
	recv := f.recv
	f.recv = nil
	if recv.received != total {
		return fmt.Errorf("raftcore: snapshot done at %d but total is %d", recv.received, total)
	}
	if err := f.installBoundary(index, lastTerm, recv.snapshotState()); err != nil {
		return err
	}
	f.send(from, f.snapshotReply(index))
	return nil
}

// snapshotState returns the snapshot envelope (the :STATE of the INSTALL-SNAPSHOT
// message this transfer carried) when the receiver holds that message whole and
// it names this transfer's boundary; otherwise nil. gr8s sends a witness the
// leader's snapshot with the application removed, printed as one Lisp form
// (raft-link-send-snapshot), so its membership is readable here.
func (r *snapshotReceiver) snapshotState() lispwire.Value {
	if len(r.header) == 0 || (!r.binary && int64(len(r.header)) != r.total) {
		return nil
	}
	msg, err := lispwire.Decode(r.header)
	if err != nil || msg.Type != "INSTALL-SNAPSHOT" {
		return nil
	}
	if index, _ := msg.Int("LAST-INDEX"); index != r.index {
		return nil
	}
	state, _ := msg.Raw("STATE")
	return state
}

func (f *Follower) snapshotReply(index int64) []byte {
	return lispwire.NewReply("INSTALL-SNAPSHOT-REPLY").
		Int("TERM", f.st.CurrentTerm).Str("FROM", f.id).Bool("SUCCESS", true).Int("MATCH-INDEX", index).Encode()
}
