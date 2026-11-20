// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// crashStore is a FileStore whose writes can be made to fail, standing for a
// crash or a full disk at that point: nothing reaches the disk and the caller
// sees an error.
type crashStore struct {
	*FileStore
	failRewrite, failAppend, failHard int // fail this many calls, then work again
}

var errInjected = errors.New("injected write failure")

func (c *crashStore) RewriteLog(e []Entry) error {
	if c.failRewrite > 0 {
		c.failRewrite--
		return errInjected
	}
	return c.FileStore.RewriteLog(e)
}

func (c *crashStore) AppendLog(e []Entry) error {
	if c.failAppend > 0 {
		c.failAppend--
		return errInjected
	}
	return c.FileStore.AppendLog(e)
}

func (c *crashStore) PutHardState(hs HardState) error {
	if c.failHard > 0 {
		c.failHard--
		return errInjected
	}
	return c.FileStore.PutHardState(hs)
}

func newCrashFollower(t *testing.T) (*Follower, *crashStore, string) {
	t.Helper()
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store := &crashStore{FileStore: fs}
	f, err := NewFollower("w", store, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.logf = func(string, ...any) {}
	return f, store, dir
}

// reload reads the directory back the way a restarted witness would.
func reload(t *testing.T, dir string) *State {
	t.Helper()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := fs.Load()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func indexes(log []Entry) []int64 {
	out := make([]int64, 0, len(log))
	for _, e := range log {
		out = append(out, e.Index)
	}
	return out
}

func wantIndexes(t *testing.T, what string, st *State, boundary, first, last int64) {
	t.Helper()
	if st.SnapshotIdx != boundary {
		t.Errorf("%s: boundary = %d, want %d", what, st.SnapshotIdx, boundary)
	}
	got := indexes(st.Log)
	var want []int64
	for i := first; i <= last; i++ {
		want = append(want, i)
	}
	if len(got) != len(want) {
		t.Fatalf("%s: log holds %v, want %d..%d", what, got, first, last)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: log holds %v, want %d..%d", what, got, first, last)
		}
	}
}

func smallEntries(first, last, term int64) []lispwire.Value {
	var out []lispwire.Value
	for i := first; i <= last; i++ {
		out = append(out, entryTriple(i, term, lispwire.List{Items: []lispwire.Value{lispwire.Sym(":PUT"), lispwire.Int(i)}}))
	}
	return out
}

// podster-sjl: a crash between the two writes of a compaction used to leave a
// log file that began past the boundary on disk, and Load returned no entries:
// the witness forgot what it had acknowledged.
func TestACrashDuringCompactionForgetsNothing(t *testing.T) {
	old1, old2 := compactWhenLogBytes, retainLogBytes
	defer func() { compactWhenLogBytes, retainLogBytes = old1, old2 }()
	f, store, dir := newCrashFollower(t)
	SetCompactionBytes(1<<30, 1<<29)
	mustStep(t, f, appendPayload(1, "a", 0, 0, smallEntries(1, 10, 1), 10, 0))
	wantIndexes(t, "before compaction", reload(t, dir), 0, 1, 10)

	// Compact now, and crash after the first write.
	SetCompactionBytes(100, 60)
	store.failRewrite = 1
	mustStep(t, f, appendPayload(1, "a", 10, 1, nil, 10, 0))
	onDisk := reload(t, dir)
	if onDisk.SnapshotIdx == 0 {
		t.Fatalf("the compaction did not start; log %v", indexes(onDisk.Log))
	}
	wantIndexes(t, "after a crash mid-compaction", onDisk, onDisk.SnapshotIdx, onDisk.SnapshotIdx+1, 10)
	if got := f.lastLogIndex(); got != 10 {
		t.Errorf("in memory the log ends at %d, want 10", got)
	}

	// The restarted witness can go on appending, and a second restart sees it all.
	fs, _ := NewFileStore(dir)
	g, err := NewFollower("w", fs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	SetCompactionBytes(1<<30, 1<<29)
	mustStep(t, g, appendPayload(1, "a", 10, 1, smallEntries(11, 12, 1), 12, 0))
	wantIndexes(t, "after restart and append", reload(t, dir), onDisk.SnapshotIdx, onDisk.SnapshotIdx+1, 12)
}

// The same for a snapshot install that keeps the log past the boundary.
func TestACrashDuringSnapshotInstallKeepsTheLogPastTheBoundary(t *testing.T) {
	f, store, dir := newCrashFollower(t)
	mustStep(t, f, appendPayload(2, "a", 0, 0, smallEntries(1, 10, 2), 3, 0))
	store.failRewrite = 1
	if err := f.installBoundary(6, 2, nil); err != nil {
		t.Fatal(err)
	}
	wantIndexes(t, "on disk", reload(t, dir), 6, 7, 10)
	wantIndexes(t, "in memory", f.st, 6, 7, 10)
}

// A boundary this witness does not hold supersedes what it has past it. Whatever
// write fails, a restart must not find those entries following the new boundary.
func TestASupersedingSnapshotNeverLeavesItsStaleSuffixBehind(t *testing.T) {
	for _, crash := range []string{"none", "first rewrite", "hard state", "last rewrite"} {
		f, store, dir := newCrashFollower(t)
		mustStep(t, f, appendPayload(2, "a", 0, 0, smallEntries(1, 10, 2), 3, 0))
		switch crash {
		case "first rewrite":
			store.failRewrite = 1
		case "hard state":
			store.failHard = 1
		case "last rewrite":
			store.failRewrite = 0
		}
		// Index 6 was written in term 5 by the snapshot's leader; ours is term 2.
		if crash == "last rewrite" {
			// Let the first rewrite through and fail the second.
			err := f.store.RewriteLog(entriesThrough(f.st.Log, 6))
			if err != nil {
				t.Fatal(err)
			}
			f.st.Log = entriesThrough(f.st.Log, 6)
			store.failRewrite = 1
		}
		err := f.installBoundary(6, 5, nil)
		st := reload(t, dir)
		for _, e := range st.Log {
			if e.Index > 6 && st.SnapshotIdx == 6 {
				t.Errorf("crash at %s: entry %d of term %d follows the new boundary", crash, e.Index, e.Term)
			}
		}
		switch crash {
		case "none", "last rewrite":
			if err != nil {
				t.Errorf("crash at %s: %v", crash, err)
			}
			wantIndexes(t, "crash at "+crash, st, 6, 7, 6)
		case "first rewrite":
			wantIndexes(t, "crash at "+crash, st, 0, 1, 10) // nothing happened
		case "hard state":
			wantIndexes(t, "crash at "+crash, st, 0, 1, 6) // the superseded suffix is gone, no more
			if got := f.lastLogIndex(); got != 6 {
				t.Errorf("crash at %s: memory ends at %d, disk at 6", crash, got)
			}
		}
	}
}

// podster-9m0: after a failed write the entries stayed in memory, so the
// leader's retry found them "held" and was told they were stored.
func TestAFailedAppendIsNotAcknowledgedOnRetry(t *testing.T) {
	f, store, dir := newCrashFollower(t)
	mustStep(t, f, appendPayload(1, "a", 0, 0, smallEntries(1, 3, 1), 3, 0))
	payload := appendPayload(1, "a", 3, 1, smallEntries(4, 6, 1), 3, 0)

	store.failAppend = 1
	if out, err := f.Step(payload); err == nil || len(out) != 0 {
		t.Fatalf("a failed write was answered: %d replies, err %v", len(out), err)
	}
	if got := f.lastLogIndex(); got != 3 {
		t.Fatalf("memory ends at %d after a failed write; disk ends at 3", got)
	}
	wantIndexes(t, "after the failed write", reload(t, dir), 0, 1, 3)

	reply := decodeReply(t, mustStep(t, f, payload))
	if m, _ := reply.Int("MATCH-INDEX"); !reply.Bool("SUCCESS") || m != 6 {
		t.Fatalf("retry: success=%v match=%d", reply.Bool("SUCCESS"), m)
	}
	wantIndexes(t, "after the retry", reload(t, dir), 0, 1, 6)
}

// The same when the write that fails replaces a conflicting suffix.
func TestAFailedOverwriteRestoresTheLog(t *testing.T) {
	f, store, dir := newCrashFollower(t)
	mustStep(t, f, appendPayload(1, "a", 0, 0, smallEntries(1, 5, 1), 2, 0))
	store.failRewrite = 1
	if _, err := f.Step(appendPayload(2, "b", 3, 1, smallEntries(4, 4, 2), 2, 0)); err == nil {
		t.Fatal("a failed overwrite was not reported")
	}
	if term, _ := f.logTerm(4); f.lastLogIndex() != 5 || term != 1 {
		t.Fatalf("memory changed: last %d, term at 4 = %d", f.lastLogIndex(), term)
	}
	wantIndexes(t, "on disk", reload(t, dir), 0, 1, 5)
}

// A torn line left by an interrupted append must not hide what is appended
// after the restart.
func TestAppendsAfterATornLineSurviveTheNextRestart(t *testing.T) {
	f, _, dir := newCrashFollower(t)
	mustStep(t, f, appendPayload(1, "a", 0, 0, smallEntries(1, 3, 1), 3, 0))
	logFile := filepath.Join(dir, "log.jsonl")
	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(`{"i":4,"t":1,"c":"(:PUT`) // the crash came mid-line
	file.Close()

	fs, _ := NewFileStore(dir)
	g, err := NewFollower("w", fs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if g.lastLogIndex() != 3 {
		t.Fatalf("restart read through %d, want 3", g.lastLogIndex())
	}
	mustStep(t, g, appendPayload(1, "a", 3, 1, smallEntries(4, 6, 1), 6, 0))
	wantIndexes(t, "after the next restart", reload(t, dir), 0, 1, 6)
}
