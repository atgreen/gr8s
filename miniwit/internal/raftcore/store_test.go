// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreHardStateAndLogRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutHardState(HardState{CurrentTerm: 7, VotedFor: "gvision", SnapshotIdx: 5, SnapshotTrm: 4}); err != nil {
		t.Fatal(err)
	}
	// Log entries begin strictly after the snapshot boundary (index 5).
	if err := s.AppendLog([]Entry{{6, 7, "(:a)"}, {7, 7, "(:b)"}}); err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.CurrentTerm != 7 || st.VotedFor != "gvision" || st.SnapshotIdx != 5 {
		t.Errorf("hard state = %+v", st.HardState)
	}
	if st.CommitIndex != 5 {
		t.Errorf("commit index should load as the snapshot boundary, got %d", st.CommitIndex)
	}
	if len(st.Log) != 2 || st.Log[0].Index != 6 || st.Log[1].Command != "(:b)" {
		t.Errorf("log = %+v", st.Log)
	}
}

// AppendLog must truly append, not rewrite: the earlier bytes stay byte-identical.
func TestFileStoreAppendDoesNotRewrite(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir)
	_ = s.AppendLog([]Entry{{1, 1, "(:a)"}})
	first, err := os.ReadFile(logPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.AppendLog([]Entry{{2, 1, "(:b)"}})
	second, err := os.ReadFile(logPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(second, first) {
		t.Fatalf("append rewrote the file; prefix not preserved:\n first=%q\nsecond=%q", first, second)
	}
	if len(second) <= len(first) {
		t.Errorf("file did not grow on append")
	}
}

// A torn trailing line (a crash mid-append) is dropped; the durable prefix survives.
func TestFileStoreToleratesTornTrailingLine(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir)
	_ = s.AppendLog([]Entry{{1, 1, "(:a)"}, {2, 1, "(:b)"}})
	// Simulate a half-written third record appended without a newline.
	f, _ := os.OpenFile(logPath(dir), os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"i":3,"t":1,"c":"(:c`) // truncated JSON, no newline
	f.Close()
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Log) != 2 {
		t.Fatalf("expected the torn line dropped, got %d entries", len(st.Log))
	}
}

// A non-contiguous log (gap) keeps only the clean prefix.
func TestFileStoreStopsAtContiguityBreak(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir)
	_ = s.AppendLog([]Entry{{1, 1, "(:a)"}})
	f, _ := os.OpenFile(logPath(dir), os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString("{\"i\":3,\"t\":1,\"c\":\"(:c)\"}\n") // index jumps 1 -> 3
	f.Close()
	st, _ := s.Load()
	if len(st.Log) != 1 {
		t.Fatalf("expected only the contiguous prefix, got %d", len(st.Log))
	}
}

func TestFileStoreRewriteReplacesLog(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileStore(dir)
	_ = s.AppendLog([]Entry{{1, 1, "(:a)"}, {2, 1, "(:b)"}, {3, 1, "(:c)"}})
	// Snapshot install at 2 keeps only index 3.
	if err := s.RewriteLog([]Entry{{3, 1, "(:c)"}}); err != nil {
		t.Fatal(err)
	}
	_ = s.PutHardState(HardState{CurrentTerm: 1, SnapshotIdx: 2, SnapshotTrm: 1})
	st, _ := s.Load()
	if len(st.Log) != 1 || st.Log[0].Index != 3 {
		t.Fatalf("log after rewrite = %+v", st.Log)
	}
	// And no leftover temp files in the dir.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" || e.Name()[0] == '.' {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}
