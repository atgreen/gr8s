// SPDX-License-Identifier: Apache-2.0

// Package raftcore implements a non-campaigning Raft follower: it grants votes,
// acknowledges AppendEntries, and accepts snapshots, so it contributes to quorum
// without ever becoming leader or applying a command. The durable format is this
// program's own private business — only the wire protocol (package lispwire) has
// to match gr8s/cl-raft.
package raftcore

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Entry is a stored log entry. Command is the Lisp-printed form of the command
// (lispwire.Write), kept verbatim: a witness stores the data for redundancy but
// never interprets or re-sends it — only Index and Term drive Raft matching.
type Entry struct {
	Index   int64  `json:"i"`
	Term    int64  `json:"t"`
	Command string `json:"c"`
}

// HardState is the small, rarely-changing durable state: the current term and
// vote (Raft's persistent hard state) plus the snapshot boundary. commitIndex is
// deliberately NOT here — Raft treats it as volatile and the leader re-advances
// it after a restart, so persisting it would only add writes.
type HardState struct {
	CurrentTerm int64  `json:"current_term"`
	VotedFor    string `json:"voted_for"`
	SnapshotIdx int64  `json:"snapshot_index"`
	SnapshotTrm int64  `json:"snapshot_term"`
}

// State is the full in-memory state the follower works from. CommitIndex starts
// at the snapshot boundary on load and is re-advanced by the leader.
type State struct {
	HardState
	CommitIndex int64
	Log         []Entry // entries strictly after SnapshotIdx, contiguous
}

// Store persists the durable state. It separates the hard state (a tiny file
// rewritten only on a term/vote/snapshot change) from the log (appended to, so a
// routine AppendEntries writes only its new entries rather than the whole log) so
// that steady following costs O(new entries) of I/O, not O(log size) — which
// matters on the modest flash a firewall runs on. FileStore is the production
// implementation; tests use an in-memory store.
type Store interface {
	Load() (*State, error)
	PutHardState(HardState) error   // atomic small write; term/vote/snapshot changes
	AppendLog(entries []Entry) error // append new entries + fsync; the hot path
	RewriteLog(entries []Entry) error // replace the whole log; truncation/snapshot only
}

// FileStore keeps hard state in hardstate.json (replaced atomically) and the log
// in log.jsonl (one entry per line, appended in place). A crash can leave a
// torn trailing line; Load drops it, which is safe because an entry is only acked
// after its append has fsynced.
type FileStore struct {
	dir string
	mu  sync.Mutex
}

func hardPath(dir string) string { return filepath.Join(dir, "hardstate.json") }
func logPath(dir string) string  { return filepath.Join(dir, "log.jsonl") }

// NewFileStore prepares dir for the hard-state and log files.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStore{dir: dir}, nil
}

// Load reconstructs the state from hardstate.json and log.jsonl, or a zero state
// if nothing is persisted yet.
func (s *FileStore) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &State{}
	if data, err := os.ReadFile(hardPath(s.dir)); err == nil {
		if err := json.Unmarshal(data, &st.HardState); err != nil {
			return nil, fmt.Errorf("raftcore: corrupt hard state: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	st.CommitIndex = st.SnapshotIdx // volatile; the leader re-advances it
	entries, err := readLog(logPath(s.dir), st.SnapshotIdx)
	if err != nil {
		return nil, err
	}
	st.Log = entries
	return st, nil
}

// readLog reads the contiguous entry prefix that sits strictly after snapshotIdx.
// It stops at the first line that is unparseable (a torn trailing write) or breaks
// contiguity, keeping only the durable, in-order prefix.
func readLog(path string, snapshotIdx int64) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	expect := snapshotIdx + 1
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			break // torn trailing line: stop, the rest was never durably acked
		}
		if e.Index != expect {
			break // contiguity broken: keep only the clean prefix
		}
		entries = append(entries, e)
		expect++
	}
	return entries, nil
}

// PutHardState atomically replaces hardstate.json.
func (s *FileStore) PutHardState(hs HardState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(hs)
	if err != nil {
		return err
	}
	return writeFileAtomic(hardPath(s.dir), data)
}

// AppendLog appends entries to log.jsonl and fsyncs. This is the steady-state hot
// path, and it writes only the new entries.
func (s *FileStore) AppendLog(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(logPath(s.dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		w.Write(line)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return f.Sync()
}

// RewriteLog replaces the whole log file atomically. Only the rare truncation and
// snapshot-install paths use it.
func (s *FileStore) RewriteLog(entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return writeFileAtomic(logPath(s.dir), buf)
}

// writeFileAtomic writes data to a temp file, fsyncs it, renames it over path, and
// fsyncs the directory — so a crash leaves either the old file or the new one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
