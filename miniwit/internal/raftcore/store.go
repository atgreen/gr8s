// SPDX-License-Identifier: Apache-2.0

// Package raftcore implements a Raft witness: it grants votes, acknowledges
// AppendEntries, and accepts snapshots, so it contributes to quorum without
// applying a command or accepting a proposal. It leads only to hand its log to a
// voter that is behind it (standin.go). The durable format is this program's own
// private business — only the wire protocol (package lispwire) has to match
// gr8s/cl-raft.
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
// (lispwire.Write), kept verbatim. A witness never interprets it, apart from
// reading the membership out of a config entry: Index and Term drive Raft
// matching. The command is sent on only when the witness stands in for a voter
// that lacks the entry.
type Entry struct {
	Index   int64  `json:"i"`
	Term    int64  `json:"t"`
	Command string `json:"c"`
}

// HardState is the small, rarely-changing durable state: the current term and
// vote (Raft's persistent hard state), the snapshot boundary, and the cluster
// membership. commitIndex is deliberately NOT here — Raft treats it as volatile
// and the leader re-advances it after a restart, so persisting it would only add
// writes.
//
// Members maps each member id to "voter", "witness" or "learner"; empty means
// the membership is unknown (see membership.go). MembersIdx is the log index it
// was last taken from — a committed config entry or a snapshot boundary — so the
// entries the leader re-commits after a restart are not applied to it twice. The
// map is replaced, never changed in place, so a HardState value can be copied.
type HardState struct {
	CurrentTerm int64             `json:"current_term"`
	VotedFor    string            `json:"voted_for"`
	SnapshotIdx int64             `json:"snapshot_index"`
	SnapshotTrm int64             `json:"snapshot_term"`
	Members     map[string]string `json:"members,omitempty"`
	MembersIdx  int64             `json:"members_index,omitempty"`
}

// State is the full in-memory state the follower works from. CommitIndex starts
// at the snapshot boundary on load and is re-advanced by the leader.
type State struct {
	HardState
	CommitIndex int64
	Log         []Entry // entries strictly after SnapshotIdx, contiguous
}

// Store persists the durable state. It separates the hard state (a tiny file
// rewritten only on a term/vote/snapshot/membership change) from the log (appended to, so a
// routine AppendEntries writes only its new entries rather than the whole log) so
// that steady following costs O(new entries) of I/O, not O(log size) — which
// matters on the modest flash a firewall runs on. FileStore is the production
// implementation; tests use an in-memory store.
type Store interface {
	Load() (*State, error)
	PutHardState(HardState) error     // atomic small write; term/vote/snapshot changes
	AppendLog(entries []Entry) error  // append new entries + fsync; the hot path
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
	entries, clean, err := readLog(logPath(s.dir), st.SnapshotIdx)
	if err != nil {
		return nil, err
	}
	if !clean {
		// The file holds more than the log: lines at or below the boundary that a
		// compaction did not get to remove, or a torn line from an interrupted
		// append. Appending after either would hide every later entry from the
		// next Load (podster-sjl, podster-9m0), so write the log back clean first.
		if err := rewriteLog(s.dir, entries); err != nil {
			return nil, err
		}
	}
	st.Log = entries
	return st, nil
}

// readLog reads the contiguous run of entries that sits strictly after
// snapshotIdx. The boundary is written before the log is rewritten to match it
// (see Follower.maybeCompact), so the file may begin with entries at or below the
// boundary; those are skipped. Reading stops at the first line that is
// unparseable (a torn trailing write) or breaks contiguity. clean reports that
// the file held exactly the entries returned.
func readLog(path string, snapshotIdx int64) (entries []Entry, clean bool, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	clean = true
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
			clean = false
			break // torn trailing line: stop, the rest was never durably acked
		}
		if len(entries) == 0 && e.Index <= snapshotIdx {
			clean = false
			continue // below the boundary: a rewrite that did not finish
		}
		if e.Index != expect {
			clean = false
			break // contiguity broken: keep only the clean prefix
		}
		entries = append(entries, e)
		expect++
	}
	if sc.Err() != nil {
		clean = false
	}
	return entries, clean, nil
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
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	f, err := os.OpenFile(logPath(s.dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if _, err = f.Write(buf); err == nil {
		err = f.Sync()
	}
	if err != nil {
		// Leave no part of a failed append behind: a later append after a torn
		// line would be unreadable at the next Load (podster-9m0).
		_ = f.Truncate(info.Size())
		return err
	}
	return nil
}

// RewriteLog replaces the whole log file atomically. Only the rare truncation and
// snapshot-install paths use it.
func (s *FileStore) RewriteLog(entries []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return rewriteLog(s.dir, entries)
}

func rewriteLog(dir string, entries []Entry) error {
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return writeFileAtomic(logPath(dir), buf)
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
