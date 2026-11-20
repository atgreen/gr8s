// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// The config command of lispwire's "append-config" golden string, as SBCL prints
// it, and one that adds a fourth member.
const (
	configThree = `(:RAFT-CONFIG :MEMBERS (("gvision" . :VOTER) ("gr8s2" . :VOTER) ("wit" . :WITNESS)) :ADDRESSES (("gvision" "10.77.77.21" 7000)) :API-URLS NIL :PROMOTIONS NIL)`
	configFour  = `(:RAFT-CONFIG :MEMBERS (("new" . :LEARNER) ("gvision" . :VOTER) ("gr8s2" . :VOTER) ("wit" . :WITNESS)) :ADDRESSES (("gvision" "10.77.77.21" 7000) ("new" "10.77.77.30" 7001)) :API-URLS (("gvision" . "https://10.77.77.21:6443")) :PROMOTIONS (("new" . :VOTER)))`
)

var fourMembers = map[string]string{"gvision": RoleVoter, "gr8s2": RoleVoter, "wit": RoleWitness, "new": RoleLearner}

func mustRead(t *testing.T, s string) lispwire.Value {
	t.Helper()
	v, err := lispwire.Read(s)
	if err != nil {
		t.Fatalf("Read(%s): %v", s, err)
	}
	return v
}

func TestCommittedConfigEntrySetsAndPersistsTheMembership(t *testing.T) {
	f, ms := newTestFollower(t, &State{HardState: HardState{CurrentTerm: 7}})
	var addrs []map[string]string
	f.SetAddressSink(func(a map[string]string) { addrs = append(addrs, a) })
	entries := []lispwire.Value{
		entryTriple(1, 7, mustRead(t, `(:RAFT-BARRIER)`)),
		entryTriple(2, 7, mustRead(t, configThree)),
	}

	// Stored, but the leader has only committed through index 1: cl-raft adopts a
	// config when it applies the entry, and so does this.
	mustStep(t, f, appendPayload(7, "gvision", 0, 0, entries, 1, 1))
	if got := f.Membership(); len(got) != 0 || len(ms.hs.Members) != 0 || len(addrs) != 0 {
		t.Fatalf("an uncommitted config entry changed the membership: %v", got)
	}

	// The next heartbeat commits it.
	mustStep(t, f, appendPayload(7, "gvision", 2, 7, nil, 2, 2))
	if got := f.Membership(); !reflect.DeepEqual(got, threeMembers) {
		t.Fatalf("membership = %v, want %v", got, threeMembers)
	}
	if !reflect.DeepEqual(ms.hs.Members, threeMembers) || ms.hs.MembersIdx != 2 {
		t.Fatalf("persisted membership = %v at %d", ms.hs.Members, ms.hs.MembersIdx)
	}
	if want := []map[string]string{{"gvision": "10.77.77.21:7000"}}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("addresses = %v, want %v", addrs, want)
	}

	// A later config replaces it whole, in the same step that commits it.
	mustStep(t, f, appendPayload(7, "gvision", 2, 7, []lispwire.Value{entryTriple(3, 7, mustRead(t, configFour))}, 3, 3))
	if got := f.Membership(); !reflect.DeepEqual(got, fourMembers) {
		t.Fatalf("membership = %v, want %v", got, fourMembers)
	}
	if got := addrs[len(addrs)-1]; got["new"] != "10.77.77.30:7001" {
		t.Fatalf("addresses = %v", got)
	}

	// It survives a restart.
	g, err := NewFollower("wit", ms, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Membership(); !reflect.DeepEqual(got, fourMembers) {
		t.Fatalf("membership after reload = %v, want %v", got, fourMembers)
	}
}

// After a restart the commit index begins at the snapshot boundary, and the
// leader's first heartbeat walks it back over entries already taken into
// account. They must not undo a membership learned since, such as the one the
// Join on startup returned.
func TestRecommittedEntriesDoNotRollTheMembershipBack(t *testing.T) {
	st := &State{
		HardState: HardState{CurrentTerm: 7, Members: threeMembers, MembersIdx: 2},
		Log: []Entry{
			{Index: 1, Term: 7, Command: `(:RAFT-BARRIER)`},
			{Index: 2, Term: 7, Command: configThree},
			{Index: 3, Term: 7, Command: `(:PUT "k" "v")`},
		},
	}
	f, _ := newTestFollower(t, st)
	if err := f.SetMembership(fourMembers); err != nil {
		t.Fatal(err)
	}
	mustStep(t, f, appendPayload(7, "gvision", 3, 7, nil, 3, 1))
	if got := f.Membership(); !reflect.DeepEqual(got, fourMembers) {
		t.Fatalf("membership = %v, want the one from Join %v", got, fourMembers)
	}
	// A config entry beyond the one already recorded still applies.
	mustStep(t, f, appendPayload(7, "gvision", 3, 7, []lispwire.Value{entryTriple(4, 7, mustRead(t, configThree))}, 4, 2))
	if got := f.Membership(); !reflect.DeepEqual(got, threeMembers) {
		t.Fatalf("membership = %v, want %v", got, threeMembers)
	}
}

func TestSetMembershipFromJoin(t *testing.T) {
	f, ms := newTestFollower(t, nil)
	if err := f.SetMembership(map[string]string{"gvision": RoleVoter, "wit": "observer"}); err == nil {
		t.Fatal("an unknown role must be refused")
	}
	if len(f.Membership()) != 0 {
		t.Fatal("a refused membership was recorded")
	}
	in := map[string]string{"gvision": RoleVoter, "gr8s2": RoleVoter, "wit": RoleWitness}
	if err := f.SetMembership(in); err != nil {
		t.Fatal(err)
	}
	in["gvision"] = RoleLearner // the caller's map is not ours
	if !reflect.DeepEqual(ms.hs.Members, threeMembers) || !reflect.DeepEqual(f.Membership(), threeMembers) {
		t.Fatalf("membership = %v persisted %v", f.Membership(), ms.hs.Members)
	}
	// An empty answer says nothing; it does not erase what is known.
	if err := f.SetMembership(nil); err != nil || len(f.Membership()) != 3 {
		t.Fatalf("empty membership: err %v, now %v", err, f.Membership())
	}
}

func TestFileStoreKeepsTheMembership(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFollower("wit", fs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetMembership(threeMembers); err != nil {
		t.Fatal(err)
	}
	st, err := fs.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Members, threeMembers) {
		t.Fatalf("reloaded membership = %v", st.Members)
	}
}

// A committed config that cannot be read whole must not leave an older
// membership in force: an undercounted quorum is the unsafe direction.
func TestUnreadableConfigLeavesTheMembershipUnknown(t *testing.T) {
	for name, command := range map[string]string{
		"unknown role":   `(:RAFT-CONFIG :MEMBERS (("gvision" . :VOTER) ("wit" . :OBSERVER)) :ADDRESSES NIL)`,
		"not a pair":     `(:RAFT-CONFIG :MEMBERS (("gvision" :VOTER) ("wit" . :WITNESS)) :ADDRESSES NIL)`,
		"listed twice":   `(:RAFT-CONFIG :MEMBERS (("wit" . :VOTER) ("wit" . :WITNESS)) :ADDRESSES NIL)`,
		"no members":     `(:RAFT-CONFIG :MEMBERS NIL :ADDRESSES NIL)`,
		"members absent": `(:RAFT-CONFIG :ADDRESSES NIL)`,
	} {
		t.Run(name, func(t *testing.T) {
			f, ms := newTestFollower(t, &State{HardState: HardState{CurrentTerm: 7, Members: threeMembers}})
			var logged []string
			f.logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
			mustStep(t, f, appendPayload(7, "gvision", 0, 0, []lispwire.Value{entryTriple(1, 7, mustRead(t, command))}, 1, 1))
			if len(f.Membership()) != 0 || len(ms.hs.Members) != 0 || ms.hs.MembersIdx != 1 {
				t.Fatalf("membership = %v (persisted %v at %d)", f.Membership(), ms.hs.Members, ms.hs.MembersIdx)
			}
			if len(logged) != 1 || !strings.Contains(logged[0], "membership unknown") {
				t.Fatalf("log = %v", logged)
			}
		})
	}
}

func TestParseMembershipToleratesBadAddresses(t *testing.T) {
	members, addrs, err := parseConfigCommand(`(:raft-config :members (("a" . :voter) ("w" . :witness)) :addresses (("a" "h" 7000) ("w" "h") ("x" "h" 70000) "junk"))`)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"a": RoleVoter, "w": RoleWitness}; !reflect.DeepEqual(members, want) {
		t.Fatalf("members = %v", members)
	}
	if want := map[string]string{"a": "h:7000"}; !reflect.DeepEqual(addrs, want) {
		t.Fatalf("addrs = %v", addrs)
	}
}

// installSnapshotForm is the INSTALL-SNAPSHOT message gr8s prints for a witness
// (raft-link-send-snapshot): the leader's snapshot envelope with the application
// removed. Its bytes are what the Lisp-form chunks carry.
func installSnapshotForm(index int64, members string) string {
	return fmt.Sprintf(`(:TYPE :INSTALL-SNAPSHOT :TERM 7 :FROM "gvision" :LAST-INDEX %d :LAST-TERM 6 :STATE (:CL-RAFT-SNAPSHOT 1 :APPLICATION NIL :APPLICATION-PRESENT T :MEMBERS %s :ADDRESSES (("gr8s2" "10.77.77.22" 7000) ("gvision" "10.77.77.21" 7000)) :API-URLS NIL :PROMOTIONS NIL))`, index, members)
}

// lispChunks cuts body into Lisp-form SNAPSHOT-CHUNK payloads of at most size
// bytes, with :DATA as an octet vector.
func lispChunks(index int64, body string, size int) [][]byte {
	var out [][]byte
	for offset := 0; offset < len(body); offset += size {
		end := min(offset+size, len(body))
		data := make([]lispwire.Value, 0, end-offset)
		for _, b := range []byte(body[offset:end]) {
			data = append(data, lispwire.Int(b))
		}
		out = append(out, lispwire.NewReply("SNAPSHOT-CHUNK").
			Int("TERM", 7).Str("FROM", "gvision").Int("LAST-INDEX", index).Int("LAST-TERM", 6).
			Str("TOKEN", "tk").Str("DIGEST", strings.Repeat("0", 64)).
			Int("TOTAL", int64(len(body))).Int("OFFSET", int64(offset)).
			Raw("DATA", lispwire.Vec{Items: data}).
			Bool("DONE", end == len(body)).Encode())
	}
	return out
}

const snapshotMembers = `(("gr8s2" . :VOTER) ("gvision" . :VOTER) ("wit" . :WITNESS))`

func TestWitnessSnapshotCarriesTheMembership(t *testing.T) {
	f, ms := newTestFollower(t, &State{HardState: HardState{CurrentTerm: 7}})
	var addrs map[string]string
	f.SetAddressSink(func(a map[string]string) { addrs = a })
	chunks := lispChunks(500, installSnapshotForm(500, snapshotMembers), 100)
	if len(chunks) < 3 {
		t.Fatalf("want a transfer of several chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		r := mustStep(t, f, c)
		if (r != nil) != (i == len(chunks)-1) {
			t.Fatalf("chunk %d of %d: reply %v", i, len(chunks), r)
		}
	}
	if st := f.snapshotState(); st.SnapshotIdx != 500 || st.CommitIndex != 500 {
		t.Fatalf("boundary %d commit %d", st.SnapshotIdx, st.CommitIndex)
	}
	if !reflect.DeepEqual(ms.hs.Members, threeMembers) || ms.hs.MembersIdx != 500 {
		t.Fatalf("persisted membership = %v at %d", ms.hs.Members, ms.hs.MembersIdx)
	}
	if addrs["gr8s2"] != "10.77.77.22:7000" || addrs["gvision"] != "10.77.77.21:7000" {
		t.Fatalf("addresses = %v", addrs)
	}
}

func TestInstallSnapshotMessageCarriesTheMembership(t *testing.T) {
	f, ms := newTestFollower(t, &State{HardState: HardState{CurrentTerm: 7}})
	mustStep(t, f, []byte(installSnapshotForm(500, snapshotMembers)))
	if !reflect.DeepEqual(ms.hs.Members, threeMembers) || ms.hs.MembersIdx != 500 {
		t.Fatalf("persisted membership = %v at %d", ms.hs.Members, ms.hs.MembersIdx)
	}
}

// A snapshot moves the commit index over entries this member may never have
// seen. If it cannot say what the membership is at the boundary, an older
// membership must not stay in force.
func TestSnapshotWithoutAReadableMembership(t *testing.T) {
	opaque := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	// Our log does not reach the boundary: the membership is unknown.
	f, ms := newTestFollower(t, &State{HardState: HardState{CurrentTerm: 7, Members: threeMembers, MembersIdx: 2}})
	f.logf = func(string, ...any) {}
	mustStep(t, f, buildChunkFrame("gvision", 7, 120, 6, 0, 9, opaque, true))
	if len(f.Membership()) != 0 || len(ms.hs.Members) != 0 || ms.hs.MembersIdx != 120 {
		t.Fatalf("membership = %v (persisted %v at %d)", f.Membership(), ms.hs.Members, ms.hs.MembersIdx)
	}
	// A truncated or mismatched Lisp form is no better than none.
	f, ms = newTestFollower(t, &State{HardState: HardState{CurrentTerm: 7, Members: threeMembers, MembersIdx: 2}})
	f.logf = func(string, ...any) {}
	for _, c := range lispChunks(120, installSnapshotForm(119, snapshotMembers), 4096) {
		mustStep(t, f, c)
	}
	if len(ms.hs.Members) != 0 {
		t.Fatalf("membership taken from a snapshot message for another boundary: %v", ms.hs.Members)
	}

	// Our log reaches the boundary: every skipped entry is here to look through.
	held := func(third string) *State {
		return &State{
			HardState: HardState{CurrentTerm: 7, Members: threeMembers, MembersIdx: 0},
			Log: []Entry{
				{Index: 1, Term: 6, Command: `(:PUT "k" "v")`},
				{Index: 2, Term: 6, Command: third},
				{Index: 3, Term: 6, Command: `(:PUT "k" "v")`},
				{Index: 4, Term: 7, Command: configThree}, // beyond the boundary: not committed by it
			},
		}
	}
	f, ms = newTestFollower(t, held(configFour))
	f.logf = func(string, ...any) {}
	mustStep(t, f, buildChunkFrame("gvision", 7, 3, 6, 0, 9, opaque, true))
	if !reflect.DeepEqual(ms.hs.Members, fourMembers) || ms.hs.MembersIdx != 2 {
		t.Fatalf("membership = %v at %d, want the config at index 2", ms.hs.Members, ms.hs.MembersIdx)
	}
	if st := f.snapshotState(); len(st.Log) != 1 || st.Log[0].Index != 4 {
		t.Fatalf("log after install = %+v", st.Log)
	}
	// ...and with no config among them, the membership stands.
	f, ms = newTestFollower(t, held(`(:PUT "k" "v")`))
	f.logf = func(string, ...any) {}
	mustStep(t, f, buildChunkFrame("gvision", 7, 3, 6, 0, 9, opaque, true))
	if !reflect.DeepEqual(ms.hs.Members, threeMembers) {
		t.Fatalf("membership = %v, want it unchanged", ms.hs.Members)
	}
}
