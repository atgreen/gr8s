// SPDX-License-Identifier: Apache-2.0

package raftcore

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
)

// Membership roles, spelled as the Join RPC spells them (RaftMember.role). On the
// wire inside a config entry they are the keywords :VOTER, :WITNESS, :LEARNER.
const (
	RoleVoter   = "voter"
	RoleWitness = "witness"
	RoleLearner = "learner"
)

func validRole(role string) bool {
	return role == RoleVoter || role == RoleWitness || role == RoleLearner
}

// A witness needs the membership for one thing: to count a majority when it
// stands in (standin.go). Counting against a membership that is too small is
// the dangerous direction -- two leaders could be elected in one term -- so every
// path here that cannot be sure of the membership forgets it instead. A witness
// that does not know the membership never stands in; it still votes and stores
// the log exactly as before.
//
// The membership comes from three places, as in cl-raft: the Join response
// (SetMembership), a :RAFT-CONFIG entry once it is committed (advanceCommit;
// cl-raft adopts a config when it applies the entry), and the envelope of an
// installed snapshot (membershipAcrossSnapshot).

// SetMembership records the membership the leader returned from Join: member id
// to role, self included. The leader's answer lists members it has proposed but
// not yet committed and may still list members it has removed, so it can only
// be larger than the committed membership, which is the safe direction. Committed
// config entries replace it as they arrive.
func (f *Follower) SetMembership(members map[string]string) error {
	if len(members) == 0 {
		return nil
	}
	cp := make(map[string]string, len(members))
	for id, role := range members {
		if id == "" || !validRole(role) {
			return fmt.Errorf("raftcore: member %q has unknown role %q", id, role)
		}
		cp[id] = role
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	hs := f.st.HardState
	hs.Members = cp
	if err := f.store.PutHardState(hs); err != nil {
		return err
	}
	f.st.HardState = hs
	f.logf("membership from join: %s", describeMembers(cp))
	return nil
}

// SetAddressSink registers fn to receive the peer endpoints (member id to
// "host:port") carried by each membership this member adopts. fn is called with
// the follower's lock held and must not call back into it.
func (f *Follower) SetAddressSink(fn func(map[string]string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onAddresses = fn
}

// Membership returns a copy of the membership (member id to role), empty when it
// is unknown.
func (f *Follower) Membership() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]string, len(f.st.Members))
	for id, role := range f.st.Members {
		cp[id] = role
	}
	return cp
}

func (f *Follower) learnAddresses(addrs map[string]string) {
	if f.onAddresses != nil && len(addrs) > 0 {
		f.onAddresses(addrs)
	}
}

// inQuorum reports whether id counts toward a majority: voters and witnesses do,
// learners do not (raft-configure).
func (f *Follower) inQuorum(id string) bool {
	role := f.st.Members[id]
	return role == RoleVoter || role == RoleWitness
}

// quorumPeers lists every voter and witness except this member, sorted so the
// messages of one broadcast leave in a stable order.
func (f *Follower) quorumPeers() []string {
	var peers []string
	for id := range f.st.Members {
		if id != f.id && f.inQuorum(id) {
			peers = append(peers, id)
		}
	}
	sort.Strings(peers)
	return peers
}

// majority is floor(n/2)+1 over the voters and witnesses, this member included
// (raft-majority).
func (f *Follower) majority() int {
	n := 0
	for id := range f.st.Members {
		if f.inQuorum(id) {
			n++
		}
	}
	return n/2 + 1
}

// advanceCommit moves the commit index up to index. A witness applies nothing,
// with one exception that cl-raft makes too: a :RAFT-CONFIG entry changes the
// membership when it is applied, which is when it is committed. The membership is
// persisted before the commit index moves, so a failed write is retried by the
// leader's next AppendEntries rather than skipped.
func (f *Follower) advanceCommit(index int64) error {
	if index <= f.st.CommitIndex {
		return nil
	}
	// The commit index restarts at the snapshot boundary after a restart, so
	// entries already reflected in the persisted membership pass by here again.
	from := max64(f.st.CommitIndex, f.st.MembersIdx)
	if at, command := f.lastConfigIn(from+1, index); at != 0 {
		hs := f.st.HardState
		addrs := f.adoptConfig(&hs, at, command)
		if err := f.store.PutHardState(hs); err != nil {
			return err
		}
		f.st.HardState = hs
		f.learnAddresses(addrs)
	}
	f.st.CommitIndex = index
	return nil
}

// lastConfigIn finds the newest stored :RAFT-CONFIG entry with lo <= index <= hi.
// Each config entry carries the whole membership, so only the newest matters.
func (f *Follower) lastConfigIn(lo, hi int64) (int64, string) {
	lo = max64(lo, f.st.SnapshotIdx+1)
	hi = min64(hi, f.lastLogIndex())
	for i := hi; i >= lo; i-- {
		e := f.st.Log[i-f.st.SnapshotIdx-1]
		if strings.HasPrefix(e.Command, "(:RAFT-CONFIG ") {
			return e.Index, e.Command
		}
	}
	return 0, ""
}

// adoptConfig sets hs's membership from the committed config entry at index and
// returns the addresses it carries. A committed config this program cannot read
// leaves the membership unknown rather than stale.
func (f *Follower) adoptConfig(hs *HardState, index int64, command string) map[string]string {
	hs.MembersIdx = index
	members, addrs, err := parseConfigCommand(command)
	if err != nil {
		hs.Members = nil
		f.logf("membership unknown: config entry %d: %v", index, err)
		return nil
	}
	hs.Members = members
	f.logf("membership from config entry %d: %s", index, describeMembers(members))
	return addrs
}

// membershipAcrossSnapshot sets hs's membership for a snapshot boundary at index
// that is about to be installed, and returns any addresses learned. The commit
// index jumps to the boundary, over entries that may have changed the membership:
//
//   - the snapshot envelope carries the membership frozen at the boundary
//     (raft-capture-snapshot), so use it when the transfer delivered one;
//   - failing that, if our own log reaches the boundary (held), the entries being
//     skipped are all here, so look through them as advanceCommit would;
//   - failing that, the membership is unknown until a later config entry commits
//     or the next Join.
func (f *Follower) membershipAcrossSnapshot(hs *HardState, index int64, held bool, state lispwire.Value) map[string]string {
	if plist, ok := snapshotEnvelope(state); ok {
		if members, addrs, err := parseMembership(plist); err == nil {
			hs.Members, hs.MembersIdx = members, index
			f.logf("membership from snapshot %d: %s", index, describeMembers(members))
			return addrs
		}
	}
	if held {
		from := max64(f.st.CommitIndex, f.st.MembersIdx)
		if at, command := f.lastConfigIn(from+1, index); at != 0 {
			return f.adoptConfig(hs, at, command)
		}
		return nil
	}
	if len(hs.Members) > 0 {
		f.logf("membership unknown: snapshot %d carried none this witness could read", index)
	}
	hs.Members, hs.MembersIdx = nil, index
	return nil
}

// snapshotEnvelope returns the property list of a cl-raft snapshot envelope,
// (:CL-RAFT-SNAPSHOT 1 :APPLICATION ... :MEMBERS ... :ADDRESSES ...).
func snapshotEnvelope(state lispwire.Value) ([]lispwire.Value, bool) {
	lst, ok := state.(lispwire.List)
	if !ok || lst.Dotted || len(lst.Items) < 2 || !isKeyword(lst.Items[0], "CL-RAFT-SNAPSHOT") {
		return nil, false
	}
	if version, ok := lst.Items[1].(lispwire.Int); !ok || version != 1 {
		return nil, false
	}
	return lst.Items[2:], true
}

// parseConfigCommand reads a stored config command,
// (:RAFT-CONFIG :MEMBERS (("id" . :VOTER) ...) :ADDRESSES (("id" "host" port) ...) ...).
func parseConfigCommand(command string) (members, addrs map[string]string, err error) {
	v, err := lispwire.Read(command)
	if err != nil {
		return nil, nil, err
	}
	lst, ok := v.(lispwire.List)
	if !ok || lst.Dotted || len(lst.Items) == 0 || !isKeyword(lst.Items[0], "RAFT-CONFIG") {
		return nil, nil, fmt.Errorf("not a :RAFT-CONFIG command")
	}
	return parseMembership(lst.Items[1:])
}

// parseMembership reads :MEMBERS (required: an alist of id to role keyword) and
// :ADDRESSES (optional: an alist of id to (host port)) out of a property list.
// Any member it cannot read fails the whole membership: a partial one would
// undercount the quorum.
func parseMembership(plist []lispwire.Value) (members, addrs map[string]string, err error) {
	mv, _ := plistGet(plist, "MEMBERS")
	ml, ok := mv.(lispwire.List)
	if !ok || ml.Dotted || len(ml.Items) == 0 {
		return nil, nil, fmt.Errorf("no :MEMBERS list")
	}
	members = make(map[string]string, len(ml.Items))
	for _, item := range ml.Items {
		pair, ok := item.(lispwire.List)
		if !ok || !pair.Dotted || len(pair.Items) != 2 {
			return nil, nil, fmt.Errorf("member %s is not an (id . role) pair", lispwire.Write(item))
		}
		id, okID := pair.Items[0].(lispwire.Str)
		sym, okRole := pair.Items[1].(lispwire.Sym)
		role := strings.ToLower(strings.TrimPrefix(string(sym), ":"))
		if !okID || id == "" || !okRole || !strings.HasPrefix(string(sym), ":") || !validRole(role) {
			return nil, nil, fmt.Errorf("member %s is not an (id . role) pair", lispwire.Write(item))
		}
		if _, dup := members[string(id)]; dup {
			return nil, nil, fmt.Errorf("member %q is listed twice", string(id))
		}
		members[string(id)] = role
	}
	// Addresses only tell the transport where to send; one that does not parse is
	// skipped, and that peer stays wherever the address book already has it.
	if av, ok := plistGet(plist, "ADDRESSES"); ok {
		if al, ok := av.(lispwire.List); ok && !al.Dotted {
			addrs = make(map[string]string, len(al.Items))
			for _, item := range al.Items {
				a, ok := item.(lispwire.List)
				if !ok || a.Dotted || len(a.Items) != 3 {
					continue
				}
				id, okID := a.Items[0].(lispwire.Str)
				host, okHost := a.Items[1].(lispwire.Str)
				port, okPort := a.Items[2].(lispwire.Int)
				if okID && okHost && okPort && host != "" && port >= 1 && port <= 65535 {
					addrs[string(id)] = net.JoinHostPort(string(host), strconv.FormatInt(int64(port), 10))
				}
			}
		}
	}
	return members, addrs, nil
}

// plistGet returns the value after the keyword :key in a property list.
func plistGet(plist []lispwire.Value, key string) (lispwire.Value, bool) {
	for i := 0; i+1 < len(plist); i += 2 {
		if isKeyword(plist[i], key) {
			return plist[i+1], true
		}
	}
	return nil, false
}

// isKeyword reports whether v is the keyword :name. The Lisp reader upcases, so
// case does not distinguish keywords.
func isKeyword(v lispwire.Value, name string) bool {
	sym, ok := v.(lispwire.Sym)
	return ok && strings.EqualFold(string(sym), ":"+name)
}

func describeMembers(members map[string]string) string {
	ids := make([]string, 0, len(members))
	for id := range members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id + "=" + members[id]
	}
	return strings.Join(parts, " ")
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
