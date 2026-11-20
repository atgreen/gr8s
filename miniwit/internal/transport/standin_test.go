// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
	"github.com/atgreen/gr8s/miniwit/internal/raftcore"
	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// TestStandInHandoverOverMutualTLS runs the podster-f15 handover between two
// real gRPC endpoints. The witness holds five entries; the surviving voter
// (gr8s2, scripted here to answer as a cl-raft voter does) holds four; the old
// leader (gvision) is gone and has no reachable address. The voter must end up
// with the fifth entry, exactly as stored, and with the witness's vote for the
// term after the witness's own.
func TestStandInHandoverOverMutualTLS(t *testing.T) {
	const fifth = `(:PUT "key" "va\"lue" (1 . 2))`
	ca := newTestCA(t)
	witnessID := ca.identity(t, "wit")
	voterID := ca.identity(t, "gr8s2")

	voterRec := &recordingServer{got: make(chan []byte, 64)}
	voterLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	voterSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(voterID.ServerTLS())))
	nodev1.RegisterRaftTransportServer(voterSrv, voterRec)
	go voterSrv.Serve(voterLis)
	defer voterSrv.Stop()

	ms := &memBackedStore{hs: raftcore.HardState{
		CurrentTerm: 4,
		VotedFor:    "gvision",
		Members:     map[string]string{"gvision": raftcore.RoleVoter, "gr8s2": raftcore.RoleVoter, "wit": raftcore.RoleWitness},
	}}
	for i := int64(1); i <= 4; i++ {
		ms.log = append(ms.log, raftcore.Entry{Index: i, Term: 4, Command: `(:PUT "k" "v")`})
	}
	ms.log = append(ms.log, raftcore.Entry{Index: 5, Term: 4, Command: fifth})
	follower, err := raftcore.NewFollower("wit", ms, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sender := NewPeerSender(witnessID, AddressBook{"gr8s2": voterLis.Addr().String()})
	defer sender.Close()
	svc := NewServer("wit", follower, sender)
	witnessLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	witnessSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(witnessID.ServerTLS())))
	nodev1.RegisterRaftTransportServer(witnessSrv, svc)
	go witnessSrv.Serve(witnessLis)
	defer witnessSrv.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go svc.RunClock(ctx, TickEvery)

	conn, err := grpc.NewClient(witnessLis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(voterID.MemberClientTLS())))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deliver := func(b *lispwire.Builder) {
		t.Helper()
		if _, err := nodev1.NewRaftTransportClient(conn).Deliver(ctx, &nodev1.RaftEnvelope{ProtocolVersion: 1, Payload: b.Encode()}); err != nil {
			t.Fatalf("Deliver to witness failed: %v", err)
		}
	}

	// The scripted voter: term 4, entries 1..4 of term 4.
	term, lastIndex := int64(4), int64(4)
	var received []string // commands the witness replicated to it
	var seen []string     // message types, in arrival order
	deliver(lispwire.NewReply("PRE-VOTE").Int("TERM", term+1).Str("FROM", "gr8s2").
		Int("LAST-LOG-INDEX", lastIndex).Int("LAST-LOG-TERM", 4))
	for done := false; !done; {
		var payload []byte
		select {
		case payload = <-voterRec.got:
		case <-ctx.Done():
			t.Fatalf("timed out; the voter saw %v", seen)
		}
		m, err := lispwire.Decode(payload)
		if err != nil {
			t.Fatalf("witness sent an undecodable message %q: %v", payload, err)
		}
		if from, _ := m.Str("FROM"); from != "wit" {
			t.Fatalf("message from %q: %s", from, payload)
		}
		seen = append(seen, m.Type)
		msgTerm, _ := m.Int("TERM")
		switch m.Type {
		case "PRE-VOTE-REPLY":
			if m.Bool("GRANTED") {
				t.Fatalf("the witness granted a pre-vote to a voter behind its log: %s", payload)
			}
		case "PRE-VOTE":
			// raft-handle-pre-vote: no leader heard, a term ahead, a log ahead of ours.
			deliver(lispwire.NewReply("PRE-VOTE-REPLY").Int("TERM", term).Int("PRE-TERM", msgTerm).
				Str("FROM", "gr8s2").Bool("GRANTED", true))
		case "REQUEST-VOTE":
			term = msgTerm
			deliver(lispwire.NewReply("REQUEST-VOTE-REPLY").Int("TERM", term).Str("FROM", "gr8s2").Bool("GRANTED", true))
		case "APPEND-ENTRIES":
			if msgTerm != term {
				continue
			}
			prev, _ := m.Int("PREV-LOG-INDEX")
			reply := lispwire.NewReply("APPEND-ENTRIES-REPLY").Int("TERM", term).Str("FROM", "gr8s2").Int("READ-SEQ", 0)
			if prev > lastIndex {
				// raft-handle-append-entries on a log that is too short: no hint.
				deliver(reply.Bool("SUCCESS", false).Int("MATCH-INDEX", 0))
				continue
			}
			for _, e := range m.Entries {
				if e.Index == lastIndex+1 {
					received = append(received, lispwire.Write(e.Command))
					lastIndex++
				}
			}
			deliver(reply.Bool("SUCCESS", true).Int("MATCH-INDEX", prev+int64(len(m.Entries))))
		case "TIMEOUT-NOW":
			// raft-handle-timeout-now: campaign at once, skipping Pre-Vote.
			term++
			deliver(lispwire.NewReply("REQUEST-VOTE").Int("TERM", term).Str("FROM", "gr8s2").
				Int("LAST-LOG-INDEX", lastIndex).Int("LAST-LOG-TERM", 4).Bool("LEADER-TRANSFER", true))
		case "REQUEST-VOTE-REPLY":
			if !m.Bool("GRANTED") || msgTerm != 6 {
				t.Fatalf("want the witness's vote for term 6, got %s", payload)
			}
			done = true
		default:
			t.Fatalf("unexpected %s", payload)
		}
	}
	if want := []string{fifth}; !reflect.DeepEqual(received, want) {
		t.Fatalf("the voter received %q, want %q", received, want)
	}
	if lastIndex != 5 {
		t.Fatalf("voter's last index = %d, want 5", lastIndex)
	}
	if ms.hs.CurrentTerm != 6 || ms.hs.VotedFor != "gr8s2" {
		t.Fatalf("witness hard state: term %d voted-for %q", ms.hs.CurrentTerm, ms.hs.VotedFor)
	}
	if got := follower.LeaderID(); got != "" {
		t.Fatalf("the witness still names %q as leader", got)
	}
}

func TestMemberRolesFromJoinResponse(t *testing.T) {
	members := []*nodev1.RaftMember{
		{Id: "gvision", Role: "voter"}, {Id: "wit", Role: "Witness"}, {Id: "new", Role: "learner"},
	}
	want := map[string]string{"gvision": raftcore.RoleVoter, "wit": raftcore.RoleWitness, "new": raftcore.RoleLearner}
	if got := memberRoles(members); !reflect.DeepEqual(got, want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	// An older leader that sends no role, or a role from the future: no membership
	// rather than a guessed one.
	if got := memberRoles(append(members, &nodev1.RaftMember{Id: "x"})); got != nil {
		t.Fatalf("roles = %v, want none", got)
	}
}
