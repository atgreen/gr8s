// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
	"github.com/atgreen/gr8s/miniwit/internal/raftcore"
	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// testCA mints member identities the way gr8s does: CN carries the member id and
// a fixed SAN (FixedServerSAN) stands in for a hostname, signed by one cluster CA.
type testCA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gr8s cluster CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) identity(t *testing.T, memberID string) *Identity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: memberID},
		DNSNames:     []string{FixedServerSAN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return NewIdentity(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca.cert)
}

// recordingServer is a stand-in "leader": it records every Deliver payload so the
// test can assert the witness sent its reply back over mutual TLS.
type recordingServer struct {
	nodev1.UnimplementedRaftTransportServer
	got chan []byte
}

func (r *recordingServer) Deliver(_ context.Context, env *nodev1.RaftEnvelope) (*nodev1.RaftAck, error) {
	r.got <- env.GetPayload()
	return &nodev1.RaftAck{}, nil
}

// TestDeliverRoundTripOverMutualTLS drives the whole phase-2+4 path between two
// real gRPC endpoints: a "leader" sends an AppendEntries to the witness over
// mutual TLS; the witness authenticates the CN, steps the follower, and delivers
// its append-entries-reply back to the leader.
func TestDeliverRoundTripOverMutualTLS(t *testing.T) {
	ca := newTestCA(t)
	witnessID := ca.identity(t, "wit")
	leaderID := ca.identity(t, "leader")

	// Leader's recording endpoint.
	leaderRec := &recordingServer{got: make(chan []byte, 4)}
	leaderLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	leaderSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(leaderID.ServerTLS())))
	nodev1.RegisterRaftTransportServer(leaderSrv, leaderRec)
	go leaderSrv.Serve(leaderLis)
	defer leaderSrv.Stop()
	leaderAddr := leaderLis.Addr().String()

	// Witness: follower + server, with the leader's address in its sender.
	ms := &memBackedStore{}
	follower, err := raftcore.NewFollower("wit", ms, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sender := NewPeerSender(witnessID, AddressBook{"leader": leaderAddr})
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

	// Leader dials the witness and delivers an AppendEntries heartbeat as "leader".
	conn, err := grpc.NewClient(witnessLis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(leaderID.MemberClientTLS())))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ae := lispwire.NewReply("APPEND-ENTRIES").Int("TERM", 3).Str("FROM", "leader").
		Int("PREV-LOG-INDEX", 0).Int("PREV-LOG-TERM", 0).
		Raw("ENTRIES", lispwire.Sym("NIL")).Int("LEADER-COMMIT", 0).Int("READ-SEQ", 1).Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := nodev1.NewRaftTransportClient(conn).Deliver(ctx, &nodev1.RaftEnvelope{ProtocolVersion: 1, Payload: ae}); err != nil {
		t.Fatalf("Deliver to witness failed: %v", err)
	}

	// The witness should deliver an append-entries-reply back to the leader.
	select {
	case payload := <-leaderRec.got:
		m, err := lispwire.Decode(payload)
		if err != nil {
			t.Fatalf("reply did not decode: %v", err)
		}
		if m.Type != "APPEND-ENTRIES-REPLY" {
			t.Fatalf("reply type = %q", m.Type)
		}
		if !m.Bool("SUCCESS") {
			t.Error("heartbeat reply should be success")
		}
		if from, _ := m.Str("FROM"); from != "wit" {
			t.Errorf("reply :FROM = %q, want wit", from)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the witness's reply to the leader")
	}
}

// TestDeliverRejectsSpoofedFrom ensures a member cannot speak as another: the
// :FROM must equal the authenticated certificate CN.
func TestDeliverRejectsSpoofedFrom(t *testing.T) {
	ca := newTestCA(t)
	witnessID := ca.identity(t, "wit")
	leaderID := ca.identity(t, "leader")

	ms := &memBackedStore{}
	follower, _ := raftcore.NewFollower("wit", ms, time.Second)
	sender := NewPeerSender(witnessID, nil)
	defer sender.Close()
	svc := NewServer("wit", follower, sender)
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(witnessID.ServerTLS())))
	nodev1.RegisterRaftTransportServer(srv, svc)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(leaderID.MemberClientTLS())))
	defer conn.Close()

	// "leader" cert, but claims to be "gvision": must be rejected.
	spoof := lispwire.NewReply("REQUEST-VOTE").Int("TERM", 9).Str("FROM", "gvision").
		Int("LAST-LOG-INDEX", 0).Int("LAST-LOG-TERM", 0).Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := nodev1.NewRaftTransportClient(conn).Deliver(ctx, &nodev1.RaftEnvelope{ProtocolVersion: 1, Payload: spoof})
	if err == nil {
		t.Fatal("expected Deliver to reject a spoofed :FROM")
	}
}

// memBackedStore is a trivial in-memory raftcore.Store for the transport tests.
type memBackedStore struct {
	hs  raftcore.HardState
	log []raftcore.Entry
}

func (m *memBackedStore) Load() (*raftcore.State, error) {
	return &raftcore.State{HardState: m.hs, CommitIndex: m.hs.SnapshotIdx, Log: append([]raftcore.Entry(nil), m.log...)}, nil
}
func (m *memBackedStore) PutHardState(hs raftcore.HardState) error { m.hs = hs; return nil }
func (m *memBackedStore) AppendLog(e []raftcore.Entry) error       { m.log = append(m.log, e...); return nil }
func (m *memBackedStore) RewriteLog(e []raftcore.Entry) error {
	m.log = append([]raftcore.Entry(nil), e...)
	return nil
}
