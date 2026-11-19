// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"sort"
	"sync"
	"time"

	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// raftEnvelopeProtocolVersion is the version gr8s stamps on every RaftEnvelope
// (src/raft/transport/snapshot.lisp: :protocol-version 1).
const raftEnvelopeProtocolVersion = 1

// PeerSender delivers Raft messages to peers over mutual TLS, fire-and-forget, as
// their own Deliver calls — gr8s's send model: a slow or dead peer never blocks
// delivery to the others, and Raft recovers dropped messages via its own retries.
type PeerSender struct {
	creds credentials.TransportCredentials

	mu    sync.Mutex
	addrs AddressBook
	conns map[string]*grpc.ClientConn
	known map[string]struct{} // peers we have logged as unroutable, to quiet the log
}

// NewPeerSender builds a sender that dials peers with the member certificate.
func NewPeerSender(id *Identity, addrs AddressBook) *PeerSender {
	cp := make(AddressBook, len(addrs))
	for k, v := range addrs {
		cp[k] = v
	}
	return &PeerSender{
		creds: credentials.NewTLS(id.MemberClientTLS()),
		addrs: cp,
		conns: make(map[string]*grpc.ClientConn),
		known: make(map[string]struct{}),
	}
}

// UpdateAddresses merges newly-learned peer endpoints (from a committed config).
func (s *PeerSender) UpdateAddresses(addrs AddressBook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range addrs {
		if s.addrs[k] != v && s.conns[k] != nil {
			s.conns[k].Close() // address changed: drop the stale connection
			delete(s.conns, k)
		}
		s.addrs[k] = v
	}
}

// Addresses returns every known peer endpoint.
func (s *PeerSender) Addresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	addrs := make([]string, 0, len(s.addrs))
	for _, a := range s.addrs {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	return addrs
}

// Address returns the known endpoint for a peer, if any.
func (s *PeerSender) Address(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.addrs[id]
	return a, ok
}

// Send delivers payload to peer id without blocking the caller. A peer we cannot
// reach is dropped silently (Raft retries); it is not an error path.
func (s *PeerSender) Send(to string, payload []byte) {
	conn := s.conn(to)
	if conn == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Fire-and-forget: a delivery failure is normal and self-healing.
		_, _ = nodev1.NewRaftTransportClient(conn).Deliver(ctx, &nodev1.RaftEnvelope{
			ProtocolVersion: raftEnvelopeProtocolVersion,
			Payload:         payload,
		})
	}()
}

func (s *PeerSender) conn(to string) *grpc.ClientConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.conns[to]; c != nil {
		return c
	}
	addr, ok := s.addrs[to]
	if !ok {
		return nil
	}
	c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(s.creds))
	if err != nil {
		return nil
	}
	s.conns[to] = c
	return c
}

// Close shuts down all peer connections.
func (s *PeerSender) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.Close()
	}
	s.conns = map[string]*grpc.ClientConn{}
}
