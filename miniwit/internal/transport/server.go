// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/atgreen/gr8s/miniwit/internal/lispwire"
	"github.com/atgreen/gr8s/miniwit/internal/raftcore"
	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Server implements the RaftTransport gRPC service for a witness. It serves
// Deliver (feeding the follower and sending its reply back) and answers Join as a
// non-leader redirect; every other method is refused, because a witness never
// leads, issues certificates, or serves nodes.
type Server struct {
	nodev1.UnimplementedRaftTransportServer
	follower *raftcore.Follower
	sender   *PeerSender
	selfID   string
}

// NewServer builds the witness's RaftTransport service.
func NewServer(selfID string, follower *raftcore.Follower, sender *PeerSender) *Server {
	return &Server{follower: follower, sender: sender, selfID: selfID}
}

// Serve starts the gRPC server with mutual TLS on listenAddr and blocks until the
// listener is closed. The returned *grpc.Server lets the caller GracefulStop.
func Serve(listenAddr string, id *Identity, svc *Server) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(id.ServerTLS())))
	nodev1.RegisterRaftTransportServer(gs, svc)
	go func() {
		if err := gs.Serve(lis); err != nil {
			log.Printf("miniwit: RaftTransport server stopped: %v", err)
		}
	}()
	return gs, nil
}

// Deliver authenticates the caller by its client-certificate CN, enforces that
// the message's :FROM matches that identity (authenticated-raft-message), feeds
// the message to the follower, and sends any reply back fire-and-forget.
func (s *Server) Deliver(ctx context.Context, env *nodev1.RaftEnvelope) (*nodev1.RaftAck, error) {
	peerCN, err := peerMemberID(ctx)
	if err != nil {
		return nil, err
	}
	payload := env.GetPayload()
	// A member may only speak as itself: the :FROM must equal the certificate CN.
	if msg, err := lispwire.DecodePayload(payload); err == nil {
		if from, _ := msg.Str("FROM"); from != peerCN {
			return nil, status.Errorf(codes.PermissionDenied, "member %q sent a message as %q", peerCN, from)
		}
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "undecodable Raft payload: %v", err)
	}
	if debugEnabled {
		if m, err := lispwire.DecodePayload(payload); err == nil {
			t, _ := m.Int("TERM")
			pli, _ := m.Int("PREV-LOG-INDEX")
			li, _ := m.Int("LAST-INDEX")
			log.Printf("debug: recv %s from=%s term=%d prev-log-index=%d last-index=%d bytes=%d", m.Type, peerCN, t, pli, li, len(payload))
		}
	}
	reply, err := s.follower.Step(payload)
	if err != nil {
		// A step error (e.g. a persistence failure) just means no reply; the peer
		// retries. Log it rather than failing the fire-and-forget RPC.
		log.Printf("miniwit: step from %s: %v", peerCN, err)
		return &nodev1.RaftAck{}, nil
	}
	if reply != nil {
		if debugEnabled {
			if m, err := lispwire.DecodePayload(reply.Payload); err == nil {
				ni, hasNI := m.Int("NEXT-INDEX")
				mi, _ := m.Int("MATCH-INDEX")
				log.Printf("debug: send %s to=%s success=%v match-index=%d next-index=%d(%v)", m.Type, reply.To, m.Bool("SUCCESS"), mi, ni, hasNI)
			}
		}
		s.sender.Send(reply.To, reply.Payload)
	}
	return &nodev1.RaftAck{}, nil
}

// Join answers a joiner that contacted this witness: a witness is never leader,
// so it redirects to the leader it last heard from, if any.
func (s *Server) Join(ctx context.Context, req *nodev1.JoinRequest) (*nodev1.JoinResponse, error) {
	leader := s.follower.LeaderID()
	resp := &nodev1.JoinResponse{Accepted: false, LeaderId: leader, Reason: "witness-cannot-admit"}
	if leader != "" {
		if addr, ok := s.sender.Address(leader); ok {
			if host, port, err := splitHostPort(addr); err == nil {
				resp.LeaderHost = host
				resp.LeaderPort = uint32(port)
			}
		}
	}
	return resp, nil
}

// The remaining RaftTransport methods are refused: a witness originates no
// writes, issues no certificates, and serves no node operations.

func (s *Server) Propose(context.Context, *nodev1.RaftProposal) (*nodev1.RaftProposalResult, error) {
	return &nodev1.RaftProposalResult{Committed: false, Reason: "not-leader"}, nil
}

func (s *Server) EnrollMember(context.Context, *nodev1.EnrollMemberRequest) (*nodev1.EnrollMemberResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "a witness cannot enroll members")
}

func (s *Server) RenewMember(context.Context, *nodev1.RenewMemberRequest) (*nodev1.RenewMemberResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "a witness cannot renew members")
}

func (s *Server) RelayOperation(context.Context, *nodev1.RoutedOperation) (*nodev1.RoutedOperationResult, error) {
	return &nodev1.RoutedOperationResult{Accepted: false, ErrorMessage: "witness serves no nodes"}, nil
}

func (s *Server) PatchManagement(context.Context, *nodev1.PatchManagementRequest) (*nodev1.PatchManagementResponse, error) {
	return nil, status.Error(codes.Unimplemented, "a witness runs no patch management")
}

// peerMemberID extracts the authenticated member id (the client certificate's
// Common Name) from the gRPC context, or an error if the call was not
// authenticated with a verified member certificate.
func peerMemberID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "connection is not TLS")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return "", status.Error(codes.Unauthenticated, "Raft requests require a member certificate")
	}
	cn := certs[0].Subject.CommonName
	if cn == "" {
		return "", status.Error(codes.Unauthenticated, "member certificate has no common name")
	}
	return cn, nil
}

// debugEnabled turns on per-message tracing when GOWIT_DEBUG is set.
var debugEnabled = os.Getenv("GOWIT_DEBUG") != ""

// ensure the interface is satisfied at compile time.
var _ nodev1.RaftTransportServer = (*Server)(nil)
