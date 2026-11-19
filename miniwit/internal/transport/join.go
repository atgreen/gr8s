// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// AddressBook maps a member id to its "host:port" RaftTransport endpoint.
type AddressBook map[string]string

// JoinResult is what a successful Join returns: the peer address book the leader
// sent, so the witness can reach every member to reply to.
type JoinResult struct {
	Addresses AddressBook
}

const maxJoinRedirects = 3

// Join admits this witness to the cluster via the Join RPC, authenticated by the
// member certificate (the token was already spent at enrollment). It calls any
// member at startAddr; a follower replies with the leader's address and the call
// retries there (raft-cluster-join). The witness's own RaftTransport server must
// already be listening so the leader can replicate to it before the add commits.
func Join(ctx context.Context, id *Identity, selfID, selfHost string, selfPort uint32, nodeName, role, startAddr string) (*JoinResult, error) {
	creds := credentials.NewTLS(id.MemberClientTLS())
	host, port, err := splitHostPort(startAddr)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt <= maxJoinRedirects; attempt++ {
		resp, err := callJoin(ctx, creds, net.JoinHostPort(host, strconv.Itoa(port)), &nodev1.JoinRequest{
			MemberId: selfID,
			Host:     selfHost,
			Port:     selfPort,
			Role:     role,
			NodeName: nodeName,
		})
		if err != nil {
			return nil, err
		}
		switch {
		case resp.GetAccepted():
			book := make(AddressBook)
			for _, m := range resp.GetMembers() {
				book[m.GetId()] = net.JoinHostPort(m.GetHost(), strconv.Itoa(int(m.GetPort())))
			}
			return &JoinResult{Addresses: book}, nil
		case resp.GetLeaderHost() != "" && attempt < maxJoinRedirects:
			host, port = resp.GetLeaderHost(), int(resp.GetLeaderPort())
		default:
			reason := resp.GetReason()
			if reason == "" {
				reason = "no-leader"
			}
			return nil, fmt.Errorf("join refused: %s", reason)
		}
	}
	return nil, fmt.Errorf("join: exhausted %d leader redirects", maxJoinRedirects)
}

func callJoin(ctx context.Context, creds credentials.TransportCredentials, addr string, req *nodev1.JoinRequest) (*nodev1.JoinResponse, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return nodev1.NewRaftTransportClient(conn).Join(cctx, req)
}

func splitHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %q: %w", addr, err)
	}
	return h, port, nil
}
