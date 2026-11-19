// SPDX-License-Identifier: Apache-2.0
//
// miniwit joins a gr8s HA control plane as a non-campaigning :witness
// voting member: it enrolls for a member certificate, joins the cluster, serves
// RaftTransport, and runs a follower that grants votes and acknowledges appends
// without ever leading or applying a command.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/atgreen/gr8s/miniwit/internal/raftcore"
	"github.com/atgreen/gr8s/miniwit/internal/transport"
)

var version = "0.1.0-dev"

type config struct {
	joinAddress string
	joinToken   string
	caPin       string
	memberID    string
	nodeName    string
	listen      string
	advertise   string
	joinRole    string
	dataDir     string
	maxLogBytes int64
	retainBytes int64
	renewBefore time.Duration
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("miniwit: ")

	cfg := config{}
	flag.StringVar(&cfg.joinAddress, "join-address", "", "host:port of a current cluster member to enroll and join through")
	flag.StringVar(&cfg.joinToken, "join-token", "", "one-time Raft join token (from `gr8s join-token --role witness`)")
	flag.StringVar(&cfg.caPin, "ca-pin", "", "SHA-256 hex fingerprint of the cluster CA (the join token's caPin)")
	flag.StringVar(&cfg.memberID, "member-id", "", "this witness's member id (becomes its certificate CN)")
	flag.StringVar(&cfg.nodeName, "node-name", "", "the node name the join token is bound to")
	flag.StringVar(&cfg.listen, "listen", "0.0.0.0:7000", "host:port to serve RaftTransport on")
	flag.StringVar(&cfg.advertise, "advertise", "", "host:port peers use to reach this witness (default: -listen)")
	flag.StringVar(&cfg.joinRole, "join-role", "witness", "membership role to join as: witness or learner (learner has no quorum impact, for safe validation)")
	flag.StringVar(&cfg.dataDir, "data-dir", "/var/lib/miniwit", "directory for credentials and the Raft log")
	flag.Int64Var(&cfg.maxLogBytes, "max-log-bytes", 4<<20, "compact the on-disk log once it passes this many bytes")
	flag.Int64Var(&cfg.retainBytes, "retain-log-bytes", 1<<20, "bytes of the most recent log to keep after compaction")
	flag.DurationVar(&cfg.renewBefore, "renew-before", transport.RenewBefore, "renew the member certificate once it is this close to expiry")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("miniwit %s\n", version)
		return
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config) error {
	for name, v := range map[string]string{
		"-join-address": cfg.joinAddress, "-join-token": cfg.joinToken,
		"-ca-pin": cfg.caPin, "-member-id": cfg.memberID, "-node-name": cfg.nodeName,
	} {
		if v == "" {
			return fmt.Errorf("missing required flag %s", name)
		}
	}
	advertise := cfg.advertise
	if advertise == "" {
		advertise = cfg.listen
	}
	selfHost, selfPort, err := hostPort(advertise)
	if err != nil {
		return fmt.Errorf("invalid -advertise: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. Enroll (or reuse) the member certificate.
	pkiDir := filepath.Join(cfg.dataDir, "pki")
	id, err := transport.Enroll(ctx, cfg.joinAddress, cfg.memberID, cfg.nodeName, cfg.joinToken, cfg.caPin, pkiDir)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	log.Printf("enrolled member %q (CA %s)", cfg.memberID, transport.CAFingerprint(id.CA)[:16])

	// 2. Build the follower over durable storage and start the RaftTransport server.
	raftcore.SetCompactionBytes(cfg.maxLogBytes, cfg.retainBytes)
	store, err := raftcore.NewFileStore(filepath.Join(cfg.dataDir, "raft"))
	if err != nil {
		return err
	}
	follower, err := raftcore.NewFollower(cfg.memberID, store, time.Second)
	if err != nil {
		return err
	}
	sender := transport.NewPeerSender(id, nil)
	defer sender.Close()
	svc := transport.NewServer(cfg.memberID, follower, sender)
	gs, err := transport.Serve(cfg.listen, id, svc)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer gs.GracefulStop()
	log.Printf("serving RaftTransport on %s (advertising %s)", cfg.listen, advertise)

	// 3. Join the cluster; the leader will replicate to the server we just started.
	res, err := transport.Join(ctx, id, cfg.memberID, selfHost, uint32(selfPort), cfg.nodeName, cfg.joinRole, cfg.joinAddress)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	sender.UpdateAddresses(res.Addresses)
	log.Printf("joined the cluster as %s (%d peers known)", cfg.joinRole, len(res.Addresses))

	// 4. Keep the member certificate current; a voter signs the renewal.
	go transport.RenewalLoop(ctx, id, cfg.memberID, pkiDir, sender.Addresses, cfg.renewBefore, transport.RenewCheckEvery)

	<-ctx.Done()
	log.Printf("shutting down")
	return nil
}

func hostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	if h == "0.0.0.0" || h == "" {
		return "", 0, fmt.Errorf("advertise a concrete host, not %q (use -advertise)", addr)
	}
	return h, port, nil
}
