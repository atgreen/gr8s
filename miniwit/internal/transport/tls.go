// SPDX-License-Identifier: Apache-2.0

// Package transport carries the Raft mesh: the mutual-TLS gRPC RaftTransport
// server and the per-peer Deliver clients. gr8s member certificates carry the
// member id in the subject Common Name and a fixed SAN ("gr8s-control") that TLS
// clients check in place of a hostname (src/security/raft-tls.lisp,
// src/security/pki.lisp). Peers are verified against the shared cluster CA.
package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// FixedServerSAN is the constant SAN every gr8s member certificate carries; the
// identity lives in the Common Name (pki.lisp: +node-server-common-name+).
const FixedServerSAN = "gr8s-control"

// Identity is this witness's enrolled TLS material. The member certificate is
// replaced when it is renewed, so the TLS configs below ask for it at each
// handshake rather than holding a copy.
type Identity struct {
	CA *x509.Certificate // the cluster CA, trust anchor for every peer

	mu   sync.RWMutex
	cert tls.Certificate // member leaf + key (CN == member id, SAN == FixedServerSAN)
}

// NewIdentity returns an identity presenting cert and trusting ca.
func NewIdentity(cert tls.Certificate, ca *x509.Certificate) *Identity {
	return &Identity{CA: ca, cert: cert}
}

// Certificate returns the member certificate currently presented.
func (id *Identity) Certificate() tls.Certificate {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.cert
}

// setCertificate makes cert the one presented on every handshake from now on.
// Connections already open keep the certificate they were made with.
func (id *Identity) setCertificate(cert tls.Certificate) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.cert = cert
}

func (id *Identity) caPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(id.CA)
	return p
}

// MemberClientTLS is the config a witness uses to dial a peer: it presents the
// member certificate and verifies the peer's leaf against the cluster CA plus the
// fixed SAN. Standard hostname verification is disabled because the SAN is a fixed
// label, not the dialed address.
func (id *Identity) MemberClientTLS() *tls.Config {
	pool := id.caPool()
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert := id.Certificate()
			return &cert, nil
		},
		InsecureSkipVerify:    true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: verifyAgainstCA(pool, true),
		NextProtos:            []string{"h2"},
		MinVersion:            tls.VersionTLS12,
		ServerName:            FixedServerSAN,
	}
}

// ServerTLS is the config a witness serves with. It presents the member cert and
// verifies a client certificate when one is offered (VerifyClientCertIfGiven ==
// gr8s's :tls-verify-client :optional), so EnrollMember can be reached certless
// while every Raft call is authenticated. Peer identity is read from the CN by
// the handler via PeerMemberID.
func (id *Identity) ServerTLS() *tls.Config {
	pool := id.caPool()
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := id.Certificate()
			return &cert, nil
		},
		ClientAuth:            tls.VerifyClientCertIfGiven,
		ClientCAs:             pool,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyClientIfPresent(pool),
		NextProtos:            []string{"h2"},
		MinVersion:            tls.VersionTLS12,
	}
}

// verifyAgainstCA builds a VerifyPeerCertificate that chains the leaf to pool and,
// when requireSAN, checks the fixed SAN. Used for the peers we dial.
func verifyAgainstCA(pool *x509.CertPool, requireSAN bool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		leaf, err := chainToPool(rawCerts, pool)
		if err != nil {
			return err
		}
		if requireSAN && !hasSAN(leaf, FixedServerSAN) {
			return fmt.Errorf("transport: peer certificate lacks SAN %q", FixedServerSAN)
		}
		return nil
	}
}

// verifyClientIfPresent verifies a client certificate against pool only when one
// was presented, so certless enrollment connections are still allowed through.
func verifyClientIfPresent(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil // enrollment: no client certificate yet
		}
		_, err := chainToPool(rawCerts, pool)
		return err
	}
}

func chainToPool(rawCerts [][]byte, pool *x509.CertPool) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("transport: no peer certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, err
	}
	inter := x509.NewCertPool()
	for _, der := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("transport: peer certificate not trusted: %w", err)
	}
	return leaf, nil
}

func hasSAN(cert *x509.Certificate, name string) bool {
	for _, n := range cert.DNSNames {
		if n == name {
			return true
		}
	}
	return false
}

// pinVerifier verifies, during certless enrollment, that the server's presented
// chain roots in a CA whose SHA-256 (hex) matches the pinned fingerprint
// (session.lisp: verify-enrollment-ca-pin uses certificate-fingerprint = SHA-256).
func pinVerifier(caPinHex string) func([][]byte, [][]*x509.Certificate) error {
	want := strings.ToLower(strings.TrimSpace(caPinHex))
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var ca *x509.Certificate
		pool := x509.NewCertPool()
		for _, der := range rawCerts {
			if hex.EncodeToString(sha256Sum(der)) == want {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return err
				}
				ca = c
				pool.AddCert(c)
			}
		}
		if ca == nil {
			return fmt.Errorf("transport: server CA fingerprint does not match pin %s", want)
		}
		if _, err := chainToPool(rawCerts, pool); err != nil {
			return err
		}
		return nil
	}
}

// enrollClientTLS dials the enrollment endpoint with no client certificate, trust
// established solely by the pinned CA fingerprint.
func enrollClientTLS(caPinHex string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinVerifier(caPinHex),
		NextProtos:            []string{"h2"},
		MinVersion:            tls.VersionTLS12,
		ServerName:            FixedServerSAN,
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// CAFingerprint returns the SHA-256 hex of a CA certificate's DER, the pin format
// gr8s uses (octets-to-hex of certificate-fingerprint).
func CAFingerprint(ca *x509.Certificate) string {
	return hex.EncodeToString(sha256Sum(ca.Raw))
}
