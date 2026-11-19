// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// A member certificate lasts a year. gr8s members renew theirs once it is within
// thirty days of expiry and look hourly (src/security/raft-tls.lisp:
// +raft-certificate-renewal-seconds+, +raft-renewal-check-seconds+); a witness
// does the same, or it drops out of quorum on the day its certificate runs out.
const (
	RenewBefore     = 30 * 24 * time.Hour
	RenewCheckEvery = time.Hour
)

// NotAfter reports when the member certificate currently presented expires.
func (id *Identity) NotAfter() (time.Time, error) {
	leaf, err := leafOf(id.Certificate())
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// Expiring reports whether the member certificate expires within before of now.
// A certificate that cannot be read counts as expiring: renewing is how it is fixed.
func (id *Identity) Expiring(now time.Time, before time.Duration) bool {
	notAfter, err := id.NotAfter()
	return err != nil || notAfter.Sub(now) < before
}

// Renew replaces the member certificate in dir, keeping its key, with one issued
// by the first of peers able to issue it, and has id present the new certificate
// from then on. A witness holds no CA, so it cannot renew itself as a voter can
// (raft-tls.lisp: request-raft-certificate-from-peers). Another witness refuses
// the request and the next peer is tried. Nothing on disk changes unless a peer
// returns a certificate that is ours, for our key, from our CA, and newer.
func Renew(ctx context.Context, id *Identity, memberID, dir string, peers []string) error {
	p := pathsIn(dir)
	if !fileExists(p.key) {
		return fmt.Errorf("renew: no member key at %s", p.key)
	}
	key, err := loadOrCreateKey(p.key)
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	csr, err := makeCSR(memberID, key)
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	if len(peers) == 0 {
		return errors.New("renew: this member knows no peers")
	}
	var failures []error
	for _, addr := range peers {
		chain, err := requestRenewal(ctx, id, addr, csr)
		if err == nil {
			err = installRenewed(id, p, memberID, key, chain)
		}
		if err == nil {
			return nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", addr, err))
	}
	return fmt.Errorf("renew: no peer could renew this certificate: %w", errors.Join(failures...))
}

func requestRenewal(ctx context.Context, id *Identity, addr string, csr []byte) ([]byte, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(id.MemberClientTLS())))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := nodev1.NewRaftTransportClient(conn).RenewMember(cctx, &nodev1.RenewMemberRequest{CertificateRequest: csr})
	if err != nil {
		return nil, err
	}
	return []byte(resp.GetCertificate()), nil
}

// installRenewed checks chain, a PEM member certificate followed by its CA, and
// only then writes it over the old certificate and presents it.
func installRenewed(id *Identity, p credsPaths, memberID string, key *rsa.PrivateKey, chain []byte) error {
	leaf, err := parseFirstCert(chain)
	if err != nil {
		return fmt.Errorf("renewed certificate: %w", err)
	}
	if leaf.Subject.CommonName != memberID {
		return fmt.Errorf("renewed certificate is for %q, not %q", leaf.Subject.CommonName, memberID)
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("renewed certificate is not for this member's key")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     id.caPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("renewed certificate is not from this cluster's CA: %w", err)
	}
	if current, err := id.NotAfter(); err == nil && !leaf.NotAfter.After(current) {
		return fmt.Errorf("renewed certificate expires %s, no later than the current one",
			leaf.NotAfter.Format(time.RFC3339))
	}
	keyPEM, err := os.ReadFile(p.key)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("renewed certificate: %w", err)
	}
	if err := writePrivateAtomically(p.cert, chain); err != nil {
		return err
	}
	id.setCertificate(cert)
	return nil
}

// writePrivateAtomically replaces path with data, so a crash never leaves half a
// certificate where the witness will look for a whole one at its next start.
func writePrivateAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
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
	return os.Rename(tmp.Name(), path)
}

// RenewalLoop checks the member certificate now and then every interval until ctx
// is done, renewing it once it is within before of expiry. peers is asked each
// time, because the witness learns its peers after it joins. A failure is logged
// with the days left and tried again at the next check.
func RenewalLoop(ctx context.Context, id *Identity, memberID, dir string, peers func() []string, before, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		renewIfDue(ctx, id, memberID, dir, peers(), before)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func renewIfDue(ctx context.Context, id *Identity, memberID, dir string, peers []string, before time.Duration) {
	if !id.Expiring(time.Now(), before) {
		return
	}
	if err := Renew(ctx, id, memberID, dir, peers); err != nil {
		left := "an unknown time"
		if notAfter, nerr := id.NotAfter(); nerr == nil {
			left = fmt.Sprintf("%d days", int(time.Until(notAfter).Hours()/24))
		}
		log.Printf("member certificate expires in %s and could not be renewed: %v", left, err)
		return
	}
	if notAfter, err := id.NotAfter(); err == nil {
		log.Printf("renewed the member certificate; it is now valid until %s", notAfter.Format(time.RFC3339))
	}
}

func leafOf(cert tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no member certificate loaded")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}
