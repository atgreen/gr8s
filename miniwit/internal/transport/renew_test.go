// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func pemChain(ders ...[]byte) []byte {
	var out bytes.Buffer
	for _, der := range ders {
		pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return out.Bytes()
}

// enrolled writes what Enroll leaves in dir for memberID -- key, certificate
// expiring in validFor, and CA -- and loads it back as the witness would at start.
func (ca *testCA) enrolled(t *testing.T, memberID, dir string, validFor time.Duration) *Identity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := pathsIn(dir)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	leaf := ca.sign(t, memberID, &key.PublicKey, validFor)
	for path, data := range map[string][]byte{p.key: keyPEM, p.cert: pemChain(leaf, ca.cert.Raw), p.ca: pemChain(ca.cert.Raw)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// sign issues a member certificate as a gr8s voter does: the member id in the
// Common Name, the fixed SAN, signed by the cluster CA.
func (ca *testCA) sign(t *testing.T, memberID string, pub *rsa.PublicKey, validFor time.Duration) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: memberID},
		DNSNames:     []string{FixedServerSAN},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// renewingPeer is a cluster member answering RenewMember. answer turns the
// caller's signing request into the PEM chain to send back; nil refuses, as a
// witness does.
type renewingPeer struct {
	nodev1.UnimplementedRaftTransportServer
	answer func(csr *x509.CertificateRequest) []byte
	asked  int
}

func (p *renewingPeer) RenewMember(_ context.Context, req *nodev1.RenewMemberRequest) (*nodev1.RenewMemberResponse, error) {
	p.asked++
	if p.answer == nil {
		return nil, status.Error(codes.PermissionDenied, "a witness cannot renew members")
	}
	csr, err := x509.ParseCertificateRequest(req.GetCertificateRequest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &nodev1.RenewMemberResponse{Certificate: string(p.answer(csr))}, nil
}

func (p *renewingPeer) serve(t *testing.T, id *Identity) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(id.ServerTLS())))
	nodev1.RegisterRaftTransportServer(srv, p)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// voter answers as a healthy gr8s voter: a year's certificate for whoever asked.
func (ca *testCA) voter(t *testing.T) *renewingPeer {
	return &renewingPeer{answer: func(csr *x509.CertificateRequest) []byte {
		return pemChain(ca.sign(t, csr.Subject.CommonName, csr.PublicKey.(*rsa.PublicKey), 365*24*time.Hour), ca.cert.Raw)
	}}
}

func TestRenewReplacesTheCertificateOnDiskAndOnTheWire(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	id := ca.enrolled(t, "wit", dir, 10*24*time.Hour)
	before, _ := id.NotAfter()
	witness := (&renewingPeer{}).serve(t, id) // refuses, like any witness
	voter := ca.voter(t)
	voterAddr := voter.serve(t, ca.identity(t, "cp1"))

	if err := Renew(context.Background(), id, "wit", dir, []string{witness, voterAddr}); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	after, err := id.NotAfter()
	if err != nil || !after.After(before.Add(300*24*time.Hour)) {
		t.Fatalf("certificate presented still expires %v (was %v), err %v", after, before, err)
	}
	// What a restart would load is the renewed certificate, under the same key.
	reloaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("the renewed certificate does not load with the existing key: %v", err)
	}
	if onDisk, _ := reloaded.NotAfter(); !onDisk.Equal(after) {
		t.Fatalf("on disk expires %v, presented expires %v", onDisk, after)
	}
	// And the next handshake presents it: a peer sees the new expiry.
	seen := make(chan time.Time, 1)
	cfg := ca.identity(t, "cp2").ServerTLS()
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		leaf, err := x509.ParseCertificate(raw[0])
		if err == nil {
			seen <- leaf.NotAfter
		}
		return err
	}
	cfg.ClientAuth = tls.RequireAnyClientCert
	lis, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		if conn, err := lis.Accept(); err == nil {
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	conn, err := tls.Dial("tcp", lis.Addr().String(), id.MemberClientTLS())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	select {
	case presented := <-seen:
		if !presented.Equal(after) {
			t.Fatalf("handshake presented a certificate expiring %v, want %v", presented, after)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no client certificate was presented")
	}
}

func TestRenewRejectsACertificateThatIsNotOurs(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	year := 365 * 24 * time.Hour
	for name, answer := range map[string]func(csr *x509.CertificateRequest) []byte{
		"for another member": func(csr *x509.CertificateRequest) []byte {
			return pemChain(ca.sign(t, "someone-else", csr.PublicKey.(*rsa.PublicKey), year), ca.cert.Raw)
		},
		"for another key": func(csr *x509.CertificateRequest) []byte {
			return pemChain(ca.sign(t, csr.Subject.CommonName, &stranger.PublicKey, year), ca.cert.Raw)
		},
		"from another CA": func(csr *x509.CertificateRequest) []byte {
			return pemChain(other.sign(t, csr.Subject.CommonName, csr.PublicKey.(*rsa.PublicKey), year), other.cert.Raw)
		},
		"no newer than the one we hold": func(csr *x509.CertificateRequest) []byte {
			return pemChain(ca.sign(t, csr.Subject.CommonName, csr.PublicKey.(*rsa.PublicKey), 24*time.Hour), ca.cert.Raw)
		},
		"not a certificate": func(*x509.CertificateRequest) []byte { return []byte("garbage") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			id := ca.enrolled(t, "wit", dir, 10*24*time.Hour)
			held, _ := os.ReadFile(pathsIn(dir).cert)
			before, _ := id.NotAfter()
			addr := (&renewingPeer{answer: answer}).serve(t, ca.identity(t, "cp1"))

			err := Renew(context.Background(), id, "wit", dir, []string{addr})
			if err == nil {
				t.Fatal("Renew accepted it")
			}
			if now, _ := os.ReadFile(pathsIn(dir).cert); !bytes.Equal(now, held) {
				t.Fatal("the certificate on disk changed")
			}
			if after, _ := id.NotAfter(); !after.Equal(before) {
				t.Fatal("the certificate presented changed")
			}
			if entries, _ := filepath.Glob(filepath.Join(dir, "member.crt.*")); len(entries) != 0 {
				t.Fatalf("temporary files left behind: %v", entries)
			}
		})
	}
}

func TestRenewSaysWhyWhenNoPeerCanHelp(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	id := ca.enrolled(t, "wit", dir, 10*24*time.Hour)
	if err := Renew(context.Background(), id, "wit", dir, nil); err == nil || !strings.Contains(err.Error(), "knows no peers") {
		t.Fatalf("with no peers: %v", err)
	}
	witness := &renewingPeer{}
	addr := witness.serve(t, ca.identity(t, "wit2"))
	err := Renew(context.Background(), id, "wit", dir, []string{addr})
	if err == nil || !strings.Contains(err.Error(), "a witness cannot renew members") || !strings.Contains(err.Error(), addr) {
		t.Fatalf("with only a witness to ask: %v", err)
	}
	if witness.asked != 1 {
		t.Fatalf("the peer was asked %d times", witness.asked)
	}
}

func TestACertificateIsDueThirtyDaysBeforeItExpires(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	for validFor, due := range map[time.Duration]bool{
		365 * 24 * time.Hour: false,
		31 * 24 * time.Hour:  false,
		29 * 24 * time.Hour:  true,
		-time.Hour:           true, // already expired: still worth trying
	} {
		id := ca.enrolled(t, "wit", t.TempDir(), validFor)
		if got := id.Expiring(now, RenewBefore); got != due {
			t.Errorf("a certificate with %v left: due=%v, want %v", validFor, got, due)
		}
	}
	if !NewIdentity(tls.Certificate{}, ca.cert).Expiring(now, RenewBefore) {
		t.Error("an unreadable certificate should count as due")
	}
}

func TestTheRenewalLoopRenewsADueCertificateAndThenLeavesItAlone(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	id := ca.enrolled(t, "wit", dir, 10*24*time.Hour)
	voter := ca.voter(t)
	addr := voter.serve(t, ca.identity(t, "cp1"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RenewalLoop(ctx, id, "wit", dir, func() []string { return []string{addr} }, RenewBefore, 20*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for id.Expiring(time.Now(), RenewBefore) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond) // several more checks
	cancel()
	<-done
	if id.Expiring(time.Now(), RenewBefore) {
		t.Fatal("the loop did not renew a certificate ten days from expiry")
	}
	if voter.asked != 1 {
		t.Fatalf("a current certificate was renewed again: the voter was asked %d times", voter.asked)
	}
}
