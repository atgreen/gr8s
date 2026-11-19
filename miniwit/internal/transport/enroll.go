// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	nodev1 "github.com/atgreen/gr8s/miniwit/proto/gr8s/node/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// credsPaths names the on-disk files, mirroring gr8s's raft credential layout.
type credsPaths struct{ key, cert, ca string }

func pathsIn(dir string) credsPaths {
	return credsPaths{
		key:  filepath.Join(dir, "member.key"),
		cert: filepath.Join(dir, "member.crt"),
		ca:   filepath.Join(dir, "ca.crt"),
	}
}

// Enroll exchanges a one-time join token for a witness member certificate and
// stores the credentials under dir, then returns the loaded Identity. It mirrors
// enroll-raft-member: generate an RSA key + CSR (CN == memberID), dial with the
// CA pinned by fingerprint, call EnrollMember(role="witness"), verify the
// returned CA against the same pin, and persist. If a certificate is already
// present it is simply loaded (re-enrollment is idempotent).
func Enroll(ctx context.Context, joinAddr, memberID, nodeName, token, caPinHex, dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := pathsIn(dir)
	if fileExists(p.cert) && fileExists(p.ca) && fileExists(p.key) {
		return LoadIdentity(dir)
	}
	key, err := loadOrCreateKey(p.key)
	if err != nil {
		return nil, err
	}
	csrDER, err := makeCSR(memberID, key)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(joinAddr, grpc.WithTransportCredentials(credentials.NewTLS(enrollClientTLS(caPinHex))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := nodev1.NewRaftTransportClient(conn).EnrollMember(cctx, &nodev1.EnrollMemberRequest{
		MemberId:           memberID,
		NodeName:           orElse(nodeName, memberID),
		JoinToken:          token,
		Role:               "witness",
		CertificateRequest: csrDER,
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: EnrollMember failed: %w", err)
	}

	caPEM := []byte(resp.GetCaCertificate())
	if err := verifyCAPin(caPEM, caPinHex); err != nil {
		return nil, err
	}
	if err := writePrivate(p.ca, caPEM); err != nil {
		return nil, err
	}
	// Written last: its presence means enrollment completed.
	if err := writePrivate(p.cert, []byte(resp.GetCertificate())); err != nil {
		return nil, err
	}
	return LoadIdentity(dir)
}

// LoadIdentity loads an already-enrolled Identity from dir.
func LoadIdentity(dir string) (*Identity, error) {
	p := pathsIn(dir)
	cert, err := tls.LoadX509KeyPair(p.cert, p.key)
	if err != nil {
		return nil, fmt.Errorf("load member cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(p.ca)
	if err != nil {
		return nil, err
	}
	ca, err := parseFirstCert(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA: %w", err)
	}
	return NewIdentity(cert, ca), nil
}

func makeCSR(memberID string, key *rsa.PrivateKey) ([]byte, error) {
	// gr8s requires a three-part DER PKCS#10, RSA-SHA256, with CN == member id
	// (parse-and-verify-node-csr). No SAN is required on the CSR.
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: memberID},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(data)
		if blk == nil {
			return nil, fmt.Errorf("key file %s is not PEM", path)
		}
		if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key file %s is not RSA", path)
		}
		return rk, nil
	}
	// gr8s uses RSA-2048 with e=65537.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writePrivate(path, pemBytes); err != nil {
		return nil, err
	}
	return key, nil
}

func verifyCAPin(caPEM []byte, caPinHex string) error {
	ca, err := parseFirstCert(caPEM)
	if err != nil {
		return fmt.Errorf("verify CA pin: %w", err)
	}
	if got := CAFingerprint(ca); !strings.EqualFold(got, caPinHex) {
		return fmt.Errorf("verify CA pin: enrollment CA fingerprint %s does not match pin %s", got, caPinHex)
	}
	return nil
}

func parseFirstCert(pemBytes []byte) (*x509.Certificate, error) {
	for {
		blk, rest := pem.Decode(pemBytes)
		if blk == nil {
			return nil, fmt.Errorf("no CERTIFICATE block found")
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
		pemBytes = rest
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func writePrivate(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func orElse(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
