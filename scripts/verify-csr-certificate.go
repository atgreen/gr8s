// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: MIT
//
// Purpose:
// Verify an issued CSR leaf and its policy using the independent Go X.509/TLS
// implementation. Optional client/server handshake checks prove that the signed
// API profile remains usable for ordinary TLS with the actual cluster CA.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

// fail reports an actual external verification failure and exits unsuccessfully.
func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// main validates a real PEM leaf, policy and optional ordinary TLS handshake.
func main() {
	certificatePath := flag.String("certificate", "", "issued certificate PEM")
	caPath := flag.String("ca", "", "real cluster CA PEM")
	keyPath := flag.String("key", "", "optional matching key for TLS proof")
	purpose := flag.String("purpose", "client", "client or server certificate purpose")
	dnsName := flag.String("dns-name", "", "expected server DNS SAN")
	serverCertificate := flag.String("server-certificate", "", "server certificate for mutual client TLS proof")
	serverKey := flag.String("server-key", "", "server key for mutual client TLS proof")
	flag.Parse()
	data, err := os.ReadFile(*certificatePath)
	fail(err)
	var certificates []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			fail(fmt.Errorf("unexpected PEM label %s", block.Type))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		fail(err)
		certificates = append(certificates, cert)
	}
	if len(certificates) != 1 {
		fail(fmt.Errorf("expected a single issued leaf, got %d", len(certificates)))
	}
	leaf := certificates[0]
	rootPEM, err := os.ReadFile(*caPath)
	fail(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		fail(fmt.Errorf("cluster CA is empty"))
	}
	usage := x509.ExtKeyUsageClientAuth
	if *purpose == "server" {
		usage = x509.ExtKeyUsageServerAuth
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}, DNSName: func() string {
		if *purpose == "server" {
			return *dnsName
		}
		return ""
	}()})
	fail(err)
	const profile = "2.25.239647859381961005463536084722150751259"
	found := false
	for _, policy := range leaf.Policies {
		if policy.String() == profile {
			found = true
		}
	}
	if !found {
		fail(fmt.Errorf("issuer-controlled API policy is missing"))
	}
	result := map[string]any{"verified": true, "singleLeaf": true, "profilePolicy": profile, "purpose": *purpose}
	if *keyPath != "" {
		pair, err := tls.LoadX509KeyPair(*certificatePath, *keyPath)
		fail(err)
		serverPair := pair
		serverConfig := &tls.Config{Certificates: []tls.Certificate{serverPair}, MinVersion: tls.VersionTLS12}
		clientConfig := &tls.Config{RootCAs: roots, ServerName: *dnsName, MinVersion: tls.VersionTLS12}
		if *purpose == "client" {
			serverPair, err = tls.LoadX509KeyPair(*serverCertificate, *serverKey)
			fail(err)
			serverConfig.Certificates = []tls.Certificate{serverPair}
			serverConfig.ClientCAs = roots
			serverConfig.ClientAuth = tls.RequireAndVerifyClientCert
			clientConfig.Certificates = []tls.Certificate{pair}
		}
		listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
		fail(err)
		defer listener.Close()
		done := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			var one [1]byte
			_, err = conn.Read(one[:])
			done <- err
		}()
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), clientConfig)
		fail(err)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte{1})
		fail(err)
		conn.Close()
		fail(<-done)
		result["ordinaryTLSHandshakeVerified"] = true
	}
	fail(json.NewEncoder(os.Stdout).Encode(result))
}
