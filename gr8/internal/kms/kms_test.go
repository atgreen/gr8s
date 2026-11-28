// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	kmsapi "k8s.io/kms/apis/v2"
	"k8s.io/kms/pkg/service"
)

func TestTheKeyringWrapsWithItsActiveKeyAndUnwrapsWithAnyOfIts(t *testing.T) {
	ring, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	first := ring.ActiveID()
	wrapped, id, err := ring.Encrypt([]byte("data key one"))
	if err != nil || id != first {
		t.Fatalf("Encrypt: %v, id %q", err, id)
	}
	second, err := ring.Rotate()
	if err != nil || second == first {
		t.Fatalf("Rotate: %v, %q", err, second)
	}
	if plain, err := ring.Decrypt(wrapped, first); err != nil || string(plain) != "data key one" {
		t.Errorf("unwrapping under the old key after a rotation: %q, %v", plain, err)
	}
	if _, id, _ := ring.Encrypt([]byte("x")); id != second {
		t.Errorf("a rotated ring still wraps with %q", id)
	}
	// The key id is bound to the ciphertext, and a changed byte fails.
	if _, err := ring.Decrypt(wrapped, second); err == nil {
		t.Error("unwrapped under the wrong key")
	}
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 1
	if _, err := ring.Decrypt(tampered, first); err == nil {
		t.Error("unwrapped a changed ciphertext")
	}
}

// xorSealer stands in for systemd-creds in tests.
type xorSealer struct{}

func (xorSealer) Seal(plain []byte) ([]byte, error) {
	out := bytes.Clone(plain)
	for i := range out {
		out[i] ^= 0x5a
	}
	return out, nil
}
func (sealer xorSealer) Unseal(sealed []byte) ([]byte, error) { return sealer.Seal(sealed) }
func (xorSealer) Describe() string                            { return "test" }

func TestTheKeyringIsStoredSealedAndRestoredFromARecoveryExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kms", "keyring.cred")
	if _, err := Load(path, xorSealer{}); err != ErrNoKeyring {
		t.Fatalf("Load of nothing = %v", err)
	}
	ring, _ := NewKeyring()
	if err := Save(path, ring, xorSealer{}); err != nil {
		t.Fatal(err)
	}
	stored, _ := os.ReadFile(path)
	if bytes.Contains(stored, []byte(ring.ActiveID())) {
		t.Error("the keyring was stored unsealed")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	loaded, err := Load(path, xorSealer{})
	if err != nil || loaded.ActiveID() != ring.ActiveID() {
		t.Fatalf("Load = %v, %v", loaded, err)
	}
	wrapped, id, _ := ring.Encrypt([]byte("secret data key"))
	// The machine is gone: only the export and its passphrase remain.
	export, err := ExportRecovery(ring, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportRecovery(export, []byte("wrong passphrase here")); err == nil {
		t.Error("imported with the wrong passphrase")
	}
	restored, err := ImportRecovery(export, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := restored.Decrypt(wrapped, id); err != nil || string(plain) != "secret data key" {
		t.Errorf("the restored keyring unwrapped %q, %v", plain, err)
	}
	if _, err := ExportRecovery(ring, []byte("short")); err == nil {
		t.Error("exported under a short passphrase")
	}
	// A damaged file says so rather than serving a broken ring.
	_ = os.WriteFile(path, []byte("garbage"), 0o600)
	if _, err := Load(path, xorSealer{}); err == nil {
		t.Error("loaded a damaged keyring")
	}
}

// The plugin, on k8s.io/kms's own server, answered by k8s.io/kms's own client, as
// kube-apiserver would talk to it.
func TestThePluginSpeaksKMSv2(t *testing.T) {
	ring, _ := NewKeyring()
	plugin := NewService(ring)
	socket := filepath.Join(t.TempDir(), "kms.sock")
	server := service.NewGRPCService(socket, 5*time.Second, plugin)
	go func() { _ = server.ListenAndServe() }()
	defer server.Shutdown()
	var connection *grpc.ClientConn
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	connection, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := kmsapi.NewKeyManagementServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := client.Status(ctx, &kmsapi.StatusRequest{})
	if err != nil || status.Version != "v2" || status.Healthz != "ok" || status.KeyId != ring.ActiveID() {
		t.Fatalf("Status = %+v, %v", status, err)
	}
	encrypted, err := client.Encrypt(ctx, &kmsapi.EncryptRequest{Plaintext: []byte("a data key"), Uid: "1"})
	if err != nil || encrypted.KeyId != ring.ActiveID() {
		t.Fatalf("Encrypt = %+v, %v", encrypted, err)
	}
	// After a rotation, Status reports the new key and the old one still unwraps.
	next, _ := NewKeyring()
	next.Keys[ring.ActiveID()] = ring.Keys[ring.ActiveID()]
	plugin.Reload(next)
	if status, _ := client.Status(ctx, &kmsapi.StatusRequest{}); status.KeyId != next.ActiveID() {
		t.Errorf("after a rotation Status reports %q", status.KeyId)
	}
	decrypted, err := client.Decrypt(ctx, &kmsapi.DecryptRequest{Ciphertext: encrypted.Ciphertext, KeyId: encrypted.KeyId, Uid: "2"})
	if err != nil || string(decrypted.Plaintext) != "a data key" {
		t.Fatalf("Decrypt = %+v, %v", decrypted, err)
	}
}
