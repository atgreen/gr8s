// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

// Package kms is gr8s-kms, a KMS v2 plugin for machines without an external KMS
// (podster-af7o). It keeps a ring of key-encryption keys, sealed at rest with
// systemd-creds (to the TPM when there is one), and wraps gr8s's Secret data keys with
// the active one. A recovery export, under a passphrase, outlives the machine.
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Keyring is the plugin's key-encryption keys, by id, and which one wraps new keys.
// Old keys stay, so what they wrapped can still be unwrapped.
type Keyring struct {
	Active string            `json:"active"`
	Keys   map[string][]byte `json:"keys"`

	mutex sync.RWMutex
}

// NewKeyring is a ring of one fresh key.
func NewKeyring() (*Keyring, error) {
	ring := &Keyring{Keys: map[string][]byte{}}
	if _, err := ring.Rotate(); err != nil {
		return nil, err
	}
	return ring, nil
}

// KeyID names a key by its digest, so the id changes exactly when the key does.
func KeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return "gr8s-kms-" + hex.EncodeToString(sum[:])[:16]
}

// Rotate adds a fresh key and makes it the one that wraps; it returns its id.
func (ring *Keyring) Rotate() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	id := KeyID(key)
	ring.mutex.Lock()
	defer ring.mutex.Unlock()
	if ring.Keys == nil {
		ring.Keys = map[string][]byte{}
	}
	ring.Keys[id], ring.Active = key, id
	return id, nil
}

// ActiveID is the id of the key that wraps.
func (ring *Keyring) ActiveID() string {
	ring.mutex.RLock()
	defer ring.mutex.RUnlock()
	return ring.Active
}

func sealer(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt wraps plaintext with the active key, returning the ciphertext (nonce first)
// and the key's id, which is also its associated data.
func (ring *Keyring) Encrypt(plaintext []byte) ([]byte, string, error) {
	ring.mutex.RLock()
	id, key := ring.Active, ring.Keys[ring.Active]
	ring.mutex.RUnlock()
	if key == nil {
		return nil, "", errors.New("the keyring has no active key")
	}
	aead, err := sealer(key)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(id)), id, nil
}

// Decrypt unwraps ciphertext with the key id names.
func (ring *Keyring) Decrypt(ciphertext []byte, id string) ([]byte, error) {
	ring.mutex.RLock()
	key := ring.Keys[id]
	ring.mutex.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("no key %q in the keyring", id)
	}
	aead, err := sealer(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, sealed, []byte(id))
}

// valid says whether the ring is one gr8s-kms can serve from.
func (ring *Keyring) valid() error {
	if ring.Keys[ring.Active] == nil {
		return errors.New("the keyring's active key is missing")
	}
	for id, key := range ring.Keys {
		if len(key) != 32 || KeyID(key) != id {
			return fmt.Errorf("the keyring's key %q is damaged", id)
		}
	}
	return nil
}
