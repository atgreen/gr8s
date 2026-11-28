// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/scrypt"
)

// recoveryFile is a keyring under a passphrase: what restores gr8s's Secrets when the
// machine its keyring was sealed to is gone.
type recoveryFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

const recoveryN, recoveryR, recoveryP = 1 << 17, 8, 1

// ExportRecovery seals ring under passphrase, with scrypt and AES-GCM.
func ExportRecovery(ring *Keyring, passphrase []byte) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("the passphrase must be at least 12 characters")
	}
	ring.mutex.RLock()
	plain, err := json.Marshal(ring)
	ring.mutex.RUnlock()
	if err != nil {
		return nil, err
	}
	file := recoveryFile{Version: 1, KDF: "scrypt", N: recoveryN, R: recoveryR, P: recoveryP,
		Salt: make([]byte, 16)}
	if _, err := rand.Read(file.Salt); err != nil {
		return nil, err
	}
	aead, err := recoveryAEAD(file, passphrase)
	if err != nil {
		return nil, err
	}
	file.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(file.Nonce); err != nil {
		return nil, err
	}
	file.Ciphertext = aead.Seal(nil, file.Nonce, plain, []byte("gr8s-kms recovery v1"))
	return json.MarshalIndent(file, "", "  ")
}

// ImportRecovery opens a recovery export with passphrase.
func ImportRecovery(data, passphrase []byte) (*Keyring, error) {
	var file recoveryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version != 1 || file.KDF != "scrypt" {
		return nil, errors.New("not a gr8s-kms recovery export")
	}
	aead, err := recoveryAEAD(file, passphrase)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, file.Nonce, file.Ciphertext, []byte("gr8s-kms recovery v1"))
	if err != nil {
		return nil, errors.New("wrong passphrase, or a damaged export")
	}
	var ring Keyring
	if err := json.Unmarshal(plain, &ring); err != nil {
		return nil, err
	}
	if err := ring.valid(); err != nil {
		return nil, err
	}
	return &ring, nil
}

func recoveryAEAD(file recoveryFile, passphrase []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key(passphrase, file.Salt, file.N, file.R, file.P, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
