// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CredentialName is the name the keyring is sealed under; systemd-creds unseals a blob
// only under the name it was sealed with.
const CredentialName = "gr8s-kms"

// Sealer seals the keyring for storage and unseals it.
type Sealer interface {
	Seal(plain []byte) ([]byte, error)
	Unseal(sealed []byte) ([]byte, error)
	Describe() string
}

// SystemdCreds seals with systemd-creds: to the TPM and the host key when the machine
// has a TPM, to the host key (/var/lib/systemd/credential.secret) otherwise. PCRs
// binds it to measured boot state too, which a firmware or Secure Boot change then
// breaks, so it is empty by default; the recovery export is the way back either way.
type SystemdCreds struct {
	PCRs string
}

func (creds SystemdCreds) run(input []byte, arguments ...string) ([]byte, error) {
	command := exec.Command("systemd-creds", arguments...)
	var output, errors bytes.Buffer
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(input), &output, &errors
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("systemd-creds %s: %v: %s", arguments[0], err, strings.TrimSpace(errors.String()))
	}
	return output.Bytes(), nil
}

func (creds SystemdCreds) Seal(plain []byte) ([]byte, error) {
	arguments := []string{"encrypt", "--name=" + CredentialName, "--with-key=auto"}
	if creds.PCRs != "" {
		arguments = append(arguments, "--tpm2-pcrs="+creds.PCRs)
	}
	return creds.run(plain, append(arguments, "-", "-")...)
}

func (creds SystemdCreds) Unseal(sealed []byte) ([]byte, error) {
	return creds.run(sealed, "decrypt", "--name="+CredentialName, "-", "-")
}

func (creds SystemdCreds) Describe() string {
	if exec.Command("systemd-analyze", "has-tpm2", "--quiet").Run() == nil {
		return "systemd-creds, sealed to this machine's TPM"
	}
	return "systemd-creds, sealed to this machine's host key (no TPM)"
}

// Plain stores the keyring as it is, readable by root alone: for machines without
// systemd-creds, and only when asked for.
type Plain struct{}

func (Plain) Seal(plain []byte) ([]byte, error)    { return plain, nil }
func (Plain) Unseal(sealed []byte) ([]byte, error) { return sealed, nil }
func (Plain) Describe() string                     { return "unsealed, root-only (--unsealed)" }

// ErrNoKeyring is Load's error when there is no keyring yet.
var ErrNoKeyring = errors.New("no keyring")

// Load reads and unseals the keyring at path.
func Load(path string, sealer Sealer) (*Keyring, error) {
	sealed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKeyring
	}
	if err != nil {
		return nil, err
	}
	plain, err := sealer.Unseal(sealed)
	if err != nil {
		return nil, fmt.Errorf("unsealing %s: %w (a recovery export restores it: gr8s-kms import-recovery)", path, err)
	}
	var ring Keyring
	if err := json.Unmarshal(plain, &ring); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := ring.valid(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &ring, nil
}

// Save seals the keyring and replaces the file at path with it, readable by root alone.
func Save(path string, ring *Keyring, sealer Sealer) error {
	ring.mutex.RLock()
	plain, err := json.Marshal(ring)
	ring.mutex.RUnlock()
	if err != nil {
		return err
	}
	sealed, err := sealer.Seal(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
