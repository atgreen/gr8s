// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

// gr8s-kms is a KMS v2 plugin for a gr8s machine without an external KMS
// (podster-af7o): it wraps gr8s's Secret data keys with a key sealed by systemd-creds,
// to the TPM when there is one.
//
//	gr8s-kms serve             serve the plugin on its socket
//	gr8s-kms rotate            add a new key that wraps from now on
//	gr8s-kms status            say which key is active and how the keyring is sealed
//	gr8s-kms export-recovery   write the keyring under a passphrase
//	gr8s-kms import-recovery   restore the keyring from such an export
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"
	"k8s.io/kms/pkg/service"

	"github.com/atgreen/gr8s/gr8/internal/kms"
)

const (
	defaultSocket  = "/run/gr8s/kms.sock"
	defaultKeyring = "/var/lib/gr8s/kms/keyring.cred"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet("gr8s-kms "+command, flag.ExitOnError)
	keyringPath := flags.String("keyring", defaultKeyring, "the sealed keyring")
	socket := flags.String("socket", defaultSocket, "serve: the plugin's Unix socket")
	pcrs := flags.String("tpm2-pcrs", "", "also bind the seal to these TPM PCRs (a firmware or Secure Boot change then breaks it)")
	unsealed := flags.Bool("unsealed", false, "store the keyring unsealed, root-only, where systemd-creds is missing")
	file := flags.String("file", "", "export-recovery / import-recovery: the recovery file")
	passphraseFile := flags.String("passphrase-file", "", "export-recovery / import-recovery: read the passphrase from this file, not the terminal")
	_ = flags.Parse(os.Args[2:])
	var sealer kms.Sealer = kms.SystemdCreds{PCRs: *pcrs}
	if *unsealed {
		sealer = kms.Plain{}
	}
	var err error
	switch command {
	case "serve":
		err = serve(*socket, *keyringPath, sealer)
	case "rotate":
		err = rotate(*keyringPath, sealer)
	case "status":
		err = status(*keyringPath, sealer)
	case "export-recovery":
		err = exportRecovery(*keyringPath, sealer, *file, *passphraseFile)
	case "import-recovery":
		err = importRecovery(*keyringPath, sealer, *file, *passphraseFile)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gr8s-kms %s: %v\n", command, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gr8s-kms serve|rotate|status|export-recovery|import-recovery [flags]")
}

// loadOrCreate reads the keyring, making one on first start.
func loadOrCreate(path string, sealer kms.Sealer) (*kms.Keyring, error) {
	ring, err := kms.Load(path, sealer)
	if errors.Is(err, kms.ErrNoKeyring) {
		if ring, err = kms.NewKeyring(); err == nil {
			err = kms.Save(path, ring, sealer)
		}
		if err == nil {
			fmt.Fprintf(os.Stderr, "gr8s-kms: made a keyring at %s (%s); keep a recovery export: gr8s-kms export-recovery\n",
				path, sealer.Describe())
		}
	}
	return ring, err
}

func serve(socket, path string, sealer kms.Sealer) error {
	ring, err := loadOrCreate(path, sealer)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		return err
	}
	_ = os.Remove(socket)
	plugin := kms.NewService(ring)
	server := service.NewGRPCService(socket, 10*time.Second, plugin)
	// A rotation from gr8s-kms rotate replaces the file; the server follows it.
	go func() {
		seen := modified(path)
		for range time.Tick(5 * time.Second) {
			if now := modified(path); !now.Equal(seen) {
				if next, err := kms.Load(path, sealer); err == nil {
					plugin.Reload(next)
					fmt.Fprintf(os.Stderr, "gr8s-kms: keyring reloaded; key %s wraps\n", next.ActiveID())
				} else {
					fmt.Fprintf(os.Stderr, "gr8s-kms: keeping the keyring in use: %v\n", err)
				}
				seen = now
			}
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signals
		server.Shutdown()
	}()
	// The socket is root's: what it wraps protects every Secret.
	go func() {
		for i := 0; i < 50; i++ {
			if os.Chmod(socket, 0o600) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	fmt.Fprintf(os.Stderr, "gr8s-kms: serving on %s; key %s wraps (%s)\n", socket, ring.ActiveID(), sealer.Describe())
	// A graceful stop, on SIGTERM, ends this with nil.
	return server.ListenAndServe()
}

func rotate(path string, sealer kms.Sealer) error {
	ring, err := kms.Load(path, sealer)
	if err != nil {
		return err
	}
	id, err := ring.Rotate()
	if err != nil {
		return err
	}
	if err := kms.Save(path, ring, sealer); err != nil {
		return err
	}
	fmt.Printf("key %s now wraps; gr8s follows within a minute, and gr8s secrets-encrypt reencrypt rewrites older Secrets\n", id)
	return nil
}

func status(path string, sealer kms.Sealer) error {
	ring, err := kms.Load(path, sealer)
	if err != nil {
		return err
	}
	fmt.Printf("keyring %s: %d key(s), %s wraps; %s\n", path, len(ring.Keys), ring.ActiveID(), sealer.Describe())
	return nil
}

func exportRecovery(path string, sealer kms.Sealer, file, passphraseFile string) error {
	if file == "" {
		return errors.New("--file names where to write the export")
	}
	ring, err := kms.Load(path, sealer)
	if err != nil {
		return err
	}
	passphrase, err := readPassphrase(passphraseFile, true)
	if err != nil {
		return err
	}
	data, err := kms.ExportRecovery(ring, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: keep it, and its passphrase, apart from this machine\n", file)
	return nil
}

func importRecovery(path string, sealer kms.Sealer, file, passphraseFile string) error {
	if file == "" {
		return errors.New("--file names the export to restore")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	passphrase, err := readPassphrase(passphraseFile, false)
	if err != nil {
		return err
	}
	ring, err := kms.ImportRecovery(data, passphrase)
	if err != nil {
		return err
	}
	if err := kms.Save(path, ring, sealer); err != nil {
		return err
	}
	fmt.Printf("restored %d key(s) to %s, sealed to this machine (%s)\n", len(ring.Keys), path, sealer.Describe())
	return nil
}

// readPassphrase reads it from file, or asks on the terminal (twice, when confirming).
func readPassphrase(file string, confirm bool) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		return bytes.TrimRight(data, "\r\n"), err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
		return bytes.TrimRight(line, "\r\n"), err
	}
	fmt.Fprint(os.Stderr, "passphrase: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil || !confirm {
		return first, err
	}
	fmt.Fprint(os.Stderr, "again: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("the passphrases differ")
	}
	return first, nil
}

func modified(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
