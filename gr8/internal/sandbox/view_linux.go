package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// view is the command's view of the host, kept by Enter until the command
// exits so it can copy saved files back.
type view struct {
	saved []savedFile
}

// savedFile is a --rw file in a private $HOME. The command gets a copy, so
// it can save it the usual way, beside it and renaming over it; the copy
// goes back to the real file when the command exits.
type savedFile struct {
	path     string // where the command sees it
	dirFD    int    // the real file's directory, held before $HOME is covered
	name     string // the real file's name in it
	original []byte // what it held at start; nil when it didn't exist
	mode     os.FileMode
}

// buildView covers the parts of the host's tree the command must not see
// with the Pod's own: its /proc (not the host's processes), /dev and /sys,
// fresh /run and /tmp (no host sockets), a private $HOME holding only what
// --ro and --rw name, and the Pod's resolv.conf, hosts and hostname, so names
// resolve through the cluster's DNS under policy.
func buildView(hostRoot string, config Config) (*view, error) {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, fmt.Errorf("making mounts private: %w", err)
	}
	result := &view{}
	// Hold what the covering mounts below may hide, to bind it back.
	binds, err := holdBinds(hostRoot, config)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, bind := range binds {
			unix.Close(bind.fd)
		}
	}()
	if config.PrivateHome() {
		if result.saved, err = holdSavedFiles(hostRoot, config); err != nil {
			result.close()
			return nil, err
		}
	}

	for _, path := range []string{"/proc", "/dev", "/sys"} {
		if err := bindOver(path, filepath.Join(hostRoot, path), false); err != nil {
			return nil, err
		}
	}
	tmpfses := []struct{ path, mode string }{{"/run", "0755"}, {"/tmp", "1777"}, {"/var/tmp", "1777"}}
	if config.PrivateHome() {
		tmpfses = append(tmpfses, struct{ path, mode string }{config.Home, "0700"})
	}
	for _, tmpfs := range tmpfses {
		target := filepath.Join(hostRoot, tmpfs.path)
		if !isDir(target) {
			continue
		}
		if err := unix.Mount("tmpfs", target, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode="+tmpfs.mode); err != nil {
			return nil, fmt.Errorf("mounting a tmpfs on %s: %w", tmpfs.path, err)
		}
	}
	for _, bind := range binds {
		source := fmt.Sprintf("/proc/self/fd/%d", bind.fd)
		if err := bindOver(source, filepath.Join(hostRoot, bind.path), bind.readOnly); err != nil {
			return nil, err
		}
	}
	for _, file := range result.saved {
		if err := copyIn(filepath.Join(hostRoot, file.path), file); err != nil {
			return nil, err
		}
	}
	if err := trustEgressCA(hostRoot, config.Trust); err != nil {
		return nil, err
	}
	// After the binds above: a placeholder file usually lives inside a directory the
	// command may write (~/.claude). It covers the real one in this view only.
	for index, path := range config.Placeholders {
		real, err := os.ReadFile(filepath.Join(hostRoot, path))
		if err != nil {
			continue
		}
		standIn, err := StandInCredentials(real)
		if err != nil {
			return nil, fmt.Errorf("%s is not a JSON credentials file: %w", path, err)
		}
		standInPath := filepath.Join(hostRoot, trustDirectory, fmt.Sprintf("placeholder-%d", index))
		if err := os.MkdirAll(filepath.Dir(standInPath), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(standInPath, standIn, 0o600); err != nil {
			return nil, err
		}
		if err := bindOver(standInPath, filepath.Join(hostRoot, path), false); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/hostname"} {
		if _, err := os.Stat(name); err != nil {
			continue
		}
		target, err := ResolveIn(hostRoot, name)
		if err != nil {
			return nil, err
		}
		if err := bindOver(name, target, false); err != nil {
			return nil, err
		}
	}
	return result, nil
}

type heldBind struct {
	path     string
	fd       int
	readOnly bool
}

// holdBinds opens what must be bound back after the covering mounts: the
// working directory, and in a private $HOME the --ro paths and --rw
// directories there. Parents come first, so a child binds over its parent.
func holdBinds(hostRoot string, config Config) ([]heldBind, error) {
	type wanted struct {
		path     string
		readOnly bool
		required bool
	}
	wants := []wanted{{config.Cwd, false, true}}
	if config.PrivateHome() {
		for _, path := range config.ReadOnly {
			if within(path, config.Home) {
				wants = append(wants, wanted{path, true, false})
			}
		}
		for _, path := range config.ReadWrite {
			if within(path, config.Home) && isDir(filepath.Join(hostRoot, path)) {
				wants = append(wants, wanted{path, false, false})
			}
		}
	}
	sort.SliceStable(wants, func(i, j int) bool { return len(wants[i].path) < len(wants[j].path) })
	var binds []heldBind
	for _, want := range wants {
		fd, err := unix.Open(filepath.Join(hostRoot, want.path), unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil && !want.required && errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			for _, bind := range binds {
				unix.Close(bind.fd)
			}
			return nil, fmt.Errorf("%s: %w", want.path, err)
		}
		binds = append(binds, heldBind{want.path, fd, want.readOnly})
	}
	return binds, nil
}

// holdSavedFiles reads the --rw files in $HOME and holds their real
// directories, following a symbolic link to where the file really lives.
func holdSavedFiles(hostRoot string, config Config) ([]savedFile, error) {
	var saved []savedFile
	for _, path := range config.ReadWrite {
		real := filepath.Join(hostRoot, path)
		if !within(path, config.Home) || isDir(real) {
			continue
		}
		resolved, err := ResolveIn(hostRoot, path)
		if err != nil {
			return saved, err
		}
		dirFD, err := unix.Open(filepath.Dir(resolved), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return saved, fmt.Errorf("the directory of %s: %w", path, err)
		}
		file := savedFile{path: path, dirFD: dirFD, name: filepath.Base(resolved), mode: 0o600}
		file.original, file.mode, err = readAt(dirFD, file.name)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			unix.Close(dirFD)
			return saved, fmt.Errorf("%s: %w", path, err)
		}
		if file.mode == 0 {
			file.mode = 0o600
		}
		saved = append(saved, file)
	}
	return saved, nil
}

// copyIn writes file's starting contents where the command will see it.
func copyIn(target string, file savedFile) error {
	if file.original == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	return os.WriteFile(target, file.original, file.mode)
}

// saveBack copies each saved file the command changed to the real file,
// unless the real file changed meanwhile too: then the command's version is
// not saved, rather than lose the other change.
func (v *view) saveBack() []error {
	var problems []error
	for _, file := range v.saved {
		current, err := readRegular(file.path)
		if errors.Is(err, unix.ENOENT) {
			continue // removed in the sandbox: leave the real file alone
		} else if err != nil {
			problems = append(problems, fmt.Errorf("not saving %s: %w", file.path, err))
			continue
		}
		if err := saveFile(file.dirFD, file.name, file.original, current, file.mode); err != nil {
			problems = append(problems, fmt.Errorf("not saving %s: %w", file.path, err))
		}
	}
	return problems
}

func (v *view) close() {
	for _, file := range v.saved {
		unix.Close(file.dirFD)
	}
	v.saved = nil
}

// errChangedMeanwhile says the real file changed while the command ran.
var errChangedMeanwhile = errors.New("it changed outside the sandbox meanwhile")

// saveFile replaces name in dirFD with current, atomically, if current
// differs from original and the real file still holds original.
func saveFile(dirFD int, name string, original, current []byte, mode os.FileMode) error {
	if original != nil && bytes.Equal(original, current) {
		return nil
	}
	real, _, err := readAt(dirFD, name)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if !bytes.Equal(real, original) || (real == nil) != (original == nil) {
		return errChangedMeanwhile
	}
	temporary := fmt.Sprintf(".%s.gr8-%d", name, os.Getpid())
	fd, err := unix.Openat(dirFD, temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	out := os.NewFile(uintptr(fd), temporary)
	_, err = out.Write(current)
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = unix.Renameat(dirFD, temporary, dirFD, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dirFD, temporary, 0)
	}
	return err
}

// readAt reads name in dirFD, not following a symbolic link, and returns
// its contents (never nil for an existing file) and permissions.
func readAt(dirFD int, name string) ([]byte, os.FileMode, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	return readOpen(os.NewFile(uintptr(fd), name))
}

// readRegular reads path if it is a regular file, not following a symbolic
// link: the command may have replaced a saved file with a link to a secret.
func readRegular(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	contents, _, err := readOpen(os.NewFile(uintptr(fd), path))
	return contents, err
}

func readOpen(file *os.File) ([]byte, os.FileMode, error) {
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file", file.Name())
	}
	contents, err := io.ReadAll(file)
	if contents == nil {
		contents = []byte{}
	}
	return contents, info.Mode().Perm(), err
}

// bindOver bind-mounts source over target, creating target (as a directory
// or an empty file, like source) when it is missing.
func bindOver(source, target string, readOnly bool) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		if info.IsDir() {
			err = os.MkdirAll(target, 0o755)
		} else if err = os.MkdirAll(filepath.Dir(target), 0o755); err == nil {
			err = os.WriteFile(target, nil, 0o644)
		}
		if err != nil {
			return fmt.Errorf("creating %s to mount over: %w", target, err)
		}
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("mounting %s over %s: %w", source, target, err)
	}
	if readOnly {
		return remountReadOnly(target)
	}
	return nil
}

// remountReadOnly makes the bind at target read-only. In a user namespace a
// remount must keep the flags the mount came with, so they are read first.
func remountReadOnly(target string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(target, &stat); err != nil {
		return err
	}
	flags := uintptr(unix.MS_REMOUNT | unix.MS_BIND | unix.MS_RDONLY)
	for _, kept := range []struct{ statfs, mount uintptr }{
		{unix.ST_NOSUID, unix.MS_NOSUID}, {unix.ST_NODEV, unix.MS_NODEV},
		{unix.ST_NOEXEC, unix.MS_NOEXEC}, {unix.ST_NOATIME, unix.MS_NOATIME},
		{unix.ST_NODIRATIME, unix.MS_NODIRATIME}, {unix.ST_RELATIME, unix.MS_RELATIME},
	} {
		if uintptr(stat.Flags)&kept.statfs != 0 {
			flags |= kept.mount
		}
	}
	if err := unix.Mount("", target, "", flags, ""); err != nil {
		return fmt.Errorf("making %s read-only: %w", target, err)
	}
	return nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// The sandbox's CA bundles, in its private /run.
const (
	trustDirectory = "/run/gr8"
	trustBundle    = trustDirectory + "/ca-bundle.pem"
	trustEgress    = trustDirectory + "/egress-ca.pem"
)

// systemCABundles are where distributions keep the PEM bundle TLS clients read by default.
var systemCABundles = []string{
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// trustEgressCA makes the sandbox trust the node egress proxy's certificates
// (podster-wv1w.5): the host's system roots plus the egress CA at TRUST become the
// sandbox's bundle, mounted over the host's default bundle paths so a client that
// reads the defaults trusts it too. Without a CA (no injection on this cluster) it
// does nothing.
func trustEgressCA(hostRoot, trust string) error {
	targets, err := writeTrustBundle(hostRoot, trust)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := bindOver(filepath.Join(hostRoot, trustBundle), target, false); err != nil {
			return err
		}
	}
	return nil
}

// writeTrustBundle writes the sandbox's bundles under hostRoot's /run and returns the
// host's default bundle paths (resolved under hostRoot) to cover with them.
func writeTrustBundle(hostRoot, trust string) ([]string, error) {
	if trust == "" {
		return nil, nil
	}
	egress, err := os.ReadFile(trust)
	if err != nil || len(bytes.TrimSpace(egress)) == 0 {
		return nil, nil
	}
	var system []byte
	var targets []string
	for _, path := range systemCABundles {
		target, err := ResolveIn(hostRoot, path)
		if err != nil {
			continue
		}
		if contents, err := os.ReadFile(target); err == nil {
			if system == nil {
				system = contents
			}
			if !containsString(targets, target) {
				targets = append(targets, target)
			}
		}
	}
	directory := filepath.Join(hostRoot, trustDirectory)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	combined := append(append(append([]byte{}, system...), '\n'), egress...)
	if err := os.WriteFile(filepath.Join(hostRoot, trustBundle), combined, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(hostRoot, trustEgress), egress, 0o644); err != nil {
		return nil, err
	}
	return targets, nil
}

// trustEnv is the environment telling TLS clients where the sandbox's bundle is, once
// trustEgressCA has written it.
func trustEnv() []string {
	if _, err := os.Stat(trustBundle); err != nil {
		return nil
	}
	return []string{
		"SSL_CERT_FILE=" + trustBundle, "REQUESTS_CA_BUNDLE=" + trustBundle,
		"CURL_CA_BUNDLE=" + trustBundle, "GIT_SSL_CAINFO=" + trustBundle,
		"NODE_EXTRA_CA_CERTS=" + trustEgress,
	}
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
