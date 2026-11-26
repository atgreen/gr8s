package sandbox

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseArgs(t *testing.T) {
	config, err := ParseArgs([]string{"--cwd", "/w", "--ro", "/a", "--rw", "/b", "--env", "TERM=x",
		"--", "ping", "--", "-c"})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Cwd: "/w", ReadOnly: []string{"/a"}, ReadWrite: []string{"/b"}, Env: []string{"TERM=x"},
		Command: []string{"ping", "--", "-c"}}
	if !reflect.DeepEqual(config, want) {
		t.Errorf("ParseArgs = %+v, want %+v", config, want)
	}
	for _, bad := range [][]string{
		{"--cwd", "/w"},              // no command
		{"--cwd", "w", "--", "ls"},   // relative cwd
		{"--bogus", "x", "--", "ls"}, // unknown flag
		{"--cwd", "/w", "--ro"},      // missing value
	} {
		if _, err := ParseArgs(bad); err == nil {
			t.Errorf("ParseArgs(%v) accepted", bad)
		}
	}
}

func TestResolveInStaysInsideRoot(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "run/systemd/resolve"), 0o755))
	// /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf, as systemd-resolved sets it.
	must(t, os.Symlink("/run/systemd/resolve/stub-resolv.conf", filepath.Join(root, "etc/resolv.conf")))
	must(t, os.Symlink("../run/systemd", filepath.Join(root, "etc/sd")))
	must(t, os.Symlink("/../../../../etc", filepath.Join(root, "escape")))

	for path, want := range map[string]string{
		"/etc/resolv.conf":    "/run/systemd/resolve/stub-resolv.conf",
		"/etc/sd/resolve":     "/run/systemd/resolve",
		"/etc/hosts":          "/etc/hosts",
		"/escape/resolv.conf": "/run/systemd/resolve/stub-resolv.conf",
		"/../../etc/hostname": "/etc/hostname",
	} {
		got, err := ResolveIn(root, path)
		if err != nil || got != filepath.Join(root, want) {
			t.Errorf("ResolveIn(%s) = %q, %v; want %s", path, got, err, filepath.Join(root, want))
		}
	}
	must(t, os.Symlink("loop", filepath.Join(root, "loop")))
	if _, err := ResolveIn(root, "/loop"); err == nil {
		t.Error("a symlink loop should fail")
	}
}

func TestRulesAllowTheWorkingDirectoryAndNotHome(t *testing.T) {
	config := Config{Cwd: "/home/u/work", ReadOnly: []string{"/home/u/.gitconfig"},
		ReadWrite: []string{"/home/u/.claude"}}
	access := map[string]uint64{}
	for _, rule := range config.Rules(6) {
		access[rule.Path] = rule.Access
	}
	if access["/home/u/work"] != allAccess(6) || access["/home/u/.claude"] != allAccess(6) {
		t.Error("the working directory and --rw paths must be writable")
	}
	if access["/home/u/.gitconfig"] != readAccess || access["/usr"] != readAccess {
		t.Error("--ro and system paths must be read-only")
	}
	if _, ok := access["/home/u"]; ok {
		t.Error("$HOME itself must not be allowed")
	}
}

// The Landlock test restricts a child copy of the test binary, since a
// restriction can't be lifted from the test process itself.
const landlockChild = "GR8_LANDLOCK_CHILD"

func TestLandlockConfinesWritesAndReads(t *testing.T) {
	if LandlockABI() < 1 {
		t.Skip("no Landlock in this kernel")
	}
	base := t.TempDir()
	work, outside := filepath.Join(base, "work"), filepath.Join(base, "outside")
	must(t, os.Mkdir(work, 0o755))
	must(t, os.Mkdir(outside, 0o755))
	must(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600))

	child := exec.Command(os.Args[0], "-test.run=^TestLandlockChild$")
	child.Env = append(os.Environ(), landlockChild+"="+base)
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "CONFINED") {
		t.Fatalf("child did not report:\n%s", output)
	}
}

func TestLandlockChild(t *testing.T) {
	base := os.Getenv(landlockChild)
	if base == "" {
		t.Skip("run by TestLandlockConfinesWritesAndReads")
	}
	runtime.LockOSThread()
	work, outside := filepath.Join(base, "work"), filepath.Join(base, "outside")
	abi := LandlockABI()
	// No /tmp here: the test's directories live under it.
	if err := RestrictSelf(abi, []Rule{{Path: "/usr", Access: readAccess}, {Path: work, Access: allAccess(abi)}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "ok"), []byte("x"), 0o644); err != nil {
		t.Fatalf("writing the working directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "planted"), []byte("x"), 0o644); err == nil {
		t.Fatal("wrote outside the working directory")
	}
	if _, err := os.ReadFile(filepath.Join(outside, "secret")); err == nil {
		t.Fatal("read outside the allowlist")
	}
	os.Stdout.WriteString("CONFINED\n")
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrivateHome(t *testing.T) {
	for _, c := range []struct {
		cwd, home string
		want      bool
	}{
		{"/home/u/work", "/home/u", true},
		{"/srv/project", "/home/u", true},
		{"/home/u", "/home/u", false}, // the working directory is $HOME
		{"/home", "/home/u", false},   // ... or holds it
		{"/", "/home/u", false},
		{"/home/u/work", "", false},
	} {
		config := Config{Cwd: c.cwd, Home: c.home}
		if got := config.PrivateHome(); got != c.want {
			t.Errorf("PrivateHome(cwd %s, home %s) = %v", c.cwd, c.home, got)
		}
	}
	rules := Config{Cwd: "/home/u/work", Home: "/home/u"}.Rules(6)
	if rules[0] != (Rule{Path: "/home/u", Access: allAccess(6)}) {
		t.Errorf("a private $HOME (a tmpfs) must be writable, got %v", rules[0])
	}
}

func TestParseArgsHome(t *testing.T) {
	config, err := ParseArgs([]string{"--cwd", "/w", "--home", "/home/u", "--", "ls"})
	if err != nil || config.Home != "/home/u" {
		t.Fatalf("ParseArgs = %+v, %v", config, err)
	}
	if _, err := ParseArgs([]string{"--cwd", "/w", "--home", "u", "--", "ls"}); err == nil {
		t.Error("a relative --home was accepted")
	}
}

func openDir(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	must(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func TestSaveFileCopiesBackAChangedFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, ".claude.json")
	must(t, os.WriteFile(real, []byte(`{"a":1}`), 0o600))
	must(t, saveFile(openDir(t, dir), ".claude.json", []byte(`{"a":1}`), []byte(`{"a":2}`), 0o600))
	if got, _ := os.ReadFile(real); string(got) != `{"a":2}` {
		t.Errorf("real file holds %s", got)
	}
	if info, _ := os.Stat(real); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
}

func TestSaveFileLeavesAnUnchangedFileAlone(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "f")
	must(t, os.WriteFile(real, []byte("x"), 0o600))
	before, _ := os.Stat(real)
	must(t, saveFile(openDir(t, dir), "f", []byte("x"), []byte("x"), 0o600))
	after, _ := os.Stat(real)
	if !os.SameFile(before, after) {
		t.Error("an unchanged file was rewritten")
	}
}

func TestSaveFileKeepsAChangeMadeOutsideMeanwhile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "f")
	must(t, os.WriteFile(real, []byte("outside"), 0o600))
	err := saveFile(openDir(t, dir), "f", []byte("start"), []byte("sandbox"), 0o600)
	if !errors.Is(err, errChangedMeanwhile) {
		t.Errorf("err = %v, want errChangedMeanwhile", err)
	}
	if got, _ := os.ReadFile(real); string(got) != "outside" {
		t.Errorf("real file holds %s", got)
	}
}

func TestSaveFileCreatesAFileTheCommandCreated(t *testing.T) {
	dir := t.TempDir()
	must(t, saveFile(openDir(t, dir), "new", nil, []byte("n"), 0o600))
	if got, _ := os.ReadFile(filepath.Join(dir, "new")); string(got) != "n" {
		t.Errorf("new file holds %q", got)
	}
	// Created outside meanwhile: not overwritten.
	if err := saveFile(openDir(t, dir), "new", nil, []byte("m"), 0o600); !errors.Is(err, errChangedMeanwhile) {
		t.Errorf("err = %v, want errChangedMeanwhile", err)
	}
}

func TestReadRegularRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "id_ed25519")
	must(t, os.WriteFile(secret, []byte("key"), 0o600))
	link := filepath.Join(dir, ".claude.json")
	must(t, os.Symlink(secret, link))
	if _, err := readRegular(link); err == nil {
		t.Error("a saved file replaced by a symlink to a secret was read")
	}
}

func TestWriteTrustBundleAddsTheEgressCAToTheSystemRoots(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "etc/pki/tls/certs"), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "etc/pki/ca-trust/extracted/pem"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"), []byte("SYSTEM\n"), 0o644))
	// Fedora's default bundle is a symlink to the extracted one.
	must(t, os.Symlink("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", filepath.Join(root, "etc/pki/tls/certs/ca-bundle.crt")))
	trust := filepath.Join(t.TempDir(), "egress-ca.pem")
	must(t, os.WriteFile(trust, []byte("EGRESS\n"), 0o644))

	targets, err := writeTrustBundle(root, trust)
	must(t, err)
	// Both paths are one file: it is covered once.
	if len(targets) != 1 || targets[0] != filepath.Join(root, "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem") {
		t.Errorf("targets %v", targets)
	}
	if got, _ := os.ReadFile(filepath.Join(root, trustBundle)); string(got) != "SYSTEM\n\nEGRESS\n" {
		t.Errorf("bundle %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(root, trustEgress)); string(got) != "EGRESS\n" {
		t.Errorf("egress %q", got)
	}
	// No CA mounted (a cluster without injection): nothing changes.
	if targets, err := writeTrustBundle(root, filepath.Join(root, "missing.pem")); err != nil || targets != nil {
		t.Errorf("without a CA: %v %v", targets, err)
	}
}

func TestStandInCredentialsHideTheTokens(t *testing.T) {
	real := []byte(`{"claudeAiOauth":{"accessToken":"sk-ant-oat-real","refreshToken":"sk-ant-ort-real",
		"expiresAt":1795000000000,"refreshTokenExpiresAt":1800000000000,"scopes":["user:inference"],
		"subscriptionType":"max"}}`)
	standIn, err := StandInCredentials(real)
	must(t, err)
	if strings.Contains(string(standIn), "real") {
		t.Fatalf("a real token survived: %s", standIn)
	}
	var parsed struct {
		OAuth map[string]any `json:"claudeAiOauth"`
	}
	must(t, json.Unmarshal(standIn, &parsed))
	if parsed.OAuth["accessToken"] != StandInToken || parsed.OAuth["refreshToken"] != StandInToken ||
		parsed.OAuth["expiresAt"].(float64) != standInExpiry || parsed.OAuth["subscriptionType"] != "max" {
		t.Errorf("stand-in %v", parsed.OAuth)
	}
	if _, err := StandInCredentials([]byte("not json")); err == nil {
		t.Error("a non-JSON file was accepted")
	}
}
