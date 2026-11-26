package client

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const examplePolicy = `apiVersion: gr8.gr8s.io/v1alpha1
kind: Policy
metadata: {name: claude}
spec:
  hosts: [api.anthropic.com, "*.githubusercontent.com"]
  credentials:
  - from: env:GITHUB_TOKEN
    hosts: [api.github.com, github.com]
    env: GH_TOKEN
  home:
    readWrite: [.claude, .claude.json]
    readOnly: [.config/gh]
  env: {EDITOR: vi}
  egress:
    enforcement: Audit
    binaries:
    - hosts: [api.github.com]
      paths: [/usr/bin/gh]
  desktop: {audio: false}
  resources: {cpu: "2", memory: 4Gi}
`

func TestParsePolicyReadsAndDefaults(t *testing.T) {
	policy, err := ParsePolicy([]byte(examplePolicy))
	if err != nil {
		t.Fatal(err)
	}
	credential := policy.Spec.Credentials[0]
	if credential.Header != "authorization" || credential.Template != "Bearer {{ .Token }}" {
		t.Errorf("defaults %+v", credential)
	}
	if policy.Spec.Egress["enforcement"] != "Audit" || policy.Spec.Resources.Memory != "4Gi" ||
		*policy.Spec.Desktop.Audio || policy.Spec.Desktop.Display != nil {
		t.Errorf("spec %+v", policy.Spec)
	}
	for name, bad := range map[string]string{
		"unknown field":    "spec: {hostz: [x]}",
		"wrong kind":       "kind: SandboxProfile",
		"bad host":         "spec: {hosts: [\"https://x\"]}",
		"bad source":       "spec: {credentials: [{from: \"vault:x\", hosts: [a.b]}]}",
		"no hosts":         "spec: {credentials: [{from: \"env:X\"}]}",
		"no token":         "spec: {credentials: [{from: \"env:X\", hosts: [a.b], template: \"Bearer x\"}]}",
		"climbing home":    "spec: {home: {readOnly: [../other]}}",
		"absolute home":    "spec: {home: {readWrite: [/etc]}}",
		"bad header":       "spec: {credentials: [{from: \"env:X\", hosts: [a.b], header: \"a b\"}]}",
		"bad env variable": "spec: {env: {\"A-B\": x}}",
	} {
		document := "apiVersion: gr8.gr8s.io/v1alpha1\nkind: Policy\n" + bad + "\n"
		if strings.HasPrefix(bad, "kind:") {
			document = "apiVersion: gr8.gr8s.io/v1alpha1\n" + bad + "\n"
		}
		if _, err := ParsePolicy([]byte(document)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCredentialValueReadsItsSource(t *testing.T) {
	home := t.TempDir()
	env := func(name string) string { return map[string]string{"TOKEN": "t0k"}[name] }
	if got, err := CredentialValue("env:TOKEN", home, env); err != nil || got != "t0k" {
		t.Errorf("env: %q %v", got, err)
	}
	if _, err := CredentialValue("env:MISSING", home, env); err == nil {
		t.Error("an empty variable was accepted")
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(home, ".config", "gh"), 0o700))
	must(os.WriteFile(filepath.Join(home, ".config", "gh", "hosts.yml"),
		[]byte("github.com:\n  oauth_token: gho_real\n  user: u\n"), 0o600))
	must(os.WriteFile(filepath.Join(home, "key"), []byte("sk-real\n"), 0o600))
	if got, err := CredentialValue("file:~/.config/gh/hosts.yml#github.com/oauth_token", home, env); err != nil || got != "gho_real" {
		t.Errorf("yaml path: %q %v", got, err)
	}
	if got, err := CredentialValue("file:"+filepath.Join(home, "key"), home, env); err != nil || got != "sk-real" {
		t.Errorf("whole file: %q %v", got, err)
	}
	if _, err := CredentialValue("file:~/.config/gh/hosts.yml#github.com/nothing", home, env); err == nil {
		t.Error("a missing key was accepted")
	}
}

func TestFindPolicyTrustsOnlyWhatTheSandboxCantWrite(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	config := filepath.Join(home, ".config", "gr8", "policies")
	write := func(path string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(examplePolicy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := FindPolicy("", "/usr/bin/claude", home, cwd); found || err != nil {
		t.Fatalf("found %v %v without a policy", found, err)
	}
	write(filepath.Join(cwd, ".gr8", "claude.yaml"))
	if file, _, _ := FindPolicy("", "/usr/bin/claude", home, cwd); file.Trusted {
		t.Errorf("a project policy was trusted: %+v", file)
	}
	write(filepath.Join(config, "claude.yaml"))
	if file, _, _ := FindPolicy("", "claude", home, cwd); !file.Trusted || !strings.HasPrefix(file.Path, config) {
		t.Errorf("the config directory's wasn't chosen: %+v", file)
	}
	write(filepath.Join(config, "review.yaml"))
	if file, _, _ := FindPolicy("review", "claude", home, cwd); filepath.Base(file.Path) != "review.yaml" || !file.Trusted {
		t.Errorf("--policy review: %+v", file)
	}
	if _, _, err := FindPolicy("absent", "claude", home, cwd); err == nil {
		t.Error("a missing --policy was accepted")
	}
}

func TestApprovePolicyPinsAProjectPolicy(t *testing.T) {
	home := t.TempDir()
	file := PolicyFile{Path: "/work/.gr8/claude.yaml"}
	var prompts []string
	answer := false
	ask := func(prompt string) bool { prompts = append(prompts, prompt); return answer }
	if err := ApprovePolicy(PolicyFile{Path: "/x", Trusted: true}, []byte("a"), home, ask); err != nil || prompts != nil {
		t.Fatalf("a trusted policy was questioned: %v %v", err, prompts)
	}
	if err := ApprovePolicy(file, []byte("hosts: [a]\n"), home, ask); err == nil {
		t.Error("a refused policy was used")
	}
	answer = true
	if err := ApprovePolicy(file, []byte("hosts: [a]\n"), home, ask); err != nil {
		t.Fatal(err)
	}
	prompts = nil
	if err := ApprovePolicy(file, []byte("hosts: [a]\n"), home, ask); err != nil || prompts != nil {
		t.Errorf("an approved policy was asked about again: %v %v", err, prompts)
	}
	// Changed (say, by the sandbox): asked again, with what changed.
	answer = false
	if err := ApprovePolicy(file, []byte("hosts: [a, pastebin.com]\n"), home, ask); err == nil {
		t.Error("a changed policy was used without approval")
	}
	if len(prompts) != 1 || !strings.Contains(prompts[0], "+ hosts: [a, pastebin.com]") || !strings.Contains(prompts[0], "- hosts: [a]") {
		t.Errorf("prompt %q", prompts)
	}
}

func TestAPolicyGrantsItsHomeEnvAndStandIns(t *testing.T) {
	policy, err := ParsePolicy([]byte(examplePolicy))
	if err != nil {
		t.Fatal(err)
	}
	grant := policy.withGrant(Grant{ReadOnly: []string{"/h/.gitconfig"}, Env: map[string]string{"A": "1"}}, "/h")
	if !reflect.DeepEqual(grant.ReadOnly, []string{"/h/.gitconfig", "/h/.config/gh"}) ||
		!reflect.DeepEqual(grant.ReadWrite, []string{"/h/.claude", "/h/.claude.json"}) {
		t.Errorf("paths %+v", grant)
	}
	if !reflect.DeepEqual(grant.Env, map[string]string{"A": "1", "EDITOR": "vi", "GH_TOKEN": StandIn}) {
		t.Errorf("env %v", grant.Env)
	}
}

func TestLoadPolicyFoldsHostsDesktopAndResourcesIntoOptions(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	config := filepath.Join(home, ".config", "gr8", "policies")
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "claude.yaml"), []byte(examplePolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_TOKEN", "ghp_real")
	options := Options{Command: []string{"claude"}, CPU: "8"}
	policy, values, err := loadPolicy(&options, home, cwd)
	if err != nil || policy == nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(values, []string{"ghp_real"}) {
		t.Errorf("values %v", values)
	}
	if !reflect.DeepEqual(options.Allow, []string{"api.github.com", "github.com", "api.anthropic.com", "*.githubusercontent.com"}) {
		t.Errorf("allow %v", options.Allow)
	}
	// A flag wins; the policy fills what no flag says.
	if options.CPU != "8" || options.Memory != "4Gi" || !options.NoAudio || options.NoDisplay {
		t.Errorf("options %+v", options)
	}
}

func TestEachCredentialGetsItsOwnStandIn(t *testing.T) {
	policy, err := ParsePolicy([]byte("apiVersion: gr8.gr8s.io/v1alpha1\nkind: Policy\nspec:\n  credentials:\n" +
		"  - {from: env:A, hosts: [a.example], env: A_TOKEN, prefix: gho_}\n" +
		"  - {from: env:B, hosts: [a.example], env: B_TOKEN}\n"))
	if err != nil {
		t.Fatal(err)
	}
	policy.mintStandIns()
	grant := policy.withGrant(Grant{}, "/h")
	a, b := grant.Env["A_TOKEN"], grant.Env["B_TOKEN"]
	if !strings.HasPrefix(a, "gho_"+StandIn+"-") || !strings.HasPrefix(b, StandIn+"-") || a == b ||
		len(b) != len(StandIn)+1+24 {
		t.Errorf("stand-ins %q %q", a, b)
	}
	if !reflect.DeepEqual(policy.standIns, []string{a, b}) {
		t.Errorf("recorded %v", policy.standIns)
	}
	if _, err := ParsePolicy([]byte("apiVersion: gr8.gr8s.io/v1alpha1\nkind: Policy\nspec:\n  credentials:\n" +
		"  - {from: env:A, hosts: [a.example], prefix: \"x y\"}\n")); err == nil {
		t.Error("a bad prefix was accepted")
	}
}
