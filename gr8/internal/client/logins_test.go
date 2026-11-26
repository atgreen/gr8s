package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/atgreen/gr8s/gr8/internal/sandbox"
)

func writeHomeFile(t *testing.T, home, path, contents string) {
	t.Helper()
	full := filepath.Join(home, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoginsAreThePresetsAndTheUsersOwn(t *testing.T) {
	home := t.TempDir()
	logins, err := Logins(home)
	if err != nil || !logins["claude"].For("/usr/local/bin/claude") {
		t.Fatalf("presets %v %v", logins, err)
	}
	writeHomeFile(t, home, ".config/gr8/logins.yaml", `
acme:
  commands: [acme]
  file: .config/acme/token.yaml
  accessToken: auth/access
  refreshToken: auth/refresh
  expiresAt: auth/expiry
  expiresUnit: rfc3339
  inject: {hosts: [api.acme.example]}
  refresh: {hosts: [login.acme.example], path: /oauth/token}
`)
	logins, err = Logins(home)
	if err != nil {
		t.Fatal(err)
	}
	if acme := logins["acme"]; !acme.For("acme") || !reflect.DeepEqual(acme.Hosts(), []string{"api.acme.example", "login.acme.example"}) {
		t.Errorf("acme %+v", acme)
	}
	for name, bad := range map[string]string{
		"no commands":     "x: {file: f, accessToken: a, inject: {hosts: [h.example]}}",
		"absolute file":   "x: {commands: [x], file: /etc/x, accessToken: a, inject: {hosts: [h.example]}}",
		"no inject hosts": "x: {commands: [x], file: f, accessToken: a, inject: {}}",
		"refresh no key":  "x: {commands: [x], file: f, accessToken: a, inject: {hosts: [h.example]}, refresh: {hosts: [h.example], path: /t}}",
		"bad unit":        "x: {commands: [x], file: f, accessToken: a, expiresUnit: days, inject: {hosts: [h.example]}}",
		"bad name":        "X_Y: {commands: [x], file: f, accessToken: a, inject: {hosts: [h.example]}}",
		"unknown field":   "x: {commands: [x], file: f, accessToken: a, inject: {hosts: [h.example]}, token: t}",
	} {
		writeHomeFile(t, home, ".config/gr8/logins.yaml", bad)
		if _, err := Logins(home); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestALoginReadsAndWritesOnlyItsTokens(t *testing.T) {
	home := t.TempDir()
	claude := presetLogins["claude"]
	writeHomeFile(t, home, ".claude/.credentials.json",
		`{"claudeAiOauth":{"accessToken":"a1","refreshToken":"r1","expiresAt":1795000000000,"scopes":["x"]},"other":true}`)
	tokens, err := claude.HostTokens(home)
	if err != nil || tokens != (LoginTokens{"a1", "r1", 1795000000000}) {
		t.Fatalf("tokens %+v %v", tokens, err)
	}
	if err := claude.WriteHostTokens(home, LoginTokens{"a2", "r2", 1796000000000}); err != nil {
		t.Fatal(err)
	}
	if tokens, _ := claude.HostTokens(home); tokens != (LoginTokens{"a2", "r2", 1796000000000}) {
		t.Errorf("after writing %+v", tokens)
	}
	raw, _ := os.ReadFile(filepath.Join(home, ".claude/.credentials.json"))
	if !strings.Contains(string(raw), `"other": true`) || !strings.Contains(string(raw), `"scopes"`) {
		t.Errorf("lost the rest of the file: %s", raw)
	}
	if info, _ := os.Stat(filepath.Join(home, ".claude/.credentials.json")); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}

	// YAML, a key with dots, expiry in RFC 3339.
	acme := Login{Commands: []string{"acme"}, File: ".acme/hosts.yml", AccessToken: "acme.example/token",
		RefreshToken: "acme.example/refresh", ExpiresAt: "acme.example/expiry", ExpiresUnit: "rfc3339",
		Inject: LoginInject{Hosts: []string{"acme.example"}}}
	writeHomeFile(t, home, ".acme/hosts.yml", "acme.example:\n  token: t1\n  refresh: r1\n  expiry: \"2026-11-26T12:00:00Z\"\n  user: me\n")
	tokens, err = acme.HostTokens(home)
	if err != nil || tokens.AccessToken != "t1" || tokens.ExpiresAt != 1795694400000 {
		t.Fatalf("yaml tokens %+v %v", tokens, err)
	}
	if err := acme.WriteHostTokens(home, LoginTokens{"t2", "r2", 1795698000000}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(home, ".acme/hosts.yml"))
	if !strings.Contains(string(raw), "token: t2") || !strings.Contains(string(raw), "2026-11-26T13:00:00Z") ||
		!strings.Contains(string(raw), "user: me") {
		t.Errorf("yaml after writing:\n%s", raw)
	}
	if _, err := (Login{File: ".none", AccessToken: "a"}).HostTokens(home); err == nil {
		t.Error("a missing file was read")
	}
}

func TestTheSandboxSeesStandInsAtALoginsKeysAlone(t *testing.T) {
	home := t.TempDir()
	claude := presetLogins["claude"]
	arg := claude.PlaceholderArg(home)
	path, keys, _ := strings.Cut(arg, "#")
	if path != filepath.Join(home, ".claude/.credentials.json") || keys != "claudeAiOauth/accessToken,claudeAiOauth/refreshToken" {
		t.Fatalf("placeholder %q", arg)
	}
	standIn, err := sandbox.StandInFile(path,
		[]byte(`{"claudeAiOauth":{"accessToken":"real","refreshToken":"real-r","expiresAt":5},"accessToken":"keep"}`),
		strings.Split(keys, ","))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(standIn, &document); err != nil {
		t.Fatal(err)
	}
	oauth := document["claudeAiOauth"].(map[string]any)
	if oauth["accessToken"] != StandIn || oauth["refreshToken"] != StandIn || oauth["expiresAt"] != 5.0 ||
		document["accessToken"] != "keep" {
		t.Errorf("stand-in %s", standIn)
	}
	yamlStandIn, err := sandbox.StandInFile("/h/.acme/hosts.yml", []byte("acme.example:\n  token: real\n  user: me\n"),
		[]string{"acme.example/token"})
	if err != nil || !strings.Contains(string(yamlStandIn), "token: "+StandIn) || strings.Contains(string(yamlStandIn), "real") ||
		!strings.Contains(string(yamlStandIn), "user: me") {
		t.Errorf("yaml stand-in %q %v", yamlStandIn, err)
	}
}

func TestALoginsSecurityProfileSelectsItsCommands(t *testing.T) {
	profile := LoginSecurityProfile("gr8", "claude", presetLogins["claude"])
	spec := profile["spec"].(map[string]any)
	expression := spec["selector"].(map[string]any)["matchExpressions"].([]any)[0].(map[string]any)
	if expression["key"] != LabelCommand || !reflect.DeepEqual(expression["values"], []any{"claude"}) {
		t.Errorf("selector %v", expression)
	}
	rules := spec["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules %v", rules)
	}
	// The refresh rule first, so an inject rule for the same host can't take the
	// token request and hand the client the endpoint's new real tokens.
	refresh := rules[0].(map[string]any)["actions"].(map[string]any)["tokenTransformation"].(map[string]any)
	if refresh["type"] != "OAuthRefresh" {
		t.Errorf("first rule %v, want the refresh", refresh)
	}
	// A login without a token endpoint injects only.
	if len(LoginRules("gh", Login{Inject: LoginInject{Hosts: []string{"api.github.com"}}})) != 1 {
		t.Error("a login without refresh got a refresh rule")
	}
}

func TestAPolicyMayNameAStoredLogin(t *testing.T) {
	policy, err := ParsePolicy([]byte("apiVersion: gr8.gr8s.io/v1alpha1\nkind: Policy\nspec:\n  credentials:\n" +
		"  - from: login:claude\n  - from: env:TOKEN\n    hosts: [api.example.com]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policy.Spec.loginNames(), []string{"claude"}) || len(policy.Spec.valueCredentials()) != 1 {
		t.Errorf("logins %v values %v", policy.Spec.loginNames(), policy.Spec.valueCredentials())
	}
	if _, err := ParsePolicy([]byte("apiVersion: gr8.gr8s.io/v1alpha1\nkind: Policy\nspec:\n  credentials:\n  - from: \"login:Bad Name\"\n")); err == nil {
		t.Error("a bad login name was accepted")
	}
}
