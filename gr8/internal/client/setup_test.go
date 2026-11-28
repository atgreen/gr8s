// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// APICall is one kind of request gr8 makes; namespaced ones go to the user's own
// namespace.
type APICall struct {
	Group      string `json:"group"`
	Resource   string `json:"resource"`
	Verb       string `json:"verb"`
	Namespaced bool   `json:"namespaced"`
}

// gr8Calls is every API call gr8 makes. The gr8s suite checks gr8s-server's grant to
// a gr8 user against it (tests/fixtures/gr8-api-calls.json), so a call added here
// without a grant there fails CI rather than on a desktop.
var gr8Calls = func() []APICall {
	var calls []APICall
	add := func(group, resource string, namespaced bool, verbs ...string) {
		for _, verb := range verbs {
			calls = append(calls, APICall{group, resource, verb, namespaced})
		}
	}
	add("", "pods", true, "create", "get", "delete", "patch")
	add("", "pods/exec", true, "create", "get")
	add("", "secrets", true, "create", "get", "update", "patch", "delete")
	add("agents.kruise.io", "securityprofiles", true, "create", "get", "update", "patch", "delete")
	// What the node refused the run, told at its end.
	add("gr8s.io", "flows", true, "list", "watch")
	add("", "nodes", false, "get", "list")
	add("", "namespaces", false, "get")
	add("gr8.gr8s.io", "sandboxprofiles", false, "create", "get", "list", "update", "delete")
	add("policy.networking.k8s.io", "clusternetworkpolicies", false, "create", "delete")
	return calls
}()

var gr8CallsFixture = filepath.Join("..", "..", "..", "tests", "fixtures", "gr8-api-calls.json")

func TestTheAPICallsFixtureIsGr8s(t *testing.T) {
	raw, err := json.MarshalIndent(gr8Calls, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if os.Getenv("GR8_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(gr8CallsFixture, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fixture, err := os.ReadFile(gr8CallsFixture)
	if err != nil {
		t.Fatalf("%v (GR8_UPDATE_FIXTURES=1 go test ./... writes it)", err)
	}
	if !bytes.Equal(fixture, raw) {
		t.Errorf("%s is not gr8's calls any more; rerun with GR8_UPDATE_FIXTURES=1 and check the gr8s suite", gr8CallsFixture)
	}
}

func TestDefaultKubeconfigPrefersWhatSetupWrote(t *testing.T) {
	home := t.TempDir()
	env := map[string]string{}
	getenv := func(name string) string { return env[name] }
	if !NeedsSetup("", getenv, home) {
		t.Error("an empty home needs setup")
	}
	if got := DefaultKubeconfig("", getenv, home); got != "" {
		t.Errorf("with nothing set up, DefaultKubeconfig = %q, want client-go's default", got)
	}
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".kube", "config"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if NeedsSetup("", getenv, home) {
		t.Error("an existing ~/.kube/config needs no setup")
	}
	path := SetupKubeconfig(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DefaultKubeconfig("", getenv, home); got != path {
		t.Errorf("DefaultKubeconfig = %q, want gr8's own %q before ~/.kube/config", got, path)
	}
	if got := DefaultKubeconfig("/named", getenv, home); got != "/named" {
		t.Errorf("--kubeconfig lost to %q", got)
	}
	env["KUBECONFIG"] = "/env"
	if got := DefaultKubeconfig("", getenv, home); got != "" {
		t.Errorf("$KUBECONFIG lost to %q", got)
	}
	if NeedsSetup("", getenv, t.TempDir()) {
		t.Error("$KUBECONFIG needs no setup")
	}
}

const issuedKubeconfig = `apiVersion: v1
kind: Config
clusters:
  - name: gr8s
    cluster:
      server: https://127.0.0.1:6443
contexts:
  - name: gr8s
    context:
      cluster: gr8s
      namespace: NAMESPACE
      user: gr8s
current-context: gr8s
users:
  - name: gr8s
    user:
      token: t
`

func TestGr8FollowsTheNamespaceItsKubeconfigNames(t *testing.T) {
	directory := t.TempDir()
	for namespace, want := range map[string]string{"gr8-alice": "gr8-alice", "gr8": "gr8", "default": "gr8"} {
		path := filepath.Join(directory, namespace)
		if err := os.WriteFile(path, []byte(strings.Replace(issuedKubeconfig, "NAMESPACE", namespace, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := DefaultNamespace(path); got != want {
			t.Errorf("a kubeconfig naming %s: DefaultNamespace = %q, want %q", namespace, got, want)
		}
	}
}

func TestSetupAsksTheServerAndPassesOnWhyNot(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "gr8.sock")
	if ServerRunning(socket) {
		t.Fatal("nothing listens yet")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	replies := []string{`{"kubeconfig":"apiVersion: v1\n"}`, `{"error":"alice is not in group gr8"}`}
	go func() {
		for _, reply := range replies {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = connection.Write([]byte(reply))
			connection.Close()
		}
	}()
	if kubeconfig, err := AskForKubeconfig(socket); err != nil || string(kubeconfig) != "apiVersion: v1\n" {
		t.Errorf("AskForKubeconfig = %q, %v", kubeconfig, err)
	}
	if _, err := AskForKubeconfig(socket); err == nil || !strings.Contains(err.Error(), "not in group gr8") {
		t.Errorf("a refusal came back as %v", err)
	}
}
