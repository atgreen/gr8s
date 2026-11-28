// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestOnlyPolicyRefusalsOfThisRunAreCounted(t *testing.T) {
	pod := "gr8-claude-abcde"
	for line, want := range map[string]string{
		`{"pod":"gr8-claude-abcde","verdict":"DROPPED","reason":"POLICY","l7":{"type":"dns","query":"PyPI.org."}}`:       "pypi.org",
		`{"pod":"gr8-claude-abcde","verdict":"DROPPED","reason":"POLICY","l7":{"type":"egress","host":"evil.example"}}`:  "evil.example",
		`{"pod":"gr8-claude-zzzzz","verdict":"DROPPED","reason":"POLICY","l7":{"type":"dns","query":"other.run"}}`:       "",
		`{"pod":"gr8-claude-abcde","verdict":"FORWARDED","l7":{"type":"dns","query":"api.anthropic.com"}}`:               "",
		`{"pod":"gr8-claude-abcde","verdict":"DROPPED","l7":{"type":"http","host":"github.com","path":"/x","code":404}}`: "",
		`not json`: "",
	} {
		host, ok := ParseRefusal([]byte(line), pod)
		if host != want || ok != (want != "") {
			t.Errorf("ParseRefusal(%s) = %q, %v; want %q", line, host, ok, want)
		}
	}
	watch := &refusalWatch{counts: map[string]int{}}
	watch.read(strings.NewReader(strings.Join([]string{
		`{"pod":"p","verdict":"DROPPED","reason":"POLICY","l7":{"type":"dns","query":"pypi.org"}}`,
		`{"pod":"p","verdict":"DROPPED","reason":"POLICY","l7":{"type":"dns","query":"files.pythonhosted.org"}}`,
		`{"pod":"p","verdict":"DROPPED","reason":"POLICY","l7":{"type":"egress","host":"pypi.org"}}`,
	}, "\n")), "p")
	if !slices.Equal(watch.order, []string{"pypi.org", "files.pythonhosted.org"}) || watch.counts["pypi.org"] != 2 {
		t.Errorf("collected %v %v", watch.order, watch.counts)
	}
	footer := RefusalFooter([]Refusal{{"pypi.org", 2}, {"files.pythonhosted.org", 1}})
	if !strings.Contains(footer, "pypi.org (2 times)") || !strings.Contains(footer, "  files.pythonhosted.org\n") {
		t.Errorf("footer:\n%s", footer)
	}
}

func TestAllowingAddsHostsAndKeepsThePolicysComments(t *testing.T) {
	raw := `# my claude policy
apiVersion: gr8.gr8s.io/v1alpha1
kind: Policy
metadata: {name: claude}
spec:
  hosts: [api.anthropic.com]   # the model
  egress: {enforcement: Audit}
`
	updated, err := AddHostsToPolicy([]byte(raw), []string{"pypi.org", "api.anthropic.com"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, want := range []string{"# my claude policy", "# the model", "- api.anthropic.com", "- pypi.org", "enforcement: Audit"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Count(text, "api.anthropic.com") != 1 {
		t.Errorf("a host it named was added again:\n%s", text)
	}
	policy, err := ParsePolicy(updated)
	if err != nil {
		t.Fatalf("the updated policy doesn't parse: %v\n%s", err, text)
	}
	if !slices.Equal(policy.Spec.Hosts, []string{"api.anthropic.com", "pypi.org"}) {
		t.Errorf("hosts = %v", policy.Spec.Hosts)
	}
	// A policy without hosts gets them.
	updated, err = AddHostsToPolicy([]byte("apiVersion: gr8.gr8s.io/v1alpha1\nkind: Policy\nmetadata: {name: x}\nspec: {}\n"), []string{"pypi.org"})
	if err != nil {
		t.Fatal(err)
	}
	if policy, err := ParsePolicy(updated); err != nil || !slices.Equal(policy.Spec.Hosts, []string{"pypi.org"}) {
		t.Errorf("hosts = %v, %v", policy.Spec.Hosts, err)
	}
	if policy, err := ParsePolicy(NewPolicy("claude", []string{"pypi.org", "github.com"})); err != nil ||
		!slices.Equal(policy.Spec.Hosts, []string{"pypi.org", "github.com"}) {
		t.Errorf("NewPolicy: %v, %v", policy.Spec.Hosts, err)
	}
}

func TestAllowingWritesTheRunsPolicyOrANewOne(t *testing.T) {
	home := t.TempDir()
	yes := func(string) bool { return true }
	refusals := []Refusal{{"pypi.org", 1}}
	// No policy: a new one for the command.
	offerToAllow(refusals, nil, "/usr/bin/claude", home, yes)
	created := filepath.Join(home, ".config", "gr8", "policies", "claude.yaml")
	if policy, err := os.ReadFile(created); err != nil || !strings.Contains(string(policy), "pypi.org") {
		t.Fatalf("new policy: %q, %v", policy, err)
	}
	// A working-directory policy is edited, and approved as edited, so the next run
	// doesn't ask about the change the user just made.
	cwd := t.TempDir()
	path := filepath.Join(cwd, ".gr8", "claude.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, NewPolicy("claude", []string{"api.anthropic.com"}), 0o600); err != nil {
		t.Fatal(err)
	}
	file := &PolicyFile{Path: path, Trusted: false}
	offerToAllow(refusals, file, "claude", home, yes)
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "pypi.org") {
		t.Fatalf("not added:\n%s", raw)
	}
	asked := false
	if err := ApprovePolicy(*file, raw, home, func(string) bool { asked = true; return false }); err != nil || asked {
		t.Errorf("the edited policy wasn't approved: %v (asked %v)", err, asked)
	}
	// No, or no terminal: nothing is written.
	offerToAllow([]Refusal{{"github.com", 1}}, file, "claude", home, func(string) bool { return false })
	offerToAllow([]Refusal{{"github.com", 1}}, file, "claude", home, nil)
	if raw, _ := os.ReadFile(path); strings.Contains(string(raw), "github.com") {
		t.Error("a host was allowed without a yes")
	}
}
