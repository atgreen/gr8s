// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func allows(rules []rbacv1.PolicyRule, group, resource, verb string) bool {
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, group) && slices.Contains(rule.Resources, resource) &&
			slices.Contains(rule.Verbs, verb) {
			return true
		}
	}
	return false
}

// Every API call gr8 makes, so a new one without a grant fails here, not on a desktop.
func TestSetupRBACGrantsWhatGr8CallsAndNoMore(t *testing.T) {
	role, binding, clusterRole, clusterBinding := SetupRBAC("gr8:alice", "gr8")
	namespaced := map[[2]string][]string{
		{"", "pods"}:                             {"create", "get", "delete"},
		{"", "pods/exec"}:                        {"create", "get"},
		{"", "secrets"}:                          {"create", "get", "update", "patch", "delete"},
		{"agents.kruise.io", "securityprofiles"}: {"create", "get", "update", "patch", "delete"},
	}
	cluster := map[[2]string][]string{
		{"", "nodes"}:                      {"get", "list"},
		{"", "namespaces"}:                 {"get"},
		{"gr8.gr8s.io", "sandboxprofiles"}: {"create", "get", "list", "update", "delete"},
		{"policy.networking.k8s.io", "clusternetworkpolicies"}: {"create", "delete"},
	}
	for key, verbs := range namespaced {
		for _, verb := range verbs {
			if !allows(role.Rules, key[0], key[1], verb) {
				t.Errorf("the gr8 namespace Role does not allow %s %s/%s", verb, key[0], key[1])
			}
		}
	}
	for key, verbs := range cluster {
		for _, verb := range verbs {
			if !allows(clusterRole.Rules, key[0], key[1], verb) {
				t.Errorf("the ClusterRole does not allow %s %s/%s", verb, key[0], key[1])
			}
		}
	}
	// Nothing broader: no wildcards, no Pods or Secrets beyond the namespace, no
	// namespaces made, and no RBAC of its own.
	for _, rule := range append(slices.Clone(role.Rules), clusterRole.Rules...) {
		for _, list := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs} {
			if slices.Contains(list, "*") {
				t.Errorf("rule %v has a wildcard", rule)
			}
		}
		if slices.Contains(rule.APIGroups, rbacv1.GroupName) {
			t.Errorf("rule %v grants RBAC", rule)
		}
	}
	for _, resource := range []string{"pods", "secrets"} {
		if allows(clusterRole.Rules, "", resource, "get") {
			t.Errorf("the ClusterRole grants %s in every namespace", resource)
		}
	}
	if allows(clusterRole.Rules, "", "namespaces", "create") {
		t.Error("the ClusterRole lets the user create namespaces")
	}
	if role.Namespace != "gr8" || binding.Namespace != "gr8" {
		t.Errorf("Role and RoleBinding in %q, %q", role.Namespace, binding.Namespace)
	}
	for _, subjects := range [][]rbacv1.Subject{binding.Subjects, clusterBinding.Subjects} {
		if len(subjects) != 1 || subjects[0].Kind != rbacv1.UserKind || subjects[0].Name != "gr8:alice" {
			t.Errorf("bound to %v, want only user gr8:alice", subjects)
		}
	}
	if binding.RoleRef.Name != role.Name || clusterBinding.RoleRef.Name != clusterRole.Name {
		t.Error("a binding refers to another role")
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

func TestServerStateDirectoryFollowsServerEnv(t *testing.T) {
	for environment, want := range map[string]string{
		"": "/var/lib/gr8s/server",
		"GR8S_EXEC_ARGS=serve --state-directory /var/lib/gr8s/server\n":            "/var/lib/gr8s/server",
		"# note\nGR8S_EXEC_ARGS=\"serve --port 6443 --state-directory /srv/gr8s\"": "/srv/gr8s",
		"GR8S_EXEC_ARGS=serve --state-directory=/data/gr8s":                        "/data/gr8s",
	} {
		if got := ServerStateDirectory(environment); got != want {
			t.Errorf("ServerStateDirectory(%q) = %q, want %q", environment, got, want)
		}
	}
}
