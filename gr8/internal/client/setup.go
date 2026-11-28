// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// SetupKubeconfig is where gr8 setup leaves the user's own kubeconfig. gr8 reads it
// before ~/.kube/config, so an existing kubectl setup is left alone.
func SetupKubeconfig(home string) string {
	return filepath.Join(home, ".config", "gr8", "kubeconfig")
}

// DefaultKubeconfig is the kubeconfig gr8 uses when none is named: $KUBECONFIG,
// else the one gr8 setup wrote, else "" for client-go's ~/.kube/config.
func DefaultKubeconfig(named string, getenv func(string) string, home string) string {
	if named != "" || getenv("KUBECONFIG") != "" {
		return named
	}
	if path := SetupKubeconfig(home); isFile(path) {
		return path
	}
	return ""
}

// NeedsSetup is true when gr8 has no kubeconfig at all to go on.
func NeedsSetup(named string, getenv func(string) string, home string) bool {
	return DefaultKubeconfig(named, getenv, home) == "" && getenv("KUBECONFIG") == "" &&
		!isFile(filepath.Join(home, ".kube", "config"))
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// Setup makes this machine a gr8s node for the user, through one sudo: it starts
// gr8s-server, grants the user what gr8 needs, and writes the user's kubeconfig
// (podster-q35k). The credential is the user's own, never the administrator's.
func Setup(home string) error {
	if os.Geteuid() == 0 {
		return errors.New("run gr8 --setup as the user who will run gr8, not as root")
	}
	self, err := launcherPath()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "gr8: setting up a gr8s node on this machine; sudo will ask for your password")
	var kubeconfig bytes.Buffer
	command := exec.Command("sudo", self, "--internal", "setup")
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, &kubeconfig, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("setup as root: %w", err)
	}
	path := SetupKubeconfig(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, kubeconfig.Bytes(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "gr8: ready; your kubeconfig is %s\n", path)
	return nil
}

var setupUserName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// SetupAsRoot is Setup's privileged half, run as gr8 --internal setup under sudo.
// It prints the user's kubeconfig on stdout and everything else on stderr.
func SetupAsRoot() int {
	if err := setupAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "gr8: setup: %v\n", err)
		return 1
	}
	return 0
}

func setupAsRoot() error {
	user := os.Getenv("SUDO_USER")
	if os.Geteuid() != 0 || user == "" || user == "root" {
		return errors.New("run gr8 --setup as your own user; it calls sudo itself")
	}
	if !setupUserName.MatchString(user) {
		return fmt.Errorf("unexpected user name %q", user)
	}
	gr8s, err := exec.LookPath("gr8s")
	if err != nil {
		return errors.New("gr8s is not installed; install the gr8s package first")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "gr8s-agent").Run() == nil {
		return errors.New("this machine runs gr8s-agent, so its cluster is elsewhere: ask that cluster's administrator for a kubeconfig")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "gr8s-server").Run() != nil {
		fmt.Fprintln(os.Stderr, "gr8: starting gr8s-server")
		if output, err := exec.Command("systemctl", "enable", "--now", "gr8s-server").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl enable --now gr8s-server: %v: %s", err, strings.TrimSpace(string(output)))
		}
	}
	state := ServerStateDirectory(readFile("/etc/gr8s/server.env"))
	admin := filepath.Join(state, "kubeconfig")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	fmt.Fprintln(os.Stderr, "gr8: waiting for this machine's node to be Ready")
	clientset, err := waitForAdmin(ctx, admin)
	if err != nil {
		return err
	}
	if err := waitForLocalNode(ctx, clientset); err != nil {
		return err
	}
	identity, namespace := "gr8:"+user, UserNamespace(user)
	if err := ensureUserNamespace(ctx, clientset, namespace, os.Getenv("SUDO_UID")); err != nil {
		return err
	}
	if err := applySetupRBAC(ctx, clientset, identity, namespace); err != nil {
		return err
	}
	var issued bytes.Buffer
	command := exec.Command(gr8s, "kubeconfig", "--state-directory", state, "--user", identity)
	command.Stdout, command.Stderr = &issued, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("gr8s kubeconfig --user %s: %w", identity, err)
	}
	kubeconfig, err := WithNamespace(issued.Bytes(), namespace)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(kubeconfig)
	return err
}

// UserNamespace is USER's own namespace: their runs, logins and Secrets live there,
// out of every other user's reach.
func UserNamespace(user string) string {
	return "gr8-" + strings.ReplaceAll(user, "_", "-")
}

// ensureUserNamespace makes NAMESPACE, recording the UID of the user it belongs to
// for the server's checks on what runs there (podster-tcr8).
func ensureUserNamespace(ctx context.Context, clientset kubernetes.Interface, name, uid string) error {
	namespaces := clientset.CoreV1().Namespaces()
	namespace, err := namespaces.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		namespace, err = namespaces.Create(ctx, NewNamespace(name), metav1.CreateOptions{})
	}
	if err != nil {
		return fmt.Errorf("namespace %s: %w", name, err)
	}
	if namespace.Annotations[OwnerUIDAnnotation] == uid {
		return nil
	}
	if namespace.Annotations == nil {
		namespace.Annotations = map[string]string{}
	}
	namespace.Annotations[OwnerUIDAnnotation] = uid
	_, err = namespaces.Update(ctx, namespace, metav1.UpdateOptions{})
	return err
}

// OwnerUIDAnnotation names the UID of the user a gr8 namespace belongs to.
const OwnerUIDAnnotation = "gr8s.io/gr8-uid"

// WithNamespace is KUBECONFIG with its current context's namespace set to NAMESPACE.
func WithNamespace(kubeconfig []byte, namespace string) ([]byte, error) {
	config, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("the issued kubeconfig: %w", err)
	}
	context := config.Contexts[config.CurrentContext]
	if context == nil {
		return nil, errors.New("the issued kubeconfig has no current context")
	}
	context.Namespace = namespace
	return clientcmd.Write(*config)
}

// DefaultNamespace is the namespace gr8 runs in when none is named: the
// kubeconfig's own when it is a gr8 one (gr8, or gr8-USER from gr8 --setup), else gr8.
// An administrator's kubeconfig names default, which gr8 leaves alone.
func DefaultNamespace(kubeconfig string) string {
	if home, err := os.UserHomeDir(); err == nil {
		kubeconfig = DefaultKubeconfig(kubeconfig, os.Getenv, home)
	}
	namespace, _, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{
			ExplicitPath: kubeconfig,
			Precedence:   clientcmd.NewDefaultClientConfigLoadingRules().Precedence,
		}, &clientcmd.ConfigOverrides{}).Namespace()
	if err == nil && (namespace == "gr8" || strings.HasPrefix(namespace, "gr8-")) {
		return namespace
	}
	return "gr8"
}

func readFile(path string) string {
	content, _ := os.ReadFile(path)
	return string(content)
}

// ServerStateDirectory is the --state-directory in gr8s-server's environment file,
// else the packaged default.
func ServerStateDirectory(environment string) string {
	for _, line := range strings.Split(environment, "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "GR8S_EXEC_ARGS=")
		if !ok {
			continue
		}
		fields := strings.Fields(strings.Trim(value, `"'`))
		for i, field := range fields {
			if field == "--state-directory" && i+1 < len(fields) {
				return fields[i+1]
			}
			if directory, ok := strings.CutPrefix(field, "--state-directory="); ok {
				return directory
			}
		}
	}
	return "/var/lib/gr8s/server"
}

func waitForAdmin(ctx context.Context, path string) (kubernetes.Interface, error) {
	for {
		if isFile(path) {
			if _, clientset, err := clients(path); err == nil {
				if _, err := clientset.Discovery().ServerVersion(); err == nil {
					return clientset, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("gr8s-server did not answer at %s; see journalctl -u gr8s-server", path)
		case <-time.After(2 * time.Second):
		}
	}
}

func waitForLocalNode(ctx context.Context, clientset kubernetes.Interface) error {
	for {
		if name, err := localNode(ctx, clientset); err == nil {
			if node, err := clientset.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{}); err == nil && nodeReady(node) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("this machine's node did not become Ready; see journalctl -u gr8s-server")
		case <-time.After(2 * time.Second):
		}
	}
}

func nodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// SetupRBAC is what gr8 setup grants USER: what gr8 calls, and nothing more. Pods,
// their exec, Secrets and SecurityProfiles in NAMESPACE, the user's own; reading
// Nodes, and NAMESPACE itself; and the cluster-scoped SandboxProfiles and
// ClusterNetworkPolicies gr8 makes for a run.
func SetupRBAC(user, namespace string) (*rbacv1.Role, *rbacv1.RoleBinding, *rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding) {
	name := "gr8s:gr8:" + strings.TrimPrefix(user, "gr8:")
	labels := map[string]string{"app.kubernetes.io/managed-by": "gr8"}
	meta := metav1.ObjectMeta{Name: name, Labels: labels}
	namespaced := meta
	namespaced.Namespace = namespace
	edit := []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	subjects := []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: user}}
	role := &rbacv1.Role{ObjectMeta: namespaced, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: edit},
		{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"get", "create"}},
		{APIGroups: []string{"agents.kruise.io"}, Resources: []string{"securityprofiles"}, Verbs: edit},
	}}
	clusterRole := &rbacv1.ClusterRole{ObjectMeta: meta, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}, ResourceNames: []string{namespace}},
		{APIGroups: []string{"gr8.gr8s.io"}, Resources: []string{"sandboxprofiles"}, Verbs: edit},
		{APIGroups: []string{"policy.networking.k8s.io"}, Resources: []string{"clusternetworkpolicies"}, Verbs: edit},
	}}
	binding := &rbacv1.RoleBinding{ObjectMeta: namespaced, Subjects: subjects,
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name}}
	clusterBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: meta, Subjects: subjects,
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}}
	return role, binding, clusterRole, clusterBinding
}

func applySetupRBAC(ctx context.Context, clientset kubernetes.Interface, user, namespace string) error {
	role, binding, clusterRole, clusterBinding := SetupRBAC(user, namespace)
	rbac := clientset.RbacV1()
	create, update := metav1.CreateOptions{}, metav1.UpdateOptions{}
	// Each object is created, or replaced when a previous setup made it.
	for _, step := range []struct{ create, update func() error }{
		{func() error { _, err := rbac.Roles(namespace).Create(ctx, role, create); return err },
			func() error { _, err := rbac.Roles(namespace).Update(ctx, role, update); return err }},
		{func() error { _, err := rbac.RoleBindings(namespace).Create(ctx, binding, create); return err },
			func() error { _, err := rbac.RoleBindings(namespace).Update(ctx, binding, update); return err }},
		{func() error { _, err := rbac.ClusterRoles().Create(ctx, clusterRole, create); return err },
			func() error { _, err := rbac.ClusterRoles().Update(ctx, clusterRole, update); return err }},
		{func() error { _, err := rbac.ClusterRoleBindings().Create(ctx, clusterBinding, create); return err },
			func() error { _, err := rbac.ClusterRoleBindings().Update(ctx, clusterBinding, update); return err }},
	} {
		err := step.create()
		if apierrors.IsAlreadyExists(err) {
			err = step.update()
		}
		if err != nil {
			return fmt.Errorf("granting %s: %w", user, err)
		}
	}
	return nil
}
