// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
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

// UserSocket is where gr8s-server gives local users gr8 (podster-7uof): it knows who
// connects from the kernel, makes them a namespace and grant of their own, and
// answers with their kubeconfig. $GR8_SOCKET names another.
func UserSocket(getenv func(string) string) string {
	if path := getenv("GR8_SOCKET"); path != "" {
		return path
	}
	return "/run/gr8s/gr8.sock"
}

// ServerRunning is true when gr8s-server answers on the user socket, so setup needs
// no sudo.
func ServerRunning(socket string) bool {
	connection, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

// AskForKubeconfig asks gr8s-server at socket for the caller's kubeconfig.
func AskForKubeconfig(socket string) ([]byte, error) {
	connection, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Minute))
	raw, err := io.ReadAll(connection)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Kubeconfig string `json:"kubeconfig"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, fmt.Errorf("gr8s-server's answer: %w", err)
	}
	if reply.Error != "" {
		return nil, errors.New(reply.Error)
	}
	return []byte(reply.Kubeconfig), nil
}

// Setup makes the caller a gr8 user of this machine's gr8s node (podster-q35k). When
// gr8s-server runs, that takes nothing but asking it (podster-7uof); otherwise sudo
// starts it first. The credential is the caller's own, never the administrator's.
func Setup(home string) error {
	if os.Geteuid() == 0 {
		return errors.New("run gr8 --setup as the user who will run gr8, not as root")
	}
	socket := UserSocket(os.Getenv)
	if !ServerRunning(socket) {
		fmt.Fprintln(os.Stderr, "gr8: starting gr8s-server; sudo will ask for your password")
		command := exec.Command("sudo", "systemctl", "enable", "--now", "gr8s-server")
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("sudo systemctl enable --now gr8s-server: %w", err)
		}
		if err := waitFor(4*time.Minute, func() bool { return ServerRunning(socket) }); err != nil {
			return errors.New("gr8s-server did not start; see journalctl -u gr8s-server")
		}
	}
	kubeconfig, err := AskForKubeconfig(socket)
	if err != nil {
		return fmt.Errorf("gr8s-server: %w", err)
	}
	path := SetupKubeconfig(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, kubeconfig, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "gr8: waiting for this machine's node to be Ready")
	_, clientset, err := clients(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := waitForLocalNode(ctx, clientset); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "gr8: ready; your kubeconfig is %s\n", path)
	return nil
}

func waitFor(limit time.Duration, done func() bool) error {
	for deadline := time.Now().Add(limit); !done(); time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			return errors.New("timed out")
		}
	}
	return nil
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
