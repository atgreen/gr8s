// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"

	"golang.org/x/term"

	"github.com/atgreen/gr8s/gr8/internal/sandbox"
)

// A command at a terminal runs in a session its Pod keeps (podster-dgi9), which gr8
// attaches to over an exec stream. When the stream breaks, as when a laptop sleeps or
// the network drops, gr8 waits for the Pod and attaches again; the command never
// knew. It ends with the command, or when the user leaves it running.

// errSessionGone is the sandbox ending under a session.
var errSessionGone = errors.New("the sandbox is gone")

// relayArgv is what gr8 execs in the Pod to reach its session: to start it with
// command (the launcher's argv), or, with command nil, to attach to it.
func relayArgv(launcher string, command []string) []string {
	argv := []string{launcher, sandbox.Internal, "attach"}
	if command != nil {
		argv = append(append(argv, "--start", "--"), command...)
	}
	return argv
}

// runSession starts command (the launcher's argv) in pod's session, or, with command
// nil, attaches to the one running, and stays with it until it ends, attaching again
// whenever the stream breaks. launcher is gr8's path in the Pod. It returns the
// command's status; left is true when the user left it running instead.
func runSession(ctx context.Context, config *rest.Config, clientset kubernetes.Interface,
	pod *corev1.Pod, launcher string, command []string, gate *terminalGate) (status int, left bool, err error) {
	start := command
	for {
		_, err := execInPod(ctx, config, clientset, pod, relayArgv(launcher, start), gate)
		if ctx.Err() != nil {
			// A hang-up or kill, of gr8 or its terminal: the command goes on.
			return 0, true, nil
		}
		// A broken stream ends the relay as the command ending does, and client-go
		// may report neither, so the session is asked which it was.
		if err == nil {
			status, err = execQuiet(ctx, config, clientset, pod, []string{launcher, sandbox.Internal, "attach", "--status"})
			switch {
			case err == nil && status == sandbox.ExitSessionGone:
				return 0, false, errSessionGone
			case err == nil && status != sandbox.ExitSessionRunning:
				return status, false, nil
			case err == nil:
				err = errors.New("the stream ended while the command runs")
			}
		}
		start = nil
		// At a terminal, on its bottom row, so a full-screen command's screen is
		// left as it was for when it redraws.
		if gate != nil {
			gate.Banner(fmt.Sprintf("reconnecting to %s (%s); Ctrl-C leaves it running", pod.Name, brief(err)))
		} else {
			fmt.Fprintf(os.Stderr, "gr8: reconnecting to %s (%s); Ctrl-C leaves it running\n", pod.Name, brief(err))
		}
		state := waitForSandbox(ctx, clientset, pod)
		if gate != nil {
			gate.ClearBanner()
		}
		switch state {
		case sandboxBack:
			continue
		case sandboxLeft:
			return 0, true, nil
		default:
			return 0, false, errSessionGone
		}
	}
}

type sandboxState int

const (
	sandboxBack sandboxState = iota
	sandboxLeft
	sandboxEnded
)

// waitForSandbox waits until pod answers again, backing off to 15 s. Ctrl-C, or a
// hang-up, leaves it running.
func waitForSandbox(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod) sandboxState {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	for delay := time.Second; ; delay = min(2*delay, 15*time.Second) {
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		current, err := clientset.CoreV1().Pods(pod.Namespace).Get(check, pod.Name, metav1.GetOptions{})
		cancel()
		switch {
		case err == nil && current.DeletionTimestamp == nil && current.Status.Phase == corev1.PodRunning:
			return sandboxBack
		case err == nil && current.Status.Phase != corev1.PodPending && current.Status.Phase != corev1.PodRunning,
			apierrors.IsNotFound(err):
			return sandboxEnded
		}
		select {
		case <-interrupt:
			return sandboxLeft
		case <-ctx.Done():
			return sandboxLeft
		case <-time.After(delay):
		}
	}
}

// brief is err's last part, which says what happened without client-go's prefixes.
func brief(err error) string {
	text := err.Error()
	if i := strings.LastIndex(text, ": "); i >= 0 && i+2 < len(text) {
		return text[i+2:]
	}
	return text
}

// leftRunning tells the user how to come back to the session they left.
func leftRunning(pod *corev1.Pod) {
	fmt.Fprintf(os.Stderr, "\r\ngr8: %s goes on running; gr8 --attach %s comes back to it, gr8 --sessions lists yours\r\n",
		pod.Name, pod.Name)
}

// cleanUpRun deletes a run's Pod and what gr8 made for it by its name: the
// cluster-scoped ClusterNetworkPolicy and SandboxProfile (the Pod's own Secrets and
// SecurityProfiles go with it, which own them).
func cleanUpRun(clientset kubernetes.Interface, namespace, name string) {
	deleteAllowPolicy(clientset, name)
	deleteRunSandboxProfile(clientset, name)
	deletePod(clientset, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}})
}

// ownRuns lists the user's gr8 Pods in namespace, oldest first.
func ownRuns(ctx context.Context, clientset kubernetes.Interface, namespace, user string) ([]corev1.Pod, error) {
	list, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=gr8,%s=%s", LabelManagedBy, LabelUser, LabelValue(user)),
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].CreationTimestamp.Before(&list.Items[j].CreationTimestamp)
	})
	return list.Items, nil
}

// reapEndedRuns deletes the user's runs whose sandbox has ended: a session whose
// command ended with no one to collect it, or a run whose gr8 couldn't delete it.
func reapEndedRuns(ctx context.Context, clientset kubernetes.Interface, namespace, user string) {
	runs, err := ownRuns(ctx, clientset, namespace, user)
	if err != nil {
		return
	}
	for _, run := range runs {
		if run.Status.Phase == corev1.PodSucceeded || run.Status.Phase == corev1.PodFailed {
			cleanUpRun(clientset, namespace, run.Name)
		}
	}
}

// Sessions lists the user's runs: those still running can be attached to.
func Sessions(kubeconfig, namespace string) ([]string, error) {
	ctx := context.Background()
	_, clientset, err := clients(kubeconfig)
	if err != nil {
		return nil, err
	}
	if namespace == "" {
		namespace = DefaultNamespace(kubeconfig)
	}
	identity, err := currentIdentity()
	if err != nil {
		return nil, err
	}
	runs, err := ownRuns(ctx, clientset, namespace, identity.User)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, run := range runs {
		lines = append(lines, fmt.Sprintf("%-24s %-12s %-10s %s", run.Name, run.Labels[LabelCommand],
			run.Status.Phase, time.Since(run.CreationTimestamp.Time).Round(time.Second)))
	}
	return lines, nil
}

// Attach comes back to the session in the run named pod, and stays with it as Run
// does; when its command ends, the run is cleaned up.
func Attach(kubeconfig, namespace, pod string) (int, error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	config, clientset, err := clients(kubeconfig)
	if err != nil {
		return 0, err
	}
	if namespace == "" {
		namespace = DefaultNamespace(kubeconfig)
	}
	object, err := clientset.CoreV1().Pods(namespace).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}
	if object.Labels[LabelManagedBy] != "gr8" || len(object.Spec.Containers) == 0 ||
		len(object.Spec.Containers[0].Command) == 0 {
		return 0, fmt.Errorf("%s isn't a gr8 run", pod)
	}
	launcher := object.Spec.Containers[0].Command[0]
	var gate *terminalGate
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
		gate = newTerminalGate(os.Stdin, os.Stdout, func() (int, int) {
			width, height, _ := term.GetSize(int(os.Stdout.Fd()))
			return width, height
		}, nil)
		defer gate.Detach()
	}
	status, left, err := runSession(ctx, config, clientset, object, launcher, nil, gate)
	if left {
		leftRunning(object)
		return 0, nil
	}
	if err == nil || errors.Is(err, errSessionGone) {
		cleanUpRun(clientset, namespace, pod)
	}
	return status, err
}

// execQuiet runs argv in pod with no terminal and no input, discarding its output,
// and returns its exit status.
func execQuiet(ctx context.Context, config *rest.Config, clientset kubernetes.Interface,
	pod *corev1.Pod, argv []string) (int, error) {
	request := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(pod.Namespace).Name(pod.Name).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: ContainerName, Command: argv, Stdout: true, Stderr: true},
			scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(config, "POST", request.URL())
	if err != nil {
		return 0, err
	}
	ask, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = executor.StreamWithContext(ask, remotecommand.StreamOptions{Stdout: io.Discard, Stderr: io.Discard})
	var exit utilexec.CodeExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitStatus(), nil
	default:
		return 0, err
	}
}
