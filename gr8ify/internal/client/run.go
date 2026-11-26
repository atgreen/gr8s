package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
)

// Options are the client's command-line settings.
type Options struct {
	Kubeconfig string
	Node       string
	Namespace  string
	Image      string
	Keep       bool
	Verbose    bool
	ReadOnly   []string
	ReadWrite  []string
	Env        []string
	Command    []string
	// Placeholders are NAME=VALUE stand-ins the profile sets, such as an API key the
	// node egress proxy overwrites with the real one.
	Placeholders []string
	// PlaceholderFiles are credential files the sandbox sees with stand-in tokens.
	PlaceholderFiles []string
}

// Run runs options.Command in a gr8ify Pod and returns its exit status.
func Run(options Options) (int, error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	config, clientset, err := clients(options.Kubeconfig)
	if err != nil {
		return 0, err
	}
	identity, err := currentIdentity()
	if err != nil {
		return 0, err
	}
	launcher, err := launcherPath()
	if err != nil {
		return 0, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	node := options.Node
	if node == "" {
		if node, err = localNode(ctx, clientset); err != nil {
			return 0, err
		}
	}
	if err := ensureNamespace(ctx, clientset, options.Namespace); err != nil {
		return 0, err
	}

	pod := NewPod(PodRequest{
		Namespace: options.Namespace,
		Node:      node,
		Image:     options.Image,
		Launcher:  launcher,
		Command:   filepath.Base(options.Command[0]),
		Identity:  identity,
	}, randomSuffix())
	pod, err = clientset.CoreV1().Pods(options.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return 0, fmt.Errorf("creating the Pod: %w", err)
	}
	options.logf("Pod %s/%s on node %s", pod.Namespace, pod.Name, node)
	if !options.Keep {
		defer deletePod(clientset, pod)
	}
	if err := waitRunning(ctx, clientset, pod); err != nil {
		return 0, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}
	grant := Profile(options.Command[0], home, clusterProfiles(ctx, clientset))
	options.ReadOnly = append(grant.ReadOnly, options.ReadOnly...)
	options.ReadWrite = append(grant.ReadWrite, options.ReadWrite...)
	options.PlaceholderFiles = grant.Placeholders
	for name, value := range grant.Env {
		options.Placeholders = append(options.Placeholders, name+"="+value)
	}
	// While the sandbox runs with stand-in tokens, keep the injected credential as
	// fresh as the host's own login (podster-wv1w.7).
	if len(grant.Placeholders) > 0 {
		go syncCredentials(ctx, clientset, options.Namespace, options.Command[0], home)
	}
	argv := append([]string{HostRoot + launcher, "launch", "--cwd", cwd, "--home", home},
		launchFlags(options)...)
	argv = append(append(argv, "--"), options.Command...)
	return execInPod(ctx, config, clientset, pod, argv)
}

func (options Options) logf(format string, arguments ...any) {
	if options.Verbose {
		fmt.Fprintf(os.Stderr, "gr8ify: "+format+"\n", arguments...)
	}
}

func launchFlags(options Options) []string {
	var flags []string
	for _, path := range options.ReadOnly {
		flags = append(flags, "--ro", absolute(path))
	}
	for _, path := range options.ReadWrite {
		flags = append(flags, "--rw", absolute(path))
	}
	for _, entry := range SelectEnv(os.Environ(), options.Env) {
		flags = append(flags, "--env", entry)
	}
	for _, entry := range options.Placeholders {
		flags = append(flags, "--env", entry)
	}
	for _, path := range options.PlaceholderFiles {
		flags = append(flags, "--placeholder", path)
	}
	return append(flags, "--trust", TrustMount+"/"+TrustFile)
}

func absolute(path string) string {
	if resolved, err := filepath.Abs(path); err == nil {
		return resolved
	}
	return path
}

func currentIdentity() (Identity, error) {
	current, err := user.Current()
	if err != nil {
		return Identity{}, err
	}
	identity := Identity{User: current.Username, UID: int64(os.Getuid()), GID: int64(os.Getgid())}
	groups, err := os.Getgroups()
	if err != nil {
		return Identity{}, err
	}
	for _, group := range groups {
		identity.Groups = append(identity.Groups, int64(group))
	}
	return identity, nil
}

// launcherPath is this binary's real path on the host, which the Pod reaches
// under HostRoot.
func launcherPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(executable)
}

func localNode(ctx context.Context, clientset kubernetes.Interface) (string, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing nodes: %w", err)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	var local []net.IP
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			local = append(local, network.IP)
		}
	}
	return LocalNode(nodes.Items, local)
}

func ensureNamespace(ctx context.Context, clientset kubernetes.Interface, name string) error {
	_, err := clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = clientset.CoreV1().Namespaces().Create(ctx, NewNamespace(name), metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("namespace %s: %w", name, err)
	}
	return nil
}

func randomSuffix() string {
	const alphabet = "bcdfghjklmnpqrstvwxz2456789"
	bytes := make([]byte, 5)
	_, _ = rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(bytes)
}

func waitRunning(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	pods := clientset.CoreV1().Pods(pod.Namespace)
	var last *corev1.Pod
	for {
		current, err := pods.Get(ctx, pod.Name, metav1.GetOptions{})
		if err == nil {
			last = current
			switch current.Status.Phase {
			case corev1.PodRunning:
				return nil
			case corev1.PodFailed, corev1.PodSucceeded:
				return fmt.Errorf("Pod %s stopped before the command started: %s", pod.Name, podProblem(current))
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Pod %s did not start: %s", pod.Name, podProblem(last))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func podProblem(pod *corev1.Pod) string {
	if pod == nil {
		return "no status"
	}
	for _, status := range pod.Status.ContainerStatuses {
		if waiting := status.State.Waiting; waiting != nil && waiting.Reason != "" {
			return waiting.Reason + ": " + waiting.Message
		}
		if terminated := status.State.Terminated; terminated != nil {
			return fmt.Sprintf("%s (exit %d): %s", terminated.Reason, terminated.ExitCode, terminated.Message)
		}
	}
	return string(pod.Status.Phase) + " " + pod.Status.Message
}

func deletePod(clientset kubernetes.Interface, pod *corev1.Pod) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr(int64(0))})
}

func execInPod(ctx context.Context, config *rest.Config, clientset kubernetes.Interface,
	pod *corev1.Pod, argv []string) (int, error) {
	tty := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	request := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(pod.Namespace).Name(pod.Name).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: ContainerName,
			Command:   argv,
			Stdin:     true,
			Stdout:    true,
			Stderr:    !tty,
			TTY:       tty,
		}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(config, "POST", request.URL())
	if err != nil {
		return 0, err
	}
	streams := remotecommand.StreamOptions{Stdin: os.Stdin, Stdout: os.Stdout}
	if tty {
		state, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return 0, err
		}
		defer term.Restore(int(os.Stdin.Fd()), state)
		sizes := newTerminalSizes(int(os.Stdout.Fd()))
		defer sizes.stop()
		streams.Tty = true
		streams.TerminalSizeQueue = sizes
	} else {
		streams.Stderr = os.Stderr
		// Without a terminal, ^C reaches gr8ify, not the command: end the
		// stream, and the Pod's deletion stops the command.
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
	}
	err = executor.StreamWithContext(ctx, streams)
	var exit utilexec.CodeExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitStatus(), nil
	case ctx.Err() != nil:
		return 130, nil
	default:
		return 0, fmt.Errorf("running the command: %w", err)
	}
}

// terminalSizes reports the local terminal's size at start and on SIGWINCH.
type terminalSizes struct {
	fd      int
	signals chan os.Signal
	sizes   chan remotecommand.TerminalSize
	done    chan struct{}
}

func newTerminalSizes(fd int) *terminalSizes {
	sizes := &terminalSizes{
		fd:      fd,
		signals: make(chan os.Signal, 1),
		sizes:   make(chan remotecommand.TerminalSize, 1),
		done:    make(chan struct{}),
	}
	signal.Notify(sizes.signals, syscall.SIGWINCH)
	sizes.signals <- syscall.SIGWINCH
	go func() {
		for {
			select {
			case <-sizes.done:
				return
			case <-sizes.signals:
				if width, height, err := term.GetSize(fd); err == nil {
					select {
					case sizes.sizes <- remotecommand.TerminalSize{Width: uint16(width), Height: uint16(height)}:
					case <-sizes.done:
						return
					}
				}
			}
		}
	}()
	return sizes
}

func (sizes *terminalSizes) Next() *remotecommand.TerminalSize {
	select {
	case size := <-sizes.sizes:
		return &size
	case <-sizes.done:
		return nil
	}
}

func (sizes *terminalSizes) stop() {
	signal.Stop(sizes.signals)
	close(sizes.done)
}

// clients loads kubeconfig (or $KUBECONFIG, then ~/.kube/config) into a REST config and
// clientset.
func clients(kubeconfig string) (*rest.Config, *kubernetes.Clientset, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{
			ExplicitPath: kubeconfig,
			Precedence:   clientcmd.NewDefaultClientConfigLoadingRules().Precedence,
		}, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	return config, clientset, nil
}
