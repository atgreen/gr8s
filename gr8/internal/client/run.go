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
	"slices"
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

	"github.com/atgreen/gr8s/gr8/internal/sandbox"
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
	Allow      []string // hostnames this run alone may reach
	NoDisplay  bool     // withhold the Wayland display
	NoAudio    bool     // withhold the audio sockets
	NoGPU      bool     // withhold the GPU render nodes
	Policy     string   // --policy: a policy file, or a name in ~/.config/gr8/policies
	CPU        string   // the command's CPU, request and limit; default SandboxResources
	Memory     string   // the command's memory, request and limit
	Command    []string
	// Placeholders are NAME=VALUE stand-ins the profile sets, such as an API key the
	// node egress proxy overwrites with the real one.
	Placeholders []string
	// PlaceholderFiles are credential files the sandbox sees with stand-in tokens.
	PlaceholderFiles []string
}

// Run runs options.Command in a gr8 Pod and returns its exit status.
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
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}
	policy, values, err := loadPolicy(&options, home, cwd)
	if err != nil {
		return 0, err
	}
	logins, err := Logins(home)
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

	// The logins this run carries: those stored for its command, applied by their
	// own SecurityProfiles, and those its policy names, applied for it alone. Their
	// hosts are its to reach.
	stored := storedLogins(ctx, clientset, options.Namespace, options.Command[0], logins)
	var named []string
	if policy != nil {
		for _, name := range policy.Spec.loginNames() {
			if _, ok := logins[name]; !ok {
				return 0, fmt.Errorf("the policy names login %q, which gr8 doesn't know", name)
			}
			if !slices.Contains(stored, name) {
				named = append(named, name)
			}
		}
	}
	carried := append(append([]string{}, stored...), named...)
	for _, name := range carried {
		options.Allow = append(options.Allow, logins[name].Hosts()...)
	}

	nodeObject, err := clientset.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("reading node %s: %w", node, err)
	}
	resources, err := SandboxResources(nodeObject.Status.Allocatable, options.CPU, options.Memory)
	if err != nil {
		return 0, err
	}
	pod := NewPod(PodRequest{
		Namespace: options.Namespace,
		Node:      node,
		Image:     options.Image,
		Launcher:  launcher,
		Command:   filepath.Base(options.Command[0]),
		Identity:  identity,
		GPU:       !options.NoGPU && offersGPU(nodeObject),
		Resources: resources,
	}, randomSuffix())
	// The policy goes first, so the command never starts without it.
	if len(options.Allow) > 0 {
		if err := createAllowPolicy(ctx, clientset, options.Namespace, pod.Name, options.Allow); err != nil {
			return 0, err
		}
		options.logf("ClusterNetworkPolicy %s allows %v", pod.Name, options.Allow)
		if !options.Keep {
			defer deleteAllowPolicy(clientset, pod.Name)
		}
	}
	credentials, profile := 0, false
	if policy != nil {
		credentials = len(policy.Spec.valueCredentials())
		profile = credentials > 0 || len(named) > 0
		var loginRules []any
		for _, name := range named {
			loginRules = append(loginRules, LoginRules(name, logins[name])...)
		}
		if err := createPolicyCredentials(ctx, clientset, pod, policy.Spec.valueCredentials(), values, policy.standIns, loginRules); err != nil {
			deletePolicyCredentials(clientset, pod, credentials, true)
			return 0, err
		}
		if !options.Keep {
			defer deletePolicyCredentials(clientset, pod, credentials, profile)
		}
	}
	pod, err = clientset.CoreV1().Pods(options.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return 0, fmt.Errorf("creating the Pod: %w", err)
	}
	options.logf("Pod %s/%s on node %s", pod.Namespace, pod.Name, node)
	if !options.Keep {
		defer deletePod(clientset, pod)
	}
	if policy != nil {
		adoptPolicyCredentials(ctx, clientset, pod, credentials, profile)
		if egress := policy.Spec.egressJSON(); egress != nil {
			if err := postObject(ctx, clientset, sandboxProfiles,
				RunSandboxProfile(pod.Name, filepath.Base(options.Command[0]), egress), "the SandboxProfile"); err != nil {
				return 0, err
			}
			if !options.Keep {
				defer deleteRunSandboxProfile(clientset, pod.Name)
			}
		}
	}
	if err := waitRunning(ctx, clientset, pod); err != nil {
		return 0, err
	}

	grant := Profile(options.Command[0], home, clusterProfiles(ctx, clientset, options.Namespace))
	if policy != nil {
		grant = policy.withGrant(grant, home)
	}
	options.ReadOnly = append(grant.ReadOnly, options.ReadOnly...)
	options.ReadWrite = append(grant.ReadWrite, options.ReadWrite...)
	options.PlaceholderFiles = grant.Placeholders
	for name, value := range grant.Env {
		options.Placeholders = append(options.Placeholders, name+"="+value)
	}
	// Each login's file, as the sandbox sees it, holds stand-ins at its token keys;
	// while the command runs, the host's copy and the Secret are kept in step.
	for _, name := range carried {
		options.PlaceholderFiles = append(options.PlaceholderFiles, logins[name].PlaceholderArg(home))
		go syncLogin(ctx, clientset, options.Namespace, name, logins[name], home)
	}
	argv := append([]string{HostRoot + launcher, sandbox.Internal, "launch", "--cwd", cwd, "--home", home},
		launchFlags(options)...)
	argv = append(append(argv, "--"), options.Command...)
	return execInPod(ctx, config, clientset, pod, argv)
}

// offersGPU says whether node offers GPU render nodes to Pods.
func offersGPU(node *corev1.Node) bool {
	quantity, ok := node.Status.Allocatable[GPUResource]
	return ok && !quantity.IsZero()
}

// loadPolicy finds, approves and reads the command's policy, if it has one, and
// folds what it says into options: hosts into Allow (with its credentials' hosts),
// and its desktop and resources where no flag already says. It reads each
// credential's real value now, so a missing one stops the run before it starts.
func loadPolicy(options *Options, home, cwd string) (*Policy, []string, error) {
	file, found, err := FindPolicy(options.Policy, options.Command[0], home, cwd)
	if err != nil || !found {
		return nil, nil, err
	}
	raw, err := os.ReadFile(file.Path)
	if err != nil {
		return nil, nil, err
	}
	policy, err := ParsePolicy(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file.Path, err)
	}
	ask := func(string) bool { return false }
	if term.IsTerminal(int(os.Stdin.Fd())) {
		ask = TerminalAsk(os.Stdin, os.Stderr)
	}
	if err := ApprovePolicy(file, raw, home, ask); err != nil {
		return nil, nil, err
	}
	options.logf("policy %s", file.Path)
	var values []string
	for _, credential := range policy.Spec.valueCredentials() {
		value, err := CredentialValue(credential.From, home, os.Getenv)
		if err != nil {
			return nil, nil, err
		}
		values = append(values, value)
		options.Allow = append(options.Allow, credential.Hosts...)
	}
	policy.mintStandIns()
	options.Allow = append(options.Allow, policy.Spec.Hosts...)
	if desktop := policy.Spec.Desktop; desktop != nil {
		options.NoDisplay = options.NoDisplay || (desktop.Display != nil && !*desktop.Display)
		options.NoAudio = options.NoAudio || (desktop.Audio != nil && !*desktop.Audio)
		options.NoGPU = options.NoGPU || (desktop.GPU != nil && !*desktop.GPU)
	}
	if options.CPU == "" {
		options.CPU = policy.Spec.Resources.CPU
	}
	if options.Memory == "" {
		options.Memory = policy.Spec.Resources.Memory
	}
	return &policy, values, nil
}

// withGrant adds the policy's home paths, environment and credential stand-ins to
// what the command's SandboxProfile grants.
func (policy *Policy) withGrant(grant Grant, home string) Grant {
	inHome := func(paths []string) []string {
		var out []string
		for _, path := range paths {
			out = append(out, filepath.Join(home, path))
		}
		return out
	}
	spec := policy.Spec
	grant.ReadOnly = append(grant.ReadOnly, inHome(spec.Home.ReadOnly)...)
	grant.ReadWrite = append(grant.ReadWrite, inHome(spec.Home.ReadWrite)...)
	grant.Placeholders = append(grant.Placeholders, inHome(spec.Home.Placeholders)...)
	env := map[string]string{}
	for name, value := range grant.Env {
		env[name] = value
	}
	for name, value := range spec.Env {
		env[name] = value
	}
	for i, credential := range spec.valueCredentials() {
		if credential.Env != "" {
			env[credential.Env] = policy.standIn(i)
		}
	}
	grant.Env = env
	return grant
}

// StandIn is what a sandbox holds in place of a credential, which the node egress
// proxy recognizes (podster-wv1w.12).
const StandIn = "gr8s-injected"

func (options Options) logf(format string, arguments ...any) {
	if options.Verbose {
		fmt.Fprintf(os.Stderr, "gr8: "+format+"\n", arguments...)
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
	desktop := DesktopFor(os.Getenv, os.Getuid(), !options.NoDisplay, !options.NoAudio, isSocket)
	for _, socket := range desktop.Sockets {
		flags = append(flags, "--socket", socket)
	}
	for _, entry := range desktop.Env {
		flags = append(flags, "--env", entry)
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
	var runningSince time.Time
	for {
		current, err := pods.Get(ctx, pod.Name, metav1.GetOptions{})
		if err == nil {
			last = current
			switch current.Status.Phase {
			case corev1.PodRunning:
				if runningSince.IsZero() {
					runningSince = time.Now()
				}
				// A node that predates the gate never reports it.
				ready, reported := networkReady(current)
				if ready || !reported && time.Since(runningSince) > legacyNetworkGrace {
					return nil
				}
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

// legacyNetworkGrace is how long a running Pod whose node never reports NetworkReady
// is given before the command starts anyway.
const legacyNetworkGrace = 2 * time.Second

// networkReady says whether pod is Ready, which waits for its NetworkReady gate, and
// whether its node reports that gate at all.
func networkReady(pod *corev1.Pod) (ready, reported bool) {
	for _, condition := range pod.Status.Conditions {
		switch condition.Type {
		case corev1.PodReady:
			ready = condition.Status == corev1.ConditionTrue
		case NetworkReady:
			reported = true
		}
	}
	return ready, ready || reported
}

func podProblem(pod *corev1.Pod) string {
	if pod == nil {
		return "no status"
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == NetworkReady && condition.Status != corev1.ConditionTrue {
			return "its network policy is not in place: " + condition.Message
		}
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
		// Without a terminal, ^C reaches gr8, not the command: end the
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
