// gr8 runs a command as though directly, but in a sandboxed Pod on the
// local gr8s node: subject to NetworkPolicy, visible in the dashboard, and
// confined by Landlock to the working directory.
//
//	gr8 [flags] COMMAND [ARG...]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/atgreen/gr8s/gr8/internal/client"
	"github.com/atgreen/gr8s/gr8/internal/sandbox"
)

type stringList []string

func (list *stringList) String() string     { return fmt.Sprint(*list) }
func (list *stringList) Set(s string) error { *list = append(*list, s); return nil }

func main() {
	// The Pod runs this same binary: "hold" as the container's process, and
	// "launch" then "enter" and "confine" around the command, each after
	// --internal, so no command of those names is ever mistaken for one.
	if len(os.Args) > 2 && os.Args[1] == sandbox.Internal {
		switch os.Args[2] {
		case "hold":
			os.Exit(sandbox.Hold())
		case "launch":
			os.Exit(sandbox.Launch(os.Args[3:]))
		case "enter":
			os.Exit(sandbox.Enter(client.HostRoot, os.Args[3:]))
		case "confine":
			os.Exit(sandbox.Confine(os.Args[3:]))
		}
		fmt.Fprintf(os.Stderr, "gr8: no internal mode %q\n", os.Args[2])
		os.Exit(sandbox.ExitCannotRun)
	}
	os.Exit(run())
}

func run() int {
	var options client.Options
	var readOnly, readWrite, env, allow stringList
	var login, logout string
	var logins bool
	flags := flag.NewFlagSet("gr8", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "usage: gr8 [flags] COMMAND [ARG...]\n\n"+
			"Run COMMAND in a sandboxed Pod on this host's gr8s node. It sees the host's\n"+
			"files, may write only the working directory, may reach only the hostnames a\n"+
			"ClusterNetworkPolicy or --allow permits, and gets the Wayland display, audio\n"+
			"and GPU.\n\n")
		flags.PrintDefaults()
	}
	flags.StringVar(&options.Kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG, then ~/.kube/config)")
	flags.StringVar(&options.Node, "node", "", "node to run on (default: the node with this host's address)")
	flags.StringVar(&options.Namespace, "namespace", "gr8", "namespace for the Pod")
	flags.StringVar(&options.Image, "image", "registry.k8s.io/pause:3.10", "container image (its files are not used)")
	flags.BoolVar(&options.Keep, "keep", false, "keep the Pod after the command exits")
	flags.BoolVar(&options.NoDisplay, "no-display", false, "withhold the Wayland display")
	flags.BoolVar(&options.NoAudio, "no-audio", false, "withhold audio (and the microphone)")
	flags.BoolVar(&options.NoGPU, "no-gpu", false, "withhold the GPU render nodes")
	flags.StringVar(&options.Policy, "policy", "", "the policy `FILE`, or a name in ~/.config/gr8/policies (default: the command's own)")
	flags.StringVar(&options.CPU, "cpu", "", "the command's CPUs, e.g. 4 or 500m (default: 1, up to half the node's)")
	flags.StringVar(&options.Memory, "memory", "", "the command's memory, e.g. 8Gi (default: 1Gi, up to half the node's)")
	flags.BoolVar(&options.Verbose, "v", false, "report the Pod gr8 creates")
	flags.StringVar(&login, "login", "", "move the `NAME`d login (claude, or one in ~/.config/gr8/logins.yaml) into the cluster")
	flags.StringVar(&logout, "logout", "", "remove the `NAME`d login from the cluster")
	flags.BoolVar(&logins, "logins", false, "list the logins gr8 knows and which are stored")
	flags.Var(&readOnly, "ro", "also allow reading `PATH` (repeatable)")
	flags.Var(&readWrite, "rw", "also allow writing `PATH` (repeatable)")
	flags.Var(&allow, "allow", "also allow reaching `HOSTNAME` (repeatable; *.example.com for subdomains)")
	flags.Var(&env, "env", "also pass environment variable `NAME` (repeatable)")
	_ = flags.Parse(os.Args[1:])
	switch {
	case login != "":
		if err := client.StoreLogin(options.Kubeconfig, options.Namespace, login); err != nil {
			fmt.Fprintf(os.Stderr, "gr8 --login %s: %v\n", login, err)
			return 1
		}
		fmt.Printf("gr8: %s's login is in the cluster; sandboxed runs of it hold stand-in tokens\n", login)
		return 0
	case logout != "":
		if err := client.RemoveLogin(options.Kubeconfig, options.Namespace, logout); err != nil {
			fmt.Fprintf(os.Stderr, "gr8 --logout %s: %v\n", logout, err)
			return 1
		}
		fmt.Printf("gr8: %s's login is gone from the cluster (its own file on this host is untouched)\n", logout)
		return 0
	case logins:
		lines, err := client.ListLogins(options.Kubeconfig, options.Namespace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gr8 --logins: %v\n", err)
			return 1
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		return 0
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return 2
	}
	options.ReadOnly, options.ReadWrite, options.Env, options.Allow = readOnly, readWrite, env, allow
	options.Command = flags.Args()

	status, err := client.Run(options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gr8: %v\n", err)
		return sandbox.ExitCannotRun
	}
	return status
}
