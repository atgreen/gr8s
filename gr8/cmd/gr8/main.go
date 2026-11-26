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
	// "launch" then "enter" around the command.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hold":
			os.Exit(sandbox.Hold())
		case "launch":
			os.Exit(sandbox.Launch(os.Args[2:]))
		case "enter":
			os.Exit(sandbox.Enter(client.HostRoot, os.Args[2:]))
		case "confine":
			os.Exit(sandbox.Confine(os.Args[2:]))
		}
	}
	if len(os.Args) > 2 && os.Args[1] == "login" {
		os.Exit(login(os.Args[2:]))
	}
	os.Exit(run())
}

// login stores a command's host login for the node egress proxy to inject.
func login(args []string) int {
	flags := flag.NewFlagSet("gr8 login", flag.ExitOnError)
	kubeconfig := flags.String("kubeconfig", "", "kubeconfig file (default: $KUBECONFIG, then ~/.kube/config)")
	namespace := flags.String("namespace", "gr8", "namespace for the Secret and SecurityProfile")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "usage: gr8 login [flags] claude\n\n"+
			"Move claude's subscription login into the cluster: the node egress proxy adds it\n"+
			"to claude's API requests, and claude in the sandbox sees only stand-in tokens.\n\n")
		flags.PrintDefaults()
	}
	_ = flags.Parse(args)
	if flags.NArg() != 1 || flags.Arg(0) != "claude" {
		flags.Usage()
		return 2
	}
	if err := client.LoginClaude(*kubeconfig, *namespace); err != nil {
		fmt.Fprintf(os.Stderr, "gr8 login: %v\n", err)
		return 1
	}
	fmt.Println("gr8: claude's login is in the cluster; gr8 claude now runs with stand-in tokens")
	return 0
}

func run() int {
	var options client.Options
	var readOnly, readWrite, env, allow stringList
	flags := flag.NewFlagSet("gr8", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "usage: gr8 [flags] COMMAND [ARG...]\n\n"+
			"Run COMMAND in a sandboxed Pod on this host's gr8s node. It sees the host's\n"+
			"files, may write only the working directory, and may reach only the hostnames\n"+
			"a ClusterNetworkPolicy or --allow permits.\n\n")
		flags.PrintDefaults()
	}
	flags.StringVar(&options.Kubeconfig, "kubeconfig", "", "kubeconfig file (default: $KUBECONFIG, then ~/.kube/config)")
	flags.StringVar(&options.Node, "node", "", "node to run on (default: the node with this host's address)")
	flags.StringVar(&options.Namespace, "namespace", "gr8", "namespace for the Pod")
	flags.StringVar(&options.Image, "image", "registry.k8s.io/pause:3.10", "container image (its files are not used)")
	flags.BoolVar(&options.Keep, "keep", false, "keep the Pod after the command exits")
	flags.BoolVar(&options.Verbose, "v", false, "report the Pod gr8 creates")
	flags.Var(&readOnly, "ro", "also allow reading `PATH` (repeatable)")
	flags.Var(&readWrite, "rw", "also allow writing `PATH` (repeatable)")
	flags.Var(&allow, "allow", "also allow reaching `HOSTNAME` (repeatable; *.example.com for subdomains)")
	flags.Var(&env, "env", "also pass environment variable `NAME` (repeatable)")
	_ = flags.Parse(os.Args[1:])
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
