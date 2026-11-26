package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Exit statuses for failures before the command runs, as a shell reports them.
const (
	ExitCannotRun = 126
	ExitNotFound  = 127
)

// The command runs at the end of a chain of this binary's modes:
//
//	hold     the Pod container's main process
//	launch   exec'd into the Pod as the caller; makes the namespaces
//	enter    builds the view and chroots, then waits to copy files back
//	confine  applies Landlock and execs the command

// Hold is the Pod container's main process: it waits for the Pod's deletion
// and reaps the processes exec leaves behind, as PID 1 must.
func Hold() int {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, unix.SIGTERM, unix.SIGINT, unix.SIGCHLD)
	for received := range signals {
		if received != unix.SIGCHLD {
			return 0
		}
		for {
			var status unix.WaitStatus
			if pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil); pid <= 0 || err != nil {
				break
			}
		}
	}
	return 0
}

// Launch runs inside the Pod, as the caller's uid. It starts "enter" in a
// new user and mount namespace, where it may mount, and passes on its exit.
func Launch(args []string) int {
	if _, err := ParseArgs(args); err != nil {
		return fail(ExitCannotRun, err)
	}
	child := self("enter", args)
	uid, gid := os.Getuid(), os.Getgid()
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		// Kept across exec as the same uid; confine drops them before the command.
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SYS_CHROOT},
	}
	status, err := runChild(child)
	if err != nil {
		return fail(ExitCannotRun, fmt.Errorf("creating the sandbox namespaces: %w", err))
	}
	return status
}

// Enter runs in the namespaces Launch made. It builds the command's view of
// the host under hostRoot and chroots there, runs "confine", and afterwards
// copies the files the command saved in its private $HOME back to the real one.
func Enter(hostRoot string, args []string) int {
	config, err := ParseArgs(args)
	if err != nil {
		return fail(ExitCannotRun, err)
	}
	view, err := buildView(hostRoot, config)
	if err != nil {
		return fail(ExitCannotRun, err)
	}
	defer view.close()
	if err := unix.Chroot(hostRoot); err != nil {
		return fail(ExitCannotRun, fmt.Errorf("chroot %s: %w", hostRoot, err))
	}
	if err := unix.Chdir(config.Cwd); err != nil {
		return fail(ExitCannotRun, fmt.Errorf("the working directory %s: %w", config.Cwd, err))
	}
	status, err := runChild(self("confine", args))
	if err != nil {
		return fail(ExitCannotRun, err)
	}
	for _, problem := range view.saveBack() {
		fmt.Fprintf(os.Stderr, "gr8: %v\n", problem)
	}
	return status
}

// Confine runs as the command's process: it confines itself and execs.
func Confine(args []string) int {
	// Landlock and NO_NEW_PRIVS bind the thread that sets them; exec must
	// happen from that same thread.
	runtime.LockOSThread()
	config, err := ParseArgs(args)
	if err != nil {
		return fail(ExitCannotRun, err)
	}
	path, err := lookPath(config.Command[0], config.Env)
	if err != nil {
		return fail(ExitNotFound, err)
	}
	abi := LandlockABI()
	if err := RestrictSelf(abi, config.Rules(abi)); err != nil {
		return fail(ExitCannotRun, err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fail(ExitCannotRun, fmt.Errorf("dropping capabilities: %w", err))
	}
	err = unix.Exec(path, config.Command, append(config.Env, trustEnv()...))
	return fail(ExitCannotRun, fmt.Errorf("exec %s: %w", path, err))
}

func self(mode string, args []string) *exec.Cmd {
	child := exec.Command("/proc/self/exe", append([]string{mode}, args...)...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = []string{}
	return child
}

// runChild runs child to completion and returns its exit status, 128+N for
// death by signal N. The terminal delivers ^C and the like to the whole
// foreground group, command included, so they are caught here only to
// outlive the command; SIGTERM and SIGHUP are passed on.
func runChild(child *exec.Cmd) (int, error) {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM, unix.SIGHUP)
	defer signal.Stop(signals)
	if err := child.Start(); err != nil {
		return 0, err
	}
	go func() {
		for received := range signals {
			if received == unix.SIGTERM || received == unix.SIGHUP {
				_ = child.Process.Signal(received)
			}
		}
	}()
	err := child.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	return 0, err
}

// lookPath finds command along env's PATH, in the view the command will see.
func lookPath(command string, env []string) (string, error) {
	if strings.Contains(command, "/") {
		return command, nil
	}
	search := "/usr/local/bin:/usr/bin:/bin"
	for _, entry := range env {
		if value, found := strings.CutPrefix(entry, "PATH="); found {
			search = value
		}
	}
	for _, dir := range filepath.SplitList(search) {
		candidate := filepath.Join(dir, command)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s: command not found", command)
}

func fail(status int, err error) int {
	fmt.Fprintf(os.Stderr, "gr8: %v\n", err)
	return status
}
