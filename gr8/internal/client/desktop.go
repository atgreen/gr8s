package client

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A gr8 sandbox is a desktop session's (podster-wv1w.15): it gets the caller's
// Wayland display and audio, unless asked not to. Never X11, whose clients can
// read every other window and every key, and never the D-Bus session bus, through
// which a client can start processes outside the sandbox. An audio socket also
// lets the command record from the microphone.

// Desktop is what the command gets of the caller's session.
type Desktop struct {
	Sockets []string // host paths, bound at the same paths in the sandbox
	Env     []string // NAME=VALUE pointing the command at them
}

// DesktopFor returns the sockets and environment for a command of uid, from the
// caller's environment (getenv) and the sockets that exist (isSocket).
func DesktopFor(getenv func(string) string, uid int, display, audio bool, isSocket func(string) bool) Desktop {
	runtime := getenv("XDG_RUNTIME_DIR")
	if runtime == "" {
		runtime = "/run/user/" + strconv.Itoa(uid)
	}
	var desktop Desktop
	// The sandbox binds only sockets in a user's runtime directory.
	usable := func(socket string) bool { return strings.HasPrefix(socket, "/run/user/") && isSocket(socket) }
	if display {
		name := getenv("WAYLAND_DISPLAY")
		if name == "" {
			name = "wayland-0"
		}
		socket := name
		if !filepath.IsAbs(name) {
			socket = filepath.Join(runtime, name)
		}
		if usable(socket) {
			desktop.Sockets = append(desktop.Sockets, socket)
			desktop.Env = append(desktop.Env, "WAYLAND_DISPLAY="+name)
		}
	}
	if audio {
		if socket := filepath.Join(runtime, "pipewire-0"); usable(socket) {
			desktop.Sockets = append(desktop.Sockets, socket)
		}
		if socket := filepath.Join(runtime, "pulse", "native"); usable(socket) {
			desktop.Sockets = append(desktop.Sockets, socket)
			desktop.Env = append(desktop.Env, "PULSE_SERVER=unix:"+socket)
		}
	}
	if len(desktop.Sockets) > 0 {
		desktop.Env = append(desktop.Env, "XDG_RUNTIME_DIR="+runtime)
	}
	return desktop
}

func isSocket(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}
