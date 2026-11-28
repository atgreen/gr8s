// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// A command run at a terminal lives in a session the Pod's hold process owns
// (podster-dgi9): hold gives it a terminal of its own and keeps it, so the command
// outlives the exec stream gr8 reached it by. gr8 attaches through "attach", a relay
// between the exec stream and the session; when the stream breaks, as when a laptop
// sleeps, gr8 attaches again, and the command never knew.

// SessionSocket is where hold serves the session: an abstract socket, in the Pod's
// network namespace, so only what runs in the Pod reaches it.
const SessionSocket = "@gr8s/gr8-session"

// ExitSessionGone is attach's status when there is no session to attach to, and
// ExitSessionRunning attach --status's when its command still runs.
const (
	ExitSessionGone    = 125
	ExitSessionRunning = 124
)

// sessionIdle is how long hold keeps an ended command's status for gr8 to collect
// before it exits, and with it the Pod's container.
const sessionIdle = time.Hour

const (
	frameStart  = 'S' // gr8 to hold: start the command, JSON sessionStart
	frameAttach = 'A' // gr8 to hold: attach, JSON terminal size
	frameData   = 'D' // either way: terminal bytes
	frameResize = 'R' // gr8 to hold: JSON terminal size
	frameExit   = 'X' // hold to gr8: the command's status, JSON
	frameQuery  = 'Q' // gr8 to hold: has the command ended?
	frameAlive  = 'P' // hold to gr8: it still runs
)

type terminalSize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type sessionStart struct {
	terminalSize
	Argv []string `json:"argv"`
}

func writeFrame(w io.Writer, kind byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(append(header, payload...)); err != nil {
		return err
	}
	return nil
}

func readFrame(r *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > 1<<20 {
		return 0, nil, errors.New("session frame too large")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

// session is the command hold runs on its own terminal, and the one gr8 attached.
type session struct {
	mutex   sync.Mutex
	pid     int
	master  *os.File
	client  net.Conn
	writes  sync.Mutex // one frame at a time to the client
	exited  bool
	status  int
	endedAt time.Time
	drained chan struct{} // closed once the command's terminal has no more output
}

// serveSessions answers gr8 on SessionSocket until hold ends.
func serveSessions(s *session) {
	listener, err := net.Listen("unix", SessionSocket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gr8: no session socket: %v\n", err)
		return
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go s.serve(connection)
	}
}

func (s *session) serve(connection net.Conn) {
	reader := bufio.NewReader(connection)
	kind, payload, err := readFrame(reader)
	if err != nil {
		connection.Close()
		return
	}
	var size terminalSize
	switch kind {
	case frameStart:
		var start sessionStart
		if json.Unmarshal(payload, &start) != nil || len(start.Argv) == 0 {
			connection.Close()
			return
		}
		size = start.terminalSize
		if err := s.start(start.Argv, size); err != nil {
			fmt.Fprintf(os.Stderr, "gr8: starting the session: %v\n", err)
			s.send(connection, frameExit, mustJSON(map[string]int{"status": ExitCannotRun}))
			connection.Close()
			return
		}
	case frameAttach:
		_ = json.Unmarshal(payload, &size)
	case frameQuery:
		// Asked, not attached: a broken stream ends the relay the same way the
		// command ending does, so gr8 asks which it was.
		s.mutex.Lock()
		exited, status := s.exited, s.status
		s.mutex.Unlock()
		if exited {
			s.send(connection, frameExit, mustJSON(map[string]int{"status": status}))
		} else {
			s.send(connection, frameAlive, nil)
		}
		connection.Close()
		return
	default:
		connection.Close()
		return
	}
	s.attach(connection, size)
	for {
		kind, payload, err := readFrame(reader)
		if err != nil {
			s.detach(connection)
			return
		}
		s.mutex.Lock()
		master, current := s.master, s.client == connection
		s.mutex.Unlock()
		if !current || master == nil {
			continue
		}
		switch kind {
		case frameData:
			_, _ = master.Write(payload)
		case frameResize:
			if json.Unmarshal(payload, &size) == nil {
				setSize(master, size)
			}
		}
	}
}

// start runs argv on a new terminal, as its session leader. Only the first start
// starts anything; a later one attaches to what runs.
func (s *session) start(argv []string, size terminalSize) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.master != nil || s.exited {
		return nil
	}
	master, slave, err := openTerminal()
	if err != nil {
		return err
	}
	defer slave.Close()
	setSize(master, size)
	process, err := os.StartProcess(argv[0], argv, &os.ProcAttr{
		Env:   os.Environ(),
		Files: []*os.File{slave, slave, slave},
		Sys:   &unix.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	})
	if err != nil {
		master.Close()
		return err
	}
	s.pid, s.master, s.drained = process.Pid, master, make(chan struct{})
	go s.pump(master, s.drained)
	return nil
}

// pump copies the command's terminal output to whoever is attached; with no one,
// it is dropped, and the command redraws when someone attaches.
func (s *session) pump(master *os.File, drained chan struct{}) {
	defer close(drained)
	buffer := make([]byte, 32*1024)
	for {
		n, err := master.Read(buffer)
		if n > 0 {
			s.mutex.Lock()
			client := s.client
			s.mutex.Unlock()
			if client != nil {
				s.send(client, frameData, append([]byte(nil), buffer[:n]...))
			}
		}
		if err != nil {
			return
		}
	}
}

// attach makes connection the session's client, in place of any other, and has a
// full-screen command draw itself for it: a size a row short, then the real one.
func (s *session) attach(connection net.Conn, size terminalSize) {
	s.mutex.Lock()
	previous := s.client
	s.client = connection
	master, exited, status := s.master, s.exited, s.status
	s.mutex.Unlock()
	if previous != nil && previous != connection {
		previous.Close()
	}
	if exited {
		s.send(connection, frameExit, mustJSON(map[string]int{"status": status}))
		return
	}
	if master != nil && size.Rows > 1 {
		setSize(master, terminalSize{Rows: size.Rows - 1, Cols: size.Cols})
		time.Sleep(50 * time.Millisecond)
		setSize(master, size)
	}
}

func (s *session) detach(connection net.Conn) {
	s.mutex.Lock()
	if s.client == connection {
		s.client = nil
	}
	s.mutex.Unlock()
	connection.Close()
}

func (s *session) send(connection net.Conn, kind byte, payload []byte) {
	s.writes.Lock()
	defer s.writes.Unlock()
	_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if writeFrame(connection, kind, payload) != nil {
		connection.Close()
	}
}

// ended records the command's status and tells the client, if one is attached, once
// its last output has gone to them.
func (s *session) ended(status int) {
	s.mutex.Lock()
	drained := s.drained
	s.mutex.Unlock()
	if drained != nil {
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
		}
	}
	s.mutex.Lock()
	s.exited, s.status, s.endedAt = true, status, time.Now()
	client := s.client
	s.mutex.Unlock()
	if client != nil {
		s.send(client, frameExit, mustJSON(map[string]int{"status": status}))
	}
}

// abandoned is true once the command has ended and no one collected its status for
// sessionIdle.
func (s *session) abandoned() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.exited && s.client == nil && time.Since(s.endedAt) > sessionIdle
}

func (s *session) commandPid() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.pid
}

func openTerminal() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening a terminal: %w", err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, err
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func setSize(terminal *os.File, size terminalSize) {
	if size.Rows == 0 || size.Cols == 0 {
		return
	}
	_ = unix.IoctlSetWinsize(int(terminal.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: size.Rows, Col: size.Cols})
}

func mustJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

// Attach is gr8's relay in the Pod, on the exec stream's terminal: it starts the
// session with --start -- ARGV, or attaches to the one running, and copies keys,
// output and size between them until the command ends, exiting with its status.
// The stream breaking ends only this relay; the command goes on.
func Attach(args []string) int {
	if len(args) == 1 && args[0] == "--status" {
		return sessionStatus()
	}
	var start []string
	if len(args) > 0 && args[0] == "--start" {
		if len(args) < 3 || args[1] != "--" {
			return fail(ExitCannotRun, errors.New("attach --start -- ARGV"))
		}
		start = args[2:]
	}
	connection, err := net.Dial("unix", SessionSocket)
	if err != nil {
		return fail(ExitSessionGone, fmt.Errorf("no session in this sandbox: %w", err))
	}
	defer connection.Close()
	size := localSize()
	if start != nil {
		err = writeFrame(connection, frameStart, mustJSON(sessionStart{terminalSize: size, Argv: start}))
	} else {
		err = writeFrame(connection, frameAttach, mustJSON(size))
	}
	if err != nil {
		return fail(ExitSessionGone, err)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if state, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
			defer term.Restore(int(os.Stdin.Fd()), state)
		}
	}
	var writes sync.Mutex
	send := func(kind byte, payload []byte) {
		writes.Lock()
		defer writes.Unlock()
		_ = writeFrame(connection, kind, payload)
	}
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(buffer)
			if n > 0 {
				send(frameData, append([]byte(nil), buffer[:n]...))
			}
			if err != nil {
				return
			}
		}
	}()
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, unix.SIGWINCH)
	go func() {
		for range resized {
			send(frameResize, mustJSON(localSize()))
		}
	}()
	reader := bufio.NewReader(connection)
	for {
		kind, payload, err := readFrame(reader)
		if err != nil {
			// hold went without a status: the sandbox is gone.
			return ExitSessionGone
		}
		switch kind {
		case frameData:
			_, _ = os.Stdout.Write(payload)
		case frameExit:
			var exit struct {
				Status int `json:"status"`
			}
			_ = json.Unmarshal(payload, &exit)
			return exit.Status
		}
	}
}

// sessionStatus is attach --status: the command's status when it has ended,
// ExitSessionRunning while it runs, ExitSessionGone with no session.
func sessionStatus() int {
	connection, err := net.Dial("unix", SessionSocket)
	if err != nil {
		return ExitSessionGone
	}
	defer connection.Close()
	if writeFrame(connection, frameQuery, nil) != nil {
		return ExitSessionGone
	}
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, payload, err := readFrame(bufio.NewReader(connection))
	switch {
	case err != nil:
		return ExitSessionGone
	case kind == frameAlive:
		return ExitSessionRunning
	}
	var exit struct {
		Status int `json:"status"`
	}
	_ = json.Unmarshal(payload, &exit)
	return exit.Status
}

func localSize() terminalSize {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return terminalSize{}
	}
	return terminalSize{Rows: uint16(height), Cols: uint16(width)}
}
