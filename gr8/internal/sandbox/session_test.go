// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// client is one end of a session connection, as gr8's relay would hold it.
type client struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
	output strings.Builder
}

func connect(t *testing.T, s *session) *client {
	near, far := net.Pipe()
	go s.serve(far)
	return &client{t: t, conn: near, reader: bufio.NewReader(near)}
}

func (c *client) send(kind byte, payload []byte) {
	if err := writeFrame(c.conn, kind, payload); err != nil {
		c.t.Fatal(err)
	}
}

// until reads frames until the output holds text, or the command's status arrives.
func (c *client) until(text string) (status int, exited bool) {
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for !strings.Contains(c.output.String(), text) {
		kind, payload, err := readFrame(c.reader)
		if err != nil {
			c.t.Fatalf("waiting for %q (have %q): %v", text, c.output.String(), err)
		}
		switch kind {
		case frameData:
			c.output.Write(payload)
		case frameExit:
			var exit struct{ Status int }
			_ = json.Unmarshal(payload, &exit)
			return exit.Status, true
		}
	}
	return 0, false
}

// reap waits for the session's command, as hold's reaper does, and reports it.
func reap(t *testing.T, s *session) {
	// The session starts its command when its start frame arrives: wait for that,
	// or Wait4 would wait for any child at all.
	for deadline := time.Now().Add(5 * time.Second); s.commandPid() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(s.commandPid(), &status, 0, nil); err != nil {
		t.Error(err)
		return
	}
	s.ended(status.ExitStatus())
}

func start(argv ...string) []byte {
	return mustJSON(sessionStart{terminalSize: terminalSize{Rows: 24, Cols: 80}, Argv: argv})
}

func TestACommandOutlivesItsClientAndTellsTheNextHowItEnded(t *testing.T) {
	s := &session{}
	first := connect(t, s)
	first.send(frameStart, start("/bin/sh", "-c", "echo ready; read x; echo after $x; exit 3"))
	first.until("ready")
	// The client goes, as an exec stream does when a laptop sleeps.
	first.conn.Close()
	time.Sleep(100 * time.Millisecond)
	// The command didn't notice; the next client to attach drives it.
	second := connect(t, s)
	second.send(frameAttach, mustJSON(terminalSize{Rows: 30, Cols: 100}))
	second.send(frameData, []byte("resumed\r"))
	second.until("after resumed")
	go reap(t, s)
	if status, exited := second.until("\x00never"); !exited || status != 3 {
		t.Errorf("status %d, exited %v; want 3", status, exited)
	}
	// Coming back after it ended still collects how it ended.
	third := connect(t, s)
	third.send(frameAttach, mustJSON(terminalSize{Rows: 24, Cols: 80}))
	if status, exited := third.until("\x00never"); !exited || status != 3 {
		t.Errorf("after the end, attach got status %d, exited %v", status, exited)
	}
}

func TestTheCommandsLastOutputArrivesBeforeItsStatus(t *testing.T) {
	s := &session{}
	c := connect(t, s)
	c.send(frameStart, start("/bin/sh", "-c", "printf 'last words'; exit 0"))
	go reap(t, s)
	c.until("last words")
	if status, exited := c.until("\x00never"); !exited || status != 0 {
		t.Errorf("status %d, exited %v", status, exited)
	}
}

func TestASessionStartsOnce(t *testing.T) {
	s := &session{}
	first := connect(t, s)
	first.send(frameStart, start("/bin/sh", "-c", "echo one; read x"))
	first.until("one")
	pid := s.commandPid()
	// A second start, as from a reconnect that raced, attaches instead.
	second := connect(t, s)
	second.send(frameStart, start("/bin/sh", "-c", "echo two"))
	time.Sleep(200 * time.Millisecond)
	if s.commandPid() != pid {
		t.Error("a second start started another command")
	}
	second.send(frameData, []byte("\r"))
	go reap(t, s)
	second.until("\x00never")
}

func TestASessionSaysWhetherItsCommandStillRuns(t *testing.T) {
	s := &session{}
	c := connect(t, s)
	c.send(frameStart, start("/bin/sh", "-c", "echo up; read x; exit 4"))
	c.until("up")
	query := func() (byte, []byte) {
		q := connect(t, s)
		q.send(frameQuery, nil)
		_ = q.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		kind, payload, err := readFrame(q.reader)
		if err != nil {
			t.Fatal(err)
		}
		return kind, payload
	}
	if kind, _ := query(); kind != frameAlive {
		t.Errorf("while it runs, the session answered %q", kind)
	}
	c.send(frameData, []byte("\r"))
	go reap(t, s)
	c.until("\x00never") // the attached client takes its status first
	if kind, payload := query(); kind != frameExit || string(payload) != `{"status":4}` {
		t.Errorf("after it ended, the session answered %q %s", kind, payload)
	}
}
