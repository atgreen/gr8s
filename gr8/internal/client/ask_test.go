// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuffer is a terminal gr8 writes to from more than one goroutine.
type safeBuffer struct {
	mutex sync.Mutex
	bytes.Buffer
}

func (buffer *safeBuffer) Write(p []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.Buffer.Write(p)
}

func (buffer *safeBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.Buffer.String()
}

func TestAQuestionTakesTheUsersKeysAndHoldsTheCommandsOutput(t *testing.T) {
	keys, typing := io.Pipe()
	screen := &safeBuffer{}
	redrawn := make(chan bool, 1)
	gate := newTerminalGate(keys, screen, func() (int, int) { return 80, 24 }, func() { redrawn <- true })
	// The command's stdin, as the exec stream reads it.
	command := make(chan string, 8)
	go func() {
		buffer := make([]byte, 64)
		for {
			n, err := gate.Read(buffer)
			if err != nil {
				return
			}
			command <- string(buffer[:n])
		}
	}()
	_, _ = typing.Write([]byte("ls\r"))
	if got := <-command; got != "ls\r" {
		t.Fatalf("the command got %q", got)
	}
	// The command is mid-screen: the question waits for its output to pause.
	_, _ = gate.Write([]byte("\x1b[3"))
	asked := time.Now()
	answers := make(chan byte)
	go func() { answers <- gate.Ask("claude wants pypi.org.", " [o/a/n]?", "oan", 'n') }()
	time.Sleep(20 * time.Millisecond)
	_, _ = gate.Write([]byte("1mred"))
	time.Sleep(200 * time.Millisecond)
	_, _ = gate.Write([]byte("output while asking"))
	_, _ = typing.Write([]byte("xA")) // x isn't an answer; A is, whatever its case
	if answer := <-answers; answer != 'a' {
		t.Errorf("answer = %q", answer)
	}
	<-redrawn
	text := screen.String()
	// The command's escape sequence came out whole, before gr8 wrote anything.
	if !strings.HasPrefix(text, "\x1b[31mred") {
		t.Errorf("gr8 wrote inside the command's output:\n%q", text)
	}
	if time.Since(asked) < quiet {
		t.Error("the question didn't wait for the output to pause")
	}
	// Cursor saved, bottom row, question; then the row cleared, cursor back, and the
	// held output after.
	want := "\x1b7\x1b[24;1H\x1b[2K\x1b[1mgr8:\x1b[0m claude wants pypi.org. [o/a/n]?\x1b[24;1H\x1b[2K\x1b8output while asking"
	if !strings.HasSuffix(text, want) {
		t.Errorf("screen = %q\nwant it to end %q", text, want)
	}
	select {
	case got := <-command:
		t.Errorf("the answer reached the command as %q", got)
	default:
	}
	_, _ = typing.Write([]byte("q"))
	if got := <-command; got != "q" {
		t.Errorf("after the question, the command got %q", got)
	}
	typing.Close()
}

func TestTheUsersAnswerGoesIntoTheRunsPolicy(t *testing.T) {
	policy := AllowPolicy("gr8-alice", "gr8-claude-abcde", []string{"api.anthropic.com"})
	var decoded map[string]any
	raw, _ := json.Marshal(policy)
	_ = json.Unmarshal(raw, &decoded)
	decoded = WithRunAllowed(decoded, "pypi.org")
	decoded = WithRunAllowed(decoded, "pypi.org")
	out, _ := json.Marshal(decoded)
	text := string(out)
	if strings.Count(text, "pypi.org") != 1 || !strings.Contains(text, `"domainNames":["api.anthropic.com","pypi.org"]`) {
		t.Errorf("allowed hosts: %s", text)
	}
	// A no is a label the node reads, the same as gr8s computes (gr8-refuse-label).
	if label := RefuseLabel("Example.com"); label != "gr8s.io/refuse-a379a6f6eeafb9a5" {
		t.Errorf("RefuseLabel = %q", label)
	}
	if !strings.Contains(text, `"subject"`) || !strings.Contains(text, "gr8-alice") {
		t.Errorf("the policy lost its subject: %s", text)
	}
}

func TestAHostTheUserDecidedIsAskedOnceAndNotToldAgain(t *testing.T) {
	if host, ok := ParsePending([]byte(`{"pod":"p","verdict":"PENDING","reason":"POLICY","l7":{"type":"egress","host":"PyPI.org"}}`), "p"); !ok || host != "pypi.org" {
		t.Errorf("ParsePending = %q, %v", host, ok)
	}
	if _, ok := ParsePending([]byte(`{"pod":"q","verdict":"PENDING","l7":{"host":"pypi.org"}}`), "p"); ok {
		t.Error("another run's question was taken")
	}
	asked := make(chan string, 4)
	watch := &refusalWatch{counts: map[string]int{}, decided: map[string]bool{}, onPending: func(host string) { asked <- host },
		done: make(chan struct{}), cancel: func() {}}
	watch.read(strings.NewReader(strings.Join([]string{
		`{"pod":"p","verdict":"PENDING","reason":"POLICY","l7":{"type":"egress","host":"pypi.org"}}`,
		`{"pod":"p","verdict":"PENDING","reason":"POLICY","l7":{"type":"egress","host":"pypi.org"}}`,
		`{"pod":"p","verdict":"DROPPED","reason":"POLICY","l7":{"type":"egress","host":"pypi.org"}}`,
		`{"pod":"p","verdict":"DROPPED","reason":"POLICY","l7":{"type":"dns","query":"other.example"}}`,
	}, "\n")), "p")
	close(watch.done)
	if host := <-asked; host != "pypi.org" {
		t.Errorf("asked about %q", host)
	}
	select {
	case host := <-asked:
		t.Errorf("asked again, about %q", host)
	case <-time.After(50 * time.Millisecond):
	}
	refusals := watch.Stop()
	if len(refusals) != 1 || refusals[0].Host != "other.example" {
		t.Errorf("the footer tells %v; a host the user answered for isn't told again", refusals)
	}
}

func TestWhenTheCommandEndsTheNextKeysGoToGr8sQuestion(t *testing.T) {
	keys, typing := io.Pipe()
	gate := newTerminalGate(keys, &safeBuffer{}, nil, nil)
	// The exec stream's reader, still waiting when the command ends.
	ended := make(chan error, 1)
	go func() {
		_, err := gate.Read(make([]byte, 16))
		ended <- err
	}()
	time.Sleep(20 * time.Millisecond)
	gate.Detach()
	if err := <-ended; err != io.EOF {
		t.Fatalf("the command's stdin didn't end: %v", err)
	}
	go func() { _, _ = typing.Write([]byte("y\n")) }()
	if !TerminalAsk(gate.After(), &safeBuffer{})("Allow them from now on?") {
		t.Error("the answer typed after the command ended was lost")
	}
	typing.Close()
}

func TestAQuestionFitsOneRowAndAlwaysShowsItsAnswers(t *testing.T) {
	for _, width := range []int{110, 60, 30} {
		gate := newTerminalGate(strings.NewReader(""), &safeBuffer{}, func() (int, int) { return width, 24 }, nil)
		screen := &safeBuffer{}
		gate.out = screen
		go func() { gate.answered <- 'n' }()
		gate.Ask("claude wants raw.githubusercontent.com, which its policy doesn't allow.", " Allow [o]nce, [a]lways, [n]o?", "oan", 'n')
		text := screen.String()
		start := strings.Index(text, "gr8:")
		end := strings.Index(text[start:], "?")
		line := strings.ReplaceAll(text[start:start+end+1], "\x1b[0m", "")
		if len(line) > width-1 {
			t.Errorf("at width %d the question takes %d columns: %q", width, len(line), line)
		}
		if !strings.HasSuffix(line, "[n]o?") && !strings.HasSuffix(line, "[o/a/n]?") {
			t.Errorf("at width %d the answers were cut: %q", width, line)
		}
	}
}
