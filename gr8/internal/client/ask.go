// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// LabelAsk marks a run whose user is at its terminal: the node holds a connection its
// policy refuses until they decide (podster-3zu0).
const LabelAsk = "gr8s.io/gr8-ask"

// askTimeout is how long gr8 waits for an answer: less than the node holds the
// connection, so a no reaches it in time.
const askTimeout = 50 * time.Second

// terminalGate sits between the terminal and a command running in its sandbox. Most of
// the time it passes keys in and output out; while gr8 asks the user something, keys go
// to the question and the command's output waits, so the two don't mix. A question
// waits for the command's output to pause, so it never lands inside an escape sequence,
// and is drawn on the bottom row, the cursor saved and put back after, so a full-screen
// program's screen is disturbed as little as can be, then redrawn.
type terminalGate struct {
	in     io.Reader
	out    io.Writer
	rows   func() (width, height int) // the terminal's size, 0 when unknown
	redraw func()                     // has the command draw its screen again, after a question

	asking   sync.Mutex // one question or message at a time
	mutex    sync.Mutex
	keys     string // the answers the open question takes; "" when none is open
	holding  bool
	answered chan byte
	held     bytes.Buffer
	written  time.Time // when the command last wrote

	// One goroutine reads the terminal, so keys never go to a reader that has gone:
	// when the command ends, the exec stream's reader is let go (Detach) and what is
	// typed next goes to gr8's own questions (After).
	chunks   chan []byte
	leftover []byte
	detached chan struct{}
	detach   sync.Once
}

// quiet is how long the command's output must pause before gr8 writes over it, and
// quietLimit the most gr8 waits for that.
const (
	quiet      = 100 * time.Millisecond
	quietLimit = 2 * time.Second
)

func newTerminalGate(in io.Reader, out io.Writer, rows func() (int, int), redraw func()) *terminalGate {
	gate := &terminalGate{in: in, out: out, rows: rows, redraw: redraw, answered: make(chan byte, 1),
		chunks: make(chan []byte, 16), detached: make(chan struct{})}
	go gate.pump()
	return gate
}

// pump reads the terminal: an answer to an open question goes to it, anything else on
// to whoever reads the gate.
func (gate *terminalGate) pump() {
	buffer := make([]byte, 4096)
	for {
		n, err := gate.in.Read(buffer)
		if n > 0 {
			if chunk := gate.answer(buffer[:n]); len(chunk) > 0 {
				gate.chunks <- chunk
			}
		}
		if err != nil {
			close(gate.chunks)
			return
		}
	}
}

// answer takes an open question's answer out of keys typed, returning what is left for
// the reader: nothing while a question is open.
func (gate *terminalGate) answer(typed []byte) []byte {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	if gate.keys == "" {
		return append([]byte(nil), typed...)
	}
	for _, key := range bytes.ToLower(typed) {
		if strings.IndexByte(gate.keys, key) >= 0 {
			gate.keys = ""
			gate.answered <- key
			break
		}
	}
	return nil
}

// Read is the command's stdin, until Detach.
func (gate *terminalGate) Read(p []byte) (int, error) {
	return gate.read(p, gate.detached)
}

func (gate *terminalGate) read(p []byte, stop <-chan struct{}) (int, error) {
	if len(gate.leftover) > 0 {
		n := copy(p, gate.leftover)
		gate.leftover = gate.leftover[n:]
		return n, nil
	}
	select {
	case chunk, ok := <-gate.chunks:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		gate.leftover = chunk[n:]
		return n, nil
	case <-stop:
		return 0, io.EOF
	}
}

// Detach ends the command's stdin, once the command has ended.
func (gate *terminalGate) Detach() { gate.detach.Do(func() { close(gate.detached) }) }

// After is what is typed after Detach, for gr8's own questions.
func (gate *terminalGate) After() io.Reader { return afterReader{gate} }

type afterReader struct{ gate *terminalGate }

func (reader afterReader) Read(p []byte) (int, error) { return reader.gate.read(p, nil) }

func (gate *terminalGate) Write(p []byte) (int, error) {
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	if gate.holding {
		return gate.held.Write(p)
	}
	gate.written = time.Now()
	return gate.out.Write(p)
}

// hold waits for the command's output to pause, then holds it, and draws text on the
// bottom row. Called with gate.asking held; release undoes it.
func (gate *terminalGate) hold(text string) {
	for deadline := time.Now().Add(quietLimit); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		gate.mutex.Lock()
		idle := time.Since(gate.written) >= quiet
		if idle {
			gate.holding = true
		}
		gate.mutex.Unlock()
		if idle {
			break
		}
	}
	gate.mutex.Lock()
	defer gate.mutex.Unlock()
	gate.holding = true
	fmt.Fprint(gate.out, "\x1b7"+gate.bottomRow()+text)
}

// release clears the bottom row, puts the cursor back, lets the held output through and
// has the command redraw.
func (gate *terminalGate) release() {
	gate.mutex.Lock()
	fmt.Fprint(gate.out, gate.bottomRow()+"\x1b8")
	_, _ = gate.out.Write(gate.held.Bytes())
	gate.held.Reset()
	gate.holding = false
	gate.written = time.Now()
	gate.mutex.Unlock()
	if gate.redraw != nil {
		gate.redraw()
	}
}

// bottomRow moves to the start of the bottom row and clears it; without a known size,
// it clears the line below the cursor.
func (gate *terminalGate) bottomRow() string {
	if gate.rows != nil {
		if _, height := gate.rows(); height > 0 {
			return fmt.Sprintf("\x1b[%d;1H\x1b[2K", height)
		}
	}
	return "\r\n\x1b[2K"
}

// size is the terminal's, or zeros when unknown.
func (gate *terminalGate) size() (int, int) {
	if gate.rows == nil {
		return 0, 0
	}
	return gate.rows()
}

// fit makes "gr8: " + text + tail one row of the terminal, by shortening text, never
// tail: a question that wrapped would scroll the command's screen and outlive its
// answer, and its answers are what must show.
func (gate *terminalGate) fit(text, tail string) string {
	width, _ := gate.size()
	room := width - 1 - len("gr8: ") - len(tail)
	if width <= 0 || len(text) <= room {
		return text + tail
	}
	if room < 4 {
		return tail
	}
	return text[:room-3] + "..." + tail
}

// Ask puts question, then answers (the choices, which always show), to the user and
// returns the key they answered with, one of keys (lowercase), or fallback when they
// don't answer within askTimeout.
func (gate *terminalGate) Ask(question, answers, keys string, fallback byte) byte {
	gate.asking.Lock()
	defer gate.asking.Unlock()
	if width, _ := gate.size(); width > 0 && len("gr8: ")+len(answers)+8 > width-1 {
		// Too narrow for the choices in words: their keys alone.
		answers = " [" + strings.Join(strings.Split(keys, ""), "/") + "]?"
	}
	gate.hold("\x1b[1mgr8:\x1b[0m " + gate.fit(question, answers))
	gate.mutex.Lock()
	gate.keys = keys
	gate.mutex.Unlock()
	var answer byte
	select {
	case answer = <-gate.answered:
	case <-time.After(askTimeout):
		answer = fallback
	}
	gate.mutex.Lock()
	gate.keys = ""
	select { // an answer that came as the time ran out
	case <-gate.answered:
	default:
	}
	gate.mutex.Unlock()
	gate.release()
	return answer
}

// Say shows message on the bottom row for a moment, as Ask shows a question.
func (gate *terminalGate) Say(message string) {
	gate.asking.Lock()
	defer gate.asking.Unlock()
	gate.hold("\x1b[1mgr8:\x1b[0m " + gate.fit(message, ""))
	time.Sleep(2 * time.Second)
	gate.release()
}

// WithRunAllowed returns the run's ClusterNetworkPolicy (as JSON-decoded) with host
// added to its gr8-allow rule, making the rule when it has none (podster-3zu0).
func WithRunAllowed(policy map[string]any, host string) map[string]any {
	spec, _ := policy["spec"].(map[string]any)
	egress, _ := spec["egress"].([]any)
	for _, item := range egress {
		rule, _ := item.(map[string]any)
		to, _ := rule["to"].([]any)
		if rule["name"] != "gr8-allow" || len(to) == 0 {
			continue
		}
		peer, _ := to[0].(map[string]any)
		domains, _ := peer["domainNames"].([]any)
		if !slices.Contains(domains, any(host)) {
			peer["domainNames"] = append(domains, host)
		}
		return policy
	}
	spec["egress"] = append(egress, map[string]any{
		"name": "gr8-allow", "action": "Accept",
		"to": []any{map[string]any{"domainNames": []any{host}}},
	})
	return policy
}

// RefuseLabel is the label on a run's Pod saying its user said no to host, which the
// node reads to refuse the connection it holds at once (podster-3zu0). A digest, so any
// name makes a valid key; gr8s computes the same.
func RefuseLabel(host string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(host)))
	return "gr8s.io/refuse-" + hex.EncodeToString(sum[:])[:16]
}

// decideRunHost carries out the user's answer about host: allowed, it goes into the
// run's ClusterNetworkPolicy, made when the run has none, and true is returned when it
// was made, for the run to delete as it does the one --allow makes; refused, the run's
// Pod is labelled so.
func decideRunHost(ctx context.Context, clientset kubernetes.Interface, namespace, pod, host string, allow bool) (bool, error) {
	if !allow {
		patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]string{RefuseLabel(host): "true"}}})
		_, err := clientset.CoreV1().Pods(namespace).Patch(ctx, pod, types.MergePatchType, patch, metav1.PatchOptions{})
		return false, err
	}
	rest := clientset.Discovery().RESTClient()
	for attempt := 0; attempt < 5; attempt++ {
		raw, err := rest.Get().AbsPath(clusterNetworkPolicies, pod).DoRaw(ctx)
		created := false
		var policy map[string]any
		switch {
		case apierrors.IsNotFound(err):
			policy, created = AllowPolicy(namespace, pod, []string{host}), true
		case err != nil:
			return false, err
		default:
			if err := json.Unmarshal(raw, &policy); err != nil {
				return false, err
			}
			policy = WithRunAllowed(policy, host)
		}
		body, err := json.Marshal(policy)
		if err != nil {
			return false, err
		}
		if created {
			err = rest.Post().AbsPath(clusterNetworkPolicies).Body(body).
				SetHeader("Content-Type", "application/json").Do(ctx).Error()
		} else {
			err = rest.Put().AbsPath(clusterNetworkPolicies, pod).Body(body).
				SetHeader("Content-Type", "application/json").Do(ctx).Error()
		}
		if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
			continue
		}
		return created && err == nil, err
	}
	return false, fmt.Errorf("the run's ClusterNetworkPolicy kept changing")
}

// ParsePending reads one flow event and returns the host the node holds pod's
// connection to while its user decides.
func ParsePending(line []byte, pod string) (string, bool) {
	var flow struct {
		Pod     string `json:"pod"`
		Verdict string `json:"verdict"`
		L7      struct {
			Host string `json:"host"`
		} `json:"l7"`
	}
	if json.Unmarshal(line, &flow) != nil || flow.Pod != pod || flow.Verdict != "PENDING" || flow.L7.Host == "" {
		return "", false
	}
	return strings.ToLower(flow.L7.Host), true
}
