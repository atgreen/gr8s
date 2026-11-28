// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	yaml "go.yaml.in/yaml/v3"
	"k8s.io/client-go/kubernetes"
)

// Refusal is a host the node's egress policy kept a run from, and how often.
type Refusal struct {
	Host  string
	Count int
}

// ParseRefusal reads one flow event, a JSON line from the flows API, and returns the
// host it refused POD, when it is a refusal by policy of a name lookup or connection.
func ParseRefusal(line []byte, pod string) (string, bool) {
	var flow struct {
		Pod     string `json:"pod"`
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
		L7      struct {
			Type  string `json:"type"`
			Query string `json:"query"`
			Host  string `json:"host"`
		} `json:"l7"`
	}
	if json.Unmarshal(line, &flow) != nil || flow.Pod != pod || flow.Verdict != "DROPPED" || flow.Reason != "POLICY" {
		return "", false
	}
	host := ""
	switch flow.L7.Type {
	case "dns":
		host = flow.L7.Query
	case "egress":
		host = flow.L7.Host
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host, host != ""
}

// refusalWatch collects what the node refuses a run's Pod while it runs, and passes on
// each host it holds a connection to for the user to decide.
type refusalWatch struct {
	mutex     sync.Mutex
	counts    map[string]int
	order     []string
	decided   map[string]bool // hosts the user answered for, asked once and not told again
	onPending func(host string)
	cancel    context.CancelFunc
	done      chan struct{}
}

// watchRefusals follows the flow events of pod in namespace until Stop. onPending, when
// given, is called (on its own goroutine) once for each host the node holds pod's
// connection to while its user decides.
func watchRefusals(ctx context.Context, clientset kubernetes.Interface, namespace, pod string,
	onPending func(host string)) *refusalWatch {
	ctx, cancel := context.WithCancel(ctx)
	watch := &refusalWatch{counts: map[string]int{}, decided: map[string]bool{}, onPending: onPending,
		cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(watch.done)
		stream, err := clientset.Discovery().RESTClient().Get().
			AbsPath("/apis/gr8s.io/v1/namespaces", namespace, "flows").Param("watch", "true").Stream(ctx)
		if err != nil {
			return
		}
		defer stream.Close()
		watch.read(stream, pod)
	}()
	return watch
}

func (watch *refusalWatch) read(stream io.Reader, pod string) {
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if host, ok := ParsePending(scanner.Bytes(), pod); ok && watch.onPending != nil {
			watch.mutex.Lock()
			first := !watch.decided[host]
			watch.decided[host] = true
			watch.mutex.Unlock()
			if first {
				go watch.onPending(host)
			}
			continue
		}
		if host, ok := ParseRefusal(scanner.Bytes(), pod); ok {
			watch.mutex.Lock()
			if watch.counts[host] == 0 {
				watch.order = append(watch.order, host)
			}
			watch.counts[host]++
			watch.mutex.Unlock()
		}
	}
}

// Stop ends the watch, after a moment for the node's last events to arrive, and returns
// what was refused, in the order it first was.
func (watch *refusalWatch) Stop() []Refusal {
	select {
	case <-watch.done:
	case <-time.After(1500 * time.Millisecond):
	}
	watch.cancel()
	<-watch.done
	watch.mutex.Lock()
	defer watch.mutex.Unlock()
	var refusals []Refusal
	for _, host := range watch.order {
		if !watch.decided[host] {
			refusals = append(refusals, Refusal{host, watch.counts[host]})
		}
	}
	return refusals
}

// RefusalFooter is what gr8 prints when a run is refused hosts.
func RefusalFooter(refusals []Refusal) string {
	var out strings.Builder
	fmt.Fprintln(&out, "gr8: the sandbox's policy refused:")
	for _, refusal := range refusals {
		times := ""
		if refusal.Count > 1 {
			times = fmt.Sprintf(" (%d times)", refusal.Count)
		}
		fmt.Fprintf(&out, "gr8:   %s%s\n", refusal.Host, times)
	}
	return out.String()
}

// AddHostsToPolicy returns the policy RAW with HOSTS appended to spec.hosts, keeping
// its comments and layout; hosts it already names are left out.
func AddHostsToPolicy(raw []byte, hosts []string) ([]byte, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the policy is not a YAML mapping")
	}
	_, spec := mappingValue(document.Content[0], "spec", yaml.MappingNode)
	key, list := mappingValue(spec, "hosts", yaml.SequenceNode)
	// A block list reads one host to a line, as an edited file should; a comment
	// on the line of a flow list moves to its key's line.
	if list.Style&yaml.FlowStyle != 0 && list.LineComment != "" && key.LineComment == "" {
		key.LineComment, list.LineComment = list.LineComment, ""
	}
	list.Style = 0
	var have []string
	for _, item := range list.Content {
		have = append(have, item.Value)
	}
	for _, host := range hosts {
		if !slices.Contains(have, host) {
			list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: host})
			have = append(have, host)
		}
	}
	var out strings.Builder
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

// mappingValue is MAPPING's key node for KEY and its value, added as an empty node of
// KIND when missing.
func mappingValue(mapping *yaml.Node, key string, kind yaml.Kind) (*yaml.Node, *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i], mapping.Content[i+1]
		}
	}
	name, value := &yaml.Node{Kind: yaml.ScalarNode, Value: key}, &yaml.Node{Kind: kind}
	mapping.Content = append(mapping.Content, name, value)
	return name, value
}

// NewPolicy is a policy for command allowing hosts and nothing else.
func NewPolicy(command string, hosts []string) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\nspec:\n  hosts:\n", PolicyAPIVersion, PolicyKind, command)
	for _, host := range hosts {
		fmt.Fprintf(&out, "    - %s\n", host)
	}
	return []byte(out.String())
}

// offerToAllow prints what the run was refused and, when ask says yes, adds it to the
// policy the run used (file), or to a new one for command in ~/.config/gr8/policies.
func offerToAllow(refusals []Refusal, file *PolicyFile, command, home string, ask func(string) bool) {
	if len(refusals) == 0 {
		return
	}
	fmt.Fprint(os.Stderr, RefusalFooter(refusals))
	hosts := make([]string, len(refusals))
	for i, refusal := range refusals {
		hosts[i] = refusal.Host
	}
	path := filepath.Join(home, ".config", "gr8", "policies", filepath.Base(command)+".yaml")
	if file != nil {
		path = file.Path
	}
	if ask == nil {
		fmt.Fprintf(os.Stderr, "gr8: to allow them, add them to %s or pass --allow\n", path)
		return
	}
	if !ask(fmt.Sprintf("Allow them from now on, in %s?", path)) {
		return
	}
	if err := allowInPolicy(hosts, file, command, home); err != nil {
		fmt.Fprintf(os.Stderr, "gr8: %s: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "gr8: %s now allows %s\n", path, strings.Join(hosts, ", "))
}

// allowInPolicy adds hosts to the policy the run used (file), or to a new one for
// command in ~/.config/gr8/policies.
func allowInPolicy(hosts []string, file *PolicyFile, command, home string) error {
	path := filepath.Join(home, ".config", "gr8", "policies", filepath.Base(command)+".yaml")
	if file != nil {
		path = file.Path
	}
	var updated []byte
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		updated, err = AddHostsToPolicy(raw, hosts)
	case errors.Is(err, os.ErrNotExist) && file == nil:
		updated, err = NewPolicy(filepath.Base(command), hosts), nil
	}
	if err == nil {
		_, err = ParsePolicy(updated)
	}
	if err == nil {
		err = writePolicy(path, updated, file, home)
	}
	return err
}

// writePolicy replaces path with raw. A working-directory policy is approved by its
// content (ApprovePolicy); the user just made this change, so it is approved with it.
func writePolicy(path string, raw []byte, file *PolicyFile, home string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path+".new", raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(path+".new", path); err != nil {
		return err
	}
	if file == nil || file.Trusted {
		return nil
	}
	record := approvalRecord(home, file.Path)
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		return err
	}
	return os.WriteFile(record, raw, 0o600)
}
