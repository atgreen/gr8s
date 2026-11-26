package client

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// A gr8 Policy (podster-wv1w.14) is one file saying everything a command gets: the
// hosts it may reach, the credentials injected for it, what it gets in $HOME, its
// egress inspection, desktop and resources. gr8 turns it into resources scoped to
// the one run's Pod, which go when the run does.
//
// A policy in ~/.config/gr8/policies is trusted. One in the working directory is
// not, since the sandbox can write there: gr8 pins it by hash once approved, and
// shows what changed and asks again whenever it differs, so a command can't widen
// its own next run.

// PolicyAPIVersion and PolicyKind name a policy file's document.
const (
	PolicyAPIVersion = "gr8.gr8s.io/v1alpha1"
	PolicyKind       = "Policy"
)

// Policy is a gr8 policy file.
type Policy struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec PolicySpec `json:"spec"`
}

// PolicySpec is what a command gets.
type PolicySpec struct {
	Hosts       []string           `json:"hosts,omitempty"`
	Credentials []PolicyCredential `json:"credentials,omitempty"`
	Home        struct {
		ReadWrite    []string `json:"readWrite,omitempty"`
		ReadOnly     []string `json:"readOnly,omitempty"`
		Placeholders []string `json:"placeholders,omitempty"`
	} `json:"home,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Egress    map[string]any    `json:"egress,omitempty"`
	Desktop   *PolicyDesktop    `json:"desktop,omitempty"`
	Resources struct {
		CPU    string `json:"cpu,omitempty"`
		Memory string `json:"memory,omitempty"`
	} `json:"resources,omitempty"`
}

// PolicyCredential is one credential the proxy injects into requests to Hosts.
type PolicyCredential struct {
	// From is where the real value is read on the host when the run starts:
	// env:NAME, or file:PATH, or file:PATH#key/path into a YAML or JSON file (keys
	// split on /, since they hold dots: github.com/oauth_token); or login:NAME, a
	// login stored with gr8 --login, with its own hosts and refresh.
	From     string   `json:"from"`
	Hosts    []string `json:"hosts"`
	Header   string   `json:"header,omitempty"`   // default authorization
	Template string   `json:"template,omitempty"` // default "Bearer {{ .Token }}"
	// Env names a variable the sandbox gets holding a stand-in, for a client that
	// only sends the header when it has some token.
	Env string `json:"env,omitempty"`
}

// PolicyDesktop withholds what a command gets of the desktop by default.
type PolicyDesktop struct {
	Display *bool `json:"display,omitempty"`
	Audio   *bool `json:"audio,omitempty"`
	GPU     *bool `json:"gpu,omitempty"`
}

var (
	policyHost   = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	policyHeader = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	policyEnv    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	policyToken  = regexp.MustCompile(`\{\{\s*\.Token\s*\}\}`)
)

// ParsePolicy reads a policy file, refusing fields it doesn't know and anything
// it couldn't do as written.
func ParsePolicy(raw []byte) (Policy, error) {
	var policy Policy
	if err := yaml.UnmarshalStrict(raw, &policy); err != nil {
		return Policy{}, err
	}
	if policy.APIVersion != PolicyAPIVersion || policy.Kind != PolicyKind {
		return Policy{}, fmt.Errorf("not a %s %s", PolicyAPIVersion, PolicyKind)
	}
	spec := &policy.Spec
	for _, host := range spec.Hosts {
		if !policyHost.MatchString(host) {
			return Policy{}, fmt.Errorf("hosts: %q is not a hostname or *.hostname", host)
		}
	}
	for i := range spec.Credentials {
		credential := &spec.Credentials[i]
		if name, ok := strings.CutPrefix(credential.From, "login:"); ok {
			if !loginNameOK(name) {
				return Policy{}, fmt.Errorf("credentials[%d].from: %q names no login", i, credential.From)
			}
			continue
		}
		if !strings.HasPrefix(credential.From, "env:") && !strings.HasPrefix(credential.From, "file:") {
			return Policy{}, fmt.Errorf("credentials[%d].from: %q is not env:NAME, file:PATH or login:NAME", i, credential.From)
		}
		if len(credential.Hosts) == 0 {
			return Policy{}, fmt.Errorf("credentials[%d] names no hosts to send it to", i)
		}
		for _, host := range credential.Hosts {
			if !policyHost.MatchString(host) {
				return Policy{}, fmt.Errorf("credentials[%d].hosts: %q is not a hostname", i, host)
			}
		}
		if credential.Header == "" {
			credential.Header = "authorization"
		}
		if !policyHeader.MatchString(credential.Header) {
			return Policy{}, fmt.Errorf("credentials[%d].header: %q is not a header name", i, credential.Header)
		}
		if credential.Template == "" {
			credential.Template = "Bearer {{ .Token }}"
		}
		if !policyToken.MatchString(credential.Template) {
			return Policy{}, fmt.Errorf("credentials[%d].template must use {{ .Token }}", i)
		}
		if credential.Env != "" && !policyEnv.MatchString(credential.Env) {
			return Policy{}, fmt.Errorf("credentials[%d].env: %q is not a variable name", i, credential.Env)
		}
	}
	for _, list := range [][]string{spec.Home.ReadWrite, spec.Home.ReadOnly, spec.Home.Placeholders} {
		for _, path := range list {
			if filepath.IsAbs(path) || path == "" || strings.Contains("/"+path+"/", "/../") {
				return Policy{}, fmt.Errorf("home: %q must be a path relative to $HOME, without ..", path)
			}
		}
	}
	for name := range spec.Env {
		if !policyEnv.MatchString(name) {
			return Policy{}, fmt.Errorf("env: %q is not a variable name", name)
		}
	}
	return policy, nil
}

// valueCredentials are the policy's credentials read from a source on the host, as
// opposed to stored logins.
func (spec PolicySpec) valueCredentials() []PolicyCredential {
	var out []PolicyCredential
	for _, credential := range spec.Credentials {
		if !strings.HasPrefix(credential.From, "login:") {
			out = append(out, credential)
		}
	}
	return out
}

// loginNames are the stored logins the policy's credentials name.
func (spec PolicySpec) loginNames() []string {
	var out []string
	for _, credential := range spec.Credentials {
		if name, ok := strings.CutPrefix(credential.From, "login:"); ok {
			out = append(out, name)
		}
	}
	return out
}

// CredentialValue reads a credential's real value on the host from its source.
func CredentialValue(from, home string, getenv func(string) string) (string, error) {
	if name, ok := strings.CutPrefix(from, "env:"); ok {
		value := getenv(name)
		if value == "" {
			return "", fmt.Errorf("%s: $%s is empty", from, name)
		}
		return value, nil
	}
	path, keys, _ := strings.Cut(strings.TrimPrefix(from, "file:"), "#")
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		path = filepath.Join(home, rest)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", from, err)
	}
	if keys == "" {
		value := strings.TrimSpace(string(raw))
		if value == "" {
			return "", fmt.Errorf("%s is empty", from)
		}
		return value, nil
	}
	var document any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return "", fmt.Errorf("%s: %w", from, err)
	}
	for _, key := range strings.Split(keys, "/") {
		object, ok := document.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s: no %q", from, key)
		}
		document = object[key]
	}
	value, ok := document.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s holds no string there", from)
	}
	return value, nil
}

// PolicyFile is where a command's policy was found, and whether it is trusted
// as it stands or must be approved.
type PolicyFile struct {
	Path    string
	Trusted bool
}

// FindPolicy returns the policy for command: the one --policy names (a file, or a
// name in the config directory), else the config directory's command.yaml, else the
// working directory's .gr8/command.yaml; ok is false when there is none.
func FindPolicy(flag, command, home, cwd string) (file PolicyFile, ok bool, err error) {
	config := filepath.Join(home, ".config", "gr8", "policies")
	trusted := func(path string) PolicyFile {
		absolute, _ := filepath.Abs(path)
		// The sandbox may write the working directory; nothing there is trusted.
		return PolicyFile{Path: absolute, Trusted: !within(absolute, cwd)}
	}
	if flag != "" {
		path := flag
		if !strings.ContainsRune(flag, '/') && !strings.HasSuffix(flag, ".yaml") {
			path = filepath.Join(config, flag+".yaml")
		}
		if _, err := os.Stat(path); err != nil {
			return PolicyFile{}, false, fmt.Errorf("--policy %s: %w", flag, err)
		}
		return trusted(path), true, nil
	}
	name := filepath.Base(command) + ".yaml"
	for _, path := range []string{filepath.Join(config, name), filepath.Join(cwd, ".gr8", name)} {
		if _, err := os.Stat(path); err == nil {
			return trusted(path), true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return PolicyFile{}, false, err
		}
	}
	return PolicyFile{}, false, nil
}

func within(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// ApprovePolicy returns raw if file may be used as it is: trusted, or the same as
// the last approved copy. Otherwise it shows ask what it would grant, or what
// changed since its approval, and records the approval if ask says yes.
func ApprovePolicy(file PolicyFile, raw []byte, home string, ask func(prompt string) bool) error {
	if file.Trusted {
		return nil
	}
	sum := sha256.Sum256([]byte(file.Path))
	record := filepath.Join(home, ".config", "gr8", "approved", hex.EncodeToString(sum[:])+".yaml")
	approved, err := os.ReadFile(record)
	switch {
	case err == nil && string(approved) == string(raw):
		return nil
	case err == nil:
		if !ask(fmt.Sprintf("%s changed since you approved it:\n%s\nUse it?", file.Path, LineDiff(string(approved), string(raw)))) {
			return fmt.Errorf("%s changed and was not approved", file.Path)
		}
	case errors.Is(err, os.ErrNotExist):
		if !ask(fmt.Sprintf("%s is in the working directory, which the sandbox can write. It grants:\n%s\nUse it?", file.Path, raw)) {
			return fmt.Errorf("%s was not approved", file.Path)
		}
	default:
		return err
	}
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		return err
	}
	return os.WriteFile(record, raw, 0o600)
}

// LineDiff shows the lines of after that before lacks (+) and the reverse (-), in
// order, as a reviewer reads a changed policy.
func LineDiff(before, after string) string {
	a, b := strings.Split(before, "\n"), strings.Split(after, "\n")
	// Longest common subsequence, small enough for a policy file.
	table := make([][]int, len(a)+1)
	for i := range table {
		table[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else {
				table[i][j] = max(table[i+1][j], table[i][j+1])
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || table[i][j+1] >= table[i+1][j]):
			fmt.Fprintf(&out, "+ %s\n", b[j])
			j++
		default:
			fmt.Fprintf(&out, "- %s\n", a[i])
			i++
		}
	}
	return out.String()
}

// TerminalAsk asks on the terminal, reading y or yes from in; anything else is no.
func TerminalAsk(in io.Reader, out io.Writer) func(string) bool {
	return func(prompt string) bool {
		fmt.Fprintf(out, "gr8: %s [y/N] ", prompt)
		line, _ := bufio.NewReader(in).ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes"
	}
}

// egressJSON is a policy's egress block as the SandboxProfile's spec.egress.
func (spec PolicySpec) egressJSON() map[string]any {
	if spec.Egress == nil {
		return nil
	}
	raw, _ := json.Marshal(spec.Egress)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}
