// Package sandbox is the in-Pod half of gr8: it builds the command's view
// of the host and confines it with Landlock before exec.
package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is what "gr8 launch" is asked to run.
type Config struct {
	Cwd  string
	Home string
	// Trust is the egress CA's PEM in the Pod (outside the sandbox's root), or "".
	Trust string
	// Placeholders are credential files the sandbox sees with stand-in tokens.
	Placeholders []string
	ReadOnly     []string
	ReadWrite    []string
	Env          []string
	Command      []string
}

// ParseArgs parses launch's arguments: --cwd DIR, then any of --home DIR,
// --ro PATH, --rw PATH and --env NAME=VALUE, then -- and the command.
func ParseArgs(args []string) (Config, error) {
	var config Config
	for len(args) > 0 {
		flag := args[0]
		args = args[1:]
		if flag == "--" {
			config.Command = args
			break
		}
		if len(args) == 0 {
			return Config{}, fmt.Errorf("%s needs a value", flag)
		}
		value := args[0]
		args = args[1:]
		switch flag {
		case "--cwd":
			config.Cwd = value
		case "--home":
			config.Home = value
		case "--trust":
			config.Trust = value
		case "--placeholder":
			config.Placeholders = append(config.Placeholders, value)
		case "--ro":
			config.ReadOnly = append(config.ReadOnly, value)
		case "--rw":
			config.ReadWrite = append(config.ReadWrite, value)
		case "--env":
			config.Env = append(config.Env, value)
		default:
			return Config{}, fmt.Errorf("unknown launch flag %s", flag)
		}
	}
	if len(config.Command) == 0 {
		return Config{}, fmt.Errorf("no command")
	}
	if !filepath.IsAbs(config.Cwd) {
		return Config{}, fmt.Errorf("--cwd must be absolute, not %q", config.Cwd)
	}
	if config.Home != "" && !filepath.IsAbs(config.Home) {
		return Config{}, fmt.Errorf("--home must be absolute, not %q", config.Home)
	}
	return config, nil
}

// systemPaths are readable and executable. $HOME is not among them: only the
// working directory and what --ro/--rw name are reachable there.
var systemPaths = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt",
	"/nix", "/snap", "/home/linuxbrew", "/proc", "/sys", "/dev", "/run",
}

// scratchPaths are writable; /tmp and /run are the sandbox's own tmpfs.
var scratchPaths = []string{
	"/tmp", "/var/tmp", "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
	"/dev/tty", "/dev/ptmx", "/dev/pts", "/dev/shm",
}

// PrivateHome reports whether the command gets its own tmpfs $HOME, holding
// only what --ro and --rw name. It doesn't when the working directory is $HOME
// or holds it: the command may write there anyway.
func (config Config) PrivateHome() bool {
	return config.Home != "" && config.Home != "/" && !within(config.Home, config.Cwd)
}

// Rules is the Landlock allowlist for config. A private $HOME is writable:
// it is a tmpfs, and the read-only paths bound into it are read-only mounts.
func (config Config) Rules(abi int) []Rule {
	all := allAccess(abi)
	var rules []Rule
	if config.PrivateHome() {
		rules = append(rules, Rule{Path: config.Home, Access: all})
	}
	for _, path := range append(append([]string{}, systemPaths...), config.ReadOnly...) {
		rules = append(rules, Rule{Path: path, Access: readAccess})
	}
	for _, path := range append(append(append([]string{}, scratchPaths...), config.ReadWrite...), config.Cwd) {
		rules = append(rules, Rule{Path: path, Access: all})
	}
	return rules
}

func within(path, dir string) bool {
	return path == dir || dir == "/" || strings.HasPrefix(path, dir+"/")
}

// ResolveIn resolves path's symbolic links as if root were /, never leaving
// root, and returns the result relative to the real /. A missing final
// component is kept as is, so a mount target can still be created there.
func ResolveIn(root, path string) (string, error) {
	resolved := "/"
	remaining := strings.Split(strings.Trim(filepath.Clean("/"+path), "/"), "/")
	for hops := 0; len(remaining) > 0; {
		part := remaining[0]
		remaining = remaining[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		target, err := os.Readlink(filepath.Join(root, next))
		if err != nil {
			// Not a link, or missing: keep the component.
			resolved = next
			continue
		}
		if hops++; hops > 40 {
			return "", fmt.Errorf("too many symbolic links resolving %s", path)
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		remaining = append(strings.Split(strings.Trim(target, "/"), "/"), remaining...)
	}
	return filepath.Join(root, resolved), nil
}

// Stand-ins for the tokens a placeholder credential file holds: the proxy injects the
// real access token, and an expiry far off means the sandbox never tries to refresh.
const (
	StandInToken  = "gr8s-injected"
	standInExpiry = 4102444800000 // 2100-01-01, in milliseconds
)

// StandInCredentials returns the JSON credentials file contents with every
// accessToken and refreshToken replaced by StandInToken and every expiresAt and
// refreshTokenExpiresAt moved to 2100 (podster-wv1w.7).
func StandInCredentials(contents []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(contents, &value); err != nil {
		return nil, err
	}
	var walk func(any) any
	walk = func(node any) any {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				switch key {
				case "accessToken", "refreshToken":
					typed[key] = StandInToken
				case "expiresAt", "refreshTokenExpiresAt":
					typed[key] = standInExpiry
				default:
					typed[key] = walk(child)
				}
			}
		case []any:
			for i, child := range typed {
				typed[i] = walk(child)
			}
		}
		return node
	}
	return json.MarshalIndent(walk(value), "", "  ")
}
