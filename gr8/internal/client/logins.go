package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// A login (podster-wv1w.20) is how a command-line tool keeps an OAuth login, and
// where its access token goes. `gr8 --login NAME` copies the tokens from the tool's
// own file into the Secret login-NAME, and applies a SecurityProfile through which
// the node egress proxy injects the access token into requests to the login's
// hosts and, when the login refreshes, performs the refresh itself, keeping the new
// tokens and writing them back to the Secret. A sandboxed run of one of the login's
// commands sees the tool's file with stand-ins at exactly the token keys, and gr8
// keeps that file on the host and the Secret in step, the later expiry winning, so
// the tool outside the sandbox goes on working after a refresh inside it retires
// its old refresh token.

// Login describes one tool's OAuth login.
type Login struct {
	// Commands are the commands (base names) the login is for.
	Commands []string `json:"commands"`
	// File is where the tool keeps its login, relative to $HOME: JSON, or YAML when
	// it ends in .yaml or .yml.
	File string `json:"file"`
	// AccessToken, RefreshToken and ExpiresAt are key paths into File, split on /
	// (a key may hold dots); RefreshToken and ExpiresAt are optional.
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
	// ExpiresUnit is ExpiresAt's form: milliseconds (the default), seconds or rfc3339.
	ExpiresUnit string      `json:"expiresUnit,omitempty"`
	Inject      LoginInject `json:"inject"`
	// Refresh is the token endpoint; without it the token is used as it stands.
	Refresh *LoginRefresh `json:"refresh,omitempty"`
}

// LoginInject says where the access token goes, and how.
type LoginInject struct {
	Hosts    []string `json:"hosts"`
	Header   string   `json:"header,omitempty"`   // default authorization
	Template string   `json:"template,omitempty"` // default "Bearer {{ .Token }}"
}

// LoginRefresh names a login's OAuth token endpoint.
type LoginRefresh struct {
	Hosts []string `json:"hosts"`
	Path  string   `json:"path"`
}

// presetLogins are the logins gr8 knows; ~/.config/gr8/logins.yaml adds others or
// replaces these.
var presetLogins = map[string]Login{
	"claude": {
		Commands:     []string{"claude"},
		File:         ".claude/.credentials.json",
		AccessToken:  "claudeAiOauth/accessToken",
		RefreshToken: "claudeAiOauth/refreshToken",
		ExpiresAt:    "claudeAiOauth/expiresAt",
		Inject:       LoginInject{Hosts: []string{"api.anthropic.com"}},
		Refresh:      &LoginRefresh{Hosts: []string{"platform.claude.com"}, Path: "/v1/oauth/token"},
	},
}

// Logins returns the logins gr8 knows: its presets, and those in
// ~/.config/gr8/logins.yaml (a map of name to Login), which win.
func Logins(home string) (map[string]Login, error) {
	logins := map[string]Login{}
	for name, login := range presetLogins {
		logins[name] = login
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "gr8", "logins.yaml"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var defined map[string]Login
		if err := yaml.UnmarshalStrict(raw, &defined); err != nil {
			return nil, fmt.Errorf("~/.config/gr8/logins.yaml: %w", err)
		}
		for name, login := range defined {
			logins[name] = login
		}
	}
	for name, login := range logins {
		if err := login.validate(name); err != nil {
			return nil, err
		}
	}
	return logins, nil
}

var loginName = policyEnv

func (login Login) validate(name string) error {
	switch {
	case !loginNameOK(name):
		return fmt.Errorf("login %q: a name is letters, digits and -", name)
	case len(login.Commands) == 0:
		return fmt.Errorf("login %s names no commands", name)
	case login.File == "" || filepath.IsAbs(login.File) || strings.Contains("/"+login.File+"/", "/../"):
		return fmt.Errorf("login %s: file must be relative to $HOME, without ..", name)
	case login.AccessToken == "":
		return fmt.Errorf("login %s names no accessToken key", name)
	case len(login.Inject.Hosts) == 0:
		return fmt.Errorf("login %s names no hosts to inject into", name)
	case login.Refresh != nil && (login.RefreshToken == "" || len(login.Refresh.Hosts) == 0 ||
		!strings.HasPrefix(login.Refresh.Path, "/")):
		return fmt.Errorf("login %s: refresh needs refreshToken, hosts and a path", name)
	}
	switch login.ExpiresUnit {
	case "", "milliseconds", "seconds", "rfc3339":
	default:
		return fmt.Errorf("login %s: expiresUnit is milliseconds, seconds or rfc3339", name)
	}
	for _, host := range append(append([]string{}, login.Inject.Hosts...), login.refreshHosts()...) {
		if !policyHost.MatchString(host) {
			return fmt.Errorf("login %s: %q is not a hostname", name, host)
		}
	}
	return nil
}

func loginNameOK(name string) bool {
	if name == "" || len(name) > 40 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func (login Login) refreshHosts() []string {
	if login.Refresh == nil {
		return nil
	}
	return login.Refresh.Hosts
}

// Hosts are every host the login's token goes to or is refreshed at.
func (login Login) Hosts() []string {
	return append(append([]string{}, login.Inject.Hosts...), login.refreshHosts()...)
}

// For says whether the login is for command.
func (login Login) For(command string) bool {
	return slices.Contains(login.Commands, filepath.Base(command))
}

// LoginSecretName names the Secret a login's tokens are kept in.
func LoginSecretName(name string) string { return "login-" + name }

// LoginTokens are a login's real tokens and the access token's expiry in
// milliseconds since the epoch, 0 when unknown; the later expiry is the newer copy.
type LoginTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

func (login Login) path(home string) string { return filepath.Join(home, login.File) }

func (login Login) yamlFile() bool {
	extension := strings.ToLower(filepath.Ext(login.File))
	return extension == ".yaml" || extension == ".yml"
}

func (login Login) readFile(home string) (map[string]any, error) {
	raw, err := os.ReadFile(login.path(home))
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if login.yamlFile() {
		err = yaml.Unmarshal(raw, &document)
	} else {
		err = json.Unmarshal(raw, &document)
	}
	if err != nil {
		return nil, fmt.Errorf("~/%s: %w", login.File, err)
	}
	return document, nil
}

func lookupPath(document map[string]any, path string) (any, bool) {
	var node any = document
	for _, key := range strings.Split(path, "/") {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		if node, ok = object[key]; !ok {
			return nil, false
		}
	}
	return node, true
}

func setPath(document map[string]any, path string, value any) bool {
	keys := strings.Split(path, "/")
	object := document
	for _, key := range keys[:len(keys)-1] {
		next, ok := object[key].(map[string]any)
		if !ok {
			return false
		}
		object = next
	}
	if _, ok := object[keys[len(keys)-1]]; !ok {
		return false
	}
	object[keys[len(keys)-1]] = value
	return true
}

// HostTokens reads the login's tokens from the tool's own file.
func (login Login) HostTokens(home string) (LoginTokens, error) {
	document, err := login.readFile(home)
	if err != nil {
		return LoginTokens{}, err
	}
	var tokens LoginTokens
	if value, ok := lookupPath(document, login.AccessToken); ok {
		tokens.AccessToken, _ = value.(string)
	}
	if tokens.AccessToken == "" {
		return LoginTokens{}, fmt.Errorf("~/%s holds no %s; log in with the tool first", login.File, login.AccessToken)
	}
	if login.RefreshToken != "" {
		if value, ok := lookupPath(document, login.RefreshToken); ok {
			tokens.RefreshToken, _ = value.(string)
		}
	}
	if login.ExpiresAt != "" {
		if value, ok := lookupPath(document, login.ExpiresAt); ok {
			tokens.ExpiresAt = login.expiryMillis(value)
		}
	}
	return tokens, nil
}

func (login Login) expiryMillis(value any) int64 {
	switch login.ExpiresUnit {
	case "rfc3339":
		text, _ := value.(string)
		if at, err := time.Parse(time.RFC3339, text); err == nil {
			return at.UnixMilli()
		}
		return 0
	case "seconds":
		return numberValue(value) * 1000
	default:
		return numberValue(value)
	}
}

func (login Login) expiryValue(millis int64) any {
	switch login.ExpiresUnit {
	case "rfc3339":
		return time.UnixMilli(millis).UTC().Format(time.RFC3339)
	case "seconds":
		return millis / 1000
	default:
		return millis
	}
}

func numberValue(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int64:
		return typed
	case string:
		number, _ := strconv.ParseInt(typed, 10, 64)
		return number
	}
	return 0
}

// WriteHostTokens puts tokens into the tool's own file at the login's keys,
// keeping everything else and the file's mode.
func (login Login) WriteHostTokens(home string, tokens LoginTokens) error {
	document, err := login.readFile(home)
	if err != nil {
		return err
	}
	setPath(document, login.AccessToken, tokens.AccessToken)
	if login.RefreshToken != "" && tokens.RefreshToken != "" {
		setPath(document, login.RefreshToken, tokens.RefreshToken)
	}
	if login.ExpiresAt != "" && tokens.ExpiresAt != 0 {
		setPath(document, login.ExpiresAt, login.expiryValue(tokens.ExpiresAt))
	}
	var out []byte
	if login.yamlFile() {
		out, err = yaml.Marshal(document)
	} else {
		out, err = json.MarshalIndent(document, "", "  ")
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(login.path(home))
	if err != nil {
		return err
	}
	temporary := login.path(home) + ".gr8"
	if err := os.WriteFile(temporary, out, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(temporary, login.path(home))
}

// PlaceholderArg is what the launcher is given to show the sandbox the login's file
// with stand-ins at its token keys: PATH#key,key.
func (login Login) PlaceholderArg(home string) string {
	keys := []string{login.AccessToken}
	if login.RefreshToken != "" {
		keys = append(keys, login.RefreshToken)
	}
	return login.path(home) + "#" + strings.Join(keys, ",")
}

// LoginRules are the SecurityProfile rules injecting a login's access token from
// its Secret and, with a token endpoint, handling its refresh.
func LoginRules(name string, login Login) []any {
	hosts := func(list []string) []any {
		out := make([]any, len(list))
		for i, host := range list {
			out[i] = host
		}
		return out
	}
	header, template := login.Inject.Header, login.Inject.Template
	if header == "" {
		header = "authorization"
	}
	if template == "" {
		template = "Bearer {{ .Token }}"
	}
	secret := LoginSecretName(name)
	// The refresh rule comes first: rules match in order, and an inject rule for the
	// same host would otherwise take the token request, so the endpoint's new real
	// tokens would reach the client.
	var rules []any
	if login.Refresh != nil {
		rules = append(rules, map[string]any{
			"name": name + "-refresh",
			"match": []any{map[string]any{
				"domains": hosts(login.Refresh.Hosts), "schemes": []any{"https"}, "methods": []any{"POST"},
				"paths": []any{map[string]any{"type": "Prefix", "value": login.Refresh.Path}},
			}},
			"actions": map[string]any{"tokenTransformation": map[string]any{
				"type": "OAuthRefresh", "failStrategy": "Block",
				"credentialRef": map[string]any{"secret": map[string]any{"name": secret}},
			}},
		})
	}
	rules = append(rules, map[string]any{
		"name":  name,
		"match": []any{map[string]any{"domains": hosts(login.Inject.Hosts), "schemes": []any{"https"}}},
		"actions": map[string]any{"tokenTransformation": map[string]any{
			"type": "ApiKey", "failStrategy": "Block",
			"credentialRef": map[string]any{"secret": map[string]any{"name": secret, "key": "accessToken"}},
			"apiKey": map[string]any{
				"targetHeaders": map[string]any{"names": []any{header}},
				"value":         map[string]any{"template": template},
			},
		}},
	})
	return rules
}

// LoginSecurityProfile is the SecurityProfile applying a login to its commands'
// gr8 Pods in namespace.
func LoginSecurityProfile(namespace, name string, login Login) map[string]any {
	commands := make([]any, len(login.Commands))
	for i, command := range login.Commands {
		commands[i] = LabelValue(command)
	}
	return map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1", "kind": "SecurityProfile",
		"metadata": map[string]any{"name": LoginSecretName(name), "namespace": namespace,
			"labels": map[string]any{LabelManagedBy: "gr8"}},
		"spec": map[string]any{
			"selector": map[string]any{"matchExpressions": []any{map[string]any{
				"key": LabelCommand, "operator": "In", "values": commands}}},
			"rules": LoginRules(name, login),
		},
	}
}

func loginSecret(namespace, name string, tokens LoginTokens) *corev1.Secret {
	data := map[string]string{"accessToken": tokens.AccessToken}
	if tokens.RefreshToken != "" {
		data["refreshToken"] = tokens.RefreshToken
	}
	if tokens.ExpiresAt != 0 {
		data["expiresAt"] = strconv.FormatInt(tokens.ExpiresAt, 10)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: LoginSecretName(name), Namespace: namespace,
			Labels: map[string]string{LabelManagedBy: "gr8", LabelLogin: name}},
		Type:       corev1.SecretTypeOpaque,
		StringData: data,
	}
}

// LabelLogin marks a login's Secret with the login's name.
const LabelLogin = "gr8s.io/gr8-login"

// clusterTokens reads the tokens a login's Secret holds; found is false without it.
func clusterTokens(ctx context.Context, clientset kubernetes.Interface, namespace, name string) (LoginTokens, *corev1.Secret, bool, error) {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, LoginSecretName(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return LoginTokens{}, nil, false, nil
	}
	if err != nil {
		return LoginTokens{}, nil, false, err
	}
	expires, _ := strconv.ParseInt(string(secret.Data["expiresAt"]), 10, 64)
	return LoginTokens{AccessToken: string(secret.Data["accessToken"]),
		RefreshToken: string(secret.Data["refreshToken"]), ExpiresAt: expires}, secret, true, nil
}

func storeTokens(ctx context.Context, clientset kubernetes.Interface, namespace, name string, tokens LoginTokens) error {
	current, existing, found, err := clusterTokens(ctx, clientset, namespace, name)
	if err != nil {
		return err
	}
	secret := loginSecret(namespace, name, tokens)
	if !found {
		_, err = clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
		return err
	}
	if current == tokens {
		return nil
	}
	// Keep the Secret's metadata (the node's rotation annotation among it).
	existing.Data, existing.StringData = nil, secret.StringData
	_, err = clientset.CoreV1().Secrets(namespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// legacyClaudeLogin names what `gr8 login claude` used to apply, which a login of
// claude replaces.
var legacyClaudeLogin = struct{ secret, securityProfile, sandboxProfile string }{
	"claude-oauth", "claude-oauth", "claude"}

// StoreLogin copies the login name's tokens into the cluster and applies its
// SecurityProfile: `gr8 --login NAME`.
func StoreLogin(kubeconfig, namespace, name string) error {
	ctx := context.Background()
	_, clientset, err := clients(kubeconfig)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	logins, err := Logins(home)
	if err != nil {
		return err
	}
	login, ok := logins[name]
	if !ok {
		return fmt.Errorf("no login %q; gr8 knows %s (define others in ~/.config/gr8/logins.yaml)",
			name, strings.Join(LoginNames(logins), ", "))
	}
	tokens, err := login.HostTokens(home)
	if err != nil {
		return err
	}
	if err := ensureNamespace(ctx, clientset, namespace); err != nil {
		return err
	}
	if err := storeTokens(ctx, clientset, namespace, name, tokens); err != nil {
		return fmt.Errorf("storing the login: %w", err)
	}
	if err := applyObject(ctx, clientset, fmt.Sprintf(securityProfiles, namespace),
		LoginSecretName(name), LoginSecurityProfile(namespace, name, login)); err != nil {
		return fmt.Errorf("the SecurityProfile: %w", err)
	}
	if name == "claude" {
		removeLegacyClaudeLogin(ctx, clientset, namespace)
	}
	return nil
}

// RemoveLogin deletes a login's Secret and SecurityProfile: `gr8 --logout NAME`.
// The tool's own file on the host is left as it is.
func RemoveLogin(kubeconfig, namespace, name string) error {
	ctx := context.Background()
	_, clientset, err := clients(kubeconfig)
	if err != nil {
		return err
	}
	rest := clientset.Discovery().RESTClient()
	err = clientset.CoreV1().Secrets(namespace).Delete(ctx, LoginSecretName(name), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	err = rest.Delete().AbsPath(fmt.Sprintf(securityProfiles, namespace), LoginSecretName(name)).Do(ctx).Error()
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if name == "claude" {
		removeLegacyClaudeLogin(ctx, clientset, namespace)
	}
	return nil
}

func removeLegacyClaudeLogin(ctx context.Context, clientset kubernetes.Interface, namespace string) {
	rest := clientset.Discovery().RESTClient()
	_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, legacyClaudeLogin.secret, metav1.DeleteOptions{})
	_ = rest.Delete().AbsPath(fmt.Sprintf(securityProfiles, namespace), legacyClaudeLogin.securityProfile).Do(ctx).Error()
	_ = rest.Delete().AbsPath(sandboxProfiles, legacyClaudeLogin.sandboxProfile).Do(ctx).Error()
}

// LoginNames are logins' names, sorted.
func LoginNames(logins map[string]Login) []string {
	names := make([]string, 0, len(logins))
	for name := range logins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListLogins reports each login gr8 knows and whether it is stored: `gr8 --logins`.
func ListLogins(kubeconfig, namespace string) ([]string, error) {
	ctx := context.Background()
	_, clientset, err := clients(kubeconfig)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	logins, err := Logins(home)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, name := range LoginNames(logins) {
		_, err := clientset.CoreV1().Secrets(namespace).Get(ctx, LoginSecretName(name), metav1.GetOptions{})
		state := "not stored"
		if err == nil {
			state = "stored"
		}
		lines = append(lines, fmt.Sprintf("%-12s %-11s for %s, injected into %s", name, state,
			strings.Join(logins[name].Commands, ", "), strings.Join(logins[name].Inject.Hosts, ", ")))
	}
	return lines, nil
}

// storedLogins are the logins for command whose Secret is in namespace.
func storedLogins(ctx context.Context, clientset kubernetes.Interface, namespace, command string,
	logins map[string]Login) []string {
	var names []string
	for _, name := range LoginNames(logins) {
		if !logins[name].For(command) {
			continue
		}
		if _, err := clientset.CoreV1().Secrets(namespace).Get(ctx, LoginSecretName(name), metav1.GetOptions{}); err == nil {
			names = append(names, name)
		}
	}
	return names
}

// NewerTokens returns the copy the other side should take, else nil: whichever of
// host and cluster changed since last, the copy both last held; when both did, the
// later expiry, the cluster's on a tie (a refresh at the proxy, which retires the
// host's refresh token). Nil when they agree or either is unknown.
func NewerTokens(last, host LoginTokens, hostOK bool, cluster LoginTokens, clusterOK bool) *LoginTokens {
	switch {
	case !hostOK || !clusterOK || host == cluster:
		return nil
	case cluster == last:
		return &host
	case host == last, cluster.ExpiresAt >= host.ExpiresAt:
		return &cluster
	default:
		return &host
	}
}

// syncLogin keeps a login's Secret and the host's file in step until ctx ends, the
// later expiry winning: the host's own tool may refresh the file, and a refresh in
// the sandbox goes through the proxy into the Secret, which retires the file's
// refresh token. Best-effort; only a login that refreshes needs it.
func syncLogin(ctx context.Context, clientset kubernetes.Interface, namespace, name string, login Login, home string) {
	if login.Refresh == nil {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	last, _ := login.HostTokens(home)
	for {
		host, hostErr := login.HostTokens(home)
		cluster, _, found, clusterErr := clusterTokens(ctx, clientset, namespace, name)
		switch next := NewerTokens(last, host, hostErr == nil, cluster, found && clusterErr == nil); {
		case next == nil:
			if hostErr == nil && host == cluster {
				last = host
			}
		case *next == host:
			if storeTokens(ctx, clientset, namespace, name, host) == nil {
				last = host
			}
		default:
			if login.WriteHostTokens(home, *next) == nil {
				last = *next
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
