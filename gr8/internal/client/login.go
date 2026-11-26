package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Claude Code's subscription login, for `gr8 login claude` (podster-wv1w.7): its
// tokens move into a Secret, the node egress proxy injects the access token as a
// bearer token, and the sandbox sees the credentials file with stand-in tokens. When
// the sandboxed claude refreshes, the proxy exchanges the real refresh token and
// keeps the new tokens, which the node writes back to the Secret (podster-kn03).
const (
	claudeCredentials = ".claude/.credentials.json"
	claudeSecret      = "claude-oauth"
	claudeProfile     = "claude-oauth"
)

// claudeTokens is what the Secret and the host's credentials file share: the real
// tokens and the access token's expiry, in milliseconds, which orders two copies.
type claudeTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
}

// claudeHostTokens reads the tokens from the host's credentials file.
func claudeHostTokens(home string) (claudeTokens, error) {
	raw, err := os.ReadFile(filepath.Join(home, claudeCredentials))
	if err != nil {
		return claudeTokens{}, err
	}
	var credentials struct {
		OAuth claudeTokens `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &credentials); err != nil {
		return claudeTokens{}, fmt.Errorf("%s: %w", claudeCredentials, err)
	}
	if credentials.OAuth.AccessToken == "" {
		return claudeTokens{}, fmt.Errorf("%s holds no subscription login; run claude and log in first", claudeCredentials)
	}
	return credentials.OAuth, nil
}

// writeClaudeHostTokens puts tokens into the host's credentials file, keeping its
// other fields, so the host's own claude goes on working after the sandbox refreshed:
// the old refresh token no longer does.
func writeClaudeHostTokens(home string, tokens claudeTokens) error {
	path := filepath.Join(home, claudeCredentials)
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	var file map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	oauth, _ := file["claudeAiOauth"].(map[string]any)
	if oauth == nil {
		return fmt.Errorf("%s holds no subscription login", claudeCredentials)
	}
	oauth["accessToken"], oauth["refreshToken"], oauth["expiresAt"] = tokens.AccessToken, tokens.RefreshToken, tokens.ExpiresAt
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".gr8"
	if err := os.WriteFile(temporary, out, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// ClaudeSecurityProfile is the SecurityProfile injecting the access token from
// claudeSecret into the requests claude sends to the Anthropic API.
func ClaudeSecurityProfile(namespace string) map[string]any {
	return map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1", "kind": "SecurityProfile",
		"metadata": map[string]any{"name": claudeProfile, "namespace": namespace},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{LabelCommand: "claude"}},
			"rules": []any{map[string]any{
				"name":  "anthropic-oauth",
				"match": []any{map[string]any{"domains": []any{"api.anthropic.com"}, "schemes": []any{"https"}}},
				"actions": map[string]any{"tokenTransformation": map[string]any{
					"type": "ApiKey", "failStrategy": "Block",
					"credentialRef": map[string]any{"secret": map[string]any{"name": claudeSecret, "key": "accessToken"}},
					"apiKey": map[string]any{
						"targetHeaders": map[string]any{"names": []any{"authorization"}},
						"value":         map[string]any{"template": "Bearer {{ .Token }}"},
					},
				}},
			}, map[string]any{
				// The refresh exchange: the proxy swaps in the real refresh token and
				// keeps the tokens the response carries (podster-kn03).
				"name": "anthropic-oauth-refresh",
				"match": []any{map[string]any{
					"domains": []any{"platform.claude.com", "console.anthropic.com"}, "schemes": []any{"https"},
					"methods": []any{"POST"},
					"paths":   []any{map[string]any{"type": "Prefix", "value": "/v1/oauth/token"}},
				}},
				"actions": map[string]any{"tokenTransformation": map[string]any{
					"type": "OAuthRefresh", "failStrategy": "Block",
					"credentialRef": map[string]any{"secret": map[string]any{"name": claudeSecret}},
				}},
			}},
		},
	}
}

// ClaudeSandboxProfile is the SandboxProfile giving claude its state with the
// credentials file as stand-ins.
func ClaudeSandboxProfile() map[string]any {
	return map[string]any{
		"apiVersion": "gr8.gr8s.io/v1alpha1", "kind": "SandboxProfile",
		"metadata": map[string]any{"name": "claude"},
		"spec": map[string]any{
			"commands": []any{"claude"},
			"home": map[string]any{
				"readWrite":    []any{".claude", ".claude.json"},
				"placeholders": []any{claudeCredentials},
			},
		},
	}
}

// claudeSecretTokens reads the tokens the Secret holds, and whether it exists.
func claudeSecretTokens(ctx context.Context, clientset kubernetes.Interface, namespace string) (claudeTokens, *corev1.Secret, error) {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, claudeSecret, metav1.GetOptions{})
	if err != nil {
		return claudeTokens{}, nil, err
	}
	expires, _ := strconv.ParseInt(string(secret.Data["expiresAt"]), 10, 64)
	return claudeTokens{
		AccessToken:  string(secret.Data["accessToken"]),
		RefreshToken: string(secret.Data["refreshToken"]),
		ExpiresAt:    expires,
	}, secret, nil
}

func upsertSecret(ctx context.Context, clientset kubernetes.Interface, namespace string, tokens claudeTokens) error {
	secrets := clientset.CoreV1().Secrets(namespace)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: claudeSecret, Namespace: namespace,
			Labels: map[string]string{LabelManagedBy: "gr8"}},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken,
			"expiresAt": strconv.FormatInt(tokens.ExpiresAt, 10)},
	}
	current, existing, err := claudeSecretTokens(ctx, clientset, namespace)
	if apierrors.IsNotFound(err) {
		_, err = secrets.Create(ctx, secret, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if current == tokens {
		return nil
	}
	secret.ResourceVersion = existing.ResourceVersion
	_, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// applyObject creates or replaces a custom resource at path (the collection URL).
func applyObject(ctx context.Context, clientset kubernetes.Interface, collection, name string, object map[string]any) error {
	rest := clientset.Discovery().RESTClient()
	body, err := json.Marshal(object)
	if err != nil {
		return err
	}
	existing, err := rest.Get().AbsPath(collection, name).DoRaw(ctx)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		return rest.Post().AbsPath(collection).Body(body).SetHeader("Content-Type", "application/json").Do(ctx).Error()
	}
	var current struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(existing, &current)
	object["metadata"].(map[string]any)["resourceVersion"] = current.Metadata.ResourceVersion
	if body, err = json.Marshal(object); err != nil {
		return err
	}
	return rest.Put().AbsPath(collection, name).Body(body).SetHeader("Content-Type", "application/json").Do(ctx).Error()
}

// LoginClaude stores the host's claude login for injection: the Secret, the
// SecurityProfile that injects it, and the SandboxProfile that hides it.
func LoginClaude(kubeconfig, namespace string) error {
	ctx := context.Background()
	_, clientset, err := clients(kubeconfig)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	tokens, err := claudeHostTokens(home)
	if err != nil {
		return err
	}
	if err := ensureNamespace(ctx, clientset, namespace); err != nil {
		return err
	}
	if err := upsertSecret(ctx, clientset, namespace, tokens); err != nil {
		return fmt.Errorf("storing the login: %w", err)
	}
	if err := applyObject(ctx, clientset, fmt.Sprintf("/apis/agents.kruise.io/v1alpha1/namespaces/%s/securityprofiles", namespace),
		claudeProfile, ClaudeSecurityProfile(namespace)); err != nil {
		return fmt.Errorf("the SecurityProfile: %w", err)
	}
	if err := applyObject(ctx, clientset, "/apis/gr8.gr8s.io/v1alpha1/sandboxprofiles", "claude",
		ClaudeSandboxProfile()); err != nil {
		return fmt.Errorf("the SandboxProfile: %w", err)
	}
	return nil
}

// syncCredentials keeps the Secret and the host's credentials file in step until ctx
// ends, the later expiry winning: the host's own claude may refresh the file, and a
// refresh in the sandbox goes through the proxy into the Secret, which retires the
// file's refresh token, so the file gets the new tokens. Best-effort.
func syncCredentials(ctx context.Context, clientset kubernetes.Interface, namespace, command, home string) {
	if filepath.Base(command) != "claude" {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		host, hostErr := claudeHostTokens(home)
		cluster, _, clusterErr := claudeSecretTokens(ctx, clientset, namespace)
		switch next := NewerTokens(host, hostErr == nil, cluster, clusterErr == nil); {
		case next == nil:
		case *next == host:
			_ = upsertSecret(ctx, clientset, namespace, host)
		default:
			_ = writeClaudeHostTokens(home, *next)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// NewerTokens returns whichever of host and cluster expires later, when they differ
// and both are known, else nil: the copy the other should take.
func NewerTokens(host claudeTokens, hostOK bool, cluster claudeTokens, clusterOK bool) *claudeTokens {
	if !hostOK || !clusterOK || host == cluster {
		return nil
	}
	if host.ExpiresAt >= cluster.ExpiresAt {
		return &host
	}
	return &cluster
}
