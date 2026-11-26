package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Claude Code's subscription login, for `gr8 login claude` (podster-wv1w.7): its
// access token moves into a Secret the node egress proxy injects as a bearer token,
// and the sandbox sees the credentials file with stand-in tokens.
const (
	claudeCredentials = ".claude/.credentials.json"
	claudeSecret      = "claude-oauth"
	claudeProfile     = "claude-oauth"
)

// claudeAccessToken reads the access token from the host's credentials file.
func claudeAccessToken(home string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(home, claudeCredentials))
	if err != nil {
		return "", err
	}
	var credentials struct {
		OAuth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &credentials); err != nil {
		return "", fmt.Errorf("%s: %w", claudeCredentials, err)
	}
	if credentials.OAuth.AccessToken == "" {
		return "", fmt.Errorf("%s holds no subscription login; run claude and log in first", claudeCredentials)
	}
	return credentials.OAuth.AccessToken, nil
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

func upsertSecret(ctx context.Context, clientset kubernetes.Interface, namespace, token string) error {
	secrets := clientset.CoreV1().Secrets(namespace)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: claudeSecret, Namespace: namespace,
			Labels: map[string]string{LabelManagedBy: "gr8"}},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{"accessToken": token},
	}
	existing, err := secrets.Get(ctx, claudeSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = secrets.Create(ctx, secret, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if string(existing.Data["accessToken"]) == token {
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
	token, err := claudeAccessToken(home)
	if err != nil {
		return err
	}
	if err := ensureNamespace(ctx, clientset, namespace); err != nil {
		return err
	}
	if err := upsertSecret(ctx, clientset, namespace, token); err != nil {
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

// syncCredentials keeps the injected token in step with the host's credentials file,
// which the host's own claude refreshes, until ctx ends. Best-effort.
func syncCredentials(ctx context.Context, clientset kubernetes.Interface, namespace, command, home string) {
	if filepath.Base(command) != "claude" {
		return
	}
	var last time.Time
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if info, err := os.Stat(filepath.Join(home, claudeCredentials)); err == nil && info.ModTime().After(last) {
			last = info.ModTime()
			if token, err := claudeAccessToken(home); err == nil {
				_ = upsertSecret(ctx, clientset, namespace, token)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
