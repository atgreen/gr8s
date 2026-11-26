package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// What a policy adds to one run (podster-wv1w.14): its credentials' Secrets and the
// SecurityProfile injecting them, owned by the run's Pod so they go with it even if
// gr8 doesn't; and, for its egress block, a SandboxProfile for this run alone,
// which is cluster-scoped and so is deleted when the run ends.

const (
	securityProfiles = "/apis/agents.kruise.io/v1alpha1/namespaces/%s/securityprofiles"
	sandboxProfiles  = "/apis/gr8.gr8s.io/v1alpha1/sandboxprofiles"
)

func ownedBy(pod *corev1.Pod) []metav1.OwnerReference {
	return []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}}
}

// CredentialSecretName names a run's i-th credential's Secret.
func CredentialSecretName(pod string, i int) string { return fmt.Sprintf("%s-credential-%d", pod, i) }

// RunSecurityProfile is the SecurityProfile injecting credentials into the requests
// of the Pod named pod alone, each from its CredentialSecretName.
func RunSecurityProfile(namespace, pod string, credentials []PolicyCredential, extra ...any) map[string]any {
	var rules []any
	for i, credential := range credentials {
		hosts := make([]any, len(credential.Hosts))
		for j, host := range credential.Hosts {
			hosts[j] = host
		}
		rules = append(rules, map[string]any{
			"name":  fmt.Sprintf("credential-%d", i),
			"match": []any{map[string]any{"domains": hosts, "schemes": []any{"https"}}},
			"actions": map[string]any{"tokenTransformation": map[string]any{
				"type": "ApiKey", "failStrategy": "Block",
				"credentialRef": map[string]any{"secret": map[string]any{"name": CredentialSecretName(pod, i), "key": "token"}},
				"apiKey": map[string]any{
					"targetHeaders": map[string]any{"names": []any{credential.Header}},
					"value":         map[string]any{"template": credential.Template},
				},
			}},
		})
	}
	rules = append(rules, extra...)
	return map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1", "kind": "SecurityProfile",
		"metadata": map[string]any{"name": pod, "namespace": namespace, "labels": map[string]any{LabelManagedBy: "gr8"}},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{LabelRun: pod}},
			"rules":    rules,
		},
	}
}

// RunSandboxProfile is the SandboxProfile carrying a policy's egress block for the
// run of command in the Pod named pod alone; the node prefers it to any other.
func RunSandboxProfile(pod, command string, egress map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "gr8.gr8s.io/v1alpha1", "kind": "SandboxProfile",
		"metadata": map[string]any{"name": pod, "labels": map[string]any{LabelManagedBy: "gr8", LabelRun: pod}},
		"spec":     map[string]any{"commands": []any{command}, "run": pod, "egress": egress},
	}
}

// AnnotationStandIn records on a credential's Secret the stand-in its sandbox holds.
const AnnotationStandIn = "gr8s.io/stand-in"

// createPolicyCredentials creates a Secret holding each of values, annotated with
// its stand-in, and the SecurityProfile injecting them for the Pod pod will be. They
// come before the Pod: a node receives a Secret with the assignment of the Pod that
// uses it, so one made after would not reach it.
func createPolicyCredentials(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod,
	credentials []PolicyCredential, values, standIns []string, loginRules []any) error {
	if len(credentials) == 0 && len(loginRules) == 0 {
		return nil
	}
	for i, value := range values {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: CredentialSecretName(pod.Name, i), Namespace: pod.Namespace,
				Labels: map[string]string{LabelManagedBy: "gr8", LabelRun: pod.Name}},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{"token": value},
		}
		if i < len(standIns) {
			// The proxy swaps this credential in where a request carries its stand-in
			// (podster-wv1w.27).
			secret.Annotations = map[string]string{AnnotationStandIn: standIns[i]}
		}
		if _, err := clientset.CoreV1().Secrets(pod.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("storing credential %d: %w", i, err)
		}
	}
	return postObject(ctx, clientset, fmt.Sprintf(securityProfiles, pod.Namespace),
		RunSecurityProfile(pod.Namespace, pod.Name, credentials, loginRules...), "the SecurityProfile")
}

// adoptPolicyCredentials makes the run's Pod own its credentials' Secrets and
// SecurityProfile, so they go with it even if gr8 doesn't. Best-effort: gr8 deletes
// them itself when the run ends.
func adoptPolicyCredentials(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod, count int, profile bool) {
	if !profile {
		return
	}
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"ownerReferences": ownedBy(pod)}})
	for i := range count {
		_, _ = clientset.CoreV1().Secrets(pod.Namespace).Patch(ctx, CredentialSecretName(pod.Name, i),
			types.MergePatchType, patch, metav1.PatchOptions{})
	}
	_ = clientset.Discovery().RESTClient().Patch(types.MergePatchType).
		AbsPath(fmt.Sprintf(securityProfiles, pod.Namespace), pod.Name).Body(patch).Do(ctx).Error()
}

// deletePolicyCredentials removes a run's credentials' Secrets and SecurityProfile.
func deletePolicyCredentials(clientset kubernetes.Interface, pod *corev1.Pod, count int, profile bool) {
	if !profile {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := range count {
		_ = clientset.CoreV1().Secrets(pod.Namespace).Delete(ctx, CredentialSecretName(pod.Name, i), metav1.DeleteOptions{})
	}
	_ = clientset.Discovery().RESTClient().Delete().
		AbsPath(fmt.Sprintf(securityProfiles, pod.Namespace), pod.Name).Do(ctx).Error()
}

func postObject(ctx context.Context, clientset kubernetes.Interface, collection string, object map[string]any, what string) error {
	body, err := json.Marshal(object)
	if err != nil {
		return err
	}
	err = clientset.Discovery().RESTClient().Post().AbsPath(collection).
		Body(body).SetHeader("Content-Type", "application/json").Do(ctx).Error()
	if err != nil {
		return fmt.Errorf("creating %s: %w", what, err)
	}
	return nil
}

func deleteRunSandboxProfile(clientset kubernetes.Interface, pod string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = clientset.Discovery().RESTClient().Delete().AbsPath(sandboxProfiles, pod).Do(ctx).Error()
}
