package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"
)

// A gr8 sandbox may reach only the names a ClusterNetworkPolicy allows
// (podster-1mzb). For --allow, gr8 creates one that selects this run's Pod alone
// and deletes it with the Pod; RBAC on clusternetworkpolicies decides who may.
const clusterNetworkPolicies = "/apis/policy.networking.k8s.io/v1alpha2/clusternetworkpolicies"

// AllowPolicy is the ClusterNetworkPolicy letting the Pod named pod reach names.
func AllowPolicy(namespace, pod string, names []string) map[string]any {
	domains := make([]any, len(names))
	for i, name := range names {
		domains[i] = name
	}
	return map[string]any{
		"apiVersion": "policy.networking.k8s.io/v1alpha2", "kind": "ClusterNetworkPolicy",
		"metadata": map[string]any{"name": pod, "labels": map[string]any{LabelManagedBy: "gr8"}},
		"spec": map[string]any{
			"tier": "Admin", "priority": 10,
			"subject": map[string]any{"pods": map[string]any{
				"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace}},
				"podSelector":       map[string]any{"matchLabels": map[string]any{LabelRun: pod}},
			}},
			"egress": []any{map[string]any{
				"name": "gr8-allow", "action": "Accept",
				"to": []any{map[string]any{"domainNames": domains}},
			}},
		},
	}
}

func createAllowPolicy(ctx context.Context, clientset kubernetes.Interface, namespace, pod string, names []string) error {
	body, err := json.Marshal(AllowPolicy(namespace, pod, names))
	if err != nil {
		return err
	}
	err = clientset.Discovery().RESTClient().Post().AbsPath(clusterNetworkPolicies).
		Body(body).SetHeader("Content-Type", "application/json").Do(ctx).Error()
	if err != nil {
		return fmt.Errorf("creating the --allow ClusterNetworkPolicy: %w", err)
	}
	return nil
}

func deleteAllowPolicy(clientset kubernetes.Interface, pod string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = clientset.Discovery().RESTClient().Delete().AbsPath(clusterNetworkPolicies, pod).Do(ctx).Error()
}
