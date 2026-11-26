package client

import (
	"context"
	"encoding/json"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

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
