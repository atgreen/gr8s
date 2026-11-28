// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// gr8PodFixture is gr8's Pod as the gr8s suite checks it against the server's rules
// for a gr8 user's namespace (podster-tcr8), so a change here the server would refuse
// fails there. GR8_UPDATE_FIXTURES=1 rewrites it.
var gr8PodFixture = filepath.Join("..", "..", "..", "tests", "fixtures", "gr8-pod.json")

func fixturePod() *corev1.Pod {
	return NewPod(PodRequest{
		Namespace: "gr8-alice", Node: "gr8-local", Image: "registry.k8s.io/pause:3.10",
		Launcher: "/usr/bin/gr8", Command: "claude", GPU: true,
		Identity: Identity{User: "alice", UID: 1000, GID: 1000, Groups: []int64{1000, 10}},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")},
		},
	}, "abcde")
}

func TestGr8sPodGainsNoPrivilege(t *testing.T) {
	pod := fixturePod()
	for _, container := range pod.Spec.Containers {
		context := container.SecurityContext
		if context == nil || context.AllowPrivilegeEscalation == nil || *context.AllowPrivilegeEscalation {
			t.Errorf("container %s may escalate privilege", container.Name)
		}
		if context == nil || context.Capabilities == nil || len(context.Capabilities.Drop) != 1 ||
			context.Capabilities.Drop[0] != "ALL" || len(context.Capabilities.Add) != 0 {
			t.Errorf("container %s keeps capabilities: %+v", container.Name, context)
		}
	}
	raw, err := json.MarshalIndent(pod, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if os.Getenv("GR8_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(gr8PodFixture, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fixture, err := os.ReadFile(gr8PodFixture)
	if err != nil {
		t.Fatalf("%v (GR8_UPDATE_FIXTURES=1 go test ./... writes it)", err)
	}
	if !bytes.Equal(fixture, raw) {
		t.Errorf("%s is not gr8's Pod any more; rerun with GR8_UPDATE_FIXTURES=1 and check the gr8s suite", gr8PodFixture)
	}
}

func TestARunsSandboxProfileIsForItsOwnNamespace(t *testing.T) {
	profile := RunSandboxProfile("gr8-alice", "gr8-claude-abcde", "claude", nil)
	selector, _ := profile["spec"].(map[string]any)["namespaceSelector"].(map[string]any)
	labels, _ := selector["matchLabels"].(map[string]any)
	if len(selector) != 1 || len(labels) != 1 || labels["kubernetes.io/metadata.name"] != "gr8-alice" {
		t.Errorf("namespaceSelector = %v, want gr8-alice alone", selector)
	}
}
