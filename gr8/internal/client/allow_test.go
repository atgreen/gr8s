package client

import (
	"encoding/json"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestAllowPolicySelectsOnlyThisRunsPod(t *testing.T) {
	pod := NewPod(PodRequest{Namespace: "gr8", Command: "curl", Identity: Identity{User: "green"}}, "abcde")
	if pod.Labels[LabelRun] != pod.Name {
		t.Fatalf("run label %q, want the Pod's name %q", pod.Labels[LabelRun], pod.Name)
	}
	raw, _ := json.Marshal(AllowPolicy("gr8", pod.Name, []string{"example.com", "*.github.com"}))
	var policy struct {
		Metadata struct{ Name string }
		Spec     struct {
			Tier    string
			Subject struct {
				Pods struct {
					NamespaceSelector struct{ MatchLabels map[string]string }
					PodSelector       struct{ MatchLabels map[string]string }
				}
			}
			Egress []struct {
				Action string
				To     []struct{ DomainNames []string }
			}
		}
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Metadata.Name != pod.Name || policy.Spec.Tier != "Admin" {
		t.Errorf("policy %s in tier %s", policy.Metadata.Name, policy.Spec.Tier)
	}
	subject := policy.Spec.Subject.Pods
	if !reflect.DeepEqual(subject.PodSelector.MatchLabels, map[string]string{LabelRun: pod.Name}) ||
		subject.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "gr8" {
		t.Errorf("subject %+v, want this Pod alone", subject)
	}
	// Accept only: the sandbox's own baseline denies the rest.
	if len(policy.Spec.Egress) != 1 || policy.Spec.Egress[0].Action != "Accept" ||
		!reflect.DeepEqual(policy.Spec.Egress[0].To[0].DomainNames, []string{"example.com", "*.github.com"}) {
		t.Errorf("egress %+v", policy.Spec.Egress)
	}
}

func TestTheCommandWaitsForTheNodeToEnforceItsNetworkPolicy(t *testing.T) {
	pod := NewPod(PodRequest{Namespace: "gr8", Command: "curl"}, "abcde")
	if len(pod.Spec.ReadinessGates) != 1 || pod.Spec.ReadinessGates[0].ConditionType != NetworkReady {
		t.Fatalf("readiness gates %v", pod.Spec.ReadinessGates)
	}
	ready := corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue}
	notReady := corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionFalse}
	pending := corev1.PodCondition{Type: NetworkReady, Status: corev1.ConditionFalse}
	for _, test := range []struct {
		conditions      []corev1.PodCondition
		ready, reported bool
	}{
		// Ready waits for the gate, even where the server does not list it.
		{[]corev1.PodCondition{ready}, true, true},
		{[]corev1.PodCondition{notReady, pending}, false, true},
		// A node that predates the gate reports neither.
		{[]corev1.PodCondition{notReady}, false, false},
	} {
		pod.Status.Conditions = test.conditions
		if ready, reported := networkReady(pod); ready != test.ready || reported != test.reported {
			t.Errorf("%v: ready %v reported %v", test.conditions, ready, reported)
		}
	}
}
