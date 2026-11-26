package client

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// SandboxProfile is gr8.gr8s.io/v1alpha1 SandboxProfile's spec: what a command gets
// beyond its working directory.
type SandboxProfile struct {
	Commands []string `json:"commands"`
	Home     struct {
		ReadWrite    []string `json:"readWrite"`
		ReadOnly     []string `json:"readOnly"`
		Placeholders []string `json:"placeholders"`
	} `json:"home"`
	Env map[string]string `json:"env"`
	// NamespaceSelector limits the profile to the gr8 Pods of the namespaces it selects.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// builtinProfiles apply when the cluster has no SandboxProfile for a command.
var builtinProfiles = []SandboxProfile{
	func() SandboxProfile {
		var p SandboxProfile
		p.Commands = []string{"claude"}
		p.Home.ReadWrite = []string{".claude", ".claude.json"}
		return p
	}(),
}

// defaultReadOnly is what every command reads in home: git's configuration.
var defaultReadOnly = []string{".gitconfig", ".config/git"}

// Grant is what a command gets beyond its working directory, as absolute paths.
type Grant struct {
	ReadOnly, ReadWrite, Placeholders []string
	Env                               map[string]string
}

// Profile returns the Grant for command: from the first of profiles naming it, else
// the built-in table. Every command also reads git's configuration.
func Profile(command, home string, profiles []SandboxProfile) Grant {
	inHome := func(names []string) []string {
		var paths []string
		for _, name := range names {
			paths = append(paths, filepath.Join(home, name))
		}
		return paths
	}
	grant := Grant{ReadOnly: inHome(defaultReadOnly)}
	base := filepath.Base(command)
	for _, list := range [][]SandboxProfile{profiles, builtinProfiles} {
		for _, profile := range list {
			for _, name := range profile.Commands {
				if name == base {
					grant.ReadOnly = append(grant.ReadOnly, inHome(profile.Home.ReadOnly)...)
					grant.ReadWrite = inHome(profile.Home.ReadWrite)
					grant.Placeholders = inHome(profile.Home.Placeholders)
					grant.Env = profile.Env
					return grant
				}
			}
		}
	}
	return grant
}

// clusterProfiles lists the cluster's SandboxProfiles for namespace's gr8 Pods, in the
// order the node picks them (see ProfilesFor); a cluster without the API, or a caller
// who may not list them, has none.
func clusterProfiles(ctx context.Context, clientset kubernetes.Interface, namespace string) []SandboxProfile {
	raw, err := clientset.Discovery().RESTClient().Get().
		AbsPath("/apis/gr8.gr8s.io/v1alpha1/sandboxprofiles").DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []NamedProfile `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var labels map[string]string
	if object, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{}); err == nil {
		labels = object.Labels
	}
	return ProfilesFor(list.Items, namespace, labels)
}

// NamedProfile is a SandboxProfile as listed: its name and spec.
type NamedProfile struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec SandboxProfile `json:"spec"`
}

// ProfilesFor returns the profiles that apply in namespace, whose labels are labels:
// those without a namespaceSelector and those whose selector matches, the matching
// ones first, each group by name. The node chooses among them the same way.
func ProfilesFor(items []NamedProfile, namespace string, labels map[string]string) []SandboxProfile {
	all := map[string]string{"kubernetes.io/metadata.name": namespace}
	for key, value := range labels {
		all[key] = value
	}
	var scoped, unscoped []NamedProfile
	for _, item := range items {
		if item.Spec.NamespaceSelector == nil {
			unscoped = append(unscoped, item)
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(item.Spec.NamespaceSelector)
		if err == nil && selector.Matches(k8slabels.Set(all)) {
			scoped = append(scoped, item)
		}
	}
	var profiles []SandboxProfile
	for _, group := range [][]NamedProfile{scoped, unscoped} {
		sort.SliceStable(group, func(i, j int) bool { return group[i].Metadata.Name < group[j].Metadata.Name })
		for _, item := range group {
			profiles = append(profiles, item.Spec)
		}
	}
	return profiles
}
