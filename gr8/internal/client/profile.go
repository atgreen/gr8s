package client

import (
	"context"
	"encoding/json"
	"path/filepath"

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

// clusterProfiles lists the cluster's SandboxProfiles; a cluster without the API, or
// a caller who may not list them, has none.
func clusterProfiles(ctx context.Context, clientset kubernetes.Interface) []SandboxProfile {
	raw, err := clientset.Discovery().RESTClient().Get().
		AbsPath("/apis/gr8.gr8s.io/v1alpha1/sandboxprofiles").DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []struct {
			Spec SandboxProfile `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var profiles []SandboxProfile
	for _, item := range list.Items {
		profiles = append(profiles, item.Spec)
	}
	return profiles
}
