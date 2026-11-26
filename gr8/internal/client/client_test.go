package client

import (
	"net"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewPodRunsAsTheCallerOnTheNodeWithTheHostMounted(t *testing.T) {
	pod := NewPod(PodRequest{
		Namespace: "gr8", Node: "gr8s-local", Image: "pause", Launcher: "/usr/bin/gr8",
		Command:  "ping",
		Identity: Identity{User: "green", UID: 1000, GID: 1000, Groups: []int64{1000, 10, 39}},
	}, "abcde")

	if pod.Name != "gr8-ping-abcde" || pod.Namespace != "gr8" || pod.Spec.NodeName != "gr8s-local" {
		t.Fatalf("placed as %s/%s on %q", pod.Namespace, pod.Name, pod.Spec.NodeName)
	}
	if pod.Labels[LabelCommand] != "ping" || pod.Labels[LabelUser] != "green" {
		t.Errorf("labels %v", pod.Labels)
	}
	context := pod.Spec.SecurityContext
	if *context.RunAsUser != 1000 || *context.RunAsGroup != 1000 {
		t.Errorf("runs as %d:%d", *context.RunAsUser, *context.RunAsGroup)
	}
	if !reflect.DeepEqual(context.SupplementalGroups, []int64{10, 39}) {
		t.Errorf("supplemental groups %v, want the caller's without the primary group", context.SupplementalGroups)
	}
	if len(context.Sysctls) != 1 || context.Sysctls[0].Name != "net.ipv4.ping_group_range" {
		t.Errorf("sysctls %v", context.Sysctls)
	}
	container := pod.Spec.Containers[0]
	if !reflect.DeepEqual(container.Command, []string{"/host/usr/bin/gr8", "hold"}) {
		t.Errorf("command %v", container.Command)
	}
	if container.VolumeMounts[0].MountPath != HostRoot || pod.Spec.Volumes[0].HostPath.Path != "/" {
		t.Errorf("host / is not mounted at %s", HostRoot)
	}
	if *pod.Spec.AutomountServiceAccountToken {
		t.Error("the command must not get a service account token")
	}
}

func TestNewNamespaceAdmitsHostPath(t *testing.T) {
	if NewNamespace("gr8").Labels["pod-security.kubernetes.io/enforce"] != "privileged" {
		t.Error("a hostPath volume needs the privileged Pod Security level")
	}
}

func TestPodNameIsADNSSubdomain(t *testing.T) {
	for command, want := range map[string]string{
		"ping":                        "gr8-ping-xyz",
		"Python3.12":                  "gr8-python3-12-xyz",
		"__":                          "gr8-command-xyz",
		strings.Repeat("a", 60) + "!": "gr8-" + strings.Repeat("a", 40) + "-xyz",
	} {
		if got := PodName(command, "xyz"); got != want {
			t.Errorf("PodName(%q) = %q, want %q", command, got, want)
		}
	}
}

func TestLabelValue(t *testing.T) {
	for in, want := range map[string]string{
		"green":                 "green",
		"DOMAIN\\user":          "DOMAIN-user",
		"-x-":                   "x",
		"":                      "unknown",
		strings.Repeat("b", 70): strings.Repeat("b", 63),
	} {
		if got := LabelValue(in); got != want {
			t.Errorf("LabelValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSelectEnvPassesOnlyTheAllowlistAndNamedVariables(t *testing.T) {
	environ := []string{"TERM=xterm", "LC_ALL=C", "SSH_AUTH_SOCK=/run/x", "GITHUB_TOKEN=s3cret",
		"AWS_REGION=x", "PATH=/usr/bin", "NOEQUALS"}
	got := SelectEnv(environ, []string{"AWS_REGION"})
	want := []string{"TERM=xterm", "LC_ALL=C", "AWS_REGION=x", "PATH=/usr/bin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SelectEnv = %v, want %v", got, want)
	}
}

func node(name string, addresses ...string) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for _, address := range addresses {
		n.Status.Addresses = append(n.Status.Addresses,
			corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: address})
	}
	return n
}

func TestLocalNodeMatchesThisHostsAddresses(t *testing.T) {
	nodes := []corev1.Node{node("gr8s2", "10.77.77.20"), node("gr8s-local", "10.77.77.10")}
	local := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.77.77.10")}
	if name, err := LocalNode(nodes, local); err != nil || name != "gr8s-local" {
		t.Errorf("LocalNode = %q, %v", name, err)
	}
	if _, err := LocalNode(nodes, []net.IP{net.ParseIP("192.0.2.1")}); err == nil {
		t.Error("no matching node should be an error")
	}
	twice := append(nodes, node("other", "10.77.77.10"))
	if _, err := LocalNode(twice, local); err == nil {
		t.Error("two matching nodes should be an error")
	}
}

func TestProfile(t *testing.T) {
	grant := Profile("/usr/local/bin/claude", "/home/u", nil)
	if !reflect.DeepEqual(grant.ReadOnly, []string{"/home/u/.gitconfig", "/home/u/.config/git"}) {
		t.Errorf("read-only %v", grant.ReadOnly)
	}
	if !reflect.DeepEqual(grant.ReadWrite, []string{"/home/u/.claude", "/home/u/.claude.json"}) || grant.Env != nil {
		t.Errorf("read-write %v, env %v", grant.ReadWrite, grant.Env)
	}
	if grant := Profile("ping", "/home/u", nil); grant.ReadWrite != nil {
		t.Errorf("ping gets %v", grant.ReadWrite)
	}
	// A SandboxProfile in the cluster wins over the built-in table.
	var cluster SandboxProfile
	cluster.Commands = []string{"claude"}
	cluster.Home.ReadOnly = []string{".config/claude"}
	cluster.Home.Placeholders = []string{".claude/.credentials.json"}
	cluster.Env = map[string]string{"ANTHROPIC_API_KEY": "gr8s-injected"}
	grant = Profile("claude", "/home/u", []SandboxProfile{cluster})
	if !reflect.DeepEqual(grant.ReadOnly, []string{"/home/u/.gitconfig", "/home/u/.config/git", "/home/u/.config/claude"}) ||
		grant.ReadWrite != nil || grant.Env["ANTHROPIC_API_KEY"] != "gr8s-injected" ||
		!reflect.DeepEqual(grant.Placeholders, []string{"/home/u/.claude/.credentials.json"}) {
		t.Errorf("cluster profile gave %+v", grant)
	}
}

func TestNewPodMountsTheEgressTrustBundle(t *testing.T) {
	pod := NewPod(PodRequest{Namespace: "gr8", Node: "n", Image: "pause", Launcher: "/usr/bin/gr8",
		Command: "claude", Identity: Identity{User: "u", UID: 1000, GID: 1000}}, "x")
	var found bool
	for _, volume := range pod.Spec.Volumes {
		if volume.Projected != nil && len(volume.Projected.Sources) == 1 {
			bundle := volume.Projected.Sources[0].ClusterTrustBundle
			found = bundle != nil && *bundle.Name == TrustBundle && *bundle.Optional && bundle.Path == TrustFile
		}
	}
	if !found {
		t.Errorf("no optional %s trust bundle volume in %+v", TrustBundle, pod.Spec.Volumes)
	}
}

func TestProfilesForPrefersANamespacesOwnProfile(t *testing.T) {
	named := func(name, command string, selector *metav1.LabelSelector) NamedProfile {
		var item NamedProfile
		item.Metadata.Name = name
		item.Spec.Commands = []string{command}
		item.Spec.Env = map[string]string{"FROM": name}
		item.Spec.NamespaceSelector = selector
		return item
	}
	items := []NamedProfile{
		named("z-default", "claude", nil),
		named("a-default", "claude", nil),
		named("team", "claude", &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}),
		named("prod", "claude", &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "prod"}}),
	}
	from := func(profiles []SandboxProfile) []string {
		var names []string
		for _, profile := range profiles {
			names = append(names, profile.Env["FROM"])
		}
		return names
	}
	if got := from(ProfilesFor(items, "gr8", map[string]string{"team": "a"})); !reflect.DeepEqual(got, []string{"team", "a-default", "z-default"}) {
		t.Errorf("team a: %v", got)
	}
	if got := from(ProfilesFor(items, "prod", nil)); !reflect.DeepEqual(got, []string{"prod", "a-default", "z-default"}) {
		t.Errorf("prod, by its name label: %v", got)
	}
	if got := Profile("claude", "/home/u", ProfilesFor(items, "other", nil)); got.Env["FROM"] != "a-default" {
		t.Errorf("elsewhere the first unscoped profile applies, got %v", got.Env)
	}
}
