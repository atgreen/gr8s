// Package client creates the Pod a gr8ify command runs in, on the local
// gr8s node, and streams the command's terminal through Pod exec.
package client

import (
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HostRoot is where the Pod mounts the host's /; the launcher chroots into it.
const HostRoot = "/host"

// ContainerName names the one container of a gr8ify Pod.
const ContainerName = "command"

// The egress CA's ClusterTrustBundle, mounted so the launcher can make the sandbox
// trust the node egress proxy where it injects credentials (podster-wv1w.5).
const (
	TrustBundle = "gr8s-egress"
	TrustMount  = "/gr8ify-trust"
	TrustFile   = "egress-ca.pem"
)

// Labels a NetworkPolicy can select gr8ify Pods by.
const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelCommand   = "gr8s.io/gr8ify-command"
	LabelUser      = "gr8s.io/gr8ify-user"
)

// Identity is the caller the command runs as.
type Identity struct {
	User   string
	UID    int64
	GID    int64
	Groups []int64
}

// PodRequest describes the Pod to create.
type PodRequest struct {
	Namespace string
	Node      string
	Image     string
	Launcher  string // the gr8ify binary's path on the host
	Command   string // the command's base name
	Identity  Identity
}

// NewPod returns the Pod that holds a gr8ify command. Its container only
// waits ("gr8ify hold"); the command itself is started by Pod exec, so no
// output is lost before the terminal is attached.
func NewPod(request PodRequest, suffix string) *corev1.Pod {
	hostPathDirectory := corev1.HostPathDirectory
	var supplemental []int64
	for _, group := range request.Identity.Groups {
		if group != request.Identity.GID {
			supplemental = append(supplemental, group)
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PodName(request.Command, suffix),
			Namespace: request.Namespace,
			Labels: map[string]string{
				LabelManagedBy: "gr8ify",
				LabelCommand:   LabelValue(request.Command),
				LabelUser:      LabelValue(request.Identity.User),
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                      request.Node,
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			TerminationGracePeriodSeconds: ptr(int64(1)),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:          ptr(request.Identity.UID),
				RunAsGroup:         ptr(request.Identity.GID),
				SupplementalGroups: supplemental,
				// Unprivileged ICMP sockets, so ping needs no CAP_NET_RAW.
				Sysctls: []corev1.Sysctl{{Name: "net.ipv4.ping_group_range", Value: "0 2147483647"}},
				// The launcher creates a user namespace, which RuntimeDefault forbids.
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
			},
			Containers: []corev1.Container{{
				Name:    ContainerName,
				Image:   request.Image,
				Command: []string{HostRoot + request.Launcher, "hold"},
				VolumeMounts: []corev1.VolumeMount{
					{Name: "host", MountPath: HostRoot},
					{Name: "egress-trust", MountPath: TrustMount, ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				{
					Name: "host",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/", Type: &hostPathDirectory},
					},
				},
				{
					Name: "egress-trust",
					VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{{ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
							Name: ptr(TrustBundle), Path: TrustFile, Optional: ptr(true),
						}}},
					}},
				},
			},
		},
	}
}

// NewNamespace returns the namespace gr8ify Pods live in. Mounting the host's
// / is a hostPath volume, which only the privileged Pod Security level admits.
func NewNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			LabelManagedBy:                       "gr8ify",
			"pod-security.kubernetes.io/enforce": "privileged",
		},
	}}
}

// PodName returns "gr8ify-COMMAND-SUFFIX" as a valid DNS subdomain.
func PodName(command, suffix string) string {
	base := strings.Trim(mapInvalid(strings.ToLower(command), func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
	}), "-")
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	if base == "" {
		base = "command"
	}
	return "gr8ify-" + base + "-" + suffix
}

// LabelValue turns s into a valid label value: at most 63 characters of
// [A-Za-z0-9-_.], beginning and ending with an alphanumeric.
func LabelValue(s string) string {
	value := mapInvalid(s, func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
	})
	if len(value) > 63 {
		value = value[:63]
	}
	value = strings.TrimFunc(value, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	if value == "" {
		return "unknown"
	}
	return value
}

func mapInvalid(s string, valid func(rune) bool) string {
	return strings.Map(func(r rune) rune {
		if valid(r) {
			return r
		}
		return '-'
	}, s)
}

// LocalNode returns the one Node with an address this host has.
func LocalNode(nodes []corev1.Node, local []net.IP) (string, error) {
	var matches []string
	for _, node := range nodes {
		if nodeHasAddress(node, local) {
			matches = append(matches, node.Name)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no node has an address of this host; is a gr8s agent running here? (name one with --node)")
	default:
		return "", fmt.Errorf("nodes %s all have addresses of this host (name one with --node)",
			strings.Join(matches, ", "))
	}
}

func nodeHasAddress(node corev1.Node, local []net.IP) bool {
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP && address.Type != corev1.NodeExternalIP {
			continue
		}
		ip := net.ParseIP(address.Address)
		for _, mine := range local {
			if ip != nil && ip.Equal(mine) {
				return true
			}
		}
	}
	return false
}

func ptr[T any](value T) *T { return &value }
