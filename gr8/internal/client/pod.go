// Package client creates the Pod a gr8 command runs in, on the local
// gr8s node, and streams the command's terminal through Pod exec.
package client

import (
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HostRoot is where the Pod mounts the host's /; the launcher chroots into it.
const HostRoot = "/host"

// ContainerName names the one container of a gr8 Pod.
const ContainerName = "command"

// The egress CA's ClusterTrustBundle, mounted so the launcher can make the sandbox
// trust the node egress proxy where it injects credentials (podster-wv1w.5).
const (
	TrustBundle = "gr8s-egress"
	TrustMount  = "/gr8-trust"
	TrustFile   = "egress-ca.pem"
)

// Labels a NetworkPolicy can select gr8 Pods by.
const (
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelCommand   = "gr8s.io/gr8-command"
	LabelUser      = "gr8s.io/gr8-user"
	// LabelRun is the Pod's name, so a policy can select this one run.
	LabelRun = "gr8s.io/gr8-run"
)

// NetworkReady is the readiness gate a gr8 Pod waits on: the node reports it once it
// enforces the Pod's network policy, so the command never runs before its allowlist
// does (podster-ae08).
const NetworkReady corev1.PodConditionType = "gr8s.io/NetworkReady"

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
	Launcher  string // the gr8 binary's path on the host
	Command   string // the command's base name
	Identity  Identity
	GPU       bool // ask for the node's GPU render nodes (GPUResource)
	// Resources are the command's CPU and memory requests and limits.
	Resources corev1.ResourceRequirements
}

// GPUResource is the extended resource a gr8s node offers its GPU render nodes as
// (podster-wv1w.16): shared, so many sandboxes hold them at once.
const GPUResource corev1.ResourceName = "gr8s.io/dri"

// NewPod returns the Pod that holds a gr8 command. Its container only
// waits ("gr8 hold"); the command itself is started by Pod exec, so no
// output is lost before the terminal is attached.
func NewPod(request PodRequest, suffix string) *corev1.Pod {
	hostPathDirectory := corev1.HostPathDirectory
	var supplemental []int64
	for _, group := range request.Identity.Groups {
		if group != request.Identity.GID {
			supplemental = append(supplemental, group)
		}
	}
	name := PodName(request.Command, suffix)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: request.Namespace,
			Labels: map[string]string{
				LabelManagedBy: "gr8",
				LabelCommand:   LabelValue(request.Command),
				LabelUser:      LabelValue(request.Identity.User),
				LabelRun:       name,
			},
		},
		Spec: corev1.PodSpec{
			NodeName:                      request.Node,
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			TerminationGracePeriodSeconds: ptr(int64(1)),
			ReadinessGates:                []corev1.PodReadinessGate{{ConditionType: NetworkReady}},
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
				Name:      ContainerName,
				Image:     request.Image,
				Command:   []string{HostRoot + request.Launcher, "hold"},
				Resources: withGPU(request.Resources, request.GPU),
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

// withGPU adds a GPU slot to resources when gpu.
func withGPU(resources corev1.ResourceRequirements, gpu bool) corev1.ResourceRequirements {
	if !gpu {
		return resources
	}
	limits := corev1.ResourceList{GPUResource: resource.MustParse("1")}
	for name, quantity := range resources.Limits {
		limits[name] = quantity
	}
	resources.Limits = limits
	return resources
}

// SandboxResources returns the command's CPU and memory requests and limits on a node
// whose allocatable is given. Without cpu or memory (Kubernetes quantities), a command
// requests 1 CPU and 1Gi and may use up to half the node's: capped, so a runaway build
// can't take the desktop, and Burstable, so it isn't the first thing the kernel kills
// under memory pressure, as a BestEffort Pod is. A given cpu or memory is both the
// request and the limit.
func SandboxResources(allocatable corev1.ResourceList, cpu, memory string) (corev1.ResourceRequirements, error) {
	requests, limits := corev1.ResourceList{}, corev1.ResourceList{}
	for _, item := range []struct {
		name    corev1.ResourceName
		given   string
		request string
	}{{corev1.ResourceCPU, cpu, "1"}, {corev1.ResourceMemory, memory, "1Gi"}} {
		if item.given != "" {
			quantity, err := resource.ParseQuantity(item.given)
			if err != nil || quantity.Sign() <= 0 {
				return corev1.ResourceRequirements{}, fmt.Errorf("--%s %q is not a positive quantity", item.name, item.given)
			}
			requests[item.name], limits[item.name] = quantity, quantity
			continue
		}
		request := resource.MustParse(item.request)
		available, ok := allocatable[item.name]
		if !ok || available.IsZero() {
			requests[item.name] = request
			continue
		}
		half := halfOf(item.name, available)
		if half.Cmp(request) < 0 {
			request = half
		}
		requests[item.name], limits[item.name] = request, half
	}
	if len(limits) == 0 {
		limits = nil
	}
	return corev1.ResourceRequirements{Requests: requests, Limits: limits}, nil
}

func halfOf(name corev1.ResourceName, quantity resource.Quantity) resource.Quantity {
	if name == corev1.ResourceCPU {
		return *resource.NewMilliQuantity(quantity.MilliValue()/2, resource.DecimalSI)
	}
	return *resource.NewQuantity(quantity.Value()/2, resource.BinarySI)
}

// NewNamespace returns the namespace gr8 Pods live in. Mounting the host's
// / is a hostPath volume, which only the privileged Pod Security level admits.
func NewNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			LabelManagedBy:                       "gr8",
			"pod-security.kubernetes.io/enforce": "privileged",
		},
	}}
}

// PodName returns "gr8-COMMAND-SUFFIX" as a valid DNS subdomain.
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
	return "gr8-" + base + "-" + suffix
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
