# Whistler networking for foreign clusters: standalone CNI and Gateway API

## Goal

Package gr8s's Whistler eBPF networking so it installs on any conformant
Kubernetes cluster, as two features of one product:

1. **A full-dataplane CNI**: Pod connectivity (routed veth / VXLAN fabric,
   IPAM from `node.spec.podCIDR`), NetworkPolicy enforcement through the
   per-Pod Whistler TCX guards, and a kube-proxy replacement built on the
   Whistler service NAT/LB programs.
2. **A Gateway API implementation**: the existing GatewayClass/Gateway/
   HTTPRoute planner and hot-swapped L7 proxy (plus the L4 and sklookup
   paths), reconciling the `gr8s.io/gateway-controller` class.

Both build from this repository, as modes of the one dumped `gr8s` binary,
and ship together: one container image, one DaemonSet, one Helm chart, with
the Gateway feature behind a values flag.

## What exists and what is new

The dataplane needs no new mechanism. `cni-main` is already a spec-compliant
CNI plugin that relays to the node agent over the authenticated Unix socket;
the agent already owns IPAM, the veth/VXLAN fabrics, the NetworkPolicy
guards, the service NAT programs, and the node-integrated Gateway proxy.
The single hard coupling is ingestion: every one of those consumers today
reads desired state from gr8s's own store through the gr8s node protocol.

The new work is therefore concentrated in three pieces:

1. **A Kubernetes API watch client** (new). List+watch with resourceVersion
   resume and bookmarks, watch re-establishment with backoff, ServiceAccount
   token and kubeconfig authentication, built on `gr8s.http-client` (which
   gains streaming response reads). It materializes watched objects as the
   same JSON-shaped hash tables the controllers already consume. It also
   provides `coordination.k8s.io` Lease leader election.
2. **A desired-state seam** (refactor). The network and gateway consumers
   read through a narrow interface with two implementations: the gr8s store
   (today's behavior, unchanged) and the watch client's cache. The planners
   and dataplane code do not change.
3. **`gr8s cni-agent`** (new mode). The DaemonSet entry point: starts the
   CNI control socket, watches Nodes, Pods, NetworkPolicies, Services,
   EndpointSlices — and, when the gateway flag is set, GatewayClasses,
   Gateways, HTTPRoutes and ReferenceGrants — and drives the existing
   dataplane from the watch cache.

## Topology: one DaemonSet, no operator

Every node runs the same agent. The small amount of cluster-scoped work —
provisioning one LoadBalancer Service per Gateway (so
`Gateway.status.addresses` carries a real LB/VIP address, Cilium-style) and
writing Gateway/HTTPRoute status — is done by whichever agent holds a
`coordination.k8s.io` Lease. The writes are idempotent create-or-update
under optimistic concurrency, so leadership handoff mid-write is safe.

A separate operator Deployment was considered and rejected: our cluster-wide
residue is too small to justify a second deployable. IPAM comes from
`node.spec.podCIDR`; Gateway API CRDs are installed by the cluster
administrator (as other implementations also require). If cluster-wide work
later grows real (cloud IPAM pools, for example), the lease-holder code
lifts out into an operator mechanically.

## Packaging

- The per-arch release binaries the CI already builds, wrapped in a
  container image.
- An init container installs the `gr8s` binary into `/opt/cni/bin` and
  writes the CNI conf (the existing chained-plugin configuration, pointing
  at the agent's socket).
- A Helm chart installs the DaemonSet, ServiceAccount, RBAC, and the CNI
  conf settings; `gateway.enabled` turns on the Gateway watchers and the
  GatewayClass reconciliation.

## Validation

- CNI behavior through the existing privileged root-VM harness (AGENTS.md,
  "Testing eBPF and the native runtime as root").
- kube-proxy replacement against the upstream Service/EndpointSlice
  conformance expectations; NetworkPolicy against the upstream
  NetworkPolicy conformance suite.
- Gateway API against the upstream Gateway API conformance suite, which
  also produces the support report users expect.
- The watch client against gr8s's own API server first (it serves
  list+watch already), then against a foreign distribution (k3s or kind) in
  the privileged job.

## Out of scope for v1

- A separate operator Deployment (see above).
- Cloud-provider IPAM (ENI and friends); `podCIDR` only.
- A Deployment+Service gateway topology; the proxy is per-node, addressed
  through the auto-provisioned LoadBalancer Service.
- WireGuard overlay encryption as a foreign-cluster feature flag.
- Multi-cluster, Windows nodes.
