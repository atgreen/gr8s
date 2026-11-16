# Conformance for gr8s-as-CNI

gr8s networks a foreign cluster from a DaemonSet of `gr8s net-agent` pods
(see `../chart/gr8s-net`), replacing the stock CNI, kube-proxy and any
built-in NetworkPolicy controller. These are the upstream suites that prove
the result conforms, and how to run them.

Conformance needs a real, running cluster with the gr8s dataplane (eBPF,
cgroup2, a bpffs) attached, which GitHub-hosted runners cannot provide. So
this is a reproducible harness you run against such a cluster, not a
GitHub-hosted CI job. The privileged `gr8s-root` self-hosted runner, or a
throwaway k3s on a KVM host, is the right place.

## Prepare the cluster

A k3s install with the pieces gr8s owns turned off:

```
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server \
  --flannel-backend=none --disable-network-policy \
  --disable-kube-proxy --disable=traefik --disable=servicelb" sh -
helm install gr8s-net deploy/chart/gr8s-net -n kube-system \
  --set gateway.enabled=true   # cni and serviceLb features default on
```

Join more nodes with `k3s agent` on a shared underlay and the same chart; the
agent reconciles the VXLAN fabric from the Node objects.

## Run

```
KUBECONFIG=/etc/rancher/k3s/k3s.yaml sh run-conformance.sh network   # sig-network Conformance
KUBECONFIG=/etc/rancher/k3s/k3s.yaml sh run-conformance.sh gateway   # Gateway API profile + report
KUBECONFIG=/etc/rancher/k3s/k3s.yaml sh run-conformance.sh full      # every [Conformance] test
```

## What has been verified

On a two-node k3s v1.37.2 cluster (kube-proxy, flannel and netpol disabled),
with gr8s as the sole CNI, the following passed live (see the epic
`podster-982`):

- Pod connectivity and IPAM from each node's `spec.podCIDR`, routed veths.
- Cross-node pod-to-pod traffic over the gr8s VXLAN fabric.
- Services (ClusterIP + DNS) served by the Whistler socket load balancer with
  kube-proxy disabled, including cross-node backends.
- NetworkPolicy enforced in the per-Pod Whistler eBPF guards, across nodes.
- Gateway API: HTTPRoute routing through per-node listeners, with Gateway
  status (`Accepted`/`Programmed`) and a per-Gateway LoadBalancer Service.
- sonobuoy quick-mode e2e: 8/8 passed.

The `network` suite above extends this to the upstream sig-network Conformance
set; `full` and `gateway` complete the formal profiles.

## Gateway API conformance

Run the Gateway API conformance suite (`kubernetes-sigs/gateway-api`, matching
the installed CRD bundle version) with `--gateway-class=gr8s`. Run it **from
inside the cluster network** (on a node), because a gr8s Gateway advertises the
node addresses and the suite connects to them directly:

```
go test -c ./conformance -o gwconf.test        # build once, on a machine with Go
scp gwconf.test <node>:/root/                   # copy the static binary to a node
ssh <node> 'KUBECONFIG=/etc/rancher/k3s/k3s.yaml /root/gwconf.test \
  -test.run TestConformance -gateway-class=gr8s \
  -supported-features=Gateway,HTTPRoute,ReferenceGrant'
```

Verified passing against v1.6.3 with GatewayClass gr8s: HTTPRouteSimpleSameNamespace,
HTTPRouteCrossNamespace, HTTPRouteHeaderMatching, HTTPRouteMatching,
HTTPRouteMatchingAcrossRoutes, GatewayObservedGenerationBump. Known gaps:
HTTPRoute path-match ordering and invalid-route-kind listener status.
