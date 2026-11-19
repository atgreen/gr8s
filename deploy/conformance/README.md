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

A k3s install with the pieces gr8s owns turned off. Two prerequisites: the
chart ships no CRDs, so install the Gateway API CRD bundle before enabling the
gateway; and with `serviceLb` on (the default) and nothing else serving the
`kubernetes` ClusterIP, `apiServer.host` is required — the agent cannot reach
the API through the Service it is itself bringing up (see
`../chart/gr8s-net/values.yaml`). Run the helm install from the repository
root:

```
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server \
  --flannel-backend=none --disable-network-policy \
  --disable-kube-proxy --disable=traefik --disable=servicelb" sh -
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/standard-install.yaml
helm install gr8s-net deploy/chart/gr8s-net -n kube-system \
  --set gateway.enabled=true \
  --set apiServer.host=<control-plane-node-IP>  # cni and serviceLb default on
```

Join more nodes with `k3s agent` on a shared underlay and the same chart; the
agent reconciles the VXLAN fabric from the Node objects.

## Run

From this directory (`deploy/conformance/`):

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

Build the official Gateway API suite at the release tag matching the installed
CRD bundle (currently v1.6.3). The conformance directory is its own Go module:

```
cd gateway-api/conformance
CGO_ENABLED=0 go test -c . -o gateway-conformance.test
```

Copy the binary and `run-conformance.sh` to a node with access to the advertised
Gateway Service IPs. Gateway-only testing can use the cluster's existing CNI
and kube-proxy: run `gr8s net-agent` with `--cni false --service-lb false
--gateway true`. This does not test gr8s CNI or Service BPF forwarding.

```
KUBECONFIG=/etc/rancher/k3s/k3s.yaml \
GATEWAY_CONFORMANCE_BINARY=/root/gateway-conformance.test \
GR8S_VERSION=<exact-tested-build-identifier> \
GATEWAY_CONFORMANCE_REPORT=/root/gr8s-report.yaml \
sh run-conformance.sh gateway
```

`GATEWAY_CLASS` defaults to `gr8s`; it must identify a GatewayClass whose
controller is `gr8s.io/gateway-controller`. The runner executes the complete
`GATEWAY-HTTP` profile, writes upstream report metadata, and returns the suite's
exit status. No tests are excluded. Keep the test log, report, binary digest,
cluster version, and configuration together when preparing a report submission.
Do not present a partial or failed run as a conformance claim.

On 2026-11-16, the official v1.6.3 standard-channel `GATEWAY-HTTP` profile
passed all 36 core tests, with zero failures and zero skips (exit status 0).
This includes path-match ordering and invalid-route-kind listener status.
The [unmodified report](../../docs/evidence/gateway-http-conformance-2026-11-16.yaml)
identifies the exact tested candidate by SHA-256; this is a snapshot result,
not a claim about every subsequent build.

The test ran on Fedora 44 with k3s v1.37.2+k3s1, stock flannel and kube-proxy,
and gr8s Gateway-only mode. It does not establish CNI, Service BPF, extended
Gateway feature, or ListenerSet conformance. The report and reproduction README
are prepared locally for upstream review; no upstream submission has been made.
