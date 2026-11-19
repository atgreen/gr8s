# gr8s

gr8s is a Kubernetes-compatible control plane with a foreign-cluster Gateway
controller. This report covers `gr8s net-agent --gateway` on an existing cluster,
with stock flannel and kube-proxy. The complete Gateway API v1.6.3 standard-channel
`GATEWAY-HTTP` core profile passed 36 tests, with zero failures or skips.

## Table of contents

| API channel | Implementation version | Mode | Report |
|-------------|------------------------|------|--------|
| standard | [1.37.2+git.8dc9b3e1.sha256.3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468](https://github.com/atgreen/gr8s/commit/8dc9b3e1882c157bd8617db069d9829fa6f4469c) | default | [1.37.2+git.8dc9b3e1.sha256.3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468 report](./standard-1.37.2+git.8dc9b3e1.sha256.3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468-default-report.yaml) |

## Reproduce

The tested snapshot is commit `8dc9b3e1882c157bd8617db069d9829fa6f4469c`, native executable SHA-256
`3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468`.
The version is a SemVer snapshot identifier, not a release tag. Heap dumps need
not rebuild byte-for-byte; identify any rebuilt candidate by its own digest.
The official suite was built from tag v1.6.3, commit
`c0836133e24073fcdcdbb1713aba3cc73a89d0b5`, using Go 1.27.3 and `CGO_ENABLED=0`.

1. Build gr8s on a Linux build host with SBCL, ocicl, Go, podman or docker, and
   cpio, following the repository build prerequisites:

   ```sh
   git clone https://github.com/atgreen/gr8s.git
   cd gr8s
   git checkout 8dc9b3e1882c157bd8617db069d9829fa6f4469c
   make native
   sha256sum build/gr8s
   ```

2. In a disposable Fedora 44 root VM (the run used 4 vCPUs, 4 GiB RAM and kernel
   6.19.10), install k3s v1.37.2+k3s1. Keep flannel and kube-proxy enabled; disable
   Traefik and ServiceLB. The tested guest used a QEMU disk with `cache=unsafe`
   to avoid storage stalls on the shared nested host. No performance claim is
   made. The official k3s binary used had SHA-256
   `265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda`.

   ```sh
   k3s server --disable traefik --disable servicelb --write-kubeconfig-mode 600
   ```

   Leave that server running. In another root shell, set `KUBECONFIG` and install
   only the pinned standard Gateway API CRD bundle. Do not install an older
   XListenerSet CRD for this run: the official suite rejects mixed bundle versions.

   ```sh
   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
   kubectl wait --for=condition=Ready nodes --all --timeout=180s
   kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/standard-install.yaml
   ```

3. Build the unmodified official suite on the build host. Its conformance
   directory is a separate Go module:

   ```sh
   git clone --branch v1.6.3 --depth 1 https://github.com/kubernetes-sigs/gateway-api.git
   cd gateway-api/conformance
   CGO_ENABLED=0 go test -c . -o gateway-conformance.test
   ```

   Copy `build/gr8s`, `gateway-conformance.test`, and gr8s's
   `deploy/conformance/run-conformance.sh` to `/root` in the guest. The suite must
   run inside the cluster network so Gateway Service IPs are reachable.

4. Create the class, start the Gateway-only agent using the guest's Kubernetes
   Node name, and wait for the class to be accepted:

   ```sh
   cat <<'EOF' | kubectl apply -f -
   apiVersion: gateway.networking.k8s.io/v1
   kind: GatewayClass
   metadata:
     name: gr8s
   spec:
     controllerName: gr8s.io/gateway-controller
   EOF
   /root/gr8s net-agent --kubeconfig "$KUBECONFIG" \
     --node-name "$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')" \
     --state-directory /var/tmp/gr8s-http-conformance \
     --cni false --service-lb false --gateway true > /root/gr8s-agent.log 2>&1 &
   gateway_agent_pid=$!
   kubectl wait --for=condition=Accepted gatewayclass/gr8s --timeout=120s
   ```

5. Invoke the repository runner, without test exclusions or suite modifications.
   For a rebuild, replace the version's digest with that candidate's SHA-256.
   Preserve the log, report, exit status, cluster configuration and binary digest:

   ```sh
   export GATEWAY_CONFORMANCE_BINARY=/root/gateway-conformance.test
   export GR8S_VERSION='1.37.2+git.8dc9b3e1.sha256.3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468'
   export GATEWAY_CONFORMANCE_REPORT=/root/gr8s-report.yaml
   sh /root/run-conformance.sh gateway > /root/gateway-conformance.log 2>&1
   result=$?
   printf '%s\n' "$result" > /root/gateway-conformance.exit
   kill -TERM "$gateway_agent_pid"
   wait "$gateway_agent_pid"
   test "$result" -eq 0
   ```

This report covers Gateway HTTP core only. It makes no CNI, Service BPF,
ListenerSet, extended-feature, throughput or benchmark-scale claim. Tests for
undeclared optional features are skipped by the unmodified suite; none of the
36 core tests were skipped. The report YAML is copied byte-for-byte from the
suite output.
