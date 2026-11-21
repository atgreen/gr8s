# Your first workload

This walkthrough creates a Deployment with two nginx replicas, exposes it through
a ClusterIP Service, resolves its DNS name from another Pod, and replaces its
replicas in a rolling restart. Run commands from the repository root on a disposable
Linux VM with the [build and runtime prerequisites](building-and-testing.md#requirements).
The node needs registry access for nginx and BusyBox; see [airgap images](runtime.md#preloaded-images-airgap)
for disconnected nodes.

## Start a cluster

Install a [release binary](../README.md#getting-started), or build one without
root with `make native` and use `build/gr8s` in place of `gr8s` below. Start the
server as root and leave this terminal running:

```sh
sudo gr8s serve
```

The API uses HTTPS on port 6443. In another terminal, save an administrative
kubeconfig that only you can read, and point `kubectl` at it:

```sh
(umask 077; sudo gr8s kubeconfig > ~/gr8s.kubeconfig)
export KUBECONFIG=~/gr8s.kubeconfig

kubectl wait --for=condition=Ready node/gr8s-local --timeout=180s
kubectl get nodes -o wide
```

Expect a node named `gr8s-local` with status `Ready`. Addresses, version, and age
vary by host. No CoreDNS or metrics-server deployment is needed; those services
are built into gr8s. See the [component map](kubernetes-users.md).

## Deploy and reach a Service

Apply the [complete example manifest](../examples/getting-started.yaml):

```sh
kubectl apply -f examples/getting-started.yaml
kubectl -n gr8s-demo rollout status \
  deployment/web --timeout=180s
kubectl -n gr8s-demo wait \
  --for=condition=Ready pod/client --timeout=180s
kubectl -n gr8s-demo get deploy,pods,svc
```

Expect `web` to have `READY 2/2`, two ready web Pods, a ready `client` Pod, and a
`web` ClusterIP Service on `80/TCP`. Pod suffixes and IPs are assigned by the cluster.

Query DNS and make an HTTP request **inside the client Pod**:

```sh
kubectl -n gr8s-demo exec client -- \
  nslookup web.gr8s-demo.svc.cluster.local
kubectl -n gr8s-demo exec client -- \
  wget -qO- http://web.gr8s-demo.svc.cluster.local
```

The DNS answer should include the Service's ClusterIP. The HTTP response should
contain `Welcome to nginx!`. This exercises DNS, Service forwarding, and a ready
backend; it does not require exposing a port on the host.

## Roll the Deployment

Change the Pod template with a rolling restart, using the same image:

```sh
kubectl -n gr8s-demo rollout restart deployment/web
kubectl -n gr8s-demo rollout status \
  deployment/web --timeout=180s
kubectl -n gr8s-demo get pods -l app=web
kubectl -n gr8s-demo exec client -- \
  wget -qO- http://web
```

Expect two ready replacement web Pods and another nginx response. Pod names change;
the Service name and ClusterIP stay the same. This final request checks the result
after rollout, not uninterrupted traffic during it.

## Diagnose a failed step

| Symptom | First check |
|---|---|
| Build command missing or ASDF cannot find a system | Follow [host setup](building-and-testing.md#example-build-host-fedora-44); confirm ocicl setup and run `make deps` |
| `gr8s kubeconfig` says the cluster PKI does not exist | Start `serve` first, and run both with `sudo` so they share root's state directory |
| `kubectl` asks for credentials or reaches another cluster | Check that `KUBECONFIG` points at `~/gr8s.kubeconfig` in this terminal |
| API connection refused | Keep `serve` running; inspect its first startup error and check for a port 6443 conflict |
| Pod Pending or image pull failure | Run `describe pod` and inspect server output; check registry DNS, credentials, and connectivity |
| DNS resolves but HTTP fails | Check ready Pods and `get endpointslices -l kubernetes.io/service-name=web` in `gr8s-demo` |
| BPF, mount, cgroup, or route setup fails | Check root privileges, kernel support, and existing routes; use a fresh disposable VM rather than a restricted container |

For a particular web Pod, use its name from `get pods`:

```sh
kubectl -n gr8s-demo describe pod POD_NAME
kubectl -n gr8s-demo logs POD_NAME
```

## Finish

```sh
kubectl delete namespace gr8s-demo
```

Stop the server with Ctrl-C and wait for shutdown. Root's `~/.local/state/gr8s`
preserves cluster identity and API state for the next start; `--state-directory`
picks another place.
Use the [systemd installation guide](installing.md) for persistent operation, or
[add a worker](building-and-testing.md#a-second-node) to try cross-node scheduling.
