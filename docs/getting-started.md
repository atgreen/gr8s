# Your first workload

This walkthrough creates a Deployment with two nginx replicas, exposes it through
a ClusterIP Service, resolves its DNS name from another Pod, and replaces its
replicas in a rolling restart. Run commands from the repository root on a disposable
Linux VM with the [build and runtime prerequisites](building-and-testing.md#requirements).
The node needs registry access for nginx and BusyBox; see [airgap images](runtime.md#preloaded-images-airgap)
for disconnected nodes.

## Start a cluster

Build without root, then start the server as root and leave this terminal running:

```sh
make native
sudo build/gr8s serve \
  --state-directory /tmp/gr8s-state \
  --kubeconfig /tmp/gr8s.kubeconfig
```

The API uses HTTPS on port 6443 and writes an owner-only administrative kubeconfig.
In another terminal, use `sudo` to read it:

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig wait \
  --for=condition=Ready node/gr8s-local --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig get nodes -o wide
```

Expect a node named `gr8s-local` with status `Ready`. Addresses, version, and age
vary by host. No CoreDNS or metrics-server deployment is needed; those services
are built into gr8s. See the [component map](kubernetes-users.md).

## Deploy and reach a Service

Apply the [complete example manifest](../examples/getting-started.yaml):

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig apply -f examples/getting-started.yaml
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo rollout status \
  deployment/web --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo wait \
  --for=condition=Ready pod/client --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo get deploy,pods,svc
```

Expect `web` to have `READY 2/2`, two ready web Pods, a ready `client` Pod, and a
`web` ClusterIP Service on `80/TCP`. Pod suffixes and IPs are assigned by the cluster.

Query DNS and make an HTTP request **inside the client Pod**:

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo exec client -- \
  nslookup web.gr8s-demo.svc.cluster.local
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo exec client -- \
  wget -qO- http://web.gr8s-demo.svc.cluster.local
```

The DNS answer should include the Service's ClusterIP. The HTTP response should
contain `Welcome to nginx!`. This exercises DNS, Service forwarding, and a ready
backend; it does not require exposing a port on the host.

## Roll the Deployment

Change the Pod template with a rolling restart, using the same image:

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo rollout restart deployment/web
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo rollout status \
  deployment/web --timeout=180s
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo get pods -l app=web
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo exec client -- \
  wget -qO- http://web
```

Expect two ready replacement web Pods and another nginx response. Pod names change;
the Service name and ClusterIP stay the same. This final request checks the result
after rollout, not uninterrupted traffic during it.

## Diagnose a failed step

| Symptom | First check |
|---|---|
| Build command missing or ASDF cannot find a system | Follow [host setup](building-and-testing.md#example-build-host-fedora-44); confirm OCICL setup and run `make deps` |
| Cannot read kubeconfig | Use the `sudo kubectl` commands above; the file contains administrator credentials |
| API connection refused | Keep `serve` running; inspect its first startup error and check for a port 6443 conflict |
| Pod Pending or image pull failure | Run `describe pod` and inspect server output; check registry DNS, credentials, and connectivity |
| DNS resolves but HTTP fails | Check ready Pods and `get endpointslices -l kubernetes.io/service-name=web` in `gr8s-demo` |
| BPF, mount, cgroup, or route setup fails | Check root privileges, kernel support, and existing routes; use a fresh disposable VM rather than a restricted container |

For a particular web Pod, use its name from `get pods`:

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo describe pod POD_NAME
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig -n gr8s-demo logs POD_NAME
```

## Finish

```sh
sudo kubectl --kubeconfig /tmp/gr8s.kubeconfig delete namespace gr8s-demo
```

Stop the server with Ctrl-C and wait for shutdown. The state directory preserves
cluster identity and API state for the next start; `/tmp` may be cleared by the host.
Use the [systemd installation guide](installing.md) for persistent operation, or
[add a worker](building-and-testing.md#a-second-node) to try cross-node scheduling.
