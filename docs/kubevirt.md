# KubeVirt on gr8s

KubeVirt v1.9.1 installs on the native containerd runtime. gr8s provides the
Kubernetes APIs and kubelet services; KubeVirt's unmodified operator, controllers,
handler and launcher provide the virtualization stack. QEMU uses the node's KVM
support through containerd's CRI device mappings.

The native validation uses a disposable Fedora 44 guest with nested KVM,
SELinux enforcing, one gr8s node, and the upstream CirrOS container disk. This
is a single-node boot smoke, not Kubernetes or KubeVirt conformance, migration,
HA, storage durability, or performance certification.

## Install

Run native workloads as root inside a disposable VM, as described in
[AGENTS.md](../AGENTS.md). The node needs `/dev/kvm`, `/dev/net/tun` and
`/dev/vhost-net`. Keep `/var/lib/kubelet` dedicated to this node: gr8s and a
separate kubelet cannot share its plugin registry or Pod volume directories.

Start gr8s with the containerd runtime and an explicit kubeconfig:

```sh
gr8s serve --runtime containerd --node-name gr8s-kubevirt \
  --state-directory /var/tmp/gr8s-kubevirt/state \
  --kubeconfig /var/tmp/gr8s-kubevirt/kubeconfig
export KUBECONFIG=/var/tmp/gr8s-kubevirt/kubeconfig
kubectl wait node/gr8s-kubevirt --for=condition=Ready --timeout=180s
kubectl label node gr8s-kubevirt node-role.kubernetes.io/control-plane=
```

Use the release's upstream operator and custom resource:

```sh
curl -fL https://github.com/kubevirt/kubevirt/releases/download/v1.9.1/kubevirt-operator.yaml -o kubevirt-operator.yaml
curl -fL https://github.com/kubevirt/kubevirt/releases/download/v1.9.1/kubevirt-cr.yaml -o kubevirt-cr.yaml
kubectl create -f kubevirt-operator.yaml
kubectl create -f kubevirt-cr.yaml
kubectl -n kubevirt patch kubevirt kubevirt --type=merge \
  -p '{"spec":{"infra":{"replicas":1}}}'
kubectl -n kubevirt wait kubevirt/kubevirt --for=condition=Available --timeout=900s
```

The single infrastructure replica keeps this smoke within a small test node's
memory budget. The operator itself retains its upstream two replicas. Software
emulation is disabled; the validation requires an actual `kvm` domain.

If images cannot be pulled through the registry proxy, pre-stage OCI archives
**before starting gr8s**, using the existing image preload mechanism:

```sh
scripts/save-image-archives.sh images \
  quay.io/kubevirt/virt-operator:v1.9.1 \
  quay.io/kubevirt/virt-api:v1.9.1 \
  quay.io/kubevirt/virt-controller:v1.9.1 \
  quay.io/kubevirt/virt-handler:v1.9.1 \
  quay.io/kubevirt/virt-launcher:v1.9.1 \
  quay.io/kubevirt/virt-exportproxy:v1.9.1 \
  quay.io/kubevirt/virt-template-apiserver:v0.2.3 \
  quay.io/kubevirt/virt-template-controller:v0.2.3 \
  quay.io/kubevirt/cirros-container-disk-demo:latest
mkdir -p /var/tmp/gr8s-kubevirt/state/agent/images
cp -f images/*.tar /var/tmp/gr8s-kubevirt/state/agent/images/
```

In a remote test VM, build/download on the development host and copy the
archives into the guest. The validation used preloaded images after observing
TLS failures in the registry proxy; it does not validate that proxy's Quay pull
path. The demo disk uses upstream's mutable `latest` tag; the proof records the
launcher Pod's resolved image IDs.

## Boot and inspect a guest

```sh
kubectl create -f examples/kubevirt/vm.yaml
kubectl get vm,vmi,pods
python3 scripts/test-kubevirt.py --kubeconfig "$KUBECONFIG" \
  --existing --vm-name gr8s-kubevirt-smoke --report-directory kubevirt-proof
```

The script requires a Running, Ready VMI, a libvirt domain of type `kvm`, and the
`GR8S_KUBEVIRT_BOOT_OK` marker written by the guest's boot script to its serial
console. It saves the VM, VMI, launcher Pod, node inventory, domain XML, console,
and Events alongside its JSON report. Nested virtualization on shared test
hosts can make boot slow; the default deadline is 30 minutes.

Without `--existing`, the script creates a uniquely named smoke VM and removes
it afterward. Use `--keep` to retain that newly created VM. An existing VM is
never changed or deleted by the script.

## Node integration

The kubelet device-plugin v1beta1 registry lives at
`/var/lib/kubelet/device-plugins/kubelet.sock`. Each plugin's ListAndWatch stream
updates the authenticated node report; disconnected plugins advertise zero
healthy capacity. Allocate results supply CRI devices, mounts, environment,
annotations and CDI names. Pod UID/container/device reservations and Allocate
responses are checkpointed under the agent's `device-plugins/allocations.json`
and retained across retries and native restart. Reservations are released after
native Pod cleanup. Plugins receive PreStartContainer when requested at
registration.

Managed emptyDir volumes use real directories at
`/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~empty-dir/<name>`. KubeVirt's
handler uses that standard layout to find the launcher's command socket through
its `/pods` mount; symlinks would be rejected by its safe path resolver. These
volumes retain normal per-Pod permissions and mount cleanup.

The API compatibility fixes exercised during installation cover object-level
CEL immutability rules, Kubernetes' permissive JSON Patch replacement of absent
object members and null tests for those members, and multiple named container
ports sharing one port number.

For dedicated CPUs, hugepages and node-local resource reporting, see
[native resource management](resource-management.md). The saved KubeVirt boot
smoke validates basic KVM boot; it does not certify those advanced VM options.
