# Native CPU, NUMA and hugepage resources

Managed containerd nodes can assign exclusive logical CPUs, coordinate CPU,
memory and device-plugin NUMA affinity, and serve the standard kubelet
PodResources v1 API. These policies belong to the node agent: containerd applies
the resulting CRI cgroup settings and device mappings.

## Configure a node

```sh
gr8s serve --runtime containerd \
  --state-directory /var/tmp/gr8s-resources/state \
  --kubeconfig /var/tmp/gr8s-resources/kubeconfig \
  --cpu-manager-policy static --reserved-cpus 0 \
  --topology-manager-policy single-numa-node --topology-manager-scope pod
```

The same policy arguments work with `gr8s agent`. CPU policy defaults to `none`;
`static` requires an explicit, nonempty set of online reserved CPUs and at least
one CPU left for exclusive workloads. Reserved CPUs remain in the shared pool
and reduce Node allocatable CPU. Exclusive assignments apply to integer CPU
requests in Guaranteed Pods. Fractional and Burstable workloads use the shared
pool, which is updated before newly dedicated containers start. Logical CPUs
are the allocation unit; full physical core isolation and IRQ/host-daemon
pinning are not configured by these arguments.

Topology policy defaults to `none`. The supported strict policy is
`single-numa-node`, with Pod scope: requested exclusive CPUs, ordinary memory, hugepages
and topology-aware device-plugin allocations must fit the same NUMA node.
Unhinted devices impose no NUMA restriction. Admission fails with
`TopologyAffinityError` if providers cannot agree. Other policy and scope names
are rejected. NUMA memory entries represent request reservations; they are not
RSS measurements or pre-faulted physical memory.

Regular init containers reuse the Pod's exclusive CPU pool; restartable init
sidecars retain their slice while later containers run. Pod-level CPU budgets
can reserve a pool and partition it between individually exclusive containers
and Pod-shared containers. CPU and memory affinities are retained on container
updates. A resize that changes an admitted dedicated/NUMA reservation remains
`PodResizePending` with reason `Infeasible`; replace the Pod to change it.

The authoritative checkpoint is `<agent-runtime-state>/resources/allocations.json`.
Restart preserves assignments. Changing policies or physical topology with live
reservations, corrupt/overlapping CPU assignments, or a missing checkpoint with
live managed containers fails closed. Drain before resetting this state.
`/var/lib/kubelet/cpu_manager_state` reports policy and CPU assignments for
consumers such as KubeVirt; it is not the authoritative recovery file.
Reservations return after native cleanup, or once a terminal Pod has no
running/created containers.

## Hugepages

Preallocate HugeTLB pools on the node before starting the agent. For a disposable
Linux node with a second NUMA node, for example:

```sh
echo 32 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```

Nodes advertise `hugepages-2Mi`, `hugepages-1Gi`, and any other supported canonical
page sizes from their actual pools. Requests and limits must match and contain
whole pages. Scheduling and ResourceQuota count bytes; ordinary allocatable
memory excludes those pools. Declare CPU or memory alongside hugepages.

```yaml
resources:
  limits:
    cpu: "2"
    memory: 128Mi
    hugepages-2Mi: 4Mi
```

An `emptyDir` with `medium: HugePages-2Mi` mounts a real, size-limited hugetlbfs.
Bare `HugePages` is accepted when the Pod requests exactly one page size. Mounts
survive container/agent restart and are unmounted on Pod cleanup. CRI hugepage
limits are set for requested sizes and zero for unrequested supported sizes.
Managed containerd explicitly enables its HugeTLB controller and refuses to
silently ignore a missing controller. Hugepage resourceFieldRef values can also
be used in downward environment and volume references.

## PodResources v1

The root-only endpoint is `/var/lib/kubelet/pod-resources/kubelet.sock`.
`List`, `Get` and `GetAllocatableResources` use the upstream v1 protocol pinned
to kubelet v0.37.2. Reports include exclusive CPU IDs, NUMA memory/hugepage
reservations, allocated plugin device IDs and their topology, and prepared DRA
claim/device/CDI identifiers. Pod-level fields describe Pod-level allocations;
container entries include applications and restartable init sidecars.
`GetAllocatableResources` returns total allocatable inventory, including resources
already assigned. Subtract assigned resources to calculate availability.

Build the independent upstream Go client and kernel probe on the development
host, then copy it and the native gr8s binary to a disposable guest:

```sh
(cd scripts/resource-probe && CGO_ENABLED=0 go build -o ../../build/resource-probe .)
# Inside the dedicated 4-CPU, 2-NUMA test guest as root:
python3 test-resource-management.py /root/gr8s /root/resource-probe
```

The test requires NUMA0 CPUs 0–1 and NUMA1 CPUs 2–3. It verifies shared/exclusive
CPU sets, NUMA page placement, HugeTLB limits and over-limit faults, aligned
device IDs, standard upstream RPCs, affinity rejection, agent restart without
container replacement, and CPU reuse after cleanup. Evidence includes the
binary hash, upstream RPC results, kernel probe logs and server logs. This is
a native resource-management integration test, not KubeVirt dedicated-CPU or
NUMA conformance certification.

The [native validation record](resource-management-native-2026-11-09.json)
contains the tested binary hash, live process/container identity, upstream RPC
responses and host-suite comparison with clean main. DRA reporting is additionally
checked with an independent upstream client against prepared-claim fixtures;
only claims prepared for that exact Pod UID are reported.

The ordinary restart check runs before the deliberate SIGBUS exec. Combined
fault-then-restart recovery is tracked separately in `podster-g2l`.
