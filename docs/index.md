# Documentation

Choose a path through the current guides:

| I want to… | Start here | Read next |
|---|---|---|
| Understand gr8s as a Kubernetes user | [Kubernetes component map](kubernetes-users.md) | [API coverage](kubernetes-surface.md), [compatibility gaps](k3s-gap-inventory.md) |
| Try a cluster and workload | [Build prerequisites](building-and-testing.md#requirements) | [First workload](getting-started.md), [add a worker](building-and-testing.md#a-second-node) |
| Operate a persistent cluster | [Install with systemd](installing.md) | [Certificates](certificate-management.md), [HA and recovery](high-availability.md), [metrics](control-plane-metrics.md) |
| Develop gr8s | [Architecture](design.md) | [Source map and request walkthrough](development.md), [tests and debugging](building-and-testing.md#test-matrix), [documentation style](documentation-style.md) |
| Evaluate the evidence | [Conformance results](CONFORMANCE.md) | [Gateway conformance harness](../deploy/conformance/README.md), linked validation records in each feature guide |

Feature references cover [networking](networking.md), [container runtimes](runtime.md),
[storage](persistent-storage.md), [custom resources](custom-resources.md),
[Secrets](configmap-secret-api.md), [resource management](resource-management.md),
and [KubeVirt](kubevirt.md).

Operating references cover [backup and restore](backup-restore.md),
[API client certificates](api-client-certificates.md),
[certificate signing requests](certificate-signing-requests.md),
[Raft member recovery](raft-member-recovery.md), and the
[deliberate security deviations](security-deviations.md) from upstream.

The architecture and feature guides describe the current implementation. Dated JSON
records describe the build and configuration tested on that date; they do not
certify every later build. The [historical initial design](history/initial-design.md)
and the historical section of the conformance ledger explain earlier milestones.

## Design notes

Design notes record the decisions behind the implementation:
[multi-node design](multi-node-design.md),
[HA core-resource transactions](ha-core-transactions.md),
[production store snapshot artifacts](store-snapshot-artifacts.md),
[foreign-cluster networking](design-foreign-cluster-networking.md) (gr8s as a
standalone CNI and Gateway, validated by the
[Gateway conformance harness](../deploy/conformance/README.md)),
[ListenerSets](design-listenersets.md), and
[selector-scoped kernel tracing](design-gr8s-trace.md).
The [Service identity envelope](service-wire-protocol.md) is an archived
experiment, kept for the record.
