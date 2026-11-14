# Documentation

Choose a path through the current guides:

| I want to… | Start here | Read next |
|---|---|---|
| Understand gr8s as a Kubernetes user | [Kubernetes component map](kubernetes-users.md) | [API coverage](kubernetes-surface.md), [compatibility gaps](k3s-gap-inventory.md) |
| Try a cluster and workload | [Build prerequisites](building-and-testing.md#requirements) | [First workload](getting-started.md), [add a worker](building-and-testing.md#a-second-node) |
| Operate a persistent cluster | [Install with systemd](installing.md) | [Certificates](certificate-management.md), [HA and recovery](high-availability.md), [metrics](control-plane-metrics.md) |
| Develop gr8s | [Architecture](design.md) | [Source map and request walkthrough](development.md), [tests and debugging](building-and-testing.md#test-matrix) |
| Evaluate the evidence | [Conformance results](CONFORMANCE.md) | Linked validation records in each feature guide |

Feature references cover [networking](networking.md), [container runtimes](runtime.md),
[storage](persistent-storage.md), [custom resources](custom-resources.md),
[Secrets](configmap-secret-api.md), [resource management](resource-management.md),
and [KubeVirt](kubevirt.md).

The architecture and feature guides describe the current implementation. Dated JSON
records describe the build and configuration tested on that date; they do not
certify every later build. The [historical initial design](history/initial-design.md)
and the historical section of the conformance ledger explain earlier milestones.
