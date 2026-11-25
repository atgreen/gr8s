<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# The gr8s lab's tracing

What the lab cluster runs to see [Gateway traces](../../docs/networking.md#gateway-tracing-opentelemetry)
in its Grafana (kube-prometheus-stack, in `monitoring`).

- `tempo.yaml`: Grafana Tempo 2.10 as one process in `monitoring` -- OTLP on
  4317/4318, traces on a 10 Gi `local-path` volume, kept 7 days -- and the
  Grafana data source, which kube-prometheus-stack's data-source sidecar loads
  from its `grafana_datasource: "1"` label. Search is not streamed: Grafana's
  gRPC streaming through Tempo's HTTP port came back empty.

  ```sh
  kubectl apply -f deploy/lab/tempo.yaml
  ```

- `gr8s-server-otel.conf`: the systemd drop-in that points a node's agent at
  Tempo. Install it on every node and restart the agents one at a time,
  moving Raft leadership off a member before restarting it.

In Grafana: **Explore** → **Tempo** → TraceQL `{resource.service.name="gr8s-gateway"}`.

Tempo 3.x is the current release line; moving to it is a separate change, as its
configuration differs.
