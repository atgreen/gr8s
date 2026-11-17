#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# Network/full: run upstream conformance against a cluster using gr8s as its CNI
# (docs/design-foreign-cluster-networking.md, podster-982.7).  Run this ON a
# control-plane node of a cluster already networked by the gr8s net-agent, with
# kube-proxy, the stock CNI and any built-in NetworkPolicy controller disabled.
# It drives sonobuoy's upstream e2e plugin; GitHub-hosted runners cannot host
# such a cluster, so this is the reproducible harness rather than a CI job.
#
# Gateway-only runs may retain the incumbent CNI and kube-proxy. They require
# GATEWAY_CONFORMANCE_BINARY and GR8S_VERSION; see README.md.
#
# Usage: KUBECONFIG=/etc/rancher/k3s/k3s.yaml sh run-conformance.sh [suite]
#   suite = network   (default) sig-network Conformance: Services, DNS, networking
#           gateway   Gateway API conformance profile (needs the Gateway CRDs)
#           full      every [Conformance] test (hours; a real cluster, not nested VMs)
set -e
SUITE="${1:-network}"
: "${KUBECONFIG:?set KUBECONFIG to the target cluster}"

case "$SUITE" in
  network)
    sonobuoy run --plugin e2e \
      --e2e-focus '\[sig-network\].*\[Conformance\]' \
      --e2e-skip '\[Serial\]|\[Disruptive\]' \
      --wait
    ;;
  full)
    sonobuoy run --mode certified-conformance --wait
    ;;
  gateway)
    # Build the official suite at the installed CRD bundle's release tag.
    # Execute on the cluster network so advertised Gateway IPs are reachable.
    : "${GATEWAY_CONFORMANCE_BINARY:?set GATEWAY_CONFORMANCE_BINARY to the upstream test binary}"
    : "${GR8S_VERSION:?set GR8S_VERSION to the exact tested build identifier}"
    exec "$GATEWAY_CONFORMANCE_BINARY" -test.run '^TestConformance$' \
      -test.v -test.timeout=90m \
      "--gateway-class=${GATEWAY_CLASS:-gr8s}" \
      --conformance-profiles=GATEWAY-HTTP \
      --supported-features=Gateway,HTTPRoute,ReferenceGrant \
      "--report-output=${GATEWAY_CONFORMANCE_REPORT:-gr8s-report.yaml}" \
      --organization=atgreen --project=gr8s \
      --url=https://github.com/atgreen/gr8s \
      "--version=$GR8S_VERSION" --contact=https://github.com/atgreen
    ;;
  *) echo "unknown suite: $SUITE" >&2; exit 2 ;;
esac

TARBALL="$(sonobuoy retrieve)"
sonobuoy results "$TARBALL"
STATUS="$(sonobuoy results "$TARBALL" --plugin e2e | awk '/Status:/{print $2; exit}')"
sonobuoy delete --wait >/dev/null 2>&1 || true
[ "$STATUS" = "passed" ] || { echo "conformance FAILED"; exit 1; }
echo "conformance PASSED"
