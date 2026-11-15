#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# Run upstream conformance against a cluster using gr8s as its CNI
# (docs/design-foreign-cluster-networking.md, podster-982.7).  Run this ON a
# control-plane node of a cluster already networked by the gr8s cni-agent, with
# kube-proxy, the stock CNI and any built-in NetworkPolicy controller disabled.
# It drives sonobuoy's upstream e2e plugin; GitHub-hosted runners cannot host
# such a cluster, so this is the reproducible harness rather than a CI job.
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
    # The Gateway API conformance suite ships with the Gateway API project; run
    # it with the gr8s GatewayClass and emit the support report.
    echo "Run the upstream gateway-api conformance binary against GatewayClass=gr8s:"
    echo "  go test ./conformance -run TestConformance \\"
    echo "    -args --gateway-class=gr8s --supported-features=... --report-output=gr8s-report.yaml"
    exit 0
    ;;
  *) echo "unknown suite: $SUITE" >&2; exit 2 ;;
esac

TARBALL="$(sonobuoy retrieve)"
sonobuoy results "$TARBALL"
STATUS="$(sonobuoy results "$TARBALL" --plugin e2e | awk '/Status:/{print $2; exit}')"
sonobuoy delete --wait >/dev/null 2>&1 || true
[ "$STATUS" = "passed" ] || { echo "conformance FAILED"; exit 1; }
echo "conformance PASSED"
