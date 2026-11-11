<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Kubernetes v1.37 certified-conformance: 469/469

On 2026-11-11 gr8s passed the upstream Kubernetes **v1.37
`certified-conformance`** end-to-end suite with a perfect score — **469 of 469
cases, 0 failures** — run via Sonobuoy against a native two-node gr8s cluster.
This report records the result, the defects fixed to reach it, and how to
reproduce it.

## Result

| | |
|---|---|
| Suite | upstream Kubernetes v1.37 `certified-conformance`, via Sonobuoy |
| Passed | **469 / 469** |
| Failed | **0** |
| Skipped (non-conformance) | 2744 |
| Build | `v1.37.2-gf07a06e` (development build) |
| Topology | two nodes — one control-plane + worker, one worker (libvirt VMs) |
| Harness | `scripts/e2e-two-node.sh run` (`GR8S_E2E_MODE=certified`) |

## What it took

The suite went from *not starting at all* — the first conformance pod could not
pull its image — to a clean 100%, once six infrastructure defects and one
Service feature gap were fixed. Each was root-caused on the live cluster from
packet captures and in-process backtraces.

### Infrastructure: the suite could not run

1. **Image-pull 503 under load.** Concurrent image-tracker gRPC calls raced the
   one shared HTTP/2 connection over a single pure-tls stream (an output-buffer
   overflow), and a write that failed mid-flight left the channel wedged, so
   every pull on the node then failed. Fix: serialize calls on the channel and
   reconnect on error. (`src/agent/session.lisp`)
2. **In-cluster API unreachable.** The `kubernetes` Service advertised the
   admin `--port` instead of the in-cluster apiserver port (6443), and firewalld
   never admitted 6443, so Pods were refused at `10.96.0.1:443`. Fix: advertise
   and admit 6443. (`src/server/main.lisp`, `src/network/host-firewall.lisp`)
3. **Cross-node image pull.** The peer-to-peer image server bound a random,
   un-admitted port and returned 503 instead of falling back to the origin
   registry. Fix: a stable, firewall-admitted peer port plus an origin fallback.
   (`src/security/image-peer-tls.lisp`, `src/image-distribution/oci-mirror.lisp`)
4. **Cross-node Pod→apiserver TLS handshake timeout.** The `kubernetes` endpoint
   is the control-plane node's underlay IP, so a Pod on another node reaches it
   over the underlay while the reply returns over the overlay; the asymmetric
   path is dropped by the stateful host firewall. Fix: source-NAT Pod→apiserver
   traffic to the node's address. (`src/network/host-firewall.lisp`,
   `src/server/main.lisp`)

### Service feature gap: four conformance specs failed

5. **NodePort Services.** `<nodeIP>:<nodePort>` was rejected by the host firewall
   (`EHOSTUNREACH`), and the cross-node Pod→NodePort leg was asymmetric — the
   same class of problem as (4). The conformance tests probe *every* node's
   address, so the cross-node leg failed. Fix: admit the NodePort range
   (30000–32767, TCP and UDP) and source-NAT each node's Pod→NodePort traffic to
   the node's address, scoped to the node's own Pod CIDR so an external client's
   source address at a `Local`-policy NodePort is preserved.
   (`src/network/host-firewall.lisp`, `src/server/main.lisp`)

The recurring theme: gr8s steers same-node traffic with eBPF and routes
cross-node traffic through the host firewall, so the Kubernetes entry points a
Pod on another node must reach — the apiserver Service and NodePorts — each
needed the firewall opened and the asymmetric reply path repaired with a
source-scoped masquerade.

## Reproducing

```sh
scripts/e2e-two-node.sh run        # provision two VMs, bring up gr8s, submit the suite
scripts/e2e-two-node.sh results    # retrieve and summarize pass/fail when it finishes
```

A full certified run takes roughly two hours. During the run, `sonobuoy status`
and `scripts/e2e-two-node.sh watch` show a frozen `0/462` counter: the e2e Pod's
progress endpoint is unreachable, which is a Sonobuoy-side reporting quirk, not a
gr8s problem. The final `results` are accurate.

## Scope and caveats

- This is a **single** Kubernetes version (v1.37) on a **two-node** cluster with
  a specific development build. `certified-conformance` excludes `[Disruptive]`
  and `[Serial]` cases, as the official suite does.
- gr8s is **not** a CNCF-submitted _Certified Kubernetes_ distribution. That mark
  requires submitting results to
  [`cncf/k8s-conformance`](https://github.com/cncf/k8s-conformance); this result
  is the passing conformance e2e suite, not the formal certification.
- The earlier v1.36 progression, round by round, is in
  [CONFORMANCE.md](CONFORMANCE.md).
