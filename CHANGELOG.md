# Changelog

Notable changes to gr8s. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions combine
the Kubernetes API version with a gr8s release suffix (see
[Versioning](README.md#versioning)).

## [Unreleased]

## [v1.37.2-gr8s.0] — 2026-11-15

First public release (marked pre-release as a trial).

### Added

- A single-binary, Kubernetes-compatible cluster: control plane
  (`gr8s serve`), worker agent (`gr8s agent`), HA quorum witness, Raft
  datastore, and embedded containerd/runc. Passed 100% of the upstream
  Kubernetes v1.37 `certified-conformance` suite (462/462) in a recorded
  two-node run ([evidence](docs/CONFORMANCE.md)).
- A standalone network services provider for clusters gr8s did not create:
  `gr8s net-agent` with independently selectable features — `cni`
  (Pod networking, IPAM, VXLAN or encrypted WireGuard overlay, eBPF
  NetworkPolicy, hostPort), `service-lb` (an eBPF kube-proxy replacement),
  and `gateway` (Gateway API and Ingress) — packaged as the `gr8s-net`
  Helm chart (0.2.0) and the `ghcr.io/atgreen/gr8s-net` container image.
- Live debugging of running clusters: `gr8s debug slynk` (authenticated
  Slynk tunnel), `gr8s debug icl` (ICL's browser IDE on a node's live
  image), and `gr8s debug trace` (selector-scoped kernel tracing in a
  bpftrace-compatible language, JIT-compiled to eBPF by Whistler).
- The integrated Headlamp dashboard (`gr8s dashboard`).
- Pure-Lisp TLS 1.3 with hybrid X25519MLKEM768 key exchange; no OpenSSL.
- Release artifacts for Linux amd64 and arm64: binaries with checksums,
  tarballs carrying the installer and lifecycle scripts, and CycloneDX and
  SPDX SBOMs for the Lisp dependencies.

[Unreleased]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.0...HEAD
[v1.37.2-gr8s.0]: https://github.com/atgreen/gr8s/releases/tag/v1.37.2-gr8s.0
