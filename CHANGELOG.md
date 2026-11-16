# Changelog

Notable changes to gr8s. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions combine
the Kubernetes API version with a gr8s release suffix (see
[Versioning](README.md#versioning)).

## [Unreleased]

### Added

- RPM and DEB packages for amd64 and arm64, attached to each release. They
  install `/usr/bin/gr8s`, `gr8s-killall.sh`, and disabled `gr8s-server` /
  `gr8s-agent` systemd units configured through `/etc/gr8s/*.env`. A tag
  `v<k8s>-gr8s.<n>` maps to package version `<k8s>+gr8s.<n>` with packaging
  revision 1 in both formats.

## [v1.37.2-gr8s.0] — 2026-11-15

Initial release, marked pre-release as a trial.

gr8s arrives as a single-binary, Kubernetes-compatible cluster — control
plane (`gr8s serve`), worker agent, HA quorum witness, Raft datastore, and
embedded containerd/runc — that passed 100% of the upstream Kubernetes
v1.37 `certified-conformance` suite (462/462) in a recorded two-node run
([evidence](docs/CONFORMANCE.md)). The same binary provides network
services to clusters gr8s did not create: `gr8s net-agent` with
independently selectable features — `cni` (Pod networking, IPAM, VXLAN or
encrypted WireGuard overlay, eBPF NetworkPolicy, hostPort), `service-lb`
(an eBPF kube-proxy replacement), and `gateway` (Gateway API and Ingress)
— packaged as the `gr8s-net` Helm chart (0.2.0) and the
`ghcr.io/atgreen/gr8s-net` container image.

Running clusters are debuggable live through `gr8s debug slynk`
(authenticated Slynk tunnel), `gr8s debug icl` (ICL's browser IDE on a
node's live image), and `gr8s debug trace` (selector-scoped kernel tracing
in a bpftrace-compatible language, JIT-compiled to eBPF by Whistler), and
explorable through the integrated Headlamp dashboard (`gr8s dashboard`).
Internal TLS 1.3 is pure Lisp with hybrid X25519MLKEM768 key exchange; no
OpenSSL. Release artifacts cover Linux amd64 and arm64: binaries with
checksums, tarballs carrying the installer and lifecycle scripts, and
CycloneDX and SPDX SBOMs for the Lisp dependencies.

[Unreleased]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.0...HEAD
[v1.37.2-gr8s.0]: https://github.com/atgreen/gr8s/releases/tag/v1.37.2-gr8s.0
