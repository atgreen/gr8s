# Security Policy

gr8s is an experimental project (see the warning at the top of the
[README](README.md)); it does not promise operational reliability. Security
reports are taken seriously all the same, and fixes land in `main` and the
next release.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private
vulnerability reporting:
[github.com/atgreen/gr8s/security/advisories/new](https://github.com/atgreen/gr8s/security/advisories/new).
Do not open a public issue for an exploitable bug.

Include what you can of: the gr8s version (`gr8s version`), the deployment
mode (`serve`, `agent`, or `net-agent` on a foreign cluster), reproduction
steps, and the impact you believe it has. This is a solo-maintained project;
you should normally hear back within a week.

## Supported versions

Only the latest release and `main` receive security fixes. There are no
backports to earlier releases.

## Scope

In scope: the `gr8s` binary and its embedded components, the `gr8s-net`
Helm chart and container image, and the release artifacts.

Before reporting a NetworkPolicy or RBAC behavior difference from upstream
Kubernetes, check
[deliberate security deviations](docs/security-deviations.md) — some
differences are recorded, intentional decisions rather than silent gaps.
Reports that argue one of those decisions is wrong are welcome too.
