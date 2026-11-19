# Local upstream PR draft — review required before submission

Target repository: `kubernetes-sigs/gateway-api`; base branch: `main`.
Title: `conformance: add gr8s Gateway API v1.6 HTTP core report`

Proposed PR body:

Add gr8s's standard-channel Gateway API v1.6.3 `GATEWAY-HTTP` core report.
All 36 core tests passed, zero failed/skipped, exit status 0 on 2026-11-19.
The suite and runner were unmodified, with Gateway, HTTPRoute and ReferenceGrant
as the declared features. Implementation snapshot: `1.37.2+git.8dc9b3e1.sha256.3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468`.

The report identifies the exact tested native binary. The reproduction README
specifies source, build, cluster, CRDs, agent mode and the runner invocation.
Testing used a disposable Fedora 44/k3s v1.37.2+k3s1 guest with stock flannel and
kube-proxy. This establishes HTTP core conformance only.

## Prepared files

Copy `v1.6/gr8s/README.md` and
`v1.6/gr8s/standard-1.37.2+git.8dc9b3e1.sha256.3fe42ec85a64df357c8f2e0dd80b14f88ce51345d7b6cf35c5c04fa12ef78468-default-report.yaml` from this directory into upstream
`conformance/reports/v1.6/gr8s/`. The reviewable patch is `gateway-api.patch` in this directory. It was prepared
on local branch `gr8s-http-conformance-20261119` under
`build/gateway-goal/upstream-draft`, based on upstream commit `935662a`.
Neither branch nor patch has been pushed upstream.

The report bytes must remain unchanged. The complete raw log and the initial
mixed-CRD preflight failure are retained in the gr8s evidence bundle. The latter
ran no tests; removing the legacy v1.3 XListenerSet CRD allowed the complete
standard v1.6.3 profile to run successfully.

No upstream PR has been opened. Submission requires the user's review.
