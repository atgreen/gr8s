<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Kubernetes conformance results

## Current recorded result

The native two-node run on **2026-11-11** passed every selected case of the
upstream Kubernetes **v1.37 `certified-conformance` suite: 462/462, 0 failures**.
It ran via Sonobuoy v0.57.3 using `scripts/e2e-two-node.sh`, with build
`v1.37.2-g6584550+dirty`. The tested changes are recorded as committed in
`6584550..827ef7c6`.

[Machine-generated evidence](evidence/conformance-full-v1.37-2026-11-11.json) records the
executed cases, hooks, skipped cases, artifact hashes, and run details. The
462 count excludes suite hooks and unselected tests. This is a result for that
build and two-node configuration, not a fresh run of every later checkout or a
claim about all optional Kubernetes features and topologies.

gr8s is **not yet a CNCF-submitted Certified Kubernetes distribution**. Passing
the upstream selection and obtaining certification are separate claims.
The [API reference](kubernetes-surface.md) describes current implementation
scope; the [gap inventory](k3s-gap-inventory.md) covers operational limits beyond
this test selection.

## Historical v1.36 progression

The following ledger is an archived account of early development against the
upstream v1.36 selection (446 cases). Its failure taxonomy describes the round-4
binary, not today's API support. Each row links to the evidence for that run.

### Early round ledger

Every full run is a numbered round. "Passed/Failed" are measured case outcomes
out of 446; pass rate is `passed / 446`. Per gr8s's own interpretation note, a
failure often reflects a shared setup or transport cause rather than one named
feature, so the failure count is **not** a count of distinct missing features —
read the JUnit and native log before acting on any single case.

| Round | Date | Commit | Passed | Failed | Pass rate | Δ pass | Notes |
|------:|------|--------|-------:|-------:|----------:|-------:|-------|
| 1 | 2026-11-03 | — | 19 | 427 | 4.3% | — | First full baseline. PodTemplate support; predates Pod/Service protobuf and durable watches. [evidence](evidence/conformance-full-2026-11-03.json) |
| 2 | 2026-11-03 | — | 43 | 403 | 9.6% | +24 | Pod/Service protobuf + durable stored-resource watches. [evidence](evidence/conformance-full-second-2026-11-03.json) |
| 3 | 2026-11-04 | `660ce5c` | 48 | 398 | 10.8% | +5 | Typed ServiceAccount/RBAC, Event APIs, image-pull deadline, grouped DeleteOptions (PR22–25). [evidence](evidence/conformance-full-third-2026-11-04.json) |
| 4 | 2026-11-04 | `84ec495` | 64 | 382 | 14.3% | +16 | Graceful termination, RBAC API-group defaults, Pod readiness/reconnect, generated Pod names (PR26–30). 16 newly passing, **0 regressions**. [evidence](evidence/conformance-full-fourth-2026-11-04.json) |

A pre-baseline [bootstrap evidence record](evidence/conformance-bootstrap-2026-11-03.json)
(different schema) predates round 1 and documents first end-to-end suite
execution.

**Best in this early ledger: round 4 — 64/446 (14.3%).** The later v1.37
462/462 result above supersedes this as the current recorded milestone.

### Historical failure taxonomy for round 4

Failing cases by SIG, from `countsBySIG` in the round-4 evidence. These were the
failure buckets at that stage, largest first.

| SIG | Passing | Failing | Pass trend (R1→R4) |
|-----|--------:|--------:|--------------------|
| sig-api-machinery | 11 | **88** | 5 → 10 → 10 → 11 |
| sig-node | 20 | **86** | 5 → 15 → 15 → 20 |
| sig-storage | 19 | **72** | 2 → 10 → 9 → 19 |
| sig-apps | 0 | **60** | 0 → 0 → 0 → 0 |
| sig-network | 3 | 44 | 2 → 3 → 3 → 3 |
| sig-cli | 5 | 12 | 5 → 5 → 5 → 5 |
| sig-scheduling | 0 | 11 | 0 → 0 → 0 → 0 |
| sig-auth | 2 | 8 | 0 → 0 → 2 → 2 |
| sig-architecture | 0 | 1 | 0 → 0 → 0 → 0 |
| sig-instrumentation | 4 | 0 ✅ | 0 → 0 → 4 → 4 |
| **Total** | **64** | **382** | |

### Gaps in the historical round-4 binary

- **sig-apps (60 failing, 0 passing)** — the group was unimplemented in that binary:
  Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob controllers.
  This was the largest contiguous block. The round-4 binary predated the
  Deployment/ReplicaSet controllers landing in PR33/35.
- **sig-api-machinery (88)** and **sig-node (86)** were the next-largest. Node
  had moved the most in absolute terms (5→20) and covered lifecycle, probes,
  exec/attach, and container-runtime semantics live.
- **sig-storage (72 failing)** had improved fastest proportionally (2→19) as the
  PV/PVC/StorageClass path filled in.
- **sig-scheduling (11, 0 passing)** and **sig-architecture (1)** were smaller
  outstanding groups.
- **sig-instrumentation was fully passing** in that run.

## Reproducing and recording results

- **Historical suite**: upstream v1.36 selection (446 cases), Sonobuoy v0.57.5.
  The current recorded v1.37 run uses v0.57.3 and 462 cases; use its evidence
  for exact command and configuration. Hooks are counted separately from cases.
- **Direct Sonobuoy command shape**:
  ```
  sonobuoy run --kubeconfig <rundir>/kubeconfig --dns-pod-labels= \
    --plugin=e2e --mode=certified-conformance
  ```
- **Cluster**: a native gr8s executable in a disposable root Linux guest (see
  AGENTS.md). Not a containerized control plane.
- **Evidence**: each run preserves the official Sonobuoy archive, native and
  worker logs, and the executed-spec inventory under
  `build/conformance/<date>-<id>/`, and a summary JSON is committed to `docs/`.

### Running a round

```sh
# Full certified suite (hours); requires root in a disposable guest,
# a native gr8s binary, and the sonobuoy CLI.
python3 scripts/test-podtemplates-sonobuoy.py \
  --gr8s /path/to/gr8s --sonobuoy /path/to/sonobuoy \
  --certified-conformance --timeout 21600
```

### Watching progress live

Conformance runs take hours and Sonobuoy's built-in progress reporting is
unreliable on this suite version. Tail live pass/fail counts with:

```sh
scripts/conformance-progress.py --kubeconfig <rundir>/kubeconfig
```

See that script's header for details.

### Adding a round to this ledger

1. Commit the run's summary JSON to `docs/conformance-full-<ordinal>-<date>.json`.
2. Update **Current recorded result** with the suite version, executed/pass/fail
   counts, build identity, topology, runner, and evidence link. Keep earlier
   results clearly labelled as historical; never mix denominators across versions.
3. For a failing run, include its own failure taxonomy from `countsBySIG` rather
   than presenting an old taxonomy as current.
4. If any previously-passing case now fails, call out the **regression**
   explicitly in the notes — that is the signal this ledger exists to catch.
