<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Kubernetes v1.36 Conformance

gr8s is a from-scratch Kubernetes-compatible control plane written in Common
Lisp. This document is the running ledger of conformance progress against the
**official upstream v1.36 `certified-conformance` suite** (446 selected cases),
run via Sonobuoy against a native gr8s cluster.

> **Milestone (2026-11-11):** gr8s **passes every case of the upstream Kubernetes
> v1.37 `certified-conformance` suite — 462 of 462, 0 failures**, run via Sonobuoy
> against a native two-node gr8s cluster (build `v1.37.2-g6584550+dirty`; the
> tested changes are committed in `6584550..827ef7c6`). Machine-generated
> evidence: [conformance-full-v1.37-2026-11-11.json](conformance-full-v1.37-2026-11-11.json),
> produced by `scripts/e2e-two-node.sh report`. gr8s is not yet a CNCF-submitted
> _Certified Kubernetes_ distribution.

This document reports results as-is. Each row links to the committed evidence
JSON for that run (JUnit archive, gr8s request log, and artifact hashes). The
round ledger below is the earlier **v1.36** (446-case) progression that led to
the v1.37 milestone above.

## Round ledger

Every full run is a numbered round. "Passed/Failed" are measured case outcomes
out of 446; pass rate is `passed / 446`. Per gr8s's own interpretation note, a
failure often reflects a shared setup or transport cause rather than one named
feature, so the failure count is **not** a count of distinct missing features —
read the JUnit and native log before acting on any single case.

| Round | Date | Commit | Passed | Failed | Pass rate | Δ pass | Notes |
|------:|------|--------|-------:|-------:|----------:|-------:|-------|
| 1 | 2026-11-03 | — | 19 | 427 | 4.3% | — | First full baseline. PodTemplate support; predates Pod/Service protobuf and durable watches. [evidence](conformance-full-2026-11-03.json) |
| 2 | 2026-11-03 | — | 43 | 403 | 9.6% | +24 | Pod/Service protobuf + durable stored-resource watches. [evidence](conformance-full-second-2026-11-03.json) |
| 3 | 2026-11-04 | `660ce5c` | 48 | 398 | 10.8% | +5 | Typed ServiceAccount/RBAC, Event APIs, image-pull deadline, grouped DeleteOptions (PR22–25). [evidence](conformance-full-third-2026-11-04.json) |
| 4 | 2026-11-04 | `84ec495` | 64 | 382 | 14.3% | +16 | Graceful termination, RBAC API-group defaults, Pod readiness/reconnect, generated Pod names (PR26–30). 16 newly passing, **0 regressions**. [evidence](conformance-full-fourth-2026-11-04.json) |

A pre-baseline [bootstrap evidence record](conformance-bootstrap-2026-11-03.json)
(different schema) predates round 1 and documents first end-to-end suite
execution.

**Current best: round 4 — 64/446 (14.3%).** Trend: monotonic, no regressions
across rounds 1→4.

## Failure taxonomy for round 4

Failing cases by SIG, from `countsBySIG` in the round-4 evidence. This is the
hit-list: biggest buckets first.

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

### Highest-impact gaps

- **sig-apps (60 failing, 0 passing)** — the whole group is unimplemented:
  Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob controllers.
  This is the single largest contiguous block. (The round-4 binary predates the
  Deployment/ReplicaSet controllers landing in PR33/35, so expect a step change
  here in the next round.)
- **sig-api-machinery (88)** and **sig-node (86)** are the next-largest. Node
  has moved the most in absolute terms (5→20) and is where lifecycle, probes,
  exec/attach, and container-runtime semantics live.
- **sig-storage (72 failing)** is improving fastest proportionally (2→19) as the
  PV/PVC/StorageClass path fills in.
- **sig-scheduling (11, 0 passing)** and **sig-architecture (1)** are small,
  self-contained wins.
- **sig-instrumentation is fully passing** — keep it green.

## Methodology

- **Suite**: official upstream v1.36 `certified-conformance` selection (446
  cases). Seven passing Sonobuoy suite hooks are counted separately from cases.
- **Sonobuoy**: v0.57.5. Command shape:
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
2. Add a row to the **Round ledger** (date, commit, passed/failed, Δ pass, a
   one-line note on what landed since the previous round).
3. Refresh the **Failure taxonomy** table from the new run's `countsBySIG`, and
   update the pass-trend column.
4. If any previously-passing case now fails, call out the **regression**
   explicitly in the notes — that is the signal this ledger exists to catch.
