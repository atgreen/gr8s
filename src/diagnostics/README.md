# gr8s doctor implementation

`gr8s doctor diagnose` uses this module, embedded by `gr8s.asd`. `doctor host`
retains the existing host checks in `src/server/doctor.lisp`.

The doctor's knowledge is Prolog, run by [ag-prolog](https://github.com/atgreen/ag-prolog).
Lisp reads the cluster, states what it saw as facts, asks, and writes the
answers out.

## Rules (`rules/*.pl`)

| File | Holds |
| --- | --- |
| `catalog.pl` | 150 single-resource checks as `check/5` facts, the rule that tests their premises, and which checks are advisories. A premise is a term: `has(Path, Value)`, `below(Lower, Upper)`, `positive(Path)`, `at_least(Path, N)`, `nonempty(Path)` or `empty(Path)`. |
| `references.pl` | Configuration a Pod requires and does not have. |
| `pods.pl` | Why a running Pod is not ready and why a container keeps restarting, with their explanations, and when a restart loop has stopped (`settled/2`). |
| `scheduling.pl` | Why no node will take a Pod that waits for one: each node is tried and the first thing that rules it out is named. |
| `applications.pl` | What is known about particular programs: how to recognise them, what their own report or last words mean, what to run. |
| `logs.pl` | What the last lines of a crashed run say, and `asks/1`: the facts those rules need from the cluster. |
| `access.pl` | Why the API refused a ServiceAccount: bindings, roles, and which link is missing. |
| `relations.pl` | Findings that need more than one resource, with their explanations. |
| `explanation.pl` | Which findings are symptoms, which finding says more than another (`refines/2`), which cause brings about another on a linked resource (`leads_to/2`) or anywhere in the cluster (`anywhere/2`), `verdict/2`: which causes explain an unhealthy resource, for certain or possibly, and `urgency/2`: what to fix first. |
| `impact.pl` | What stops working when a resource goes away, for `gr8s doctor impact`. |

Each file declares the facts it expects with `:- dynamic`. A fact that was not
observed is absent, and a call to it fails.

## Lisp

- `rules.lisp`: builds the rule base. It reads the `.pl` files when it is
  compiled, so a syntax error stops the build and a changed rule file rebuilds
  it; it compiles every predicate when it is loaded (`ag-prolog:compile-database`),
  so the dumped `gr8s` image starts with them compiled. `prove` asserts a question's facts, asks, and
  retracts them; `known` asks the rule base alone.
- `live.lisp`: the kubectl reader, the Pod reference facts and the single-report printer.
- `progress.lisp`: the spinner and current step shown on a terminal while a
  survey reads. `progress` names a step; it does nothing unless someone watches.
- `markdown.lisp`: how a report reaches a reader. It is written as Markdown,
  parsed by cl-commonmark, and wrapped and styled by tuition for a terminal, or
  left plain and unwrapped for a pipe. `markdown-text` escapes text from the API.
- `catalog.lisp`, `extended-catalog.lisp`: one resource as the observations the checks
  test. Lisp states what the API holds (a number as itself, a list as `count(N)`) for
  every field the checks of that kind read (`reads/2`); the rules do the comparing.
- `readiness.lisp`, `applications.lisp`, `causal.lisp`, `scheduling.lisp`, `logs.lisp`,
  `impact.lisp`: the facts for `pods.pl`, `applications.pl`, `relations.pl`,
  `scheduling.pl`, `logs.pl` with `access.pl`, and `impact.pl`.
- `pod-events.lisp`: facts read on demand for a troubled Pod: its recent Events and
  the log of a run that crashed, attached to the finding they explain, bounded.
- `doctor.lisp`: command parsing, dependency traversal, grouping and request budgets.
- `survey.lisp`: one LIST per kind, the dependency graph between the resources read,
  causes with the symptoms they explain, what has recovered, and the report as Markdown.

Lisp builds the dependency graph between the resources it read and states it as
`depends/2` and `hint/2` facts; `verdict/2` decides what explains what.

### What the explanation rules cost

`tests/doctor/explanation-benchmark.lisp` times `verdict/2` against
the same search written in Lisp and checks that they agree. On one laptop:

| Cluster | Symptom targets | Prolog | Lisp |
| --- | --- | --- | --- |
| 3,350 resources, one workload in ten failing | 300 | 0.02 s | 0.008 s |
| 3,350 resources, one node in ten not ready | 720 | 0.03 s | 0.006 s |
| 3,350 resources, everything failing | 3,000 | 0.07 s | 0.63 s |
| 6,700 resources, everything failing | 6,000 | 0.16 s | 2.6 s |
| 16,750 resources, one workload in ten failing | 1,500 | 0.12 s | 0.16 s |

The rules are thirty lines and say what they mean, and they cost a few
hundredths of a second at these sizes. That depends on two things. ag-prolog
0.3.0 finds an asserted fact through an index on its first argument; before
that it scanned the predicate's clauses, and the last row took 6.0 s. And each
fact puts first the argument the rules will know: `depends(Resource, On)`,
`cause_at(Resource, Cause)`. With `cause_at` the other way round the third row
took 2.2 s. The Lisp search in
`tests/doctor/explanation-reference.lisp` is what the rules are
checked against: every survey test runs it beside them.

## Adding a rule

A single-resource check is one `check/5` fact in `catalog.pl`, if the
observation it tests is already projected (see `resource-observations`). A new
kind of fact needs a `:- dynamic` declaration in the rule file and a line in the
Lisp collector that asserts it. Predicate names use underscores on both sides:
the atom `pod_not_ready` is the Lisp symbol `pod_not_ready`.

## Running and testing it alone

`gr8s-doctor.asd` here is the doctor as a system of its own, so it loads in a
couple of seconds without the rest of gr8s. `scripts/gr8s-doctor` runs it from
source, and `make test-doctor` runs the tests in `tests/doctor/`:

| File | Checks |
| --- | --- |
| `references-test.lisp` | Required Secrets and ConfigMaps, against fixture readers. |
| `catalog-test.lisp` | Every check holds on its full evidence, fails without any premise, and is reached from real API JSON. |
| `doctor-test.lisp` | Command parsing, grouping, budgets, readiness, Events and report text. |
| `causal-test.lisp` | Cross-resource rules and list reuse. |
| `survey-test.lisp` | Causes and symptoms, chains, scheduling, logs, access, applications, impact. Every survey is explained by the rules and by `explanation-reference.lisp`, and the two must agree. |
| `cli-test.py`, `diagnose-cli-test.py` | The command line against a fixture `kubectl`; `--server` and `--binary build/gr8s` run the full program. |
| `acceptance.py` | Fault and recovery scenarios against a disposable cluster. |
| `explanation-benchmark.lisp` | Times the explanation rules against the Lisp reference on synthetic clusters. |

See `docs/doctor.md` for operator usage and coverage.
