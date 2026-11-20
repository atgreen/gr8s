# Doctor

```sh
gr8s doctor                                      # help; no host probes
gr8s doctor diagnose                             # everything you can see
gr8s doctor diagnose -n production               # one namespace
gr8s doctor diagnose deployment/web -n production
gr8s doctor diagnose pod/web -n production --kubeconfig FILE --json
gr8s doctor diagnose --notes                     # also list configuration notes
gr8s doctor diagnose --markdown > report.md      # the report as Markdown
gr8s doctor impact node/worker-1                 # what stops if this goes away
gr8s doctor impact secret/db-password -n production
gr8s doctor host --state-directory /var/lib/gr8s   # existing host checks
```

`diagnose` only issues kubectl GET requests (`checkup` is an alias for `diagnose` without a target). `--kubeconfig FILE` selects
a configuration; without it kubectl uses its own default (`KUBECONFIG` or
`~/.kube/config`). `--context NAME` selects a context within it. They reject `--fix`.
The host subcommand retains the original host behavior, including opt-in `--fix`;
legacy forms such as `doctor --state-directory DIR --fix` continue to work.

Host cluster-port checks describe explicit runtime TCP port rules on each recorded
endpoint's local IPv4 interface. Missing explicit rules produce a warning, not a
proven packet-drop diagnosis: services, rich rules, zone targets and policies can
also affect traffic. A zone named `trusted` is not sufficient evidence of admission.
Failed queries and endpoints that cannot be mapped locally report unknown coverage.
These checks do not test reachability from a peer or modify firewall rules.
Host tool observations have a five-second command deadline and a limit of
1,048,576 output characters. Incomplete output is discarded; firewall and address
queries report unknown coverage when a command times out or exceeds the limit.
The configured node listener is recorded separately in
`metadata/server-node-endpoint.json`; its port and interface are checked independently
from Raft. Older state without that record reports unknown node-listener coverage.
These records describe startup configuration, not proof that a listener is running.
Wildcard or nonlocal addresses cannot be mapped to one local IPv4 interface and
remain explicitly unchecked.

A source-only runner, `scripts/gr8s-doctor`, runs the same diagnosis/checkup code
without loading the entire gr8s server. It does not run host checks. It requires
SBCL, kubectl and the pinned Lisp dependencies (`make deps` at the repository
root restores them, ag-prolog among them).
Native gr8s embeds the Lisp code but still requires kubectl for cluster access.

## Diagnose

Without a target, `diagnose` surveys every supported workload, node, namespace,
storage, Service, EndpointSlice, autoscaler, disruption-budget and
certificate-request resource you can read. With `-n` it surveys one namespace;
cluster-scoped resources are then read only when something in the namespace
names them. Each kind is read with one LIST. When a cluster-wide LIST is refused
or too large, each visible namespace is listed instead; what still cannot be
read is reported as incomplete coverage.

With `KIND/NAME` the same survey runs over the target's namespace (or the cluster
for a cluster-scoped kind) and the report is narrowed to the target, what it
depends on, and the symptoms above it that its problems explain. Supported
prefixes: `pod`, `node`, `event`, `pvc`, `pv`, `deployment`, `replicaset`,
`statefulset`, `daemonset`, `job`, `cronjob`, `hpa`, `csr`, `namespace`, `service`,
`endpointslice`, and `pdb`. Namespace defaults to `default` for a namespaced target.

### Causes and symptoms

The doctor links what it read: a workload depends on the objects it owns (checked
by owner UID), a Service on the Pods its selector matches, an EndpointSlice on its
Service, an autoscaler on its target, a Pod on its Node and claims, and a claim on
its volume. Required Secret and ConfigMap references are checked for every Pod.

Some rules only say that something beneath a resource is unhealthy: the Pod
readiness conditions, replica `-deficit` rules, `deployment-Available-False`,
`deployment-Progressing-False`, `service-no-ready-backends`,
`service-waits-for-label` and the empty or
unready EndpointSlice rules. Such a symptom is explained by any other warning on
the same resource or on a resource it depends on, reached only through resources
that themselves report a warning (Services, ReplicaSets and Jobs are passed
through). A healthy Pod on a troubled Node therefore does not make that Node
explain the Pod's workload.

The report lists problems, not findings. With more than three, it starts with a
one-line list of them. Quoted output is cut to six lines in text; JSON has all of it.

The report is written as Markdown. On a terminal it is rendered with styles and
wrapped to the terminal's width, at most 100 columns; commands are never broken,
so that they can be pasted. `NO_COLOR` turns the styles off. Into a pipe or a
file it is plain text with one line to a paragraph, so that a phrase can be
searched for. `--markdown` writes the Markdown itself, for an issue or a chat.
cl-commonmark parses the Markdown and tuition wraps and styles it
(`src/diagnostics/markdown.lisp`). Text from the API is escaped, and quoted
output is fenced so that nothing in it can end its block. A timestamp in the
text is said as how long ago it was, with the timestamp after it: "50 minutes
ago (2026-11-20T19:26:00Z)", or after "since" as "for 8 hours (since ...)". Quoted output and JSON keep timestamps as they are.

While it reads, the doctor shows a spinner and what it is reading now: a list
of resources, the resource it is checking and how many remain, a crashed
container's last log, a control-plane member. That line goes to standard error
when it is a terminal and is wiped before the report, so a pipe or a file never
holds it (`src/diagnostics/progress.lisp`).

- Problems are listed in the order to fix them. `urgency/2` in `explanation.pl`
  puts a fault of the cluster itself (`foundation/1`: control-plane members that
  disagree) before everything else, and a Service left empty by configuration
  (`deferred/1`) after the workload it waits for. Within those, the order is the
  one below.
- Each problem has a headline: the first clause of its summary, also `title` in JSON.
- "Because of this" has one line for each *other* resource the cause explains.
  Findings that restate the problem on the same resource (the Pod is not ready,
  the restart counter) are in the JSON `impact` only.
- A restart loop that has stopped is not a problem. A container that restarted
  five times but whose current run has lasted an hour and is ready (`settled/2`
  in `pods.pl`) gets `restarted-earlier`, a finding of severity `past`. It is
  listed under the present cause that brought it about, if the rules know one,
  and otherwise under "Recovered" (`recovered` in JSON). Recovered findings do
  not count as problems or change the exit code.
- A cause can reach a resource that no link joins it to. `anywhere/2` says
  which do: members that disagree lead to `api-answered-behind` wherever a
  program gave up on a stale answer, because every program is a client of the
  control plane.

- Each cause is shown once with the symptoms it explains under "Because of this".
- The same finding on several Pods of one workload, or several users of one
  missing Secret or ConfigMap, is one problem naming all of them.
- Causes that explain symptoms on more resources come first; among equals, the one
  whose condition changed first, when the API records that.
- A finding that says why stands for the findings on the same resource that only
  say what: a crash with its exit code and log stands for the restart counter,
  CrashLoopBackOff and the probe failures around it; an application rule stands
  for the failing readiness check it reads. These are `refines/2` in
  `src/diagnostics/rules/explanation.pl`, beside `symptom/1`.
- A cause that another cause brings about is listed under it. `leads_to/2` in
  `explanation.pl` says which do: a node that is down leads to the failing
  probes of the Pods on it, a missing Secret to the container that cannot be
  configured, a pending claim to the Pod that cannot be scheduled.
- A symptom nothing explains is still a problem, marked "No cause was found";
  the deepest such symptom stands for the ones above it.
- Configuration and history advisories are counted, and listed only with `--notes`.

A Service is also loosely linked to Pods that lack only a label its selector asks
for, because some applications label a Pod only once it reaches a certain state.
Symptoms connected to a cause only through such a link are listed under "Possibly
related", marked `"certain": false` in JSON, and do not count towards its reach.

A cause is the deepest finding the doctor could see, not proof of a root cause.
The links establish that two findings are connected, not which came first.

### Facts collected on demand

Most facts come from the surveyed lists. A few are read only when a finding calls
for them:

- **Events.** For a Pod that reports trouble (Ready is False, phase Pending,
  Failed or Unknown, or a container that has restarted five times or waits in
  CrashLoopBackOff), the namespace's Events are listed once and those of the last
  hour about that exact Pod UID are kept, the latest of each kind of occurrence.
  A Warning's message is shown, cut at 800 characters. A probe failure is attached
  to the readiness, startup or liveness finding it explains; other Warnings become
  `event-*` findings, or `pod-warning-event` for a reason outside the catalog.
- **The log of a run that crashed.** For a `restarts-crash` or `restarted-earlier`
  finding the last six lines the previous run wrote are read with
  `kubectl logs --previous`, each cut at 300 characters. In text the logfmt
  fields `ts`, `time` and `caller` are left out of them. A log that cannot be
  read is simply not shown, and the step then says to read it.
- **Application configuration.** For a Service that selects a label a known
  application sets on its own Pods, the ConfigMaps that Pod mounts are read and
  only one fact is kept: whether they mention the setting. Their text is not kept.

Event messages and log lines are the only free text the doctor shows. Anyone who
can run it can already read them, but they may contain whatever a program printed.
An Event list that cannot be read leaves the Pod's report incomplete.

JSON keeps every finding in `groups`, grouped by rule and subject with the
surveyed resources that reach it, and adds `problems` (rule, title, summary, resources,
owner, `causeFound`, `reach` and the explained `impact`), `recovered` (what has
stopped, with `recoveredAt`) and the `notes` count.
It also includes observations, individual reports, list coverage, limits and
unreadable resources. Observation IDs are local to each resource report.

Exit codes: 0 means no problems in checked coverage (notes alone do not count),
1 means problems, 2 means incomplete coverage or an error. No problems is not a
health verdict. Forbidden reads, unavailable APIs and expired collection budgets remain
unknown. A failed resource evaluation produces a `diagnosis-error` observation with
its error class, without raw response or exception text. Other resources retain their
findings; invalid list entries are skipped with incomplete coverage. Successful empty kubectl `--ignore-not-found` responses establish absence.

## Impact

`impact KIND/NAME` follows the same links upwards and says what would stop
working if the resource went away: a node drained or lost, a workload removed,
a Secret, ConfigMap or claim deleted. It reads the same kinds as a survey, of
the target's namespace or of the cluster for a node, and changes nothing.

- **Stops**: a workload all of whose ready Pods go, a Service every Pod of which
  goes, a Pod nothing owns.
- **Runs on fewer Pods**: a workload that loses some of its ready Pods.
- **Keeps running but could not restart**: Pods that require a Secret, ConfigMap
  or claim that is gone. A Secret or ConfigMap is named, never read.
- **A drain would stop at**: a Pod on the node whose PodDisruptionBudget allows
  no disruption now.

It reports what depends on the resource now. It does not check that there is
room for the Pods elsewhere. The rules are `src/diagnostics/rules/impact.pl`.

## Coverage and limits

The rules are 150 status, Event and configuration checks and the groups below.
The checks cover
replica deficits, controller observation lag, namespace termination, endpoint
readiness, restart history, scheduling gates, host/container configuration
advisories, and node pressure taints. The cross-resource rules are listed below.
A catalog comparison is made by the rules from the two counters as read, and requires both. The quota correlation treats an
omitted Deployment availableReplicas count as zero only with current controller
generation, matching the Kubernetes API serialization. Explicit JSON false is distinguished from missing.

The rules, their English explanations and suggested next steps are Prolog source
in `src/diagnostics/rules/`, run by ag-prolog. They are read and compiled when
gr8s is built: a syntax error in a rule file stops the build, and the `gr8s`
binary starts with every predicate compiled. Lisp states what it read from the
cluster as facts and asks the rule base; see `src/diagnostics/README.md`.

### Pod readiness rules

| Rule | Required observations |
| --- | --- |
| `readiness-probe-failing` | Pod condition Ready is False; a container is running, reports `started: true` and `ready: false`, and declares a readinessProbe. |
| `startup-probe-pending` | A running container reports `started: false` and declares a startupProbe. |
| `readiness-gate-unmet` | Pod condition Ready is False and a declared readiness gate has no condition with status True. |
| `restarts-crash` | A container that has restarted five times, or waits in CrashLoopBackOff, whose last run exited with a non-zero code for a reason other than OOMKilled. |
| `restarts-oom` | The same, with a last run whose reason is OOMKilled. The finding names the memory limit. |
| `restarts-liveness-kill` | The same, with a liveness probe, and either a Killing Event that mentions the liveness probe, or a recent liveness failure together with a last exit code of 137 or 143. Two clauses. A failed liveness check beside a run that exited by itself does not establish this. |
| `restarted-earlier` | A container that has restarted five times, whose last run crashed or was OOMKilled, and whose current run began at least an hour ago, is ready and has started. The three rules above then do not hold. Severity `past`. |

These rules describe the probe from the Pod spec, including an exec probe's command
line, and suggest `kubectl exec` and `kubectl logs` commands. The doctor does not
run a probe. Probe output is not in the Pod status; when the kubelet has reported
it in an `Unhealthy` Event, the finding quotes that Event. An absent `ready` or
`started` flag establishes nothing. Definitions live in
`src/diagnostics/rules/pods.pl`.

### Application rules

`src/diagnostics/rules/applications.pl` holds what the doctor knows about particular
programs, recognised by image name: OpenBao and Vault. A rule there reads only what
a generic rule has already shown.

| Rule | Required observations |
| --- | --- |
| `openbao-uninitialized` | A container of a known image whose quoted probe output is a status listing with `Initialized false`. Suggests `operator init`. |
| `openbao-sealed` | The same listing with `Initialized true` and `Sealed true`. Suggests `operator unseal`. |

It also holds what CoreDNS, etcd, PostgreSQL and Redis write before they give
up (`said/3`): a forwarding loop, a data directory from another cluster or
another major version, wrong ownership, a storage quota reached, a damaged log
or append-only file. A phrase counts only from a container that runs that program.

### Scheduling rules

For a Pod that is Pending with no node and no scheduling gate, the doctor reads
every node and the Pods on them and tries each node (`rules/scheduling.pl`).
`pod-unschedulable` is reported only when every node is ruled out, with the first
thing that rules each one out: not ready, cordoned, a `NoSchedule` or `NoExecute`
taint the Pod does not tolerate, a `nodeSelector` label it lacks, no required
node affinity term matched, a requested resource it does not offer, or too
little of one left after what the Pods already on it request. Preferences,
Pod affinity, topology spread and volume placement are not modelled, so a node
these rules accept may still be refused; nothing is concluded then.

### Rules over the log of a run that crashed

The last forty lines of a crashed run are given to `rules/logs.pl`. Each reason
is reported at most once per container and stands for the crash itself.

| Rule | The program wrote |
| --- | --- |
| `watches-unserved-kind` | That it could not list or sync a kind, in words that mean the kind was not found, and the API does not list that kind for the doctor either. |
| `cannot-reach-api` | `connection refused`, on a line about the API server or naming the `kubernetes` Service's address. |
| `api-answered-behind` | `resourceVersion is newer than storage` or `Too large resource version`: an API server refused a read that asked for a state newer than its own. Listed under `members-disagree` when that is found. |
| `connection-refused` | `connection refused` to anything else. |
| `name-not-resolved` | `no such host`. |
| `port-in-use`, `disk-full`, `wrong-architecture` | `address already in use`, `no space left on device`, `exec format error`. |

Rules may ask for facts only the cluster can supply (`asks/1`): whether the API
serves a kind, the address of the `kubernetes` Service, and the bindings and
roles below. The doctor reads them only then.

### Access rules

A line saying a ServiceAccount `is forbidden` to do something is parsed for the
account, verb, resource, API group and scope, and `rules/access.pl` reads the
ClusterRoleBindings and ClusterRoles, and for a namespaced request that
namespace's RoleBindings and Roles.

| Rule | Finding |
| --- | --- |
| `access-not-bound` | No binding that reaches the scope names the account, directly or through the `system:serviceaccounts` groups. |
| `access-verb-missing` | A role it is bound to has a rule for the resource, but none with the verb. The roles are named. |
| `access-not-granted` | It is bound to roles, none of which has a rule for the resource. |

When the roles do allow the request nothing is reported: the refusal is then
older than the roles or comes from something these rules do not read.
Aggregated ClusterRoles are read as the API presents them.

### Cross-resource rules

| Rule | Required observations |
| --- | --- |
| `service-selector-empty` | A selector-bearing Service and a complete namespace Pod list with no matches. |
| `service-waits-for-label` | A selector-bearing Service matches no Pod, but an active Pod in the complete namespace list agrees with most of the selector and lacks the remaining label keys entirely. A different value for a selector key is not a near match. Replaces `service-selector-empty` for that Service. |
| `service-label-never-set` | As `service-waits-for-label`, where every missing label carries a known application's prefix (`openbao-`, `vault-`), the near-matching Pod runs that application and mounts at least one ConfigMap, every mounted ConfigMap is readable, and neither they nor the Pod's plain environment values mention `service_registration`. Replaces `service-waits-for-label`. All Services left empty by one ConfigMap are one problem. |
| `members-disagree` | The `kubernetes` Service in namespace `default` has more than one endpoint, and Namespace `default`, read through each API server in turn, has different `resourceVersion`s. One finding names the member with the highest version, compared as numbers, and every member that differs from it. A member that cannot be reached from where the doctor runs is left out. |
| `service-named-port-missing` | A selected Pod lacks the named targetPort/protocol among regular containers and restartable init containers. Numeric targetPorts and completed Pods are excluded. |
| `service-no-ready-backends` | Selected Pods exist, but all associated EndpointSlices have no ready endpoints. All slices are considered; unspecified readiness cannot prove failure. publishNotReadyAddresses Services are excluded. |
| `pvc-consumer-bypasses-binding` | Pending PVC, WaitForFirstConsumer StorageClass, consuming Pod with nodeName, and no selected-node annotation. This suggests checking for scheduler bypass; nodeName alone does not prove how it was assigned. |
| `hpa-missing-resource-request` | An autoscaling/v1 CPU target or v2 Resource/ContainerResource utilization metric for CPU/memory and a selected running Pod missing the corresponding request. Uses supported apps/v1 workload selectors; absolute-value metrics are excluded. Pod-level requests are honored for whole-Pod metrics; ContainerResource checks only its named container and requires that container's request. DRA request substitution is reported as unsupported. |
| `rollout-quota-rejection` | A current Deployment replica deficit, UID-owned active ReplicaSet with current FailedCreate condition, and a matching Event from the last 15 minutes identifying an existing quota. Arbitrary authorization failures are excluded. |
| `pdb-blocks-healthy-eviction` | A policy/v1 PDB with current observedGeneration, zero disruptionsAllowed, and a selected healthy running Pod. This is an advisory about voluntary eviction, not an outage. |

Definitions live in `src/diagnostics/rules/relations.pl`; observations are generated
in `causal.lisp`. Every finding references the observations supporting its premises.
Related namespace lists are limited to 200 objects and must be complete; partial,
forbidden or incorrectly scoped responses never establish absence. A stale Service
owner UID on an associated EndpointSlice makes that check incomplete. Quota Events
are classified using the standard admission-message marker; their raw messages are not
included in evidence. Recognized Event timestamps must be UTC (`Z`).

Root resource versions are rechecked after diagnosis. Replacement or change discards
that resource's findings. Related resources retain collection timestamps and
versions but are not all re-read; changes between reads remain possible. Collection is not an atomic cluster snapshot; cached
LIST responses are read once per survey and retain their timestamps. They also
answer named reads of the surveyed kinds, so a surveyed resource is one
observation and its version recheck cannot detect a later change; kinds that are
not surveyed, such as Secrets, are still read and rechecked individually. An
object missing from its list is requested by name. Lists remain observations from
their original read, not proof that related objects stayed unchanged. Controller
conditions can lag the spec; previous terminations and Events are historical.

Defaults cap a survey at 2000 resources and traversal at 64 resources per root.
The CLI starts at most 500 API requests and stops starting requests after 120
seconds; an already-running request can take up to 15 more seconds. Each response
is limited to 8 MiB of characters. Reaching limits makes coverage incomplete.
Unsupported APIs are also reported as incomplete, not silently skipped.

`make test-doctor` runs engine tests, positive/negative checks for every catalog
rule, JSON-to-English fixtures, grouping and coverage tests, the native option
parser source, and CLI transport fixtures. Fixtures do not reproduce every rule
as a live cluster failure. `python3 tests/doctor/cli-test.py --server`
runs the same transport fixtures through the full source-server entry point.
Use `python3 tests/doctor/cli-test.py --binary build/gr8s`
to run those fixtures against the dumped native executable.
For real-container acceptance, copy `scripts/test-doctor-native.py` and
`scripts/test-storage-native.py` alongside each other into a disposable Linux VM
with `kubectl` and the native binary. Run as root:

```sh
python3 test-doctor-native.py --binary /root/gr8s
```

The script creates an isolated cluster, exercises causal fault/recovery scenarios,
checks Node pressure across fresh heartbeats, and prints the directory containing
its JSON evidence and server log. It deletes its workloads before stopping the
server. It never uses an existing kubeconfig.

A live loopback API trial with the fake runtime verified Service selector/port and
missing-Secret findings, then their removal after repairs using real kubectl.
A separate disposable Fedora VM trial verified the same transitions with the
dumped native executable and managed containerd, including real container execution
and Secret environment injection through `kubectl exec`. Native CLI transport
fixtures also passed. These trials cover selected failures, not every rule or
every dataplane path.
Pinned downloads were restored through batch installation; the on-demand resolver
bug remains tracked as `podster-i4p`. The full source launcher and core build/test
commands now resolve exact lockfile paths through `scripts/bootstrap.lisp`;
provenance checks cover all 106 entries, including the intentional local TLS shim.
Broader native/VM acceptance remains tracked as `podster-0m1`.
