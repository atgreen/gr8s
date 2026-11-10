# In-process patch levels

## Proposal

A versioned gr8s release can receive ordered patch levels without replacing or
restarting its running process. A signed OCI artifact carries the complete patch
history for one exact release build. gr8s loads the Lisp code into its current
SBCL image using ASDF, applies any declared state migrations, checks health, and
coordinates activation across the cluster.

This document defines the architecture and extension contracts. The implemented
arbitrary Lisp reload path and optional quiescence are documented in
[In-process patching](live-patching.md). Generation switching, cluster migrations,
and activation epochs below remain proposed extensions.

The normal successful path preserves the PID, running containers, and node
identity. A patch may briefly pause a controller or request handler at a declared
safe point. A failed patch may require process restart for recovery. Arbitrary
Lisp side effects cannot be rolled back transactionally.

## Core decisions

1. A patch train belongs to an exact binary build, not just a Kubernetes API
   version. Patch levels are a contiguous, immutable sequence: 0, 1, 2, ... .
2. An artifact for level N contains levels 1 through N. Previously published
   levels retain their original bytes and digests. An installed prefix must
   match before gr8s accepts the suffix.
3. Code loading, durable data migration, and feature activation have separate
   records and lifetimes. Code is reconstructed on every process start. Committed
   migration effects are not repeated blindly.
4. ASDF supplies dependency-aware compilation and loading. gr8s supplies safe
   points, durable migration records, health checks, and rollout coordination.
5. Rollouts are rolling operations, not distributed transactions. Mixed levels
   must be compatible. Behavior that needs cluster-wide agreement stays disabled
   until a durable activation barrier has been crossed.
6. Roll forward by default. A compensating patch is a new level. Dropping the
   desired level does not undo code or data.

## Release and patch identity

A build embeds a patch compatibility ID derived from the release source tree,
locked dependencies, patch ABI, compiler version, architecture, and relevant
compiler options. Release tags and user-visible versions remain useful labels,
but do not substitute for this identity. Multi-architecture releases have an
explicit list of permitted build IDs and independently tested payloads.

A process reports:

```text
base release:       v1.37.2-gr8s.0
build ID:           sha256:...
installed level:    7
loaded level:       7
active epoch:       3
patch chain digest: sha256:...
process boot ID:    ...
```

Installed means durably accepted for reconstruction after restart. Loaded means
successfully installed into this particular process image. Active epoch identifies
cluster-coordinated behavior. A process can be at level 7 while the cluster still
uses epoch 2. Role-inapplicable levels are recorded as verified no-ops, preserving
a single prefix per process. `serve` includes both control-plane and agent roles;
it is one patch target, not two independent code images.

A new binary release starts its own train at level 0 and incorporates prior fixes
in its source. Cross-release upgrade tooling checks the source train's durable
schema and active epoch before replacing binaries. Old patch source is never
replayed onto a different build merely because its version looks compatible.

## OCI distribution

Use an OCI image manifest with a gr8s-specific artifact type and content-addressed
layers. Each artifact contains a data-only JSON index plus patch source and ASDF
system definitions. It contains no runnable container entry point. Registry tags
are conveniences; rollout plans pin the manifest digest.

```text
index.json
patches/0001/patch.json
patches/0001/gr8s-patch-0001.asd
patches/0001/package.lisp
patches/0001/code.lisp
patches/0001/migrations.lisp
patches/0001/checks.lisp
patches/0002/...
...
```

Each level declares its predecessor's chain digest, source hashes, allowed build
IDs, patch ABI, applicable roles, required capabilities, optional safe-point domains, reload mode and descriptive replacement symbols,
health checks, migration IDs, schema compatibility, and whether activation requires
a cluster epoch. The chain hash commits to the predecessor and the canonical
level manifest. The index commits to the complete ordered chain. Reject missing
levels, rewritten history, unknown required fields, and incompatible predecessors.
A corrected level N is published as N+1, never silently overwritten.

Source is authoritative. Optional FASLs are accepted only for an exact supported
compiler/build fingerprint. Otherwise compile locally inside the running Lisp
image. Compilation itself can execute Lisp; it happens only after authorization
and signature verification. Pin dependencies to those embedded in the base build;
there is no ambient Quicklisp/OCICL update during patch loading.

Reuse the verified OCI blob cache and authenticated image distribution swarm for
transport where practical. Artifact pulling and validation need a host-level path
that works before Pods and containerd are ready; containerd image unpacking is not
a startup dependency. Keep patch artifacts pinned independently of workload-image
GC. Support offline import of the same digest-addressed artifact.

## Trust and authorization

Installing a patch grants code execution with gr8s's privileges, normally root.
Only explicit cluster upgrade authority may create or advance a rollout. Ordinary
Pod creation, registry credentials, or permission to create a CRD must not confer
this authority. Provide a dedicated API resource with separate plan, apply,
activate, and recovery authorization checks.

Verify a release-maintainer signature over the artifact digest and patch train
identity using configured trusted public keys. Registry TLS, image hashes, and
node mTLS protect different boundaries and do not replace publisher trust.
Resolve and verify metadata before evaluating any `.asd` or Lisp file. Reject
unsafe archive paths, links escaping the extraction root, duplicate file names,
and undeclared executable content; bound download and extraction sizes.

No network-delivered raw `eval` endpoint is added. The loader accepts only a
verified, approved train suffix and records the requester, digest, plan generation,
process identity, and outcome. Signed patch code is trusted code, not sandboxed
code. Keep the minimal loader, verifier, journal format, and recovery path outside
the first version's patchable surface.

## ASDF's role

Represent each level as a uniquely named ASDF system, for example
`gr8s-patch/build-abc/0007`. Register only the verified artifact's local system
files. Dependencies refer to the embedded base systems and earlier patch systems;
validate the dependency closure against the signed manifest. Use a private output
cache keyed by build ID, chain digest, and compiler fingerprint.

ASDF's normal compile/load operations order components and avoid unnecessary
rebuilds. They do not prove a migration committed, survive a restart as a ledger,
provide thread quiescence, or undo a partial load. `clear-system` also does not
unload definitions. Do not use `:force :all` on the complete gr8s application.
For a fresh process, reconstruct the accepted prefix in order regardless of
previous processes' ASDF bookkeeping.

The base image must register its embedded systems as provided so patch systems
can depend on them without requiring a source checkout. Whether those systems
are immutable must be established in the native build. Patch systems introduce
arbitrary Lisp definitions and effects; they do not ask ASDF to rediscover and
reload the base source tree.

ASDF's own upgrade path provides a useful model: load new definitions, preserve
compatible state, perform version-specific cleanup, and re-enter the requested
operation through its new definition. gr8s adopts that pattern, with optional
subsystem barriers. ASDF's private upgrade hooks are examples to learn from,
not a supported application migration API to call.

## Patch execution and optional quiescence

The default reload mode evaluates publisher-trusted Lisp in the running image.
Functions, methods, classes, globals, and live data may be changed without a
registered replacement boundary. `replaces` is descriptive metadata, not an
allowlist. The patch author owns compatibility, cleanup, synchronization, and
mixed-level behavior; ASDF cannot prove these properties.

The executor persists pending intent before loading the patch ASDF system, then
runs local migration, re-entry, and mandatory health verification. On success it
records the level durably. On restart it loads accepted code in order and uses
checkpoint records to avoid blindly repeating completed durable repairs.

`domains` is optional and defaults to an empty list. Explicitly requested domains
must be registered; they close admission and drain active operations in a fixed
order before evaluation, remain closed through verification, and reopen on success.
The built-in controller-pass barrier remains available. Registration is an optional
coordination facility and does not limit the patch's executable surface.

Without barriers, related definitions can become visible at different times.
Executing frames, retained callbacks, inlined code, object layouts, and other
threads need explicit attention. The publisher may acquire application locks,
pause workers, rebind callbacks, recompile affected callers, and repair state.
No transaction or automatic rollback covers arbitrary Lisp effects. On partial
failure, readiness is withdrawn and requested domains remain closed; without
requested domains there is no automatic global stop of application execution.

Generation switching, activation epochs, and managed cluster migrations below
remain proposed extensions, not prerequisites for ordinary live redefinition.
The current loader rejects descriptors requesting those unimplemented protocols.

## Lifecycle and migration contract

The implemented hooks are `migrate`, `reenter`, and required `verify`, receiving
the local manager context. The following table describes the broader proposed
ABI, including hooks not yet implemented:

| Hook | Execution and contract |
|---|---|
| `preflight` | Read-only compatibility and prerequisite checks before mutation |
| `prepare` | Allocate isolated process-local state; generation mode may load isolated candidate definitions |
| `reload` | Load ASDF definitions, under optional requested quiescence |
| `migrate-local` | Resumable node/process-state transformations with durable checkpoints |
| `migrate-cluster` | Leader-driven, bounded API/store transactions, using stable migration IDs |
| `publish` | Generation mode: publish the prepared generation under the domain barrier |
| `reenter` | Rebuild callbacks/caches; requested domains remain closed |
| `verify` | Local invariants and health checks before reporting success |
| `activate` | Enable behavior gated by a committed cluster epoch |
| `recover` | Inspect a recorded incomplete attempt and resume or refuse safely |

The current manifest selects reload mode for each level. Loading may replace live
definitions directly. Optional requested domains stay closed through migration,
re-entry, and verification. Future generation mode would instead prepare isolated
implementations and publish them through a barrier.

The remaining lifecycle contracts describe proposed extensions.

Hooks receive an explicit context: build ID, roles, process/boot identity, plan
generation, permit, migration store, and operation ID. Deterministic migration
steps use compare-and-swap against expected schema/resource revisions. External
side effects require idempotency keys and an inspect/resume implementation; if
neither is available, the change is not eligible for a live patch.

Cluster migrations are not arbitrary code executed inside Raft apply callbacks.
The leader computes bounded deterministic store operations and commits their
migration checkpoint with the data they modify in the same transaction. If the
store cannot supply that atomic boundary, add it before supporting that migration
class. A leader failover resumes from committed checkpoints. Local file migrations
use write-ahead records, fsync of files and parent directories, and atomic rename
where appropriate. An atomic rename alone is not a durability guarantee.

## Local journal, restart, and failure recovery

Maintain a root-owned content store and append-only patch journal under
`<process-state>/patches/`. The journal records immutable artifact identity,
accepted target prefix, last verified prefix, pending attempt, per-step migration
checkpoints, active epoch, and process boot IDs. `serve` owns the journal for its
combined process; standalone agents and witnesses have their own journals.
Serialize writers with an OS-backed lock that also excludes a second process
using the same state directory.

Before live mutation, persist the pending attempt and ensure the entire accepted
artifact is durable locally. The normal local sequence is:

```text
verified -> staged -> preflight -> prepare -> quiesce
         -> reload (subsystem mode) -> migrate
         -> publish (generation mode) -> reenter -> verify
         -> installed -> reopen admission -> healthy
```

Before the process serves requests or joins normal reconciliation on restart:

1. Verify the binary's train identity and the journal's integrity.
2. Load the code needed to interpret the recorded schema, before opening those
   stores. Bootstrap journal metadata must be readable by the unpatched loader.
3. Reconstruct the accepted code prefix; resume pending migrations from durable
   checkpoints rather than skipping code because a migration row already exists.
4. Recover an incomplete reload or publication under the same barriers, run checks,
   then advertise the actual loaded level and epoch with a new boot ID.

Redefinition/publication, external effects, and fsync cannot be one atomic transaction. A crash
between them leaves a pending attempt. Recovery inspects durable postconditions;
it does not assume either that the patch never ran or that it fully succeeded.
Once a migration has crossed its declared recovery boundary, restarting at the
previous level is forbidden even if that was the last healthy level. Track a
minimum recovery prefix explicitly.

If a live load signals an error after code or state may have changed, mark the
process tainted, stop further rollout, and withdraw affected readiness. Do not
claim that unwinding or reloading old functions restored it. Where the patch's
recovery contract permits, restart the same binary and rebuild the required prefix.
Otherwise remain in a minimal recovery mode with authenticated diagnostics. Missing
or invalid required cached artifacts prevent ordinary startup; never silently boot
unpatched against migrated state. Restore from backup is an explicit disaster
recovery operation, not a routine patch rollback.

Keep previous accepted artifacts and migration recovery metadata until a new
binary release and retention policy make them unnecessary. Avoid automatic
restart loops: bound recovery attempts and report a durable failure reason.

## Cluster coordinator

Add a built-in, cluster-scoped `PatchRollout` resource, plus a durable committed
patch policy. Desired target, immutable plan, activation epoch, migration
checkpoints, grants, and terminal results follow the replicated desired-state
path. Heartbeat metrics remain observations, but a transient healthy observation
alone never advances the durable rollout.

Only the control-plane leader coordinates. Reconcile it after leader changes like
other controllers. Use a store-serialized compare-and-swap to allow one active
rollout for a train. A plan generation freezes the artifact digest, target level,
participant identities/roles, required capabilities, ordering, health gates, and
operator-approved exclusions. A changed plan requires revalidation.

Extend node hello/status with build ID, patch ABI, installed/loaded level, chain
digest, active epoch, boot ID, taint state, and current attempt. Add desired patch
policy and signed-artifact references to the existing node desired-state channel.
Control-plane-only members and witnesses need an authenticated management channel
as well; they must not be omitted because they have no ordinary worker session.
Bind every report to its authenticated process identity and current boot ID.

Each apply grant is committed before delivery and identifies plan generation,
process identity, boot ID, exact next level, and unique attempt ID. A duplicate
grant resumes or returns the recorded result. Grants cover one level only. A
replacement leader adopts outstanding grants and reconciles their outcomes; it
does not free a rollout slot merely because a lease expired. An unreachable process
with an outstanding grant remains potentially changing until it acknowledges a
terminal outcome or is verifiably fenced/stopped. The node checks that a grant is
current before entering its mutation boundary and persists its acceptance.

This conservative grant accounting prevents leader changes, delayed messages, or
network partitions from exceeding disruption limits. Coordinator timeouts pause
progress and expose uncertainty; they are not proof of node failure.

## Rollout protocol

1. **Plan.** Resolve the artifact digest, validate publisher and prefix, inventory
   every process and role, and reject incompatible builds or unsupported safe-point
   domains. Freeze membership for accounting; serialize Raft membership and binary
   upgrades with this rollout. Show availability impact before apply.
2. **Stage.** Distribute and verify the artifact across participants without
   evaluating its Lisp. Confirm free space and durable caches.
3. **Canary.** Grant one level at a time to a suitable worker, then a
   control-plane follower when relevant. Observe declared checks for a bounded
   soak period. A control-plane-only patch uses a follower as its first canary.
4. **Roll.** Proceed in role-aware batches, respecting failure domains and
   disruption budgets. Complete each level across its required cohort before
   advancing to the next level; maintain at most adjacent loaded levels among
   healthy admitted participants. Catch up older/offline processes in isolation.
5. **Migrate and activate.** Perform the level's leader-only expansion migrations
   at its declared barrier. After all required processes durably support the new
   behavior, commit the epoch and distribute activation. An ack lost after apply
   is resolved from the participant's journal, not by issuing unrelated new work.
6. **Complete.** Require fresh, boot-bound reports at the target level and epoch,
   passing health gates, and no unresolved grants. Retain the plan and audit log.

Workers default to one changing process per failure domain, with a bounded global
maximum. A combined `serve` process consumes both control-plane and worker budgets.
Control-plane voters and witnesses roll one at a time, counting already unhealthy
and uncertain members. Keep a healthy quorum after removing the next target from
service; quorum is based on voting membership, not just API-serving nodes.

Patch followers before the leader. Before patching the leader, transfer leadership
to a healthy upgraded voter. If leadership transfer is unavailable, pause and
require an explicit maintenance strategy; do not silently kill the leader. A
two-voter-plus-witness cluster counts witness disruption against the same quorum
budget. A single-node cluster has no spare capacity: report the expected brief
control-plane pause and use the local protocol without promising HA.

## Mixed versions and activation

A patch declares which preceding level it can coexist with, the schema it can read
and write, and capability requirements. The initial policy supports only the
adjacent-level rollout described above. Existing behavior continues during the
mixed-level phase. Additive readers must be deployed before new writers are enabled.
Destructive schema changes and removal of old protocol fields need a later binary
release in the first implementation.

Activation is monotonic and durable, but it is not instantaneous across machines.
For changes that need a strong barrier, commit a minimum serving epoch. Each
operation requiring the new semantics must carry/check that epoch; a lagging
process is gated from the affected operation until it catches up. All participants
must already understand the gating protocol before committing the epoch.

Do not infer permission to serve solely from a cached epoch when isolated. Where
stale readers or writers could violate the new semantics, require a renewable,
fenced serving authorization; let old authorizations expire or explicitly revoke
and acknowledge them before activation. If that fencing is not implemented, reject
such a patch and limit epochs to backward-compatible optional behavior.

An offline process remains a rollout participant until it returns or the operator
explicitly removes and fences it. Completion may report an exclusion, but cannot
call that process upgraded. Joining and returning processes must meet committed
minimum build/level/epoch requirements before scheduling, leadership eligibility,
or incompatible service. A newly started process loads its cached required prefix
before opening normal listeners and synchronizes policy before admission.

## Pause, abort, and repair

Pause prevents new grants. An already accepted local mutation runs to a safe
terminal point; cancellation cannot interrupt arbitrary evaluation or migration.
Abort closes the rollout without rewinding completed levels. Preserve the minimum
required level, schema, and epoch; show the resulting mixed-level inventory.

Publish a compensating patch for a bad change. If a process cannot stay healthy
long enough to accept it, use authenticated local recovery to stage the approved
artifact and restart into the recoverable prefix. Never disable signature or
history checks as an automatic recovery action. A patch that needs an actual
downgrade must declare and test a separate restoration procedure.

## Proposed operator experience

```text
gr8s patch inspect REGISTRY/patches@sha256:...
gr8s patch plan REGISTRY/patches@sha256:... --level 7
gr8s patch apply PLAN_ID
gr8s patch status [ROLLOUT_ID]
gr8s patch pause ROLLOUT_ID
gr8s patch resume ROLLOUT_ID
gr8s patch abort ROLLOUT_ID
gr8s patch history --node NODE
gr8s patch import FILE --state-directory DIR
```

Plan output includes exact source and destination prefixes, roles, migrations,
reload modes, required safe points, batch order, quorum calculations, exclusions, activation
requirements, and restart/recovery implications. Application approves that exact
plan generation. `status` distinguishes staged, loaded, installed, active, tainted,
blocked, and unreachable processes, including the current hook and last error.
Expose the same inventory through the API and metrics. Preserve the existing base
version reporting and add structured patch identity; do not overload the Kubernetes
API version with a claim about patch compatibility.

## Implementation boundaries

- New `src/patch/` subsystem: manifest verification, artifact storage, journal,
  lifecycle ABI, subsystem registry, optional generation dispatch, and local executor.
- `src/server/main.lisp`: early bootstrap recovery for `serve`, `agent`, and
  `witness`, ahead of affected stores and ordinary listeners; proposed CLI commands.
- `src/apiserver/node-session.lisp` and `proto/gr8s/node/v1/node.proto`: additive
  capability, policy, grant, and boot-bound result messages, with regenerated bindings.
- Replicated resource/store integration: built-in rollout resources, deterministic
  migration/checkpoint transactions, active plan CAS, and committed grants.
- `src/raft/transport/`: coordination with leadership and membership changes,
  management of members without worker sessions. The Raft core stays unpatched.
- `src/image-distribution/`: reuse blob verification and peers, adding startup-safe
  artifact fetch/import rather than treating patch content as container images.
- Controller and API boundaries: stable supervisors, admission/quiescence controls,
  reload and re-entry hooks, optional generation dispatch, and post-patch checks.
  Instrument a small surface first.
- `src/version.lisp`: structured base-build and runtime patch identity.

Existing source is authoritative for these integration points. Several older design
documents describe earlier architectures; do not use them as evidence that a
required transaction, lease, or leadership-transfer primitive already exists.

## Delivery and validation

First ship a release with the loader, journal, supported entry points, and patch
ABI embedded. An older binary cannot acquire this protocol retroactively without
a separately audited bootstrap procedure.

Start with one controller fix using quiesce/reload/re-enter on a single node,
no durable schema change, and no activation epoch. Its supervisor stays outside
the replacement set. Add generation mode when an identified subsystem needs it. Prove that a successful update preserves PID and
Pod identity, survives restart with the patched behavior, and recovers each
injected crash boundary. Then add signed OCI distribution and ASDF exact-build
checks; cluster inventory, committed grants, and role-aware rolling application;
finally resumable migrations and compatible activation. Strong incompatible epoch
barriers wait for enforceable serving fences.

Required acceptance coverage includes wrong signatures/builds, rewritten prefixes,
missing source, compiler/load failures, inline and captured-callback behavior,
quiescence timeout, an old operation returning to the supervisor, partial ASDF
redefinition, state preservation, callback/cache reconstruction, blocked external
callers during reload, concurrent requests across publication, disk-full/fsync errors,
crash after every journal boundary, offline restart, duplicate grants, lost acks,
coordinator failover, network partitions, stale boot reports, membership changes,
combined control-plane/worker roles, witness quorum, canary failure, and artifact
GC. Test source and FASL paths separately. Use disposable root VMs for native,
container, BPF, and multi-process failure tests.

A patch release pipeline must test both level-by-level rollout and reconstruction
of every supported prefix from the base binary. Migration suites cover retries
and interruption; mixed-level suites cover protocol and store compatibility.
Publish the support/recovery contract and test evidence alongside each patch.

## Language and loader references

- [ASDF upgrade implementation](https://raw.githubusercontent.com/roswell/asdf/master/upgrade.lisp)
  and [operation wrapper](https://raw.githubusercontent.com/roswell/asdf/master/operate.lisp):
  version-specific cleanup and re-entry after self-upgrade.
- [ASDF manual](https://asdf.common-lisp.dev/asdf.html): compile/load operations,
  dependency handling, preloaded systems, and limitations of reloading/unloading.
- [Common Lisp `defun`](https://www.lispworks.com/documentation/HyperSpec/Body/m_defun.htm):
  definition and redefinition semantics.
- [Common Lisp `inline` and `notinline`](https://www.lispworks.com/documentation/HyperSpec/Body/d_inline.htm):
  inline expansion and declarations.
- [SBCL manual](https://www.sbcl.org/manual/): compiler optimizations and supported
  synchronization facilities; validate the exact shipped SBCL build in CI.
