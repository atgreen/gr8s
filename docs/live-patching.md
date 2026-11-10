# In-process patching

gr8s can load ordered Lisp patch levels into a running process through ASDF.
Successful patches preserve the PID and running containers. Each patch belongs to
an exact base build and extends an immutable history. A cumulative signed OCI
artifact contains every level through its published target.

## Operator workflow

Use the local administrative listener or an authenticated HTTPS API endpoint.
Local patch commands require the root-owned token in
`<state>/patches/admin.token`. The CLI reads the default state location's token,
`GR8S_PATCH_TOKEN`, or an explicit `--token-file FILE`/`--token TOKEN`.
An HTTPS ServiceAccount needs permission to create `gr8s.io/patchrollouts` plus
the specific `patchrollouts/inspect`, `/plan`, `/apply`, `/status`, `/history`,
`/pause`, `/resume`, or `/abort` action. Ordinary workload permissions do not
authorize code upgrades. Use `--ca-file FILE` with a private HTTPS CA.

```sh
# Inspect the signed history; no patch Lisp is evaluated.
gr8s patch inspect ghcr.io/atgreen/gr8s-patches:v1.37.2-gr8s.0

# Resolve and freeze the digest, target, inventory, and soak policy.
gr8s patch plan ghcr.io/atgreen/gr8s-patches:v1.37.2-gr8s.0 --level 7

# Apply the returned plan ID. Closing this terminal does not stop the rollout.
gr8s patch apply patch-PLAN_ID --watch

gr8s patch status
gr8s patch status patch-PLAN_ID --watch
gr8s patch pause patch-PLAN_ID
gr8s patch resume patch-PLAN_ID
gr8s patch abort patch-PLAN_ID
gr8s patch history --node worker-1
```

All commands accept `--server URL` and `--json`. `plan --soak SECONDS` configures
the health observation interval after each process update (default 60 seconds).
Planning preflights the signed index against every participant's trust policy,
build, installed prefix, and available patch domains. Changes in membership,
process boot identity, or health pause the rollout. A paused plan still reserves
its unresolved grants. Timeout does not imply that remote execution stopped.

Apply stages all content, patches a worker first, then witnesses/control-plane
followers, and finally the leader. Processes update serially, and the cluster
completes each level before starting the next. This supplies a conservative
canary and disruption budget. HA checks voting quorum and transfers leadership to
a caught-up, healthy, already patched voter before patching the old leader. A
single voting member uses a brief local subsystem pause.

Abort stops new grants and preserves installed levels. An accepted in-flight
patch finishes or remains reserved if its result is uncertain. Correct a bad patch
by publishing the next level. There is no automatic downgrade of code or data.

`gr8s version --state-directory DIR` reports the base release and installed patch
level. `/version` includes a `gr8sPatch` object with the current process's loaded
and installed levels, build and boot IDs, chain, domains, and health.

## Publisher trust and offline distribution

Configure `<state>/patches/trusted-keys.json` on every process before rollout:

```json
{"release-maintainer": "64-lowercase-hex-characters-of-Ed25519-public-key"}
```

The directory is private and the loader creates state/content files with mode
0600. Configure trusted keys through the host's administrative provisioning;
registry credentials and node certificates cannot add a publisher.

An OCI manifest's config is a signed index envelope. Ed25519 signs the exact index
bytes; the index commits to the build, ordered level descriptors, and every source
layer digest. Manifest and layer digests are verified as well. Thus publisher
trust covers the executable content and its semantics, while the approved plan
pins the outer artifact digest. Tags are resolved only during inspection/planning.

Public HTTPS registries with anonymous Bearer-token challenges and local OCI image
layouts are supported. For private registries, import an OCI layout through the
host's authenticated image tooling. The initial implementation transfers verified
blobs over authenticated gr8s management channels; it does not require containerd
or a Pod to unpack patches. Patch content has its own retention directory and is
not collected with workload images.

```sh
gr8s patch import /path/to/oci-layout --state-directory /var/lib/gr8s
```

Offline import verifies and caches content without evaluating it. It requires the
process using that state directory to be stopped. For a new/repaired process that
must join an already patched cluster, add `--level N` to authorize reconstruction
through that level on its next start. This records a bootstrap target without
evaluating patch code in the importing CLI process. To use a local layout on a
running cluster, pass its path to `inspect`/`plan` through the administrative API;
the path must be readable on the control-plane host. Other participants receive
the verified blobs through gr8s.

## Authoring a patch train

The native executable embeds its build ID. A publisher must build patches using
the same release source, dependency lock, compiler, and architecture. Obtain the
running build ID through `/version` and compare it to the artifact before release.
A new base binary begins a new patch train at level 0. For a process that has
never applied a patch, the loader archives its empty old journal and starts the
new train automatically. Upgrading a patched state directory to a different base
build requires an explicit release migration; this initial tool does not infer
that a new binary incorporates an old patch prefix.

`scripts/build-patch.lisp` takes a JSON recipe, a file containing a hex-encoded
32-byte Ed25519 secret seed, and an output OCI-layout directory:

```sh
sbcl --noinform --non-interactive --load scripts/build-patch.lisp \
  --end-toplevel-options recipe.json release-key.hex output-layout/
```

Publish the resulting OCI layout with your registry's OCI artifact tooling. Keep
previously released source bytes and descriptors unchanged when adding levels.

A recipe contains `publisher` and an ordered `levels` array. Each entry supplies:

```json
{
  "publisher": "release-maintainer",
  "levels": [{
    "summary": "Correct the controller pass",
    "mode": "reload",
    "roles": ["control-plane"],
    "system": "gr8s-patch-controller-pass-0001",
    "systemFile": "gr8s-patch-controller-pass-0001.asd",
    "sourceDirectory": "patch-source/0001/",
    "files": ["gr8s-patch-controller-pass-0001.asd", "code.lisp"]
  }]
}
```

Each `.asd` defines a uniquely named `gr8s-patch-...` system and lists its local
source files. Dependencies must already be embedded/loaded. The publisher adds
build identity, ABI, levels, source hashes, and chain hashes before signing. File
paths are flat `.asd`/`.lisp` names; archive extraction and symlinks are not used.

The patch source evaluates ordinary Lisp forms and registers lifecycle hooks. It may
redefine functions, methods or classes, update globals, and repair objects. gr8s
does not enforce a replacement allowlist or prove that these changes are compatible.
The publisher owns that compatibility and the synchronization required by the patch.

`domains` is optional and defaults to no automatic subsystem pause. To request a
registered barrier, add `"domains": ["controller-pass"]` to the level. Unknown
requested domains are rejected during preflight. `replaces`, if supplied, is only
descriptive metadata; it does not constrain evaluated Lisp.

For example, register lifecycle hooks after installing definitions:

```lisp
(gr8s.patch:register-patch
 :migrate (lambda (context)
            (declare (ignore context))
            (gr8s.patch:checkpoint
             "repair-local-record"
             (lambda ()
               ;; Inspect and idempotently repair the record here.
               )))
 :reenter (lambda (context)
            (declare (ignore context))
            ;; Rebuild affected callbacks or caches here.
            )
 :verify (lambda (context)
           (declare (ignore context))
           ;; Return true only while the patched subsystem is healthy.
           t))
```

Migration callbacks must be resumable: a crash can occur after an effect but before
the checkpoint is durable. Code definitions load again on restart, while completed
checkpoint callbacks are skipped. The latest applicable health check also runs
when the process reports inventory, including during the rollout soak interval.
Health checks must be bounded and read-only.

## Execution, synchronization, and recovery

By default, a patch loads into the running image without pausing application
subsystems. It still runs serially through the cluster, with signature checks,
durable intent, lifecycle hooks, and health verification. Related forms are not
an atomic transaction: other threads may observe intermediate definitions or data.
Existing calls and retained function objects may continue using old code; inline
callers may require explicit recompilation. Class redefinition does not establish
application invariants automatically. Authors must arrange any necessary locks,
worker pauses, callback rebinding, object repairs, and compatible mixed-level behavior.

For patches requesting domains, the supervisor closes admission and waits for
active operations to return before loading. It keeps those domains closed through
migration, re-entry, and verification, then resumes. The built-in production domain
is `controller-pass`. These barriers protect only operations participating in them;
they do not restrict what the Lisp code can redefine. Roles still determine where
code runs; nonapplicable processes record the level as a verified no-op.

Code definitions and top-level forms execute again on restart. Put durable one-time
repairs in resumable checkpoint hooks, and reconstruct process-local state on every
load or in re-entry. A checkpoint can repeat after a crash before its completion
record is written. Health checks remain required.

The loader accepts reload mode and local resumable checkpoints. It rejects declared
cluster migrations, nonzero activation epochs, and generation-switch mode because
it does not implement those coordination protocols. Arbitrary Lisp can have wider
effects, but no automatic shared-state transaction, cluster-wide atomic transition,
or compatibility proof is provided. Runtime payload replacement still needs its
own lifecycle tooling. The broader extension contracts are in
[the design](design-live-patching.md).

A partial load or failed post-load check taints the process, keeps any requested
domains closed, and withdraws API readiness. Without requested domains, application
threads can continue to execute partially changed code; readiness withdrawal is
not a global execution barrier. Its pending attempt remains durable.
On restart, the exact base binary verifies cached content, reconstructs accepted
code in order, and recovers the pending level before opening normal services.
Missing content, revoked publisher trust, or a different build prevents startup;
it never silently falls back to unpatched code against modified state. Three
consecutive unsuccessful bootstrap attempts require administrative inspection and
repair rather than an automatic retry loop. Preserve the journal, content cache,
and any required migration backups during recovery.

## Validation

`make test-patches` runs the focused suite inside an ASDF test operation. The same
signature, prefix, reload, checkpoint, recovery, authorization, and rollout-state
tests are included in `make test`. `make test-live-patching` runs three independent
fake-runtime control planes, verifies their PIDs survive the rollout, exercises
leadership handoff, and restarts a process to check reconstruction. Run the same
harness with `--witness` for two voters plus a witness, or `--gr8s build/gr8s` to
exercise the native executable without a source checkout in its working directory.
These tests do not load BPF or run real containers; use the project's disposable
VM workflow for runtime and dataplane tests.

See the [validation record](live-patching-validation-2026-11-09.json) for observed
results and the separately tracked baseline suite failures.
