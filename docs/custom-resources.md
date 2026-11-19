# Custom resources

The `apiextensions.k8s.io/v1` CustomResourceDefinition API accepts JSON and
checksum-pinned typed Kubernetes protobuf requests. It installs schema-backed
JSON resource routes. A definition becomes Established only after its group,
names, scope, versions, and structural schemas pass admission. Its served
versions appear in discovery. Their custom object and list schemas and
CRUD/status paths appear in OpenAPI v2 and v3. Definitions remain scoped to their
own durable store rather than entering a process-global user registry. Discovery
uses Kubernetes version priority, preserving native storage and workload groups.

Custom objects support create, read, list, update, JSON merge/JSON patches,
delete and collection deletion. Namespaced collections also support cluster-wide
lists. Resource versions enforce optimistic updates and delete preconditions.
The shared durable journal provides resumable watches, selector transitions,
consistent pagination and restart recovery. Watches, signed continuations and
exact historical reads remain bound to the actual CRD UID, so recreating a
definition cannot expose data from its predecessor. Group/plural storage identifiers and
explicit persisted custom entries keep equal kinds and plurals in different
groups separate from one another and from builtin resources.

Supported structural schemas apply recursive defaults and unknown-field pruning,
including marked preserved subtrees. Validation covers types, required fields,
enums, numeric/string/array/object bounds, patterns, nullable fields, logical
constraints and map/set list identities. `x-kubernetes-validations` CEL rules
are typed against their schema at admission, refused when they do not compile or
exceed upstream's estimated-cost limits, and enforced on every write with
`self`/`oldSelf` under the per-rule and per-request cost budgets. Unknown schema
keywords fail admission. A validation format outside the Kubernetes registry
validates nothing upstream either, so it is admitted and ignored rather than
refused.

Served versions share object UIDs and one storage identity. Conversion strategy
None changes the API version without transforming fields; strategy Webhook sends
a ConversionReview to the definition's webhook over the admission transport,
never under the store lock. Each version's schema
controls its defaults, pruning and validation. Removing a stored version requires
actual migration first. A declared status subresource isolates status writes from
desired fields and preserves generation. Ordinary writes preserve status. CRD
status writes preserve actual establishment/cleanup conditions and permit retiring
a stored version only after every persisted instance has really left it.

Deleting a definition deletes its actual custom instances. User finalizers block
instance deletion and keep the definition's cleanup finalizer and routes alive.
Owner garbage collection resolves exact custom owner UIDs across declared
versions and respects unknown external kinds. The controller resumes cleanup
after restart. Failed durable writes do not publish route or resource deletion.
A definition can be recreated only
after its previous instances have been removed.

The scale subresource serves autoscaling/v1 Scale reads and writes through each
version's declared replica and selector paths, and appears in discovery.
`additionalPrinterColumns` drive served Table output, with the default Age
column when a version declares none. `selectableFields` admit up to eight scalar
paths and serve custom field selectors, converting through the webhook when the
request version requires it. Server-side apply
(`application/apply-patch+yaml`) manages custom resources and their status with
`managedFields` ownership. Typed apiextensions requests and the OpenAPI v2
document negotiate protobuf; unstructured custom objects themselves require
JSON, as upstream. The native kubectl smoke passes strict creation,
real streamed watches, version identity, restart persistence and finalizer
cleanup without disabling validation. Run it against a dumped executable with:

```sh
python3 scripts/test-crd-api.py --executable build/gr8s
```

The unchanged upstream Kubernetes v1.36 five-case CRD resource focus passes
all five actual specs on the combined native checkpoint. The seven suite hook
entries are excluded from that count. The first failing run and corrected run
retain official archive hashes and clean native exit/zero-shim evidence in
[the focused result](evidence/custom-resources-upstream-2026-11-04.json). This is
supplemental evidence, not a certification result.
