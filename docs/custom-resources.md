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
constraints and map/set list identities. Unknown schema keywords, CEL and
unsupported validation formats fail admission instead of being ignored.

Served versions share object UIDs and one storage identity. Conversion strategy
None changes the API version without transforming fields; each version's schema
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

CEL, conversion webhooks, scale subresources, additional printer columns,
custom field selectors, server-side
apply, protobuf requests for unstructured custom objects, and protobuf OpenAPI
v2 wire negotiation are not implemented. gr8s does not advertise these features.
Unsupported executable schema and conversion
features are rejected. The native kubectl smoke passes strict creation,
real streamed watches, version identity, restart persistence and finalizer
cleanup without disabling validation. Run it against a dumped executable with:

```sh
python3 scripts/test-crd-api.py --executable build/gr8s
```

The unchanged upstream Kubernetes v1.36 five-case CRD resource focus passes
all five actual specs on the combined native checkpoint. The seven suite hook
entries are excluded from that count. The first failing run and corrected run
retain official archive hashes and clean native exit/zero-shim evidence in
[the focused result](custom-resources-upstream-2026-11-04.json). This is
supplemental evidence, not a certification result.
